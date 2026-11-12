from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from .envelope import EnvelopeCheck, KeyPair, KeyRegistry, build_envelope, verify_envelope
from .labels import BOTTOM, Label, join_all, writer
from .policy import FiniteType, Policy

KAPPA = {
    "discovery": "k1",
    "result": "k2",
    "interruption": "k3",
    "async": "k4",
    "continuation": "k5",
    "termination": "k6",
    "request": "req",
}


@dataclass
class Handle:
    id: int
    content: Any
    label: Label
    kind: str
    origin: str
    channel: Optional[str] = None
    typ: Optional[FiniteType] = None
    parents: tuple = ()
    owners: frozenset = frozenset()
    endorsed: bool = False
    note: str = ""

    def __repr__(self) -> str:
        return f"h{self.id}[{self.kind}:{self.origin}]{self.label}"


@dataclass
class Decision:
    allowed: bool
    rule: str
    reason: str = ""
    detail: dict = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.allowed


@dataclass
class GuardConfig:
    mode: str = "borderflow"
    use_exposure: bool = True
    join_declarations: bool = True
    context_join: bool = True
    track_pc: bool = True

    @property
    def enforcing(self) -> bool:
        return self.mode == "borderflow"


class FlowGuard:
    def __init__(self, keypair: KeyPair, policy: Policy, registry: KeyRegistry, config: Optional[GuardConfig] = None):
        self.keys = keypair
        self.me = keypair.principal
        self.policy = policy
        self.registry = registry
        self.config = config or GuardConfig()
        self.contexts: dict[str, Label] = {}
        self.ingested: dict[str, list[int]] = {}
        self.exposure: dict[tuple, Label] = {}
        self.exposure_parents: dict[tuple, list[int]] = {}
        self.epochs: dict[str, int] = {}
        self.isolated: set[str] = set()
        self.handles: dict[int, Handle] = {}
        self.events: list[dict] = []
        self.tamper_evidence: list[dict] = []
        self.endorsement_requests: list[dict] = []
        self._ids = itertools.count(1)
        self._ctx_ids = itertools.count(1)

    def _log(self, kind: str, **data) -> None:
        self.events.append({"event": kind, **data})

    def _new(self, content, label: Label, kind: str, origin: str, **kw) -> Handle:
        h = Handle(next(self._ids), content, label, kind, origin, **kw)
        self.handles[h.id] = h
        return h

    def new_context(self, name: Optional[str] = None) -> str:
        cid = name or f"c{next(self._ctx_ids)}"
        self.contexts[cid] = BOTTOM
        self.ingested[cid] = []
        return cid

    def context_label(self, cid: str) -> Label:
        return self.contexts[cid]

    def _exposure_key(self, remote: str, a2a_ctx: Optional[str]) -> tuple:
        epoch = self.epochs.get(remote, 0)
        if remote in self.isolated:
            return (remote, epoch, a2a_ctx or "")
        return (remote, epoch, None)

    def exposure_of(self, remote: str, a2a_ctx: Optional[str] = None) -> Label:
        return self.exposure.get(self._exposure_key(remote, a2a_ctx), BOTTOM)

    def local(self, content, label: Label, owner: Optional[str] = None, note: str = "") -> Handle:
        owners = frozenset({owner or self.policy.owner})
        return self._new(content, label, "local", owner or self.policy.owner, owners=owners, note=note)

    def planner_output(self, cid: str, content, note: str = "") -> Handle:
        parents = tuple(self.ingested[cid])
        owners = frozenset().union(*[self.handles[p].owners for p in parents]) if parents else frozenset({self.policy.owner})
        return self._new(content, self.contexts[cid], "planner", self.me, parents=parents, owners=owners, note=note)

    def egress(self, remote: str, h: Handle, channel: str, a2a_ctx: Optional[str] = None, wire_content=None, seq: int = 0):
        if self.config.enforcing and not h.label.can_read(remote):
            d = Decision(False, "BF-2", f"{remote} is not a permitted reader of h{h.id} {h.label}")
            self._log("egress-deny", remote=remote, handle=h.id, channel=channel, reason=d.reason)
            return d, None
        key = self._exposure_key(remote, a2a_ctx)
        self.exposure[key] = self.exposure.get(key, BOTTOM).join(h.label)
        self.exposure_parents.setdefault(key, []).append(h.id)
        envelope = None
        if self.config.enforcing:
            content = wire_content if wire_content is not None else {"text": str(h.content)}
            envelope = build_envelope(self.keys, h.label, content, channel, a2a_ctx or "", seq)
        self._log("egress", remote=remote, handle=h.id, channel=channel, label=str(h.label))
        return Decision(True, "BF-2", "permitted"), envelope

    def ingress(self, remote: str, content, channel: str, envelope: Optional[dict] = None, a2a_ctx: Optional[str] = None, wire_content=None, note: str = "") -> Handle:
        key = self._exposure_key(remote, a2a_ctx)
        exposure = self.exposure.get(key, BOTTOM) if self.config.use_exposure else BOTTOM
        parents = tuple(self.exposure_parents.get(key, [])) if self.config.use_exposure else ()
        base = exposure.join(writer(remote))
        wire = wire_content if wire_content is not None else {"text": str(content)}
        if envelope is not None and self.config.enforcing:
            check = verify_envelope(self.registry, envelope, wire, expected_sender=remote)
            if not check.valid:
                self.tamper_evidence.append({"remote": remote, "channel": channel, "reason": check.reason})
        else:
            check = EnvelopeCheck(False, None, None, "absent")
        declared = check.label if check.valid else BOTTOM
        if self.config.join_declarations:
            label = base.join(declared)
        else:
            label = declared if check.valid else base
        owners = {remote} if (check.valid and declared.readers is not None) else set()
        restriction = self.policy.restriction_for(remote)
        if restriction is not None:
            label = label.join(restriction)
            owners.add(self.policy.owner)
        h = self._new(content, label, "remote", remote, channel=channel, parents=parents, owners=frozenset(owners or {remote}), note=note)
        self._log("ingress", remote=remote, handle=h.id, channel=channel, label=str(label), envelope=check.reason)
        return h

    def extract(self, h: Handle, typ: FiniteType, extractor: Callable[[Any], Any]):
        try:
            value = extractor(h.content)
        except Exception as exc:
            return Decision(False, "BF-6", f"extraction failed: {exc}")
        if not typ.validate(value):
            self._log("extract-deny", handle=h.id, value=repr(value), type=typ.name)
            return Decision(False, "BF-6", f"value {value!r} outside {typ.name}")
        out = self._new(value, h.label, "typed", h.origin, typ=typ, parents=(h.id,), owners=h.owners)
        self._log("extract", handle=h.id, out=out.id, type=typ.name, label=str(h.label))
        return out

    def derive(self, fn: Callable[..., Any], inputs: list[Handle], typ: Optional[FiniteType] = None, note: str = "") -> Handle:
        value = fn(*[i.content for i in inputs])
        label = join_all(i.label for i in inputs)
        typed = typ is not None and all(i.typ is not None for i in inputs) and typ.validate(value)
        owners = frozenset().union(*[i.owners for i in inputs]) if inputs else frozenset()
        return self._new(value, label, "derived", self.me, typ=typ if typed else None, parents=tuple(i.id for i in inputs), owners=owners, note=note)

    def deref(self, h: Handle, cid: str):
        if self.config.context_join:
            self.contexts[cid] = self.contexts[cid].join(h.label)
        self.ingested[cid].append(h.id)
        self._log("deref", handle=h.id, context=cid, context_label=str(self.contexts[cid]))
        return h.content

    def invoke(self, sink_name: str, args: dict, cid: str, conditions: Iterable[Handle] = ()) -> Decision:
        sink = self.policy.sinks[sink_name]
        lam = self.contexts[cid]
        conditions = list(conditions) if self.config.track_pc else []
        values = {k: v.content for k, v in args.items()}
        detail = {"sink": sink_name, "context": str(lam), "args": {k: str(v.label) for k, v in args.items()}}
        if self.config.enforcing:
            if not lam.writers <= sink.trust:
                return self._deny_sink(sink_name, "context", f"context writers {sorted(lam.writers - sink.trust)} not trusted for {sink_name}", detail)
            for cond in conditions:
                if cond.label.writers <= sink.trust:
                    continue
                if cond.typ is not None and isinstance(cond.typ, sink.pc_exempt_types) and cond.typ.validate(cond.content):
                    continue
                return self._deny_sink(sink_name, "pc", f"branch condition h{cond.id} carries untrusted writers {sorted(cond.label.writers - sink.trust)}", detail)
            for name, h in args.items():
                if h.label.writers <= sink.trust:
                    continue
                t = sink.exempt.get(name)
                if t is not None and h.typ is not None and t.validate(h.content):
                    continue
                return self._deny_sink(sink_name, "argument", f"argument '{name}' carries untrusted writers {sorted(h.label.writers - sink.trust)}", detail)
            audience = sink.audience(values)
            conf = lam.join(join_all(a.label for a in args.values()))
            if not conf.readers_include(audience):
                return self._deny_sink(sink_name, "audience", f"audience {sorted(audience)} not within readers {conf}", detail)
        result = sink.effect(values) if sink.effect else None
        self._log("invoke", sink=sink_name, args={k: repr(v) for k, v in values.items()}, context=str(lam))
        return Decision(True, "BF-5", "permitted", {**detail, "result": result})

    def _deny_sink(self, sink: str, part: str, reason: str, detail: dict) -> Decision:
        self._log("invoke-deny", sink=sink, part=part, reason=reason)
        return Decision(False, "BF-5", reason, {**detail, "part": part})

    def request_endorsement(self, h: Handle, reason: str) -> dict:
        req = {"handle": h.id, "label": str(h.label), "content": h.content, "reason": reason}
        self.endorsement_requests.append(req)
        return req

    def endorse(self, h: Handle, endorser: str, approve: bool, initiating_cid: Optional[str] = None):
        if endorser not in self.policy.endorsers:
            return Decision(False, "BF-4", f"{endorser} is not an endorser")
        if initiating_cid is not None and not self.contexts[initiating_cid].writers <= self.policy.trusted_initiators:
            return Decision(False, "BF-4", "relabelling initiated from a tainted context")
        if not approve:
            return Decision(False, "BF-4", "endorser declined")
        out = self._new(h.content, Label(h.label.readers, frozenset({endorser})), "endorsed", endorser, typ=h.typ, parents=(h.id,), owners=h.owners, endorsed=True)
        self._log("endorse", handle=h.id, out=out.id, endorser=endorser)
        return out

    def declassify(self, h: Handle, add_readers: Iterable[str], owner: str, approve: bool, initiating_cid: Optional[str] = None):
        if owner not in h.owners:
            return Decision(False, "BF-4", f"{owner} does not own the reader policy of h{h.id}")
        if initiating_cid is not None and not self.contexts[initiating_cid].writers <= self.policy.trusted_initiators:
            return Decision(False, "BF-4", "relabelling initiated from a tainted context")
        if not approve:
            return Decision(False, "BF-4", "owner declined")
        readers = None if h.label.readers is None else h.label.readers | frozenset(add_readers)
        out = self._new(h.content, Label(readers, h.label.writers), "declassified", owner, typ=h.typ, parents=(h.id,), owners=h.owners, endorsed=True)
        self._log("declassify", handle=h.id, out=out.id, owner=owner)
        return out

    def attest_isolation(self, remote: str, endorser: str) -> Decision:
        if endorser not in self.policy.endorsers:
            return Decision(False, "BF-4", "isolation claim not endorsed")
        self.isolated.add(remote)
        return Decision(True, "scope", f"context scope enabled for {remote}")

    def reset_epoch(self, remote: str, endorser: str) -> Decision:
        if endorser not in self.policy.endorsers:
            return Decision(False, "BF-4", "memory-wipe claim not endorsed")
        self.epochs[remote] = self.epochs.get(remote, 0) + 1
        return Decision(True, "scope", f"epoch {self.epochs[remote]} for {remote}")


class ServerGuard:
    def __init__(self, keypair: KeyPair, registry: KeyRegistry, own_label: Label):
        self.keys = keypair
        self.me = keypair.principal
        self.registry = registry
        self.own_label = own_label
        self.contexts: dict[str, Label] = {}
        self.events: list[dict] = []

    def admit(self, a2a_ctx: str, sender: Optional[str], declared: Iterable[Label]) -> Decision:
        if sender is None:
            self.events.append({"event": "admit-deny", "ctx": a2a_ctx, "reason": "unauthenticated sender"})
            return Decision(False, "BF-7e", "unauthenticated sender")
        if a2a_ctx in self.contexts and not self.contexts[a2a_ctx].can_read(sender):
            self.events.append({"event": "admit-deny", "ctx": a2a_ctx, "sender": sender})
            return Decision(False, "BF-7e", f"{sender} is not a reader of context {a2a_ctx}")
        lam = self.contexts.get(a2a_ctx, BOTTOM).join(writer(sender))
        for d in declared:
            lam = lam.join(d)
        self.contexts[a2a_ctx] = lam
        self.events.append({"event": "admit", "ctx": a2a_ctx, "sender": sender, "label": str(lam)})
        return Decision(True, "BF-7e", "admitted")

    def outgoing_label(self, a2a_ctx: str) -> Label:
        return self.contexts.get(a2a_ctx, BOTTOM).join(self.own_label)

    def check_egress(self, a2a_ctx: str, recipient: str) -> Decision:
        label = self.outgoing_label(a2a_ctx)
        if not label.can_read(recipient):
            return Decision(False, "BF-2", f"{recipient} not a reader of {label}")
        return Decision(True, "BF-2", "permitted")

    def envelope(self, a2a_ctx: str, content, channel: str, seq: int = 0) -> dict:
        return build_envelope(self.keys, self.outgoing_label(a2a_ctx), content, channel, a2a_ctx, seq)
