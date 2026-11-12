from __future__ import annotations

import random
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Optional

from borderflow.envelope import KeyPair, KeyRegistry, build_envelope
from borderflow.guard import FlowGuard, GuardConfig, Handle
from borderflow.labels import Label
from borderflow.policy import BOOL, BoundedDecimal, Policy, Sink

LOCAL = ["U"]
REMOTES = ["B1", "B2", "B3"]
UNIVERSE = ["U", "A", "B1", "B2", "B3", "PAY"]
AMOUNT = BoundedDecimal(Decimal("0"), Decimal("100"))

MUTANTS = {
    "BorderFlow (all rules)": GuardConfig(),
    "without exposure term (BF-3)": GuardConfig(use_exposure=False),
    "trusting declarations (BF-3)": GuardConfig(join_declarations=False),
    "without context join (BF-1)": GuardConfig(context_join=False),
    "without pc tracking (BF-5)": GuardConfig(track_pc=False),
    "without any checks": GuardConfig(mode="none"),
}


@dataclass
class Oracle:
    parents: dict = field(default_factory=dict)
    acc: dict = field(default_factory=dict)
    source_label: dict = field(default_factory=dict)
    ctx_in: dict = field(default_factory=dict)
    sent: dict = field(default_factory=dict)

    def add(self, h: Handle, parents: tuple, acc: frozenset, source: Optional[Label] = None) -> None:
        self.parents[h.id] = parents
        self.acc[h.id] = acc
        if source is not None:
            self.source_label[h.id] = source

    def ancestors(self, hid: int) -> set:
        seen, stack = set(), list(self.parents.get(hid, ()))
        while stack:
            p = stack.pop()
            if p not in seen:
                seen.add(p)
                stack.extend(self.parents.get(p, ()))
        return seen

    def acc_union(self, ids) -> frozenset:
        out = frozenset()
        for i in ids:
            out |= self.acc[i]
        return out


def _rand_readers(rng: random.Random) -> Optional[set]:
    if rng.random() < 0.15:
        return None
    return {"A"} | {p for p in UNIVERSE if p != "A" and rng.random() < 0.6}


def _sinks(rng: random.Random) -> Policy:
    policy = Policy(owner="U")
    for i in range(3):
        trust = {"U", "A"} | {p for p in REMOTES if rng.random() < 0.3}
        audience = {rng.choice(["PAY", "U", "B1", "B2"])}
        exempt = {"amount": AMOUNT} if rng.random() < 0.6 else {}
        pc_types = (type(BOOL),) if rng.random() < 0.6 else ()
        policy.add_sink(Sink.make(f"s{i}", trust=trust, audience=audience, exempt=exempt, pc_exempt_types=pc_types))
    return policy


def run_trace(config: GuardConfig, seed: int, steps: int = 40) -> dict:
    rng = random.Random(seed)
    keys = {p: KeyPair.generate(p) for p in ["A", "U"] + REMOTES}
    reg = KeyRegistry()
    for k in keys.values():
        reg.register(k)
    policy = _sinks(rng)
    g = FlowGuard(keys["A"], policy, reg, config)
    o = Oracle()
    contexts = [g.new_context("c0"), g.new_context("c1")]
    for c in contexts:
        o.ctx_in[c] = []
    pool: list = []
    violations = {"lemma": 0, "thm1": 0, "thm2": 0}

    def check_lemma(h: Handle) -> None:
        if not h.label.writers >= o.acc[h.id]:
            violations["lemma"] += 1
            return
        for a in o.ancestors(h.id):
            if not g.handles[a].label.flows_to(h.label):
                violations["lemma"] += 1
                return

    for _ in range(steps):
        op = rng.choices(["local", "send", "recv", "deref", "plan", "extract", "derive", "invoke"], [3, 4, 4, 4, 3, 2, 1, 4])[0]
        if op == "local" or not pool:
            label = Label.of(_rand_readers(rng), {"U"})
            value = str(rng.randint(1, 99)) if rng.random() < 0.5 else "text"
            h = g.local(value, label)
            o.add(h, (), frozenset({"U"}), source=label)
            pool.append(h)
        elif op == "send":
            h, remote = rng.choice(pool), rng.choice(REMOTES)
            decision, _ = g.egress(remote, h, "request")
            if decision:
                o.sent.setdefault(remote, []).append(h.id)
                for a in o.ancestors(h.id) | {h.id}:
                    if a in o.source_label and not o.source_label[a].can_read(remote):
                        violations["thm2"] += 1
                        break
        elif op == "recv":
            remote = rng.choice(REMOTES)
            content = {"text": str(rng.randint(1, 99))}
            mode = rng.choice(["none", "raise", "lower", "forged", "tampered"])
            env = None
            if mode == "raise":
                env = build_envelope(keys[remote], Label.of({"A", "U"}, {remote, "B2"}), content, "result")
            elif mode == "lower":
                env = build_envelope(keys[remote], Label.of(None, []), content, "result")
            elif mode == "forged":
                env = build_envelope(keys[remote], Label.of(None, ["U"]), content, "result")
                env["snd"] = "U"
            elif mode == "tampered":
                env = build_envelope(keys[remote], Label.of(None, []), {"text": "other"}, "result")
            h = g.ingress(remote, content["text"], "result", env, None, content)
            parents = tuple(o.sent.get(remote, []))
            o.add(h, parents, frozenset({remote}) | o.acc_union(parents))
            pool.append(h)
        elif op == "deref":
            h, c = rng.choice(pool), rng.choice(contexts)
            g.deref(h, c)
            o.ctx_in[c].append(h.id)
        elif op == "plan":
            c = rng.choice(contexts)
            h = g.planner_output(c, "plan-text")
            parents = tuple(o.ctx_in[c])
            o.add(h, parents, o.acc_union(parents) or frozenset())
            pool.append(h)
        elif op == "extract":
            src = rng.choice(pool)
            out = g.extract(src, AMOUNT, lambda v: Decimal(str(v)) if str(v).isdigit() else Decimal("-1"))
            if isinstance(out, Handle):
                o.add(out, (src.id,), o.acc[src.id])
                pool.append(out)
            flag = g.derive(lambda v: Decimal(str(v)) > 50 if str(v).isdigit() else False, [src], BOOL)
            o.add(flag, (src.id,), o.acc[src.id])
            pool.append(flag)
        elif op == "derive":
            typed = [h for h in pool if h.typ is not None]
            if len(typed) >= 2:
                a, b = rng.sample(typed, 2)
                out = g.derive(lambda x, y: min(x, y) if not isinstance(x, bool) and not isinstance(y, bool) else False, [a, b], AMOUNT)
                o.add(out, (a.id, b.id), o.acc[a.id] | o.acc[b.id])
                pool.append(out)
        elif op == "invoke":
            sink = rng.choice(list(policy.sinks.values()))
            c = rng.choice(contexts)
            args = {"amount": rng.choice(pool), "memo": rng.choice(pool)}
            conds = [rng.choice(pool)] if rng.random() < 0.5 else []
            if g.invoke(sink.name, args, c, conditions=conds):
                bad = False
                if not o.acc_union(o.ctx_in[c]) <= sink.trust:
                    bad = True
                for name, h in args.items():
                    if o.acc[h.id] <= sink.trust:
                        continue
                    t = sink.exempt.get(name)
                    if not (t is not None and h.typ is not None and t.validate(h.content)):
                        bad = True
                for h in conds:
                    if o.acc[h.id] <= sink.trust:
                        continue
                    if not (h.typ is not None and isinstance(h.typ, sink.pc_exempt_types) and h.typ.validate(h.content)):
                        bad = True
                audience = sink.audience({})
                sources = set(o.ctx_in[c])
                for h in args.values():
                    sources |= {h.id}
                for s_ in list(sources):
                    sources |= o.ancestors(s_)
                for s_ in sources:
                    if s_ in o.source_label and not o.source_label[s_].readers_include(audience):
                        bad = True
                if bad:
                    violations["thm1"] += 1
    for h in pool:
        check_lemma(h)
    return violations


def campaign(traces: int = 10000, steps: int = 40) -> dict:
    results = {}
    for name, cfg in MUTANTS.items():
        totals = {"lemma": 0, "thm1": 0, "thm2": 0}
        failing = 0
        first = None
        for seed in range(traces):
            v = run_trace(cfg, seed, steps)
            if any(v.values()):
                failing += 1
                if first is None:
                    first = seed
            for k in totals:
                totals[k] += 1 if v[k] else 0
        results[name] = {"traces": traces, "failing_traces": failing, "first_failing_seed": first, **{f"traces_violating_{k}": n for k, n in totals.items()}}
    return results
