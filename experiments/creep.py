from __future__ import annotations

import random
import statistics

from borderflow.envelope import KeyPair, KeyRegistry
from borderflow.guard import FlowGuard, GuardConfig
from borderflow.labels import Label
from borderflow.policy import Policy

PARTNERS = ["X1", "X2", "X3", "X4", "X5"]
ALLOWS_C = {"X1": True, "X2": True, "X3": True, "X4": False, "X5": False}
SINK_TRUST = frozenset({"U", "A", "B"})
STRATEGIES = ["principal", "context", "epoch", "identities"]


def _guard(name: str) -> FlowGuard:
    kp = KeyPair.generate(name)
    reg = KeyRegistry()
    reg.register(kp)
    return FlowGuard(kp, Policy(owner="U", endorsers=frozenset({"U"})), reg, GuardConfig())


def simulate(strategy: str, steps: int = 200, p_partner: float = 0.5, group: int = 5, epoch: int = 20,
             identities: int = 3, seed: int = 0) -> list:
    rng = random.Random(seed)
    guards = [_guard(f"A{i}") for i in range(identities if strategy == "identities" else 1)]
    if strategy == "context":
        for g in guards:
            g.attest_isolation("B", "U")
    rows = []
    for t in range(steps):
        topic = None
        items = [Label.of({"U", "A", "B", "C"}, {"U"})]
        if rng.random() < p_partner:
            topic = rng.choice(PARTNERS)
            readers = {"U", "A", "B"} | ({"C"} if ALLOWS_C[topic] else set())
            items.append(Label.of(readers, {topic}))
        if strategy == "identities":
            g = guards[1 + PARTNERS.index(topic) % (identities - 1)] if topic else guards[0]
        else:
            g = guards[0]
        if strategy == "epoch" and t > 0 and t % epoch == 0:
            g.reset_epoch("B", "U")
        ctx = f"ctx-{t // group}" if strategy == "context" else None
        for label in items:
            g.egress("B", g.local("payload", label), "request", ctx)
        reply = g.ingress("B", "reply", "result", None, ctx)
        rows.append({
            "t": t,
            "clean": topic is None,
            "forwardable": reply.label.can_read("C"),
            "usable": reply.label.writers <= SINK_TRUST,
        })
    return rows


def summarize(steps: int = 200, seeds: int = 20) -> dict:
    out = {}
    for strategy in STRATEGIES:
        fwd, use, lock = [], [], []
        for seed in range(seeds):
            rows = [r for r in simulate(strategy, steps=steps, seed=seed) if r["clean"]]
            fwd.append(sum(r["forwardable"] for r in rows) / len(rows))
            use.append(sum(r["usable"] for r in rows) / len(rows))
            locked = [r["t"] for r in rows if not r["usable"]]
            lock.append(locked[0] if locked else steps)
        out[strategy] = {
            "clean_forwardable": statistics.mean(fwd),
            "clean_usable": statistics.mean(use),
            "first_locked_clean_reply_median": statistics.median(lock),
        }
    return out


def curve(strategy: str, steps: int = 200, seeds: int = 20, window: int = 10) -> list:
    hits = [0.0] * steps
    counts = [0] * steps
    for seed in range(seeds):
        for r in simulate(strategy, steps=steps, seed=seed):
            if r["clean"]:
                hits[r["t"]] += r["usable"]
                counts[r["t"]] += 1
    rate = [h / c if c else None for h, c in zip(hits, counts)]
    out = []
    for i in range(steps):
        vals = [v for v in rate[max(0, i - window + 1): i + 1] if v is not None]
        out.append(sum(vals) / len(vals) if vals else None)
    return out
