from __future__ import annotations

import asyncio
import platform
import statistics
import time

from agents.procurement import Attack, Network
from borderflow.envelope import KeyPair, KeyRegistry, build_envelope, envelope_size, verify_envelope
from borderflow.guard import FlowGuard, GuardConfig
from borderflow.labels import Label
from borderflow.policy import Policy

PRINCIPAL_IDS = [f"https://agent-{i}.org-{i}.example/a2a" for i in range(16)]


def envelope_sizes(max_k: int = 8) -> list:
    kp = KeyPair.generate(PRINCIPAL_IDS[0])
    content = {"text": "Quote from S1: price: 1200.00 USD; lead_time: 10 days."}
    rows = []
    for k in range(1, max_k + 1):
        readers = PRINCIPAL_IDS[: max(1, k // 2 + k % 2)]
        writers = PRINCIPAL_IDS[: k // 2]
        env = build_envelope(kp, Label.of(readers, writers), content, "result", "ctx-7f3a9c2e", 0)
        rows.append({"principals": len(readers) + len(writers), "bytes": envelope_size(env)})
    return rows


def _time(fn, n: int) -> float:
    samples = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        fn()
        samples.append(time.perf_counter_ns() - t0)
    return statistics.median(samples) / 1000.0


def crypto_and_guard(n: int = 2000) -> dict:
    a, b = KeyPair.generate("A"), KeyPair.generate("B")
    reg = KeyRegistry()
    reg.register(a)
    reg.register(b)
    content = {"text": "Quote from S1: price: 1200.00 USD; lead_time: 10 days."}
    label = Label.of({"U", "A", "B", "L"}, {"B"})
    env = build_envelope(b, label, content, "result", "ctx", 0)
    guard = FlowGuard(a, Policy(owner="U"), reg, GuardConfig())
    h = guard.local("rfq", Label.of({"U", "A", "B"}, {"U"}))
    c = guard.new_context()
    return {
        "sign_us": _time(lambda: build_envelope(b, label, content, "result", "ctx", 0), n),
        "verify_us": _time(lambda: verify_envelope(reg, env, content, "B"), n),
        "egress_us": _time(lambda: guard.egress("B", h, "request"), n),
        "ingress_us": _time(lambda: guard.ingress("B", content["text"], "result", env, None, content), n),
        "ingress_unsigned_us": _time(lambda: guard.ingress("B", content["text"], "result", None, None, content), n),
        "deref_us": _time(lambda: guard.deref(h, c), n),
    }


async def _roundtrip(mode: str, n: int) -> float:
    net = Network(mode=mode, attack=Attack(None))
    try:
        await net.client["S1"].send([net.request])
        samples = []
        for _ in range(n):
            t0 = time.perf_counter_ns()
            await net.client["S1"].send([net.request])
            samples.append(time.perf_counter_ns() - t0)
        return statistics.median(samples) / 1e6
    finally:
        await net.close()


def roundtrip(n: int = 200) -> dict:
    base = asyncio.run(_roundtrip("none", n))
    guarded = asyncio.run(_roundtrip("borderflow", n))
    return {"none_ms": base, "borderflow_ms": guarded, "overhead_pct": 100.0 * (guarded - base) / base}


def machine() -> dict:
    return {"python": platform.python_version(), "machine": platform.machine(), "processor": platform.processor() or "n/a", "system": platform.system()}
