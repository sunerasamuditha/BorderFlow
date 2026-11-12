from __future__ import annotations

import argparse
import asyncio
import logging
import sys

logging.disable(logging.WARNING)

from agents.procurement import Attack, Network, local_urls, served
from borderflow.planner import CompliantPlanner
from experiments.attacks import ATTACKS, _hit, run_attack
from experiments.plans import Trace, procure_cheapest

EXPLAIN = {
    "egress": "A sends h{handle} to {remote} ({channel}); label {label}",
    "egress-deny": "BLOCKED by BF-2: {reason}",
    "ingress": "{remote} -> A ({channel}): new value h{handle} labelled {label}; envelope: {envelope}",
    "deref": "planner reads h{handle}; its context label is now {context_label}",
    "extract": "quarantined extraction h{handle} -> typed h{out} ({type})",
    "invoke": "ALLOWED by BF-5: {sink}({args})",
    "invoke-deny": "BLOCKED by BF-5 ({part} check): {sink}: {reason}",
    "endorse": "U endorsed h{handle} -> h{out}",
    "declassify": "{owner} declassified h{handle} -> h{out}",
}
HTTP_ATTACKS = ("card", "artifact", "status", "push", "error", "forge")


def narrate(events: list) -> None:
    for e in events:
        template = EXPLAIN.get(e["event"])
        if template:
            print("   " + template.format(**e))


def banner(kind: str, mode: str, bilateral: bool, transport: str) -> None:
    desc = dict((k, d) for k, _, d in ATTACKS)[kind]
    print(f"\nAttack   : {kind} - {desc}")
    print(f"Defence  : {mode}{' (bilateral)' if bilateral else ''}")
    print(f"Transport: {transport}\n")


async def in_memory(kind: str, mode: str, bilateral: bool) -> None:
    captured = {}
    original = Network.close

    async def capture(self):
        captured["events"] = list(self.guard.events)
        await original(self)

    Network.close = capture
    try:
        outcome = await run_attack(kind, mode, bilateral)
    finally:
        Network.close = original
    banner(kind, mode, bilateral, "A2A JSON-RPC over an in-memory ASGI transport")
    narrate(captured["events"])
    print("\nRESULT:", "ATTACK SUCCEEDED" if outcome.success else "ATTACK BLOCKED")


async def over_http(kind: str, mode: str, bilateral: bool) -> None:
    atk = Attack(kind)
    net = Network(mode=mode, bilateral=bilateral, attack=atk, urls=local_urls())
    async with served(net):
        g = net.guard
        c1 = g.new_context("s1")
        r1 = await net.client["S1"].send([net.request])
        CompliantPlanner(g, c1).obey(r1.handles)
        c2 = g.new_context("s2")
        p2 = CompliantPlanner(g, c2)
        if kind == "card":
            _, handles = await net.client["S2"].fetch_card()
            p2.obey(handles)
        r2 = await net.client["S2"].send([net.request])
        p2.obey(r2.handles)
        if kind == "push":
            p2.obey(net.inbox)
        success = _hit(net, atk)
        banner(kind, mode, bilateral, "A2A JSON-RPC over real HTTP sockets (127.0.0.1:8101-8104)")
        narrate(g.events)
    print("\nRESULT:", "ATTACK SUCCEEDED" if success else "ATTACK BLOCKED")


def _clean(s: str) -> str:
    for a, b in (("\\texttt", ""), ("\\checkmark", "OK"), ("\\varepsilon", "eps"), ("\\lambda", "lambda"), ("\\sqcup", " join "),
                 ("\\rho", "rho"), ("\\tau", "tau"), ("\\leftarrow", "<-"), ("\\arg\\min", "argmin"), ("\\subseteq", " subset of "), ("\\emptyset", "{}"),
                 ("\\notin", " not in "), ("\\in", " in "), ("\\le", "<="), ("\\ell", "l"), ("\\_", "_"), ("\\{", "{"), ("\\}", "}"), ("$", ""), ("{=}", "=")):
        s = s.replace(a, b)
    return " ".join(s.split())


async def plan() -> None:
    net = Network("borderflow")
    trace = Trace()
    await procure_cheapest(net, trace)
    print("\nWorked plan: compare two quotes through typed handles, pay the cheaper supplier, then a planner mistake\n")
    for r in trace.rows:
        print(f" {r['step']:>2}. {_clean(r['operation'])}")
        print(f"     label: {_clean(r['label'])}")
        if r["check"]:
            print(f"     check: {_clean(r['check'])}")
    print("\nPayments made    :", net.world.payments)
    print("Pickups scheduled:", net.world.pickups)
    print("E-mails sent     :", net.world.emails)
    await net.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="BorderFlow demo")
    ap.add_argument("--attack", default="artifact", choices=[a[0] for a in ATTACKS])
    ap.add_argument("--mode", default="borderflow", choices=["borderflow", "none", "token"])
    ap.add_argument("--bilateral", action="store_true")
    ap.add_argument("--plan", action="store_true", help="show the worked plan with every label computation")
    ap.add_argument("--http", action="store_true", help="serve the agents on real localhost sockets")
    args = ap.parse_args()
    if args.plan:
        asyncio.run(plan())
    elif args.http:
        if args.attack not in HTTP_ATTACKS:
            sys.exit("--http supports: " + ", ".join(HTTP_ATTACKS))
        asyncio.run(over_http(args.attack, args.mode, args.bilateral))
    else:
        asyncio.run(in_memory(args.attack, args.mode, args.bilateral))


if __name__ == "__main__":
    main()
