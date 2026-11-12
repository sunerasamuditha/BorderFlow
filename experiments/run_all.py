from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logging.disable(logging.WARNING)

from borderflow.guard import GuardConfig
from experiments import creep, invariants, overhead
from experiments.attacks import ATTACKS, run_attack
from experiments.plans import TASKS, Trace, procure_cheapest, run_task
from agents.procurement import Network

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
COLUMNS = [
    ("none", "none", False, None),
    ("token", "token", False, None),
    ("bf_uni", "borderflow", False, None),
    ("bf_bi", "borderflow", True, None),
    ("abl_no_exposure", "borderflow", False, GuardConfig(use_exposure=False)),
    ("abl_trust_decl", "borderflow", False, GuardConfig(join_declarations=False)),
    ("abl_no_ctx_join", "borderflow", False, GuardConfig(context_join=False)),
]


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


async def e1(variants: int) -> dict:
    table = {}
    for kind, channel, desc in ATTACKS:
        row = {"channel": channel, "description": desc}
        for col, mode, bilateral, cfg in COLUMNS:
            wins = 0
            for v in range(variants):
                wins += int((await run_attack(kind, mode, bilateral, v, cfg)).success)
            row[col] = wins
        table[kind] = row
        log(f"E1 {kind}: " + " ".join(f"{c[0]}={row[c[0]]}" for c in COLUMNS))
    return {"variants": variants, "rows": table}


async def e2() -> dict:
    rows = []
    for mode in ("none", "borderflow"):
        for attack in (None, "artifact"):
            for fn in TASKS:
                r = await run_task(fn, mode, attack)
                rows.append({"mode": mode, "attack": attack or "none", **r.__dict__})
    net = Network("borderflow")
    trace = Trace()
    await procure_cheapest(net, trace)
    await net.close()
    return {"tasks": rows, "worked_plan": trace.rows}


def tex_attack_table(r: dict) -> str:
    n = r["variants"]
    names = {
        "card": "Card text instruction", "artifact": "Artifact instruction", "tamper": "Chunk tampering (V5)",
        "clarify": "Clarification exfiltration", "auth": "Credential request (V8)", "status": "SSE status instruction",
        "push": "Push-notification instruction", "cross_client": "Cross-client context (V3)", "error": "Error-message instruction",
        "launder": "Laundering via honest $L$", "forge": "Forged envelope",
    }
    ch = {"k1": "$\\kappa_1$", "k2": "$\\kappa_2$", "k3": "$\\kappa_3$", "k4": "$\\kappa_4$", "k5": "$\\kappa_5$", "k6": "$\\kappa_6$", "via L": "$\\kappa_2$"}
    lines = []
    for kind, row in r["rows"].items():
        cells = [str(row[c]) for c in ("none", "token", "bf_uni", "bf_bi")]
        lines.append(f"{ch[row['channel']]} & {names[kind]} & " + " & ".join(cells) + " \\\\")
    return "\n".join(lines) + f"\n% each cell: successful attacks out of {n} variants"


def tex_worked_plan(rows: list) -> str:
    out = []
    for r in rows:
        label = r["label"].replace("{", "\\{").replace("}", "\\}") if not r["label"].startswith("$") else r["label"]
        label = label.replace("R=", "$R{=}$").replace("W=", "$W{=}$") if not label.startswith("$") else label
        out.append(f"{r['step']} & {r['operation']} & {label} & {r['check']} \\\\")
    return "\n".join(out)


def write_markdown(results: dict) -> str:
    md = ["# BorderFlow reference prototype: results", ""]
    m = results["machine"]
    md.append(f"Machine: {m['system']} {m['machine']}, Python {m['python']}. A2A SDK: a2a-sdk {results['a2a_sdk']}.")
    md += ["", "## E1. Attack matrix (successful attacks / variants)", "",
           "| Attack | Channel | None | Token-only | BorderFlow (unilateral) | BorderFlow (bilateral) | -exposure | trust decl. | -context join |",
           "|---|---|---|---|---|---|---|---|---|"]
    n = results["e1"]["variants"]
    for kind, row in results["e1"]["rows"].items():
        cells = [f"{row[c[0]]}/{n}" for c in COLUMNS]
        md.append(f"| {row['description']} | {row['channel']} | " + " | ".join(cells) + " |")
    md += ["", "## E2. Benign tasks with a disciplined (handle-based) planner", "",
           "| Mode | S2 attacking | Task | Class | Completed | Autonomous | Endorsements | Declassifications | Q calls | Denials |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    for t in results["e2"]["tasks"]:
        md.append(f"| {t['mode']} | {t['attack']} | {t['task']} | {t['cls']} | {t['completed']} | {t['autonomous']} | {t['endorsements']} | {t['declassifications']} | {t['q_calls']} | {t['denials']} |")
    md += ["", "### Worked plan (label trace)", "", "| Step | Operation | Label | Check |", "|---|---|---|---|"]
    for r in results["e2"]["worked_plan"]:
        md.append(f"| {r['step']} | {r['operation']} | {r['label']} | {r['check']} |")
    o = results["e3"]
    md += ["", "## E3. Overhead", "", "| Principals in label | Envelope bytes |", "|---|---|"]
    for s in o["envelope_sizes"]:
        md.append(f"| {s['principals']} | {s['bytes']} |")
    c = o["crypto"]
    md += ["", f"Median per-operation cost: sign {c['sign_us']:.1f} us, verify {c['verify_us']:.1f} us, egress {c['egress_us']:.1f} us, ingress with verification {c['ingress_us']:.1f} us, ingress without envelope {c['ingress_unsigned_us']:.1f} us, deref {c['deref_us']:.1f} us.",
           f"A2A JSON-RPC round trip (in-memory ASGI, no LLM): {o['roundtrip']['none_ms']:.2f} ms without BorderFlow, {o['roundtrip']['borderflow_ms']:.2f} ms with BorderFlow (+{o['roundtrip']['borderflow_ms'] - o['roundtrip']['none_ms']:.2f} ms)."]
    md += ["", "## E4. Label creep in a long relationship (200 interactions, 20 seeds)", "",
           "| Strategy | Clean replies usable by a sink trusting {U,A,B} | Clean replies forwardable to C |", "|---|---|---|"]
    for s, v in results["e4"].items():
        md.append(f"| {s} | {100 * v['clean_usable']:.1f}% | {100 * v['clean_forwardable']:.1f}% |")
    md += ["", "## E5. Randomized invariant checking", "", "| Configuration | Traces | Failing traces | Lemma 1 | Theorem 1 | Theorem 2 |", "|---|---|---|---|---|---|"]
    for name, v in results["e5"].items():
        md.append(f"| {name} | {v['traces']} | {v['failing_traces']} | {v['traces_violating_lemma']} | {v['traces_violating_thm1']} | {v['traces_violating_thm2']} |")
    return "\n".join(md) + "\n"


def plot_creep(path: str) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(6, 3.2))
    names = {"principal": "principal scope (default)", "context": "context scope (attested)", "epoch": "epoch reset every 20", "identities": "identity separation (3 ids)"}
    for s in creep.STRATEGIES:
        y = creep.curve(s)
        ax.plot(range(len(y)), [v if v is not None else float("nan") for v in y], label=names[s])
    ax.set_xlabel("interaction with the same counterpart")
    ax.set_ylabel("clean replies usable")
    ax.set_ylim(-0.05, 1.05)
    ax.legend(fontsize=7, loc="center right")
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=200)


def main() -> None:
    ap = argparse.ArgumentParser(description="Run all BorderFlow experiments")
    ap.add_argument("--variants", type=int, default=20)
    ap.add_argument("--traces", type=int, default=10000)
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    if args.quick:
        args.variants, args.traces = 3, 300
    os.makedirs(OUT, exist_ok=True)
    import importlib.metadata as md
    results = {"machine": overhead.machine(), "a2a_sdk": md.version("a2a-sdk")}
    log("E1 attack matrix")
    results["e1"] = asyncio.run(e1(args.variants))
    log("E2 benign tasks and worked plan")
    results["e2"] = asyncio.run(e2())
    log("E3 overhead")
    results["e3"] = {"envelope_sizes": overhead.envelope_sizes(), "crypto": overhead.crypto_and_guard(2000 if not args.quick else 200),
                     "roundtrip": overhead.roundtrip(200 if not args.quick else 20)}
    log("E4 label creep")
    results["e4"] = creep.summarize(200, 20)
    log(f"E5 invariant checking ({args.traces} traces per configuration)")
    results["e5"] = invariants.campaign(args.traces, 40)
    with open(os.path.join(OUT, "results.json"), "w") as f:
        json.dump(results, f, indent=2, default=str)
    with open(os.path.join(OUT, "summary.md"), "w") as f:
        f.write(write_markdown(results))
    with open(os.path.join(OUT, "table_attacks.tex"), "w") as f:
        f.write(tex_attack_table(results["e1"]) + "\n")
    with open(os.path.join(OUT, "table_worked_plan.tex"), "w") as f:
        f.write(tex_worked_plan(results["e2"]["worked_plan"]) + "\n")
    try:
        plot_creep(os.path.join(OUT, "creep.png"))
    except Exception as exc:
        log(f"plot skipped: {exc}")
    log("done; see results/summary.md")


if __name__ == "__main__":
    main()
