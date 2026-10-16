"""Ensemble analysis: all three questions together, per question and combined.

The hook allows ONLY when every gate question clears to accept (hooks/core.py: "a single
non-accept route escalates"). So the ensemble's detection rate is not any single question's
recall: a case is caught if ANY question flags it, and a safe case is falsely blocked if ANY
question flags it. FPR compounds across questions.

Per-question bounds come from the kit's own evaluator on the new (v5) suite rows. This answers
the design question for the per-family split: if the ensemble already covers the sudo and chmod
bands through widens_permission, splitting `destructive` further is the wrong move.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from jev_kit.calibration.promotion import select_bounds  # noqa: E402

HERE = Path(__file__).parent
DIR = Path.home() / ".local/share/hermes/jev-calibration"

cases = json.loads((HERE / "dangerous_suite.json").read_text())["cases"]
by_cmd = {c["command"]: c for c in cases}
rows = [json.loads(line) for line in (HERE / "_suite_rows.jsonl").read_text().splitlines()]

QUESTIONS = ("destructive", "exfiltrates", "widens_permission")

# join: command -> {question: noul}
joined = []
for row in rows:
    case = by_cmd.get(row["command"])
    if case is None:
        continue
    scores = {}
    for q in QUESTIONS:
        noul = (row.get(q) or {}).get("noul")
        if isinstance(noul, (int, float)):
            scores[q] = float(noul)
    if len(scores) == len(QUESTIONS):
        joined.append({"id": case["id"], "command": case["command"],
                       "label": int(case["destructive"]), **scores})

print(f"joined (all three questions answered): {len(joined)}/{len(cases)}")
labels = [j["label"] for j in joined]
print(f"  destructive={sum(labels)}  safe={len(labels) - sum(labels)}")

# ---------------------------------------------------------------- per-question evaluator
bounds = {}
print("\n=== per-question evaluator (kit's own select_bounds) ===")
for q in QUESTIONS:
    samples = [(j[q], j["label"]) for j in joined]
    result = select_bounds(samples, samples, reference_accuracy=0.95, tolerance=0.0)
    bounds[q] = (result.no_bound, result.yes_bound)
    print(f"  {q:<18} promotable={result.promotable}  no={result.no_bound}  "
          f"yes={result.yes_bound}  coverage={result.coverage:.3f}  accuracy={result.accuracy:.3f}")

# ---------------------------------------------------------------- per-question confusion
def confusion(scores, label_col, no, yes):
    tp = fp = fn = tn = 0
    for item in scores:
        v, lab = item[label_col], item["label"]
        flagged = v >= yes
        if flagged and lab:
            tp += 1
        elif flagged:
            fp += 1
        elif lab:
            fn += 1
        else:
            tn += 1
    return tp, fp, fn, tn


print("\n=== per-question confusion at its own bounds ===")
for q in QUESTIONS:
    no, yes = bounds[q]
    tp, fp, fn, tn = confusion(joined, q, no, yes)
    print(f"  {q:<18} TP={tp:<3} FP={fp:<3} FN={fn:<3} TN={tn:<3}  "
          f"missed: {[j['id'] for j in joined if j[q] < yes and j['label']]}")

# ---------------------------------------------------------------- ensemble
print("\n=== ENSEMBLE: caught if ANY question flags; blocked if ANY question flags ===")
tp = fp = fn = tn = 0
caught_by: dict[str, list[str]] = {}
for item in joined:
    flagged = [q for q in QUESTIONS if item[q] >= bounds[q][1]]
    if flagged and item["label"]:
        tp += 1
        caught_by[item["id"]] = flagged
    elif flagged:
        fp += 1
    elif item["label"]:
        fn += 1
        caught_by[item["id"]] = []
    else:
        tn += 1
print(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}")
print(f"  ensemble recall = {tp}/{tp + fn} = {tp / (tp + fn):.2f}   "
      f"FPR = {fp}/{fp + tn} = {fp / (fp + tn):.2f}")
print(f"  accuracy = {(tp + tn) / len(joined):.3f}  "
      f"(majority baseline {max(sum(labels), len(labels) - sum(labels)) / len(labels):.3f})")
print("\n  destructive cases caught by which question(s):")
for cid, qs in sorted(caught_by.items()):
    if qs:
        print(f"    {cid:<26} {', '.join(qs)}")
print("\n  destructive cases MISSED by the whole ensemble:")
for cid, qs in sorted(caught_by.items()):
    if not qs:
        print(f"    {cid}")
print("\n  safe cases falsely flagged (ensemble FPR = the compounding problem):")
for item in joined:
    flagged = [q for q in QUESTIONS if item[q] >= bounds[q][1]]
    if flagged and not item["label"]:
        print(f"    {item['id']:<26} {', '.join(flagged)}")