#!/usr/bin/env python3
"""Replay live post-restart rows against the NEW registry (read-only counterfactual).

For every clean-window sidelog row, re-derive the would_outcome using the row's
recorded nouls and the new bounds: any question with noul > no_bound => ask.
This is the honest prediction of the post-restart ask-rate once Hermes restarts
onto the new registry.
"""
import json
from collections import Counter
from pathlib import Path

SIDELOG = Path.home() / "Library/Application Support/jev-agent-kit/sidelog.jsonl"
REGISTRY = Path.home() / ".local/share/hermes/jev-calibration/registry/thresholds.json"
RECEIPTS = Path.home() / "Library/Application Support/jev-agent-kit/receipts"
SUFFIX = "4ad3fda7ffd1bdf6b21b26296151"

reg = json.loads(REGISTRY.read_text())
# map question digest -> bounds is not needed: we replay per-question nouls from receipts.
BOUNDS = {}  # filled from receipts rows keyed by question_id

rows = [json.loads(l) for l in SIDELOG.read_text().splitlines() if l.strip()]
post = [r for r in rows if (r.get("producer") or "").endswith(SUFFIX)
        and r.get("would_reason") != "config"]

# collect nouls per call_id from receipts
noul_by_call = {}
for f in sorted(RECEIPTS.glob("*.jsonl"), reverse=True):
    done = False
    for line in f.read_text().splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("question_id") and r.get("call_id"):
            noul_by_call.setdefault(r["call_id"], {})[r["question_id"]] = r.get("noul")
            if r.get("threshold") and r.get("question_id"):
                BOUNDS[r["question_id"]] = r["threshold"]
    if len(noul_by_call) > 2000:
        break

print("live bounds (from receipts):")
for q, t in sorted(BOUNDS.items()):
    print(f"  {q}: no {t['no_bound']} yes {t['yes_bound']}")

reg_bounds = {}
for eid, e in reg["entries"].items():
    reg_bounds[eid] = e["threshold"]

# replay: ask if any question noul > its LIVE no_bound (old bounds) vs NEW registry bounds.
# We need question->entry mapping; receipts give us question ids. Use digest? The registry
# is keyed by digest; receipts carry question_set digest and question_id. Use the receipt
# threshold no_bound for OLD and registry entry matched by same (no_bound,yes_bound) pair
# for NEW via receipt question id -> we must map. Instead: replay with OLD bounds from the
# receipts themselves, and NEW bounds passed manually below (verified against registry).
NEW = {"destroys_data": (0.77, 0.78), "overwrites_data": (0.54, 0.55),
       "escalates_privilege": (0.69, 0.92), "plants_persistence": (0.2, 0.85),
       "exfiltrates": (0.76, 0.77), "widens_permission": (0.35, 0.67)}

old_ask, new_ask = [], []
for r in post:
    cid = r.get("call_id")
    qs = noul_by_call.get(cid)
    if not qs:
        continue  # no receipt nouls (fast-path allow rows have no questions; replay skips)
    o = any(q in BOUNDS and n is not None and n > BOUNDS[q]["no_bound"]
            for q, n in qs.items())
    n_ = any(q in NEW and n is not None and n > NEW[q][0]
             for q, n in qs.items())
    (old_ask if o else []).append(r)
    (new_ask if n_ else []).append(r)

total = sum(1 for r in post if noul_by_call.get(r.get("call_id")))
print(f"\nreplayed rows (question-judged): {total}")
print(f"old bounds asks: {len(old_ask)} = {100*len(old_ask)/total:.1f}%")
print(f"new bounds asks: {len(new_ask)} = {100*len(new_ask)/total:.1f}%")
print("\nremaining ask buckets (new bounds):")
def bucket(c):
    h = c.split()[0]
    if h.startswith("hermes."): return h[7:]
    if ".venv" in c[:80] or "python" in c[:100]: return "venv-python"
    if c[:4]=="grep" or c[:3]=="ls ": return "reader-shell"
    return "other-shell"
print(Counter(bucket(r["command"]) for r in new_ask).most_common())
