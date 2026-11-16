#!/usr/bin/env python3
"""Calibrate the replay formula against ACTUAL would_route from receipts (read-only)."""
import json
from collections import Counter
from pathlib import Path

RECEIPTS = Path.home() / "Library/Application Support/jev-agent-kit/receipts"
SIDELOG = Path.home() / "Library/Application Support/jev-agent-kit/sidelog.jsonl"
SUFFIX = "4ad3fda7ffd1bdf6b21b26296151"

rows = [json.loads(l) for l in SIDELOG.read_text().splitlines() if l.strip()]
post = [r for r in rows if (r.get("producer") or "").endswith(SUFFIX)
        and r.get("would_reason") != "config"]
post_ids = {r["call_id"]: r.get("would_outcome") for r in post}

per_call = {}
for f in sorted(RECEIPTS.glob("*.jsonl"), reverse=True):
    for line in f.read_text().splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        cid = r.get("call_id")
        if cid in post_ids:
            per_call.setdefault(cid, []).append(r)
    if len(per_call) >= len(post_ids):
        break

# formula: ask iff any question noul > no_bound (per its own threshold)
pred_vs_actual = Counter()
mismatches = []
for cid, qrows in per_call.items():
    actual = post_ids[cid]
    pred_ask = False
    for r in qrows:
        if not r.get("question_id"):
            continue
        n = r.get("noul")
        th = r.get("threshold") or {}
        if isinstance(n, (int, float)) and isinstance(th.get("no_bound"), (int, float)):
            if n > th["no_bound"]:
                pred_ask = True
    pred = "ask" if pred_ask else "allow"
    pred_vs_actual[(pred, actual)] += 1
    if pred != actual and len(mismatches) < 8:
        mismatches.append((cid, actual, [(r.get("question_id"), r.get("noul"),
                                          r.get("would_route"),
                                          (r.get("threshold") or {}).get("no_bound"))
                                         for r in qrows if r.get("question_id")]))

print("(predicted, actual) ->", dict(pred_vs_actual))
for cid, actual, qs in mismatches:
    print(f"\nMISMATCH actual={actual} {cid[:16]}")
    for q, n, wr, nb in qs:
        print(f"   {q} noul={n} no_bound={nb} would_route={wr}")
