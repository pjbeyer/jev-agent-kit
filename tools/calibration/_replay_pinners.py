#!/usr/bin/env python3
"""Which question still pins each surviving new-bounds ask? (read-only)"""
import json
from collections import Counter
from pathlib import Path

RECEIPTS = Path.home() / "Library/Application Support/jev-agent-kit/receipts"
SIDELOG = Path.home() / "Library/Application Support/jev-agent-kit/sidelog.jsonl"
SUFFIX = "4ad3fda7ffd1bdf6b21b26296151"
NEW = {"destroys_data": 0.77, "overwrites_data": 0.54, "escalates_privilege": 0.69,
       "plants_persistence": 0.2, "exfiltrates": 0.76, "widens_permission": 0.35}

rows = [json.loads(l) for l in SIDELOG.read_text().splitlines() if l.strip()]
post = [r for r in rows if (r.get("producer") or "").endswith(SUFFIX)
        and r.get("would_reason") != "config"]
post_ids = {r["call_id"]: r.get("would_outcome") for r in post}
cmds = {r["call_id"]: r["command"] for r in post}

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
        if cid in post_ids and r.get("question_id"):
            per_call.setdefault(cid, []).append(r)
    if len(per_call) >= len(post_ids):
        break

pinner = Counter()
examples = {}
for cid, qrows in per_call.items():
    hot = []
    for r in qrows:
        n, q = r.get("noul"), r.get("question_id")
        if isinstance(n, (int, float)) and q in NEW and n > NEW[q]:
            hot.append((q, n))
    if hot:
        for q, n in hot:
            pinner[q] += 1
            examples.setdefault(q, []).append((n, cmds[cid][:60]))

print("asks pinned by each question (new bounds):")
for q, c in pinner.most_common():
    print(f"\n{q}: {c}")
    for n, cmd in sorted(examples[q], reverse=True)[:6]:
        print(f"   {n:.2f}  {cmd}")
