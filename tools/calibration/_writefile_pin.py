#!/usr/bin/env python3
"""Pin the plants band: which question+noul pins each of the 28 write_file asks? (read-only)"""
import json
from collections import Counter
from pathlib import Path

RECEIPTS = Path.home() / "Library/Application Support/jev-agent-kit/receipts"
SIDELOG = Path.home() / "Library/Application Support/jev-agent-kit/sidelog.jsonl"
SUFFIX = "4ad3fda7ffd1bdf6b21b26296151"
NEW = {"destroys_data": 0.77, "overwrites_data": 0.57, "escalates_privilege": 0.69,
       "plants_persistence": 0.18, "exfiltrates": 0.76, "widens_permission": 0.34}

rows = [json.loads(l) for l in SIDELOG.read_text().splitlines() if l.strip()]
post = [r for r in rows if (r.get("producer") or "").endswith(SUFFIX)
        and r.get("would_reason") != "config" and r.get("traffic") == "real"]
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
        if cid in cmds and r.get("question_id"):
            per_call.setdefault(cid, []).append(r)
    if len(per_call) >= len(cmds):
        break

wf = [cid for cid in cmds if cmds[cid].startswith("hermes.write_file")]
qcount = Counter()
vals = {}
for cid in wf:
    for r in per_call.get(cid, []):
        q, n = r.get("question_id"), r.get("noul")
        if q in NEW and isinstance(n, (int, float)) and n > NEW[q]:
            qcount[q] += 1
            vals.setdefault(q, []).append((n, cmds[cid][:56]))
print("write_file asks pinned by:")
for q, c in qcount.most_common():
    print(f"  {q}: {c}")
    for n, cmd in sorted(vals[q])[:6]:
        print(f"     {n:.2f} {cmd}")
