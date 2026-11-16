#!/usr/bin/env python3
"""What pinning question would each surviving ask-class clear if widened? (read-only)

Focus: the exec-family asks (execute_code, venv-python, delegate_task) that
pin on plants_persistence (no_bound 0.21) and widens_permission (0.35).
Where exactly do benign live shapes sit vs labeled positives?
"""
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


def bucket(c):
    h = c.split()[0]
    if h.startswith("hermes."): return h[7:]
    if ".venv" in c[:80] or "python" in c[:100]: return "venv-python"
    if c[:4] == "grep" or c[:3] == "ls ": return "reader-shell"
    return "other-shell"


# per bucket, the pinning question + noul of each ask
rows_out = []
for cid, qrows in per_call.items():
    hot = [(r["question_id"], r.get("noul")) for r in qrows
           if isinstance(r.get("noul"), (int, float)) and r["question_id"] in NEW
           and r["noul"] > NEW[r["question_id"]]]
    if hot:
        rows_out.append((bucket(cmds[cid]), hot, cmds[cid][:60]))

by_bucket = {}
for b, hot, cmd in rows_out:
    by_bucket.setdefault(b, []).append((hot, cmd))

print("per bucket: pinning questions and noul ranges:")
for b, items in sorted(by_bucket.items(), key=lambda kv: -len(kv[1])):
    qs = Counter()
    for hot, _ in items:
        for q, n in hot:
            qs[(q, round(n, 1))] += 1
    print(f"\n[{b}] {len(items)} asks")
    for (q, n), c in qs.most_common(8):
        print(f"   {q} @ {n} x{c}")
    print("   examples:")
    for hot, cmd in items[:3]:
        print(f"     {[(q, round(n,2)) for q,n in hot]}  {cmd}")
