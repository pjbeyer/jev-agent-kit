#!/usr/bin/env python3
"""Counterfactual replay v2: exclude no-noul calls; verify formula; project new-bounds ask rate (read-only)."""
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
        and r.get("would_reason") != "config"
        and r.get("traffic") == "real"]
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
        if cid in post_ids and r.get("question_id"):
            per_call.setdefault(cid, []).append(r)
    if len(per_call) >= len(post_ids):
        break

# only calls with at least one noul-bearing question row (question-judged calls)
judged = {cid: qrows for cid, qrows in per_call.items()
          if any(isinstance(r.get("noul"), (int, float)) for r in qrows)}
print(f"question-judged calls: {len(judged)} of {len(post_ids)} post-restart calls")

valid, mismatch = 0, 0
old_asks, new_asks = [], []
cmds = {r["call_id"]: r["command"] for r in post}
for cid, qrows in judged.items():
    actual = post_ids[cid]
    old_ask = new_ask = False
    for r in qrows:
        n, th, q = r.get("noul"), r.get("threshold") or {}, r.get("question_id")
        if not isinstance(n, (int, float)):
            continue
        if isinstance(th.get("no_bound"), (int, float)) and n > th["no_bound"]:
            old_ask = True
        if q in NEW and n > NEW[q]:
            new_ask = True
    pred_old = "ask" if old_ask else "allow"
    if pred_old == actual:
        valid += 1
    else:
        mismatch += 1
    if old_ask:
        old_asks.append(cid)
    if new_ask:
        new_asks.append(cid)

print(f"formula agreement with actual (old bounds): {valid}/{valid+mismatch}")
print(f"old-bounds asks among judged: {len(old_asks)} = {100*len(old_asks)/len(judged):.1f}%")
print(f"new-bounds asks projection: {len(new_asks)} = {100*len(new_asks)/len(judged):.1f}%")


def bucket(c):
    h = c.split()[0]
    if h.startswith("hermes."): return h[7:]
    if ".venv" in c[:80] or "python" in c[:100]: return "venv-python"
    if c[:4] == "grep" or c[:3] == "ls ": return "reader-shell"
    return "other-shell"


print("\nremaining ask buckets (new bounds, distinct commands):")
print(Counter(bucket(cmds[c]) for c in set(new_asks)).most_common())
print("\nsample surviving asks:")
for cid in list(dict.fromkeys(new_asks))[:10]:
    print("  ", cmds[cid][:70])
