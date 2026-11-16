#!/usr/bin/env python3
"""Remaining mcp_call_tool ask ids: which sessions called them, what were they? (read-only)"""
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
post_ids = {r["call_id"]: r for r in post}

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

# distinct mcp ids still asking and their session contexts
mcp_asks = {}
for cid, qrows in per_call.items():
    cmd = post_ids[cid]["command"]
    if not cmd.startswith("hermes.mcp_call_tool"):
        continue
    hot = [(r["question_id"], r.get("noul")) for r in qrows
           if isinstance(r.get("noul"), (int, float)) and r["question_id"] in NEW
           and r["noul"] > NEW[r["question_id"]]]
    if hot:
        mcp_asks.setdefault(cmd.split()[1][:40], []).append((post_ids[cid]["context"], hot))

for tid, occurrences in mcp_asks.items():
    ctxs = Counter(c for c, _ in occurrences)
    print(f"{tid}: {len(occurrences)} asks, contexts: {dict(list(ctxs.items())[:3])}")
    print("   pinning:", Counter(q for _, hot in occurrences for q, _ in hot))
