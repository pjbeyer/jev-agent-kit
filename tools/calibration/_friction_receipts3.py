#!/usr/bin/env python3
"""Deeper join: use noul/distribution/margin/route fields from live receipts (read-only)."""
import json
from collections import Counter, defaultdict
from pathlib import Path

SIDELOG = Path.home() / "Library/Application Support/jev-agent-kit/sidelog.jsonl"
RECEIPTS = Path.home() / "Library/Application Support/jev-agent-kit/receipts"
SUFFIX = "4ad3fda7ffd1bdf6b21b26296151"

rows = [json.loads(l) for l in SIDELOG.read_text().splitlines() if l.strip()]
post = [r for r in rows if (r.get("producer") or "").endswith(SUFFIX)
        and r.get("would_reason") != "config"]
asks = [r for r in post if r.get("would_outcome") == "ask"]
want_ids = {r["call_id"] for r in asks}
cmd_by_id = {r["call_id"]: r["command"] for r in asks}

found = defaultdict(dict)
for f in sorted(RECEIPTS.glob("*.jsonl"), reverse=True):
    for line in f.read_text().splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        cid = r.get("call_id")
        if cid in want_ids and r.get("question_id"):
            found[cid][r["question_id"]] = r
    if not (want_ids - set(found)):
        break

sample = next(iter(found.values()))[next(iter(next(iter(found.values()))))]
print("full receipt row fields:")
for k, v in sample.items():
    print(f"  {k}: {str(v)[:100]}")

# which question produced the ask (would_route / margin)?
routes = Counter()
for cid, qs in found.items():
    for q, r in qs.items():
        routes[(q, r.get("would_route") or r.get("route"), r.get("kind"))] += 1
print("\nquestion x route x kind:")
for k, n in routes.most_common(24):
    print(" ", k, "x", n)
