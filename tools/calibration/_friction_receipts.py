#!/usr/bin/env python3
"""Find live-pilot receipts matching the residual friction asks (read-only).

Joins post-restart sidelog ask rows to receipt rows by call_id to surface
the per-question verdicts/scores that drove each ask, so batch-16 teaches
the right question the right thing.
"""
import json
from collections import Counter, defaultdict
from pathlib import Path

SIDELOG = Path.home() / "Library/Application Support/jev-agent-kit/sidelog.jsonl"
RECEIPTS = Path.home() / ".local/share/hermes/jev-calibration/receipts"
SUFFIX = "4ad3fda7ffd1bdf6b21b26296151"

rows = [json.loads(l) for l in SIDELOG.read_text().splitlines() if l.strip()]
post = [r for r in rows if (r.get("producer") or "").endswith(SUFFIX)
        and r.get("would_reason") != "config"]
asks = [r for r in post if r.get("would_outcome") == "ask"]
want_ids = {r["call_id"] for r in asks}
print(f"asks to explain: {len(asks)} (call_ids: {len(want_ids)})")

# scan receipt files (jsonl, newest first) until we cover the call_ids
found = defaultdict(dict)  # call_id -> question_id -> row
files = sorted(RECEIPTS.glob("*.jsonl"), reverse=True)
for f in files:
    for line in f.read_text().splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        cid = r.get("call_id")
        if cid in want_ids:
            qid = r.get("question_id") or r.get("question") or "?"
            found[cid][qid] = r
    if len(found) >= len(want_ids):
        break

print(f"call_ids found in receipts: {len(found)}")
if found:
    sample_cid = next(iter(found))
    print("\nsample receipt row (call_id", sample_cid[:20] + "…):")
    print(json.dumps(found[sample_cid], indent=1)[:1600])

# aggregate: which question says yes on these asks?
qcount = Counter()
for cid, qs in found.items():
    for qid, r in qs.items():
        v = r.get("verdict") or r.get("answer") or r.get("value")
        qcount[(qid, str(v))] += 1
print("\nquestion verdicts across matched asks:")
for (qid, v), n in qcount.most_common(20):
    print(f"  {qid}: {v} x{n}")
