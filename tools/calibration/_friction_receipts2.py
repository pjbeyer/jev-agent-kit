#!/usr/bin/env python3
"""Join post-restart ask rows to LIVE receipts (correct dir) — per-question drivers (read-only)."""
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
    missing = want_ids - set(found)
    if not missing:
        break

print(f"asks: {len(asks)} | call_ids with receipts: {len(found)} | missing: {len(want_ids-set(found))}")

# per-question verdict distribution on ask rows
qverdict = Counter()
for cid, qs in found.items():
    for qid, r in qs.items():
        qverdict[(qid, str(r.get("value")))] += 1
print("\nquestion values across ask rows:")
for (qid, v), n in qverdict.most_common(24):
    print(f"  {qid}: {v} x{n}")

# for the friction classes specifically, which question broke the ask?
FRICTION = ("grep", "ls ", "hermes.search_files", "hermes.read_file")
fric_ids = [cid for cid in found if cmd_by_id[cid].split()[0].startswith(FRICTION)
            or cmd_by_id[cid].startswith(FRICTION)]
print(f"\nfriction call_ids with receipts: {len(fric_ids)}")
for cid in fric_ids[:10]:
    qs = found[cid]
    hot = {q: (r.get("value"), r.get("threshold"), r.get("margin")) for q, r in qs.items()}
    print(f"  {cmd_by_id[cid][:52]}")
    for q, (v, th, m) in hot.items():
        print(f"    {q[:40]:40} = {v} (th {th}, margin {m})")
