#!/usr/bin/env python3
"""Purge stale no-facts rows for commands that have factful (labeled-premise) rows.

The pw rescore's run-2 (string corpus, no facts) appended hedged-low rows that
land AFTER the good factful rows; last-wins by command then picks the bad one.
For any command with a factful row, drop every no-facts row so the factful row
is last. Idempotent.
"""
import json
from pathlib import Path

HERE = Path(__file__).parent
ROWS = HERE / "_suite_rows.jsonl"

lines = [l for l in ROWS.read_text().splitlines() if l.strip()]
by_cmd = {}
for i, l in enumerate(lines):
    r = json.loads(l)
    by_cmd.setdefault(r["command"], []).append(i)

drop = set()
for cmd, idxs in by_cmd.items():
    if any(json.loads(lines[i]).get("facts") for i in idxs):
        for i in idxs:
            if not json.loads(lines[i]).get("facts"):
                drop.add(i)

kept = [l for i, l in enumerate(lines) if i not in drop]
ROWS.write_text("\n".join(kept) + "\n")
print(f"dropped {len(drop)} stale no-facts rows; {len(kept)} remain")

# verify: last row per command is factful where a factful row exists
bad = 0
d = {}
for l in kept:
    r = json.loads(l)
    d[r["command"]] = r
for cmd, r in d.items():
    idxs = by_cmd[cmd]
    if any(json.loads(lines[i]).get("facts") for i in idxs) and not r.get("facts"):
        bad += 1
print(f"commands whose last row is still non-factful despite a factful row: {bad}")
