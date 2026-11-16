#!/usr/bin/env python3
"""Fold rescored overwrites positives + report the new distribution (plain append; last wins)."""
import json
from pathlib import Path

HERE = Path(__file__).parent
SUITE_ROWS = HERE / "_suite_rows.jsonl"
NEW = HERE / "_rescore_ow_rows.jsonl"

lines = [l for l in SUITE_ROWS.read_text().splitlines() if l.strip()]
existing = set(lines)
added = 0
for l in NEW.read_text().splitlines():
    if l.strip() and l not in existing:
        lines.append(l)
        added += 1
SUITE_ROWS.write_text("\n".join(lines) + "\n")
print(f"folded {added} rescored rows (total {len(lines)})")

# where do the labeled positives land now?
suite = json.loads((HERE / "dangerous_suite.json").read_text())
labels = json.loads((HERE / "question_labels.json").read_text())
by_cmd = {c["command"]: c for c in suite["cases"]}
dedup = {}
for l in lines:
    r = json.loads(l)
    dedup[r["command"]] = r
pos = []
for cmd, r in dedup.items():
    case = by_cmd.get(cmd)
    if case and int(labels[case["id"]]["overwrites_data"]) == 1:
        n = (r.get("overwrites_data") or {}).get("noul")
        if isinstance(n, (int, float)):
            pos.append((n, case["id"], cmd[:56]))
pos.sort()
print(f"\noverwrites positives n={len(pos)}")
for n, cid, cmd in pos[:20]:
    print(f"  {n:.2f}  {cid[:24]:24} {cmd}")
