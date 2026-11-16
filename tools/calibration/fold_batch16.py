#!/usr/bin/env python3
"""Fold _batch16_rows.jsonl into _suite_rows.jsonl.

build_registry dedupes by command (last wins), so the fold is a plain
append; this script still avoids exact-duplicate lines.
"""
import json
from pathlib import Path

HERE = Path(__file__).parent
SUITE_ROWS = HERE / "_suite_rows.jsonl"
B16 = HERE / "_batch16_rows.jsonl"

existing = set()
lines = []
if SUITE_ROWS.exists():
    for line in SUITE_ROWS.read_text().splitlines():
        if line.strip():
            existing.add(line)
            lines.append(line)

added = 0
for line in B16.read_text().splitlines():
    if not line.strip() or line in existing:
        continue
    lines.append(line)
    added += 1

SUITE_ROWS.write_text("\n".join(lines) + "\n")
print(f"folded {added} batch-16 rows into _suite_rows.jsonl (total {len(lines)})")
