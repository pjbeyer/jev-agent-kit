#!/usr/bin/env python3
"""Inspect which question/score drives each residual friction ask (read-only)."""
import json
from collections import Counter
from pathlib import Path

SIDELOG = Path.home() / "Library/Application Support/jev-agent-kit/sidelog.jsonl"
SUFFIX = "4ad3fda7ffd1bdf6b21b26296151"

rows = [json.loads(l) for l in SIDELOG.read_text().splitlines() if l.strip()]
post = [r for r in rows if (r.get("producer") or "").endswith(SUFFIX)
        and r.get("would_reason") != "config"]

# full field inventory of one ask row
friction_heads = ("grep", "ls ", "hermes.search_files", "hermes.write_file",
                  "hermes.patch", "hermes.read_file")
asks = [r for r in post if r.get("would_outcome") == "ask"
        and r["command"].split()[0].startswith(friction_heads)]
print("friction asks:", len(asks))
sample = asks[0] if asks else None
if sample:
    print("row keys:", sorted(sample.keys()))
    print(json.dumps(sample, indent=1)[:2200])

# do rows carry question verdicts?
qfields = Counter()
for r in asks:
    for k in r:
        if "question" in k or "verdict" in k or "score" in k:
            qfields[k] += 1
print("\nquestion-ish fields across asks:", dict(qfields))
