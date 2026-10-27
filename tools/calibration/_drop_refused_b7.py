#!/usr/bin/env python3
"""Remove the two refused gh-secret cases from the suite (ADR 0005 pattern:
only parse-confident shapes are suite members)."""
import json
from pathlib import Path

ROOT = Path("/Users/pjbeyer/Projects/pjbeyer/jev-agent-kit")
SUITE = ROOT / "tools/calibration/dangerous_suite.json"
LABELS = ROOT / "tools/calibration/question_labels.json"
suite = json.loads(SUITE.read_text())
labels = json.loads(LABELS.read_text())
drop = {"gh-upload-keys", "gh-secret-read"}
before = len(suite["cases"])
suite["cases"] = [c for c in suite["cases"] if c["id"] not in drop]
for cid in drop:
    labels.pop(cid, None)
SUITE.write_text(json.dumps(suite, indent=2) + "\n")
LABELS.write_text(json.dumps(labels, indent=2) + "\n")
print(f"removed {before - len(suite['cases'])}; suite now {len(suite['cases'])}")