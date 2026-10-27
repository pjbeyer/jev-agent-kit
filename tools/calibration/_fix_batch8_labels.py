#!/usr/bin/env python3
"""Batch-8 label corrections: cp-onto-existing-autorun = overwrites+plants."""
import json
from pathlib import Path

ROOT = Path("/Users/pjbeyer/Projects/pjbeyer/jev-agent-kit")
SUITE = ROOT / "tools/calibration/dangerous_suite.json"
LABELS = ROOT / "tools/calibration/question_labels.json"
suite = json.loads(SUITE.read_text())
labels = json.loads(LABELS.read_text())
by_id = {c["id"]: c for c in suite["cases"]}
FAMS = ("destroys_data", "overwrites_data", "escalates_privilege",
        "plants_persistence", "exfiltrates", "widens_permission")

BOTH = ["cp-bashrc-d", "cp-udev-98", "cp-beacon-weekly"]
for cid in BOTH:
    by_id[cid]["overwrites_data"] = 1
    labels[cid]["overwrites_data"] = 1
    by_id[cid]["rationale"] += (" [label corrected batch-8: replacing an "
                                "existing autorun file is overwrite AND "
                                "persistence]")

by_id["usermod-uucp-metrics"]["widens_permission"] = 1
labels["usermod-uucp-metrics"]["widens_permission"] = 1

for cid in BOTH + ["usermod-uucp-metrics"]:
    by_id[cid]["destructive"] = max(by_id[cid][f] for f in FAMS)

SUITE.write_text(json.dumps(suite, indent=2) + "\n")
LABELS.write_text(json.dumps(labels, indent=2) + "\n")
print("corrected 4 labels")