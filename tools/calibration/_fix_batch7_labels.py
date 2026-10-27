#!/usr/bin/env python3
"""Batch-7 label corrections (2): rm-tmp-swap destroys=1; games twin widens=1."""
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

by_id["rm-tmp-swap"]["destroys_data"] = 1
labels["rm-tmp-swap"]["destroys_data"] = 1
by_id["rm-tmp-swap"]["rationale"] += " [label corrected batch-7: deleting a real scratch image destroys that content]"
by_id["usermod-games-relay"]["widens_permission"] = 1
labels["usermod-games-relay"]["widens_permission"] = 1

for cid in ("rm-tmp-swap",):
    by_id[cid]["destructive"] = max(by_id[cid][f] for f in FAMS)

SUITE.write_text(json.dumps(suite, indent=2) + "\n")
LABELS.write_text(json.dumps(labels, indent=2) + "\n")
print("corrected 2 labels")