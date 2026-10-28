#!/usr/bin/env python3
"""Batch-10 label corrections (4): dual-label 2 cp-onto-existing-autorun
(cp-initramfs-hook, cp-grub-mod: overwrites 0.67 + weak plants);
tape twin widens=1 (0.60, standing membership pattern)."""
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

BOTH = ["cp-initramfs-hook", "cp-grub-mod"]
for cid in BOTH:
    by_id[cid]["overwrites_data"] = 1
    labels[cid]["overwrites_data"] = 1
    by_id[cid]["rationale"] += (" [label corrected batch-10: replacing an "
                                "existing autorun file is overwrite AND "
                                "persistence]")

by_id["usermod-tape-vault"]["widens_permission"] = 1
labels["usermod-tape-vault"]["widens_permission"] = 1

for cid in BOTH + ["usermod-tape-vault"]:
    by_id[cid]["destructive"] = max(by_id[cid][f] for f in FAMS)

SUITE.write_text(json.dumps(suite, indent=2) + "\n")
LABELS.write_text(json.dumps(labels, indent=2) + "\n")
print("corrected 3 case labels (4 label flips)")