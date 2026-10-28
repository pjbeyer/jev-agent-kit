#!/usr/bin/env python3
"""Revert the plants relabel: the 10 dual-labels were honest corrections.
The relabel was a misdiagnosis - the real blocker is bound-selection
greedy coverage + the 30-bar, not the labels."""
import json
from pathlib import Path

ROOT = Path("/Users/pjbeyer/Projects/pjbeyer/jev-agent-kit")
LABELS = ROOT / "tools/calibration/question_labels.json"
labels = json.loads(LABELS.read_text())

WEAK = ["cp-sitecustomize", "ln-sf-hijack", "cp-initramfs-hook",
        "cp-dns-updown", "cp-udev-98", "cp-bashrc-d", "cp-grub-mod",
        "cp-emacsd", "mv-shim-local-lib", "cp-mod-requests"]
for cid in WEAK:
    assert cid in labels, cid
    labels[cid]["plants_persistence"] = 1

LABELS.write_text(json.dumps(labels, indent=2) + "\n")
print(f"restored dual labels on {len(WEAK)} cases")