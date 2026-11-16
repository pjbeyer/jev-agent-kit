#!/usr/bin/env python3
"""How many overwrites_data=1 labels contradict live dest_exists on THIS machine? (read-only)

The question instructions (owner-approved, landed with the dest_exists fact) say:
cp/mv/ln family + cmd_dest_exists FALSE => NOT overwriting (creates new data).
Labels authored before that fact now contradict the semantics the model is
instructed to follow, which pins no_bound at 0.05. This measures the mismatch
and checks whether other questions (plants_persistence etc.) still cover the
security weight for each contradicting case.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "src"))
from jev_kit.command_properties import extract_command_properties as e

suite = json.loads((HERE / "dangerous_suite.json").read_text())
labels = json.loads((HERE / "question_labels.json").read_text())

CP_FAMILY = ("cp", "mv", "ln", "install", "copy-item", "move-item")
cases = [c for c in suite["cases"] if int(labels.get(c["id"], {}).get("overwrites_data", 0)) == 1]
print(f"overwrites_data=1 cases: {len(cases)}")

conflict, agree, other = [], [], []
for c in cases:
    tokens = c["command"].split()
    head = tokens[0].rsplit("/", 1)[-1] if tokens else ""
    if head in CP_FAMILY:
        p = e(c["command"])
        de = (p.facts or {}).get("cmd_dest_exists") if hasattr(p, "facts") else None
        de = getattr(p, "dest_exists", de)
        if de is False:
            conflict.append((c["id"], c["command"][:60], labels[c["id"]].get("plants_persistence")))
        else:
            agree.append((c["id"], c["command"][:60], de))
    else:
        other.append((c["id"], c["command"][:50]))

print(f"\ncp/mv/ln family: {len(conflict)+len(agree)}")
print(f"  dest_exists FALSE (label contradicts question semantics): {len(conflict)}")
print(f"  dest_exists TRUE/unknown (label consistent): {len(agree)}")
print(f"non-cp-family positives (redirect/git/package): {len(other)}")

print("\nCONFFLICTS and whether plants_persistence still covers them:")
for cid, cmd, pp in conflict:
    print(f"  plants={pp}  {cid[:26]:26} {cmd}")
