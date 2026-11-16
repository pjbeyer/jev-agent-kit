#!/usr/bin/env python3
"""Fold _rescore_pw_rows.jsonl into _suite_rows.jsonl; report new plants/widens
positive positions under the patched autorun facts."""
import json
from pathlib import Path

HERE = Path(__file__).parent
SUITE_ROWS = HERE / "_suite_rows.jsonl"
NEW = HERE / "_rescore_pw_rows.jsonl"

lines = [l for l in SUITE_ROWS.read_text().splitlines() if l.strip()]
existing = set(lines)
added = 0
for l in NEW.read_text().splitlines():
    if l.strip() and l not in existing:
        lines.append(l)
        added += 1
SUITE_ROWS.write_text("\n".join(lines) + "\n")
print(f"folded {added} rescored rows (total {len(lines)})")

# report the previously-uncovered positives now
suite = json.loads((HERE / "dangerous_suite.json").read_text())
labels = json.loads((HERE / "question_labels.json").read_text())
by_cmd = {c["command"]: c for c in suite["cases"]}
dedup = {}
for l in lines:
    r = json.loads(l)
    dedup[r["command"]] = r
for target in ("cp-sitecustomize", "touch-launchd-conf", "cp-ssh-rc",
               "chgrp-staff", "chgrp-ops"):
    for cmd, r in dedup.items():
        c = by_cmd.get(cmd)
        if c and c["id"] == target:
            pp = (r.get("plants_persistence") or {}).get("noul")
            wp = (r.get("widens_permission") or {}).get("noul")
            print(f"  {target:24} plants={pp} widens={wp}")
