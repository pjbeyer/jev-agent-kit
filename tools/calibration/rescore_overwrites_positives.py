#!/usr/bin/env python3
"""Rescore STALE overwrites_data positives under the current fact set (jak ask-rate follow-up).

The cp/mv/ln family positives in _suite_rows.jsonl were scored BEFORE the
cmd_dest_exists fact landed (330f817); their stale low nouls (0.06-0.14)
pin overwrites_data no_bound at 0.05 and make benign reads inseparable
from system-file overwrites. This script rescres those rows live through
the shadow pilot under the CURRENT producer/facts, so build_registry's
last-wins dedupe replaces the stale rows.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
REPO = HERE.parent.parent
DIR = Path.home() / ".local/share/hermes/jev-calibration"

sys.path.insert(0, str(REPO / "src"))

suite = json.loads((HERE / "dangerous_suite.json").read_text())
labels = json.loads((HERE / "question_labels.json").read_text())
rows = [json.loads(l) for l in (HERE / "_suite_rows.jsonl").read_text().splitlines() if l.strip()]
deduped = {}
for r in rows:
    deduped[r["command"]] = r

# all commands whose overwrites_data label is 1 (stale rows predate dest_exists)
by_cmd = {c["command"]: c for c in suite["cases"]}
ow_pos = []
for cmd, r in deduped.items():
    case = by_cmd.get(cmd)
    if not case:
        continue
    if int(labels[case["id"]]["overwrites_data"]) == 1:
        noul = (r.get("overwrites_data") or {}).get("noul")
        if isinstance(noul, (int, float)):
            ow_pos.append((noul, cmd))
ow_pos.sort()
# The static corpus cannot stat the destination; the cp/mv/ln family positives
# are labeled on the DESTINATION-EXISTS premise (the overwrite happens because
# the target file is already there). Supply that premise as a labeled fact,
# exactly what the runner's {command, facts} entry form exists for.
RESCORE = [{"command": cmd, "facts": {"cmd_dest_exists": True}} for _, cmd in ow_pos]
print(f"overwrites_data labeled positives with scored rows: {len(RESCORE)}")

env = dict(os.environ)
for var in ("TYPESAFE_API_KEY", "TYPESAFE_API_KEY_COMMAND",
            "JEV_KIT_HMAC_KEY_COMMAND",
            "JEV_KIT_HMAC_KEY", "JEV_KIT_ATTESTATION", "JEV_KIT_BASE_URL",
            "JEV_KIT_ENDPOINT_ALLOWLIST", "JEV_KIT_RECEIPTS_DIR",
            "JEV_KIT_SRC", "JEV_KIT_SIDELOG_PATH"):
    env.pop(var, None)
env.update({
    "TYPESAFE_API_KEY_COMMAND": os.environ["TYPESAFE_API_KEY_COMMAND"],
    "JEV_KIT_ATTESTATION": str(DIR / "attestation.json"),
    "JEV_KIT_HMAC_KEY": (DIR / "hmac-key").read_text().strip(),
    "JEV_KIT_SOURCE_ALLOWLIST": "agent_context",
    "JEV_KIT_BASE_URL": "https://litellm.shared.getflex.org/typesafe",
    "JEV_KIT_ENDPOINT_ALLOWLIST": "litellm.shared.getflex.org",
    "JEV_KIT_RECEIPTS_DIR": str(DIR / "probe-receipts"),
})

corpus = HERE / "_rescore_ow_corpus.json"
corpus.write_text(json.dumps(RESCORE))
out = HERE / "_rescore_ow_rows.jsonl"
proc = subprocess.run(
    [str(REPO / ".venv/bin/python"), str(HERE / "shadow_pilot" / "run_pilot.py"),
     "--corpus", str(corpus), "--live", "--limit", str(len(RESCORE)),
     "--out", str(out)],
    env=env, capture_output=True, text=True, cwd=str(REPO))
print("rc:", proc.returncode)
if proc.returncode != 0:
    print(proc.stdout[-2000:])
    print(proc.stderr[-2000:])
    sys.exit(1)
print(proc.stdout[-2500:])
