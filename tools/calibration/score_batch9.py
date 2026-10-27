#!/usr/bin/env python3
"""Score the batch-9 delta (29 commands) via run_pilot, one 29-call chunk."""
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
REPO = HERE.parent.parent
DIR = Path.home() / ".local/share/hermes/jev-calibration"

cmds = json.loads((HERE / "_batch9_commands.json").read_text())
print("delta commands:", len(cmds))

env = dict(os.environ)
for var in ("TYPESAFE_API_KEY_COMMAND", "JEV_KIT_HMAC_KEY_COMMAND",
            "JEV_KIT_HMAC_KEY", "JEV_KIT_ATTESTATION", "JEV_KIT_BASE_URL",
            "JEV_KIT_ENDPOINT_ALLOWLIST", "JEV_KIT_RECEIPTS_DIR",
            "JEV_KIT_SRC", "JEV_KIT_SIDELOG_PATH"):
    env.pop(var, None)
env.update({
    "JEV_KIT_ATTESTATION": str(DIR / "attestation.json"),
    "JEV_KIT_HMAC_KEY": (DIR / "hmac-key").read_text().strip(),
    "JEV_KIT_SOURCE_ALLOWLIST": "agent_context",
    "JEV_KIT_BASE_URL": "https://litellm.shared.getflex.org/typesafe",
    "JEV_KIT_ENDPOINT_ALLOWLIST": "litellm.shared.getflex.org",
    "JEV_KIT_RECEIPTS_DIR": str(DIR / "calibration-receipts"),
})
corpus = HERE / "_batch9_corpus.json"
corpus.write_text(json.dumps(cmds))
out = HERE / "_batch9_rows.jsonl"
proc = subprocess.run(
    [str(REPO / ".venv/bin/python"), str(HERE / "shadow_pilot/run_pilot.py"),
     "--corpus", str(corpus), "--live", "--limit", str(len(cmds)),
     "--out", str(out)],
    env=env, capture_output=True, text=True, cwd=str(REPO))
print("rc:", proc.returncode)
if proc.returncode != 0:
    print(proc.stdout[-1500:])
    print(proc.stderr[-800:])
    sys.exit(1)

rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
scored = sum(1 for r in rows
             if any(isinstance((r.get(q) or {}).get("noul"), (int, float))
                    for q in ("destroys_data", "overwrites_data", "escalates_privilege",
                              "plants_persistence", "exfiltrates", "widens_permission")))
print(f"rows: {len(rows)} scored: {scored}")