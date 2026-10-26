#!/usr/bin/env python3
"""Score the 3 repaired batch-3b commands (single chunk, well under budget)."""
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
REPO = HERE.parent.parent
DIR = Path.home() / ".local/share/hermes/jev-calibration"

cmds = json.loads((HERE / "_batch3b_commands.json").read_text())
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
corpus = HERE / "_batch3b_corpus.json"
corpus.write_text(json.dumps(cmds))
out = HERE / "_batch3b_rows.jsonl"
proc = subprocess.run(
    [str(REPO / ".venv/bin/python"), str(HERE / "shadow_pilot/run_pilot.py"),
     "--corpus", str(corpus), "--live", "--limit", str(len(cmds)), "--out", str(out)],
    env=env, capture_output=True, text=True, cwd=str(REPO))
print("rc:", proc.returncode)
if proc.returncode != 0:
    print(proc.stdout[-1200:], proc.stderr[-600:])
    sys.exit(1)

# merge
existing = {}
for line in (HERE / "_suite_rows.jsonl").read_text().splitlines():
    if line.strip():
        r = json.loads(line)
        existing[r["command"]] = r
added = 0
for line in out.read_text().splitlines():
    if line.strip():
        r = json.loads(line)
        if r["command"] not in existing:
            existing[r["command"]] = r
            added += 1
(HERE / "_suite_rows.jsonl").write_text(
    "".join(json.dumps(r) + "\n" for r in existing.values()))
print(f"merged {added}; total {len(existing)}")
