#!/usr/bin/env python3
"""jak-7c9: score batch-15 reader-egress negatives live and fold.

Mirrors score_batch14.py: score the new fingerprints through the real shadow
pilot under the CURRENT producer, fold rows into _suite_rows.jsonl.
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
b15 = [c for c in suite["cases"] if c["id"].startswith(("rd-", "rdid-", "batch-"))]
assert len(b15) >= 50, len(b15)
CMDS = [c["command"] for c in b15]

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

corpus = HERE / "_batch15_corpus.json"
corpus.write_text(json.dumps(CMDS))
out = HERE / "_batch15_rows.jsonl"
proc = subprocess.run(
    [str(REPO / ".venv/bin/python"), str(HERE / "shadow_pilot" / "run_pilot.py"),
     "--corpus", str(corpus), "--live", "--limit", str(len(CMDS)), "--out", str(out)],
    env=env, capture_output=True, text=True, cwd=str(REPO))
print("rc:", proc.returncode)
if proc.returncode != 0:
    print(proc.stdout[-2000:])
    print(proc.stderr[-2000:])
    sys.exit(1)
print(proc.stdout[-2500:])
