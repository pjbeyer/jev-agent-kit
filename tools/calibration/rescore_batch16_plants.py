#!/usr/bin/env python3
"""Rescore batch-16 benign rows under the amended plants_persistence instructions.

The question edit (persistence = EXECUTION paths, regenerable/scratch churn is
not a plant) changed the plants fingerprint; every batch-16 row's plants cell
is stale. The rekey's probe corpus contains none of these shapes, so rescore
them explicitly and fold (last wins).
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
b16 = [c for c in suite["cases"] if c["id"].startswith("b16-")]
CMDS = [c["command"] for c in b16]
print(f"batch-16 cases: {len(CMDS)}")

env = dict(os.environ)
for var in ("TYPESAFE_API_KEY", "TYPESAFE_API_KEY_COMMAND", "JEV_KIT_HMAC_KEY_COMMAND",
            "JEV_KIT_HMAC_KEY", "JEV_KIT_ATTESTATION", "JEV_KIT_BASE_URL",
            "JEV_KIT_ENDPOINT_ALLOWLIST", "JEV_KIT_RECEIPTS_DIR", "JEV_KIT_SRC",
            "JEV_KIT_SIDELOG_PATH"):
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

corpus = HERE / "_b16_rescore_corpus.json"
corpus.write_text(json.dumps(CMDS))
out = HERE / "_b16_rescore_rows.jsonl"
proc = subprocess.run(
    [str(REPO / ".venv/bin/python"), str(HERE / "shadow_pilot" / "run_pilot.py"),
     "--corpus", str(corpus), "--live", "--limit", str(len(CMDS)), "--out", str(out)],
    env=env, capture_output=True, text=True, cwd=str(REPO))
print("rc:", proc.returncode)
if proc.returncode != 0:
    print(proc.stdout[-1500:])
    print(proc.stderr[-1500:])
    sys.exit(1)
print(proc.stdout[-1800:])

lines = [l for l in (HERE / "_suite_rows.jsonl").read_text().splitlines() if l.strip()]
existing = set(lines)
added = 0
for l in out.read_text().splitlines():
    if l.strip() and l not in existing:
        lines.append(l)
        added += 1
(HERE / "_suite_rows.jsonl").write_text("\n".join(lines) + "\n")
print(f"folded {added} rows (total {len(lines)})")
