#!/usr/bin/env python3
"""Rescore plants_persistence + widens_permission positives under the patched
autorun table (command_properties.py edit) so the fit sees the new facts.

Targets: every labeled positive of either question whose current noul is
<= 0.5 (near/below the bound — the ones that widen or miss). The live
re-score replaces stale rows (last wins).
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
dedup = {}
for r in rows:
    dedup[r["command"]] = r
by_cmd = {c["command"]: c for c in suite["cases"]}

targets = []
for cmd in by_cmd:
    case = by_cmd[cmd]
    lab = labels.get(case["id"])
    if not lab:
        continue
    r = dedup.get(cmd)
    if not r:
        continue
    pin = ((lab.get("plants_persistence") == 1 and isinstance((r.get("plants_persistence") or {}).get("noul"), (int, float))
            and r["plants_persistence"]["noul"] <= 0.5)
           or (lab.get("widens_permission") == 1 and isinstance((r.get("widens_permission") or {}).get("noul"), (int, float))
               and r["widens_permission"]["noul"] <= 0.5))
    if pin:
        targets.append(cmd)

# The static corpus cannot stat destinations; the cp/mv/ln family positives are
# labeled on the destination-exists premise (same as rescore_overwrites_positives).
# Without this fact the rescore's overwrites cells regress to hedged-low values
# and, appended last, CLOBBER the dest-exists rows already folded (observed
# 2026-11-15: registry reverted 0.54 -> 0.05). Every target here carries the
# premise so its overwrites cell stays consistent with the ow rescore.
RESCORE = [{"command": cmd, "facts": {"cmd_dest_exists": True}} for cmd in targets]
print(f"positives to rescore (noul <= 0.5): {len(RESCORE)}")

env = dict(os.environ)
for var in ("TYPESAFE_API_KEY", "TYPESAFE_API_KEY_COMMAND",
            "JEV_KIT_HMAC_KEY_COMMAND", "JEV_KIT_HMAC_KEY",
            "JEV_KIT_ATTESTATION", "JEV_KIT_BASE_URL",
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

corpus = HERE / "_rescore_pw_corpus.json"
corpus.write_text(json.dumps(RESCORE))
out = HERE / "_rescore_pw_rows.jsonl"
proc = subprocess.run(
    [str(REPO / ".venv/bin/python"), str(HERE / "shadow_pilot" / "run_pilot.py"),
     "--corpus", str(corpus), "--live", "--limit", str(len(targets)),
     "--out", str(out)],
    env=env, capture_output=True, text=True, cwd=str(REPO))
print("rc:", proc.returncode)
if proc.returncode != 0:
    print(proc.stdout[-2000:])
    print(proc.stderr[-2000:])
    sys.exit(1)
print(proc.stdout[-2200:])
