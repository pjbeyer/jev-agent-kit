"""KEY: RateBudget max_calls=100 process-wide. --limit 542 selected all,
but only the first 100 got live calls; the rest record 'ask' routes
(the throttled remainder reported as failures). The docstring says:
chunk across PROCESSES with --skip. So: 6 chunks of 100 (542 total
confident), each a fresh process.

The 'route ask' rows are throttled artifacts, NOT shadow behavior.
Re-run in 6 chunks with --skip 0,100,...,500 and merge. Note receipts
dedupe by call; unique commands only."""
import json
import subprocess
import os
from pathlib import Path

HERE = Path("tools/calibration")
REPO = Path(".")
DIR = Path.home() / ".local/share/hermes/jev-calibration"

cmds = json.loads((HERE / "_pilot_corpus.json").read_text())

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

merged = {}
for skip in range(0, 542, 100):
    chunk = cmds[skip:skip + 100]
    corpus = HERE / "_pilot_chunk.json"
    corpus.write_text(json.dumps(chunk))
    out = HERE / f"_pilot_rows_{skip}.jsonl"
    proc = subprocess.run(
        [str(REPO / ".venv/bin/python"),
         str(HERE / "shadow_pilot/run_pilot.py"),
         "--corpus", str(corpus), "--live", "--limit", "100",
         "--skip", "0", "--out", str(out)],
        env=env, capture_output=True, text=True)
    print(f"chunk {skip}: rc {proc.returncode}")
    if proc.returncode != 0:
        print(proc.stdout[-800:]); print(proc.stderr[-500:])
        continue
    for line in out.read_text().splitlines():
        if line.strip():
            r = json.loads(line)
            merged[r["command"]] = r
(HERE / "_pilot_rows_all.jsonl").write_text(
    "".join(json.dumps(r) + "\n" for r in merged.values()))
print("merged unique commands:", len(merged))
scored = sum(1 for r in merged.values()
             if isinstance((r.get("plants_persistence") or {}).get("noul"), (int, float)))
print("rows with live scores:", scored)