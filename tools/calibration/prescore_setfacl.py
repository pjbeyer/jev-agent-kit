"""Re-score rows whose parser facts changed (setfacl grant rule) and merge results."""
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
CAL = REPO / "tools/calibration"
ROWS = CAL / "_suite_rows.jsonl"

CMDS = [
    "setfacl -m u:attacker:rwx /etc/shadow",
    "setfacl -x u:guest /home/alice/shared",
    "setfacl -b /home/alice/shared",
]

(CAL / "_rescore_commands.json").write_text(json.dumps(CMDS))

rows = [json.loads(line) for line in ROWS.read_text().splitlines() if line.strip()]
kept = [r for r in rows if r["command"] not in CMDS]
with ROWS.open("w") as fh:
    for r in kept:
        fh.write(json.dumps(r) + "\n")
print(f"kept {len(kept)}, re-scoring {len(CMDS)}")