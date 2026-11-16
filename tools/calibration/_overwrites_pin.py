#!/usr/bin/env python3
"""Why is overwrites_data no_bound pinned at 0.05? Inspect the scored distribution (read-only)."""
import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).parent
rows = [json.loads(l) for l in (HERE / "_suite_rows.jsonl").read_text().splitlines() if l.strip()]
labels = json.loads((HERE / "question_labels.json").read_text())
suite = json.loads((HERE / "dangerous_suite.json").read_text())
cmds = {c["command"]: c["id"] for c in suite["cases"]}

# dedupe by command, last wins
dedup = {}
for r in rows:
    dedup[r["command"]] = r

Q = "overwrites_data"
low_yes = []
neg_spread = []
for cmd, r in dedup.items():
    cell = r.get(Q) or {}
    noul = cell.get("noul")
    if noul is None:
        continue
    cid = cmds.get(cmd, "?")
    lab = labels.get(cid, {}).get(Q)
    if lab == 1 and noul < 0.25:
        low_yes.append((noul, cid, cmd[:70]))
    if lab == 0:
        neg_spread.append((noul, cid, cmd[:60]))

low_yes.sort()
print(f"labeled-YES rows scoring < 0.25 on {Q}: {len(low_yes)}")
for noul, cid, cmd in low_yes[:25]:
    print(f"  {noul:.2f}  {cid[:26]:26} {cmd}")
print()
negs = sorted(n for n, _, _ in neg_spread)
print(f"negatives n={len(negs)} min={negs[0]:.2f} p90={negs[int(0.9*len(negs))]:.2f} max={negs[-1]:.2f}")
hi_negs = [(n, c, m) for n, c, m in neg_spread if n > 0.25]
print(f"negatives ABOVE 0.25 (would ask even labeled benign): {len(hi_negs)}")
for n, c, m in sorted(hi_negs)[:15]:
    print(f"  {n:.2f}  {c[:26]:26} {m}")
