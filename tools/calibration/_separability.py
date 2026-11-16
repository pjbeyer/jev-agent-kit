#!/usr/bin/env python3
"""Separability check for the residual ask pinner questions (read-only).

For plants_persistence and widens_permission: where do labeled positives vs
labeled negatives sit right now? If positives are high and benign live shapes
are mid-band, a corpus batch can move the no_bound; if they overlap, it can't.
"""
import json
from pathlib import Path

HERE = Path(__file__).parent
rows = [json.loads(l) for l in (HERE / "_suite_rows.jsonl").read_text().splitlines() if l.strip()]
suite = json.loads((HERE / "dangerous_suite.json").read_text())
labels = json.loads((HERE / "question_labels.json").read_text())
by_cmd = {c["command"]: c for c in suite["cases"]}

dedup = {}
for r in rows:
    dedup[r["command"]] = r

for Q in ("plants_persistence", "widens_permission"):
    pos, neg = [], []
    for cmd, r in dedup.items():
        case = by_cmd.get(cmd)
        if not case:
            continue
        lab = labels.get(case["id"], {}).get(Q)
        n = (r.get(Q) or {}).get("noul")
        if not isinstance(n, (int, float)) or lab is None:
            continue
        (pos if lab == 1 else neg).append((n, case["id"], cmd[:58]))
    pos.sort()
    neg.sort()
    print(f"\n=== {Q}: positives n={len(pos)}, negatives n={len(neg)}")
    print("positives (low first):")
    for n, cid, cmd in pos[:12]:
        print(f"  {n:.2f}  {cid[:26]:26} {cmd}")
    print(f"positives at p50={pos[len(pos)//2][0]:.2f} p90={pos[int(0.9*len(pos))][0]:.2f} max={pos[-1][0]:.2f}")
    print(f"negatives p50={neg[len(neg)//2][0]:.2f} p90={neg[int(0.9*len(neg))][0]:.2f} max={neg[-1][0]:.2f}")
    hi_neg = [(n, c, m) for n, c, m in neg if n > 0.3]
    print(f"negatives above 0.3: {len(hi_neg)}")
    for n, c, m in sorted(hi_neg)[:8]:
        print(f"  {n:.2f}  {c[:26]:26} {m}")
