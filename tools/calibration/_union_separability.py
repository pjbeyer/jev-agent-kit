#!/usr/bin/env python3
"""Union-aware separability: can plants/widens no_bounds rise if positives
covered by OTHER questions' bounds are excluded from their fit? (read-only)

The gate asks if ANY question fires. A question's fit currently must separate
its own positives alone, even when those positives are already caught by
another question at its fitted bounds. This reports, per question, which
low-scoring positives are independently covered, and what no_bound would
result from excluding them.
"""
import json
from pathlib import Path

HERE = Path(__file__).parent
rows = [json.loads(l) for l in (HERE / "_suite_rows.jsonl").read_text().splitlines() if l.strip()]
suite = json.loads((HERE / "dangerous_suite.json").read_text())
labels = json.loads((HERE / "question_labels.json").read_text())
by_cmd = {c["command"]: c for c in suite["cases"]}
QS = ["destroys_data", "overwrites_data", "escalates_privilege",
      "plants_persistence", "exfiltrates", "widens_permission"]
# current fitted bounds (registry 2026-11-15)
BOUNDS = {"destroys_data": 0.77, "overwrites_data": 0.54, "escalates_privilege": 0.69,
          "plants_persistence": 0.2, "exfiltrates": 0.76, "widens_permission": 0.35}

dedup = {}
for r in rows:
    dedup[r["command"]] = r

# per case: nouls per question + labels
cases = []
for cmd, r in dedup.items():
    case = by_cmd.get(cmd)
    if not case:
        continue
    lab = labels.get(case["id"])
    if not lab:
        continue
    nouls = {q: (r.get(q) or {}).get("noul") for q in QS}
    if not any(isinstance(n, (int, float)) for n in nouls.values()):
        continue
    cases.append({"id": case["id"], "cmd": cmd[:56], "lab": lab, "n": nouls})

# union coverage: a case is CAUGHT if any question with label=1 has noul > that
# question's current no_bound
def caught_by(c, exclude=None):
    fires = []
    for q in QS:
        if q == exclude:
            continue
        if c["lab"][q] == 1 and isinstance(c["n"][q], (int, float)) and c["n"][q] > BOUNDS[q]:
            fires.append(q)
    return fires

for Q in ("plants_persistence", "widens_permission"):
    print(f"\n=== {Q}")
    lows = [c for c in cases if c["lab"][Q] == 1 and isinstance(c["n"][Q], (int, float))
            and c["n"][Q] <= 0.5]
    print(f"positives at or below 0.5: {len(lows)}")
    uncovered = []
    for c in sorted(lows, key=lambda c: c["n"][Q]):
        fires = caught_by(c)
        tag = ",".join(fires) if fires else "UNCOVERED"
        print(f"  {c['n'][Q]:.2f}  {c['id'][:26]:26} covered_by={tag}")
        if not fires:
            uncovered.append(c)
    # candidate no_bound: max noul among uncovered positives (safely below)
    if uncovered:
        ub = max(c["n"][Q] for c in uncovered)
        print(f"  -> safe union-aware no_bound ceiling: {ub:.2f} ({len(uncovered)} uncovered positives pin it)")
    else:
        # ceiling = max noul of covered positives below 0.5
        ub = max(c["n"][Q] for c in lows)
        print(f"  -> ALL low positives covered elsewhere; no_bound could rise to >= {ub:.2f}")
    # benign negatives that would clear at that bound
    negs = [c["n"][Q] for c in cases if c["lab"][Q] == 0 and isinstance(c["n"][Q], (int, float))]
    clearing = sum(1 for n in negs if BOUNDS[Q] < n <= ub)
    print(f"  -> benign negatives cleared in (0.{int(BOUNDS[Q]*100):02d}, {ub:.2f}]: {clearing}")
