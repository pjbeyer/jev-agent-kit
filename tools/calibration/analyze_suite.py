"""Break down the suite run: which cases reached the question, which did not, and why.

`scored: 46/94` is ambiguous on its own, and the two explanations mean opposite things:

- The parser refused the command (unmodeled program, indirect execution). The question was never
  asked, so the case is a COVERAGE GAP and its label is unverifiable.
- The command parsed confidently and was harmless, so the gate short-circuited to ALLOW without
  asking. The question was not needed, which is correct behaviour, not a gap.

Collapsing these would either overstate the gap or hide a real one. This separates them.
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from jev_kit.command_properties import extract_command_properties  # noqa: E402

HERE = Path(__file__).parent
DIR = Path.home() / ".local/share/hermes/jev-calibration"

cases = json.loads((HERE / "dangerous_suite.json").read_text())["cases"]
rows = [json.loads(line) for line in (HERE / "_suite_rows.jsonl").read_text().splitlines()]
by_command = {r["command"]: r for r in rows}

scored_ids = set()
for row in rows:
    noul = (row.get("destructive") or {}).get("noul")
    if isinstance(noul, (int, float)):
        scored_ids.add(row["command"])

buckets: dict[str, list[dict]] = collections.defaultdict(list)
for case in cases:
    props = extract_command_properties(case["command"])
    scored = case["command"] in scored_ids
    row = by_command.get(case["command"], {})
    if scored:
        key = "asked (got a probability)"
    elif not props.parse_confident:
        key = f"NOT ASKED - parser refused: {props.reason}"
    else:
        key = "NOT ASKED - parsed and harmless (short-circuit, correct)"
    buckets[key].append({**case, "parse_confident": props.parse_confident,
                         "reason": props.reason, "route": row.get("route")})

print("=" * 100)
print("WHY EACH CASE DID OR DID NOT REACH THE QUESTION")
print("=" * 100)
for key in sorted(buckets, key=lambda k: -len(buckets[k])):
    group = buckets[key]
    pos = sum(1 for c in group if c["destructive"])
    print(f"\n{key}")
    print(f"  {len(group)} cases  (destructive={pos}, safe={len(group) - pos})")
    for c in group:
        flag = "DESTRUCTIVE" if c["destructive"] else "safe       "
        print(f"    [{flag}] {c['id']:<26} {c['command'][:56]}")

print()
print("=" * 100)
print("CROSS-TAB: label x reached the question")
print("=" * 100)
tab = collections.Counter()
for case in cases:
    props = extract_command_properties(case["command"])
    reached = "asked" if case["command"] in scored_ids else (
        "refused" if not props.parse_confident else "short-circuited")
    tab[(case["destructive"], reached)] += 1
for label in (True, False):
    name = "destructive" if label else "safe"
    asked = tab[(label, "asked")]
    refused = tab[(label, "refused")]
    short = tab[(label, "short-circuited")]
    total = asked + refused + short
    print(f"  {name:<12} asked={asked:<4} refused={refused:<4} short-circuited={short:<4} "
          f"total={total}")
print()
print("  'refused' is the coverage gap: the question never saw the command, so its label could")
print("  not be checked. 'short-circuited' is correct behaviour: a confident, harmless command.")
print("  Only 'asked' cases can contribute to detection rate.")

# ---------------------------------------------------------------- what was caught and missed
print()
print("=" * 100)
print("THE 20 DESTRUCTIVE CASES THAT REACHED THE QUESTION: caught vs missed at the bounds")
print("=" * 100)
result = json.loads((DIR / "suite-result-20261016.json").read_text())
no, yes = result["evaluator"]["no_bound"], result["evaluator"]["yes_bound"]
print(f"  evaluator bounds: no={no}  yes={yes}   (below no -> safe, at/above yes -> destructive)")
print()
caught, missed, deferred = [], [], []
for case in cases:
    if not case["destructive"] or case["command"] not in scored_ids:
        continue
    row = by_command[case["command"]]
    noul = row["destructive"]["noul"]
    if noul >= yes:
        caught.append((case["id"], noul))
    elif noul < no:
        missed.append((case["id"], noul))
    else:
        deferred.append((case["id"], noul))
print(f"  CAUGHT   ({len(caught)}): " + ", ".join(f"{i}@{v:.2f}" for i, v in caught))
print(f"  DEFERRED ({len(deferred)}): " + ", ".join(f"{i}@{v:.2f}" for i, v in deferred))
print(f"  MISSED   ({len(missed)}): " + ", ".join(f"{i}@{v:.2f}" for i, v in missed))
print()
print("  A deferred case is not a silent failure -- it escalates to a human. But it also is not")
total = len(caught) + len(deferred) + len(missed)
print(f"  a detection. {len(deferred)}/{total} destructive cases land in the defer band.")
