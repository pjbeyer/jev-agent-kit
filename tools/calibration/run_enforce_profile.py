"""What does the gate actually DO with each suite case? The protection profile.

The `destructive` question's probability only covers cases the parser could read. The 26
destructive cases it refused are covered by a different mechanism -- the safety invariant that an
unreadable command escalates rather than passes. That claim is load-bearing for the whole design,
so it is measured here rather than asserted.

Outcomes per case, in enforce mode, on real live calls:
  ALLOW / DEFER / ASK / DENY  -- whatever the gate returns.

The number that matters is not the question's recall. It is: of the destructive cases, how many
reach a human (escalated or denied) and how many pass as safe.
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from jev_kit.command_properties import extract_command_properties  # noqa: E402
from jev_kit.engine import run_json  # noqa: E402
from jev_kit.hooks.core import Mode, ToolCall, decide_tool_call  # noqa: E402
from jev_kit.secrets import resolve_api_key  # noqa: E402
from jev_kit.transport import LiveTransport  # noqa: E402

HERE = Path(__file__).parent
DIR = Path.home() / ".local/share/hermes/jev-calibration"

cases = json.loads((HERE / "dangerous_suite.json").read_text())["cases"]

_key = resolve_api_key(timeout=10)
assert _key, "no API key resolved; cannot run live"
transport = LiveTransport(_key,
                          base_url="https://litellm.shared.getflex.org/typesafe",
                          endpoint_allowlist=("litellm.shared.getflex.org",))


def runner(request):
    return run_json(request, transport=transport)


question_set = REPO / "skills/jev-runtime/questions/tool-call-gate.json"

rows = []
for case in cases:
    props = extract_command_properties(case["command"])
    try:
        decision = decide_tool_call(ToolCall(command=case["command"]), mode=Mode.ENFORCE,
                                    question_set_path=str(question_set), runner=runner)
        outcome = decision.outcome.value
    except Exception as exc:  # a crash is an outcome worth recording, not a reason to stop
        outcome = f"ERROR:{type(exc).__name__}"
    rows.append({"id": case["id"], "label": int(case["destructive"]),
                 "confidence": case["confidence"], "parse_confident": props.parse_confident,
                 "reason": props.reason, "outcome": outcome,
                 "command": case["command"]})
    print(f"  {outcome:<10} {'DESTRUCTIVE' if case['destructive'] else 'safe':<12} "
          f"{case['id']:<26} parsed={props.parse_confident!s:<5} {props.reason or ''}")

print()
print("=" * 92)
print("PROTECTION PROFILE: outcome by label, in enforce mode")
print("=" * 92)
by_label: dict[int, collections.Counter] = {1: collections.Counter(), 0: collections.Counter()}
for row in rows:
    by_label[row["label"]][row["outcome"]] += 1

outcomes = sorted({r["outcome"] for r in rows})
print(f"  {'outcome':<12}{'destructive':<14}{'safe':<10}")
for outcome in outcomes:
    print(f"  {outcome:<12}{by_label[1][outcome]:<14}{by_label[0][outcome]:<10}")
print(f"  {'TOTAL':<12}{sum(by_label[1].values()):<14}{sum(by_label[0].values()):<10}")

# An ALLOW on a destructive case is the failure mode that matters.
passed = [r for r in rows if r["label"] == 1 and r["outcome"] == "allow"]
escalated = [r for r in rows if r["label"] == 1 and r["outcome"] != "allow"]
print()
print(f"  destructive cases that PASSED as safe (ALLOW): {len(passed)}")
for row in passed:
    print(f"    {row['id']:<26} {row['command'][:58]}")
print(f"  destructive cases that reached a human (any other outcome): {len(escalated)}")
print()
denied = [r for r in rows if r["label"] == 1 and r["outcome"] in ("deny", "denied", "block")]
print(f"  of those, outright denied: {len(denied)}")

false_blocks = [r for r in rows if r["label"] == 0 and r["outcome"] != "allow"]
print(f"  safe cases that were NOT allowed (friction): {len(false_blocks)}")

summary = {
    "outcomes_by_label": {("destructive" if k == 1 else "safe"): dict(v)
                          for k, v in by_label.items()},
    "destructive_passed_as_safe": [r["id"] for r in passed],
    "destructive_reached_human": [r["id"] for r in escalated],
    "safe_blocked_or_asked": [r["id"] for r in false_blocks],
}
(DIR / "enforce-profile-20261016.json").write_text(json.dumps(summary, indent=2) + "\n")
print(f"\nwritten: {DIR / 'enforce-profile-20261016.json'}")
