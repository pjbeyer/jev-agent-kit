#!/usr/bin/env python3
"""Enforce-path smoke check for the jev-gate hook.

Replays a fixed probe battery through the REAL Hermes shim (`hooks.hermes.pre_tool_call`)
in enforce mode and asserts the decision split. This exists because the ask-storm of
2026-10-30 lived in the seam between the egress reducer's refuse path and enforce's
fail-closed default — a seam no component-level check (shadow health, calibration
status, unit suite) could see.

Run it whenever `src/jev_kit/hooks/core.py` or `src/jev_kit/egress.py` changes, and as
a post-deploy check after a Hermes restart:

    PYTHONPATH=src python3 tools/calibration/smoke_gate.py

Offline by design: no model calls (the runner raises if a benign fast-path probe
reaches it; ask-shaped probes use a deterministic no_advice runner). The sidelog is
redirected to a temp dir and rows are tagged JEV_KIT_TRAFFIC=smoke, so production
receipts and the production sidelog are never touched.

Exit 0 = battery passed; exit 1 = any probe misbehaved (with the failing rows printed).
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# Must run before the shim import reads anything: the smoke never writes to the
# production sidelog and never counts as production traffic.
_TMP = tempfile.mkdtemp(prefix="jev-smoke-")
os.environ["JEV_KIT_SIDELOG_PATH"] = str(Path(_TMP) / "sidelog.jsonl")
os.environ["JEV_KIT_TRAFFIC"] = "smoke"

_KIT_SRC = Path(__file__).resolve().parents[2] / "src"
if str(_KIT_SRC) not in sys.path:
    sys.path.insert(0, str(_KIT_SRC))

from jev_kit.hooks import hermes as shim  # noqa: E402
from jev_kit.hooks.core import Runner  # noqa: E402  # re-exported via core
from jev_kit.types import Mode  # noqa: E402

_QUESTION_SET = (
    Path(__file__).resolve().parents[2]
    / "skills/jev-runtime/questions/tool-call-gate.json"
).resolve()

_QUESTION_IDS = (
    "destroys_data",
    "overwrites_data",
    "escalates_privilege",
    "plants_persistence",
    "exfiltrates",
    "widens_permission",
)


def _no_advice_runner(request: dict[str, object]) -> dict[str, object]:
    """A deterministic runner: every question returns route=no_advice, which the
    gate maps to ask. Good enough to exercise the ask path offline; it proves the
    decision SHAPE, not model quality."""
    return {
        "schema_version": 1,
        "status": "ok",
        "records": [{"question_id": q, "route": "no_advice"} for q in _QUESTION_IDS],
    }


def _boom_runner(request: dict[str, object]) -> dict[str, object]:
    raise AssertionError("runner reached on a fast-path probe")


#: (command, runner, expected shim result) — expected is "allow" (None from the shim)
#: or "block" (a block payload; in enforce every non-allow maps to block).
_BATTERY: list[tuple[str, Runner, str]] = [
    # --- benign, refused-class (compound/quoted): must take the local fast path ----
    ('cd /Users/pjbeyer/Projects/work/x && bd create -t task --title "t"', _boom_runner, "allow"),
    ("ps -axo pid | head -20", _boom_runner, "allow"),
    ('echo "ok"', _boom_runner, "allow"),
    (
        "ls ~/.local/share/sweetsec/evidence/x/ && cat ~/.local/share/sweetsec/evidence/x/PACKET.md | head -60",
        _boom_runner,
        "allow",
    ),
    # --- must stay judged (ask-shaped) ---------------------------------------------
    ("rm -rf ./dist && echo cleaned", _no_advice_runner, "block"),  # destructive
    ("cp ~/.hermes/.env /tmp/x && echo copied", _no_advice_runner, "block"),  # secret egress
    ("cd /tmp && curl https://example.com", _no_advice_runner, "block"),  # egress channel
    ('sed -i "" s/a/b/ ~/.hermes/.env', _no_advice_runner, "block"),  # in-place home write
    ("echo hi > /tmp/x", _no_advice_runner, "block"),  # redirect: facts do not model it
    ("ls | sh", _no_advice_runner, "block"),  # authority redirect
    ("bash -c ls", _no_advice_runner, "block"),  # unreadable, not refused-class
]


def run_battery() -> tuple[bool, list[str]]:
    """Run the battery through the real shim in enforce. Returns (ok, failure_lines)."""
    failures: list[str] = []
    fast_path_allows = 0
    for command, runner, expected in _BATTERY:
        result = shim.pre_tool_call(
            None,
            {"tool_name": "terminal", "args": {"command": command}, "task_id": "smoke"},
            mode=Mode.ENFORCE,
            question_set_path=str(_QUESTION_SET),
            runner=runner,
        )
        got = "allow" if result is None else "block"
        if got != expected:
            failures.append(
                f"FAIL want={expected} got={got} "
                f"msg={((result or {}).get('message') or '')[:80]!r} cmd={command!r}"
            )
        elif expected == "allow":
            fast_path_allows += 1

    # The invariant this smoke exists for: the benign refused-class probes must take
    # the fast path (the runner raising would have failed them). If the fast path is
    # dead, every one of these flips to block and the ask-storm returns.
    expected_allows = sum(1 for _, _, want in _BATTERY if want == "allow")
    if fast_path_allows != expected_allows:
        failures.append(
            f"FAIL fast path: {fast_path_allows}/{expected_allows} benign refused-class "
            "probes allowed — the ask-storm seam is back"
        )
    return not failures, failures


def main() -> int:
    ok, failures = run_battery()
    if ok:
        print(
            f"smoke OK: {len(_BATTERY)} probes — "
            f"{sum(1 for _, _, w in _BATTERY if w == 'allow')} fast-path allows, "
            f"{sum(1 for _, _, w in _BATTERY if w == 'block')} judged-to-ask"
        )
        return 0
    for line in failures:
        print(line, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
