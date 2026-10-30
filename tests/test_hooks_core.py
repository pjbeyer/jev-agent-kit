"""Hook core tests (Phase 3): shadow never blocks, enforce fails closed to ask, the adapter
owns its own deadline. All use an injected fake runner; no engine, no network."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from jev_kit.hooks.core import HookOutcome, ToolCall, decide_tool_call
from jev_kit.types import Mode

CALL = ToolCall(command="rm -rf /data", target="db01", context="prod")
QS = str(
    Path(__file__).resolve().parents[1]
    / "skills"
    / "jev-runtime"
    / "questions"
    / "tool-call-gate.json"
)


def ok(records: list[dict[str, Any]]) -> Any:
    return lambda req: {"schema_version": 1, "status": "ok", "records": records}


def test_shadow_always_allows_even_on_failure() -> None:
    for runner in (
        ok([{"route": "ask", "fail_reason": "uncalibrated", "is_mock": False}]),
        lambda req: {"schema_version": 1, "status": "error", "reason": "transport", "records": []},
        lambda req: (_ for _ in ()).throw(RuntimeError("boom")),  # runner raises
    ):
        res = decide_tool_call(CALL, mode=Mode.SHADOW, question_set_path=QS, runner=runner)
        assert res.outcome is HookOutcome.ALLOW


def test_enforce_all_accept_safe_label_allows() -> None:
    runner = ok([
        {"route": "accept", "label": "no", "allow_labels": ["no"], "is_mock": False},
        {"route": "accept", "label": "no", "allow_labels": ["no"], "is_mock": False},
    ])
    res = decide_tool_call(CALL, mode=Mode.ENFORCE, question_set_path=QS, runner=runner)
    assert res.outcome is HookOutcome.ALLOW


def test_enforce_accept_with_dangerous_label_asks() -> None:
    # H1: a confident "destructive = yes" cleared its threshold (accept) but yes is not a safe
    # label, so the hook must ASK, never allow.
    runner = ok([{"route": "accept", "label": "yes", "allow_labels": ["no"], "is_mock": False}])
    res = decide_tool_call(CALL, mode=Mode.ENFORCE, question_set_path=QS, runner=runner)
    assert res.outcome is HookOutcome.ASK


def test_enforce_accept_without_allow_labels_asks() -> None:
    # Backstop: an accept with no declared allow-list never allows.
    runner = ok([{"route": "accept", "label": "no", "is_mock": False}])
    res = decide_tool_call(CALL, mode=Mode.ENFORCE, question_set_path=QS, runner=runner)
    assert res.outcome is HookOutcome.ASK


def test_enforce_any_ask_escalates() -> None:
    runner = ok([
        {"route": "accept", "is_mock": False},
        {"route": "ask", "fail_reason": "uncalibrated", "is_mock": False},
    ])
    res = decide_tool_call(CALL, mode=Mode.ENFORCE, question_set_path=QS, runner=runner)
    assert res.outcome is HookOutcome.ASK
    assert res.reason == "uncalibrated"


def test_enforce_failure_is_ask() -> None:
    def runner(req: dict[str, Any]) -> dict[str, Any]:
        return {"schema_version": 1, "status": "error", "reason": "egress_blocked", "records": []}

    res = decide_tool_call(CALL, mode=Mode.ENFORCE, question_set_path=QS, runner=runner)
    assert res.outcome is HookOutcome.ASK


def test_enforce_mock_never_allows() -> None:
    # A mock record can only carry route ask (engine forces it); confirm the hook escalates.
    runner = ok([{"route": "ask", "is_mock": True, "fail_reason": None}])
    res = decide_tool_call(CALL, mode=Mode.ENFORCE, question_set_path=QS, runner=runner)
    assert res.outcome is HookOutcome.ASK
    assert res.is_mock is True


def test_adapter_owns_deadline_enforce_slow_runner_asks() -> None:
    def slow(req: dict[str, Any]) -> dict[str, Any]:
        time.sleep(2.0)
        return {"schema_version": 1, "status": "ok", "records": [{"route": "accept"}]}

    res = decide_tool_call(
        CALL, mode=Mode.ENFORCE, question_set_path=QS, runner=slow, self_deadline_s=0.2
    )
    assert res.outcome is HookOutcome.ASK
    assert res.timed_out is True


def test_adapter_owns_deadline_shadow_slow_runner_allows() -> None:
    def slow(req: dict[str, Any]) -> dict[str, Any]:
        time.sleep(2.0)
        return {"schema_version": 1, "status": "ok", "records": [{"route": "accept"}]}

    res = decide_tool_call(
        CALL, mode=Mode.SHADOW, question_set_path=QS, runner=slow, self_deadline_s=0.2
    )
    assert res.outcome is HookOutcome.ALLOW  # shadow never blocks, even on timeout
    assert res.timed_out is True


def test_enforce_non_dict_records_fail_closed() -> None:
    # Phase3/4 MAJOR-1: an all-non-dict records list must not vacuously allow in enforce.
    def runner(req: dict[str, Any]) -> dict[str, Any]:
        return {"schema_version": 1, "status": "ok", "records": ["oops", 3]}

    res = decide_tool_call(CALL, mode=Mode.ENFORCE, question_set_path=QS, runner=runner)
    assert res.outcome is HookOutcome.ASK


def test_adapter_returns_within_deadline_despite_hung_runner() -> None:
    # Phase3/4 MAJOR-2: the core must return within its own deadline, not join a hung runner.
    def hung(req: dict[str, Any]) -> dict[str, Any]:
        time.sleep(5.0)
        return {"schema_version": 1, "status": "ok", "records": [{"route": "accept"}]}

    start = time.monotonic()
    res = decide_tool_call(
        CALL, mode=Mode.ENFORCE, question_set_path=QS, runner=hung, self_deadline_s=0.2
    )
    elapsed = time.monotonic() - start
    assert res.outcome is HookOutcome.ASK and res.timed_out is True
    assert elapsed < 2.0  # returned on its own deadline, did not wait ~5s for the worker


# --- Shadow would_outcome contract ---------------------------------------------
# Shadow must rehearse enforce honestly: the sidelog records what enforce would
# have done for the same response, while the host still sees ALLOW. The blind
# spot that shipped unstable enforce: the shadow collapse discarded fail reasons,
# so the sidelog showed ~100% allow and no pre-flip signal existed.


def _shadow_sidelog_rows(runner: Any, command: str = "git status", tmp=None, monkeypatch=None):
    import json as _json
    from pathlib import Path as _Path

    side = tmp / "sidelog.jsonl"
    monkeypatch.setenv("JEV_KIT_SIDELOG_PATH", str(side))
    decide_tool_call(
        ToolCall(command=command, target=None, context="would-test"),
        mode=Mode.SHADOW, question_set_path=QS, runner=runner,
    )
    return [_json.loads(line) for line in side.read_text().splitlines() if line.strip()]


def test_shadow_sidelog_records_would_ask_on_gate_escalation(tmp_path, monkeypatch) -> None:
    # A gate that would not clear in enforce must surface as would_outcome=ask in
    # shadow, with the fail reason preserved — while the outcome stays allow.
    runner = ok([{"route": "accept", "fail_reason": "egress_blocked", "is_mock": False}])
    rows = _shadow_sidelog_rows(runner, tmp=tmp_path, monkeypatch=monkeypatch)
    assert len(rows) == 1
    assert rows[0]["outcome"] == "allow"  # shadow never changes host behavior
    assert rows[0]["would_outcome"] == "ask"
    assert rows[0]["would_reason"] == "egress_blocked"


def test_shadow_sidelog_records_would_allow_on_clean_accept(tmp_path, monkeypatch) -> None:
    # A fully-clear accept with a safe label: would_outcome=allow, no would_reason.
    rec = {"route": "accept", "label": "no", "allow_labels": ["no"], "is_mock": False}
    runner = ok([rec, rec, rec])
    rows = _shadow_sidelog_rows(runner, tmp=tmp_path, monkeypatch=monkeypatch)
    assert len(rows) == 1
    assert rows[0]["outcome"] == "allow"
    assert rows[0]["would_outcome"] == "allow"
    assert "would_reason" not in rows[0]


def test_shadow_sidelog_would_ask_parse_unconfident_with_hazard(tmp_path, monkeypatch) -> None:
    # Mirror of the enforce-only rule: an unconfident parse never allows in enforce —
    # EXCEPT via the local no-egress fast path (harmless unconfident lines like
    # `date` are now decided locally). A parse-unconfident line WITH a hazard fact
    # (`sudo apt install x`: elevation + download + install) still goes to the gate,
    # whose ask the shadow sidelog must surface as would_outcome=ask.
    rec = {"route": "accept", "label": "no", "allow_labels": ["no"], "is_mock": False}
    runner = ok([rec, rec, rec])
    rows = _shadow_sidelog_rows(
        runner, command="sudo apt install x", tmp=tmp_path, monkeypatch=monkeypatch
    )
    assert len(rows) == 1
    assert rows[0]["outcome"] == "allow"
    assert rows[0]["would_outcome"] == "ask"


def test_shadow_sidelog_would_allow_fast_path(tmp_path, monkeypatch) -> None:
    # A harmless compound line (`echo "probe" && echo done`) takes the local fast
    # path in enforce: shadow records the fast-path allow as the would-be outcome,
    # and no model call is made (the runner raises if reached).
    def must_not_run(req: dict[str, Any]) -> dict[str, Any]:
        raise AssertionError("runner must not be called on the fast path")

    rows = _shadow_sidelog_rows(
        must_not_run, command='echo "probe" && echo done', tmp=tmp_path, monkeypatch=monkeypatch
    )
    assert len(rows) == 1
    assert rows[0]["outcome"] == "allow"
    assert rows[0]["would_outcome"] == "allow"
    assert rows[0]["would_reason"] == LOCAL_FAST_PATH_REASON


def test_shadow_sidelog_would_outcome_on_whole_failure(tmp_path, monkeypatch) -> None:
    # Even a whole-request failure (error envelope) carries the enforce ask in shadow.
    def runner(req: dict[str, Any]) -> dict[str, Any]:
        return {"schema_version": 1, "status": "error", "reason": "transport", "records": []}

    rows = _shadow_sidelog_rows(runner, tmp=tmp_path, monkeypatch=monkeypatch)
    assert len(rows) == 1
    assert rows[0]["outcome"] == "allow"
    assert rows[0]["would_outcome"] == "ask"
    assert rows[0]["would_reason"] == "transport"


# --- Local no-egress fast path ---------------------------------------------------
# Owner decision 2026-10-30 (option B): compound/quoted lines the egress reducer
# refuses, whose locally computed facts prove no hazard and no egress channel, are
# decided locally instead of asking. The predicate is pure: it is tested directly,
# and the decision path is tested through decide_tool_call with a runner that must
# never be reached.

from jev_kit.hooks.core import (  # noqa: E402
    LOCAL_FAST_PATH_REASON,
    _local_no_egress_verdict,
)
from jev_kit import destination as _destination  # noqa: E402


def _verdict(command: str) -> bool:
    from jev_kit.command_properties import extract_command_properties

    props = extract_command_properties(command)
    dest = _destination.resolve_destination(command, allowlist=frozenset())
    return _local_no_egress_verdict(command, props, dest)


def test_fast_path_allows_pure_local_compound() -> None:
    assert _verdict('cd /tmp/work && bd create -t task --title "x"')
    assert _verdict("ps -axo pid | head -20")
    assert _verdict('echo "ok"')
    assert _verdict("ls ~/.local/share/evidence && cat ~/.local/share/evidence/x | head -60")


def test_fast_path_rejects_confident_simple_commands() -> None:
    # Confident, simple commands stay on the judged path: the calibrated population
    # must keep flowing through the gate.
    assert not _verdict("pwd")
    assert not _verdict("git status")


def test_fast_path_rejects_hazards_redirects_and_egress() -> None:
    # Any affirmative hazard fact, any redirect, any recognized egress destination
    # keeps the call on the normal gate path.
    assert not _verdict("rm -rf ./dist && echo cleaned")
    assert not _verdict("cp /Users/x/.env /tmp/x && echo copied")
    assert not _verdict("echo hi > /tmp/x")
    assert not _verdict("cd /tmp && curl https://example.com")


def test_fast_path_rejects_home_writes_allows_home_reads() -> None:
    # A home path plus a write verb is a hazard; a home path alone is reads.
    assert not _verdict('sed -i "" s/a/b/ /Users/x/.hermes/.env')
    assert not _verdict("perl -pi -e s/a/b/ /Users/x/.hermes/.env")
    assert not _verdict("cp /Users/x/.hermes/.env /tmp/x")
    assert _verdict("cat /Users/x/.local/share/skills/x.md && echo done")
    assert _verdict("ls /Users/x/.hermes && grep x /Users/x/.hermes/y")


def test_fast_path_decides_locally_in_enforce_without_runner() -> None:
    # The decision happens before any model call: a runner that raises proves the
    # gate was never consulted, and the reason names the fast path.
    def must_not_run(req: dict[str, Any]) -> dict[str, Any]:
        raise AssertionError("runner must not be called on the fast path")

    res = decide_tool_call(
        ToolCall(command='cd /tmp && ps -axo pid | head -5', target=None, context="fp"),
        mode=Mode.ENFORCE, question_set_path=QS, runner=must_not_run,
    )
    assert res.outcome is HookOutcome.ALLOW
    assert res.reason == LOCAL_FAST_PATH_REASON


def test_fast_path_sidelog_records_local_decision(tmp_path, monkeypatch) -> None:
    import json as _json

    side = tmp_path / "sidelog.jsonl"
    monkeypatch.setenv("JEV_KIT_SIDELOG_PATH", str(side))

    def must_not_run(req: dict[str, Any]) -> dict[str, Any]:
        raise AssertionError("runner must not be called on the fast path")

    res = decide_tool_call(
        ToolCall(command='echo "probe"', target=None, context="fp"),
        mode=Mode.ENFORCE, question_set_path=QS, runner=must_not_run,
    )
    assert res.outcome is HookOutcome.ALLOW
    rows = [_json.loads(line) for line in side.read_text().splitlines() if line.strip()]
    assert len(rows) == 1
    assert rows[0]["outcome"] == "allow"
    assert rows[0]["reason"] == LOCAL_FAST_PATH_REASON
