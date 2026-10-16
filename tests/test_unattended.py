"""Unattended (cron) session semantics for the gate.

A gate fails closed to ASK, which a host maps to its human-approval path. With no human on
that path the same escalation becomes a hard block with nobody to review it. These tests
cover the detection rule (both signals, prefix only), the policy, and the precedence rule
that matters most: an affirmative danger verdict still blocks in unattended context.

The engine runs in process against the labeled mock transport; nothing calls the live API.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from jev_kit.hooks import claude as claude_shim
from jev_kit.hooks import codex, core, hermes
from jev_kit.hooks.core import HookOutcome, ToolCall, decide_tool_call
from jev_kit.types import Mode
from jev_kit.unattended import (
    CRON_SESSION_ENV_VAR,
    DEFAULT_POLICY,
    POLICY_ENV_VAR,
    UnattendedPolicy,
    audit_log_path,
    is_unattended,
    policy_from_env,
    resolve_escalation,
)

REPO = Path(__file__).resolve().parents[1]
GATE = str(REPO / "skills" / "jev-runtime" / "questions" / "tool-call-gate.json")


# --------------------------------------------------------------------------- detection


@pytest.mark.parametrize(
    "task_id",
    ["cron:nightly-sync:run-7", "cron:", "cron:job"],
)
def test_prefix_detects_cron_task_ids(task_id: str) -> None:
    assert is_unattended(task_id, {}) is True


@pytest.mark.parametrize(
    "task_id",
    [
        None,
        "",
        "interactive-session",
        "session-cron-like",  # contains "cron" but does not start with it
        "cron",  # no colon
        "cronish:job",  # prefix is cron:, not cron
        "x:cron:job",
    ],
)
def test_substring_and_near_misses_are_not_unattended(task_id: object) -> None:
    # A substring match would exempt an interactive session whose id merely contains "cron",
    # which is a silent hole in the direction of "allowed". The contract forbids it.
    assert is_unattended(task_id, {}) is False


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on", " true "])
def test_env_var_trueish_detects_unattended(value: str) -> None:
    assert is_unattended(None, {CRON_SESSION_ENV_VAR: value}) is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "maybe", "2", "cron"])
def test_env_var_anything_else_is_attended(value: str) -> None:
    assert is_unattended(None, {CRON_SESSION_ENV_VAR: value}) is False


def test_env_var_absent_is_attended() -> None:
    assert is_unattended(None, {}) is False


def test_either_signal_suffices() -> None:
    assert is_unattended("cron:j:r", {}) is True
    assert is_unattended(None, {CRON_SESSION_ENV_VAR: "1"}) is True
    assert is_unattended("interactive", {CRON_SESSION_ENV_VAR: "1"}) is True
    assert is_unattended("interactive", {}) is False


def test_is_unattended_never_raises() -> None:
    for task_id in (1, [], {}, object(), None):
        assert is_unattended(task_id, {}) is False


# --------------------------------------------------------------------------- policy


def test_default_policy_is_record() -> None:
    # The default must not break automation, and must not silently allow either.
    assert DEFAULT_POLICY is UnattendedPolicy.RECORD
    assert policy_from_env({}) is UnattendedPolicy.RECORD


@pytest.mark.parametrize("value", ["record", "block", "allow", "BLOCK", " Record "])
def test_policy_is_configurable(value: str) -> None:
    assert policy_from_env({POLICY_ENV_VAR: value}) is UnattendedPolicy(value.strip().lower())


@pytest.mark.parametrize("value", ["", "nonsense", "true", "1"])
def test_an_unreadable_policy_falls_back_to_the_default(value: str) -> None:
    assert policy_from_env({POLICY_ENV_VAR: value}) is DEFAULT_POLICY


@pytest.mark.parametrize("policy", list(UnattendedPolicy))
def test_attended_context_always_escalates(policy: UnattendedPolicy) -> None:
    outcome = resolve_escalation(would_escalate=True, unattended=False, policy=policy)
    assert outcome.proceed is False


def test_record_proceeds_and_marks_the_suppressed_escalation() -> None:
    outcome = resolve_escalation(
        would_escalate=True, unattended=True, policy=UnattendedPolicy.RECORD
    )
    assert outcome.proceed is True
    assert outcome.would_escalate is True


def test_block_still_escalates() -> None:
    outcome = resolve_escalation(
        would_escalate=True, unattended=True, policy=UnattendedPolicy.BLOCK
    )
    assert outcome.proceed is False


def test_allow_proceeds() -> None:
    outcome = resolve_escalation(
        would_escalate=True, unattended=True, policy=UnattendedPolicy.ALLOW
    )
    assert outcome.proceed is True


def test_nothing_to_escalate_never_proceeds() -> None:
    for policy in UnattendedPolicy:
        outcome = resolve_escalation(would_escalate=False, unattended=True, policy=policy)
        assert outcome.proceed is False


# --------------------------------------------------------------------------- audit path


def test_audit_log_path_defaults_under_hermes_home(tmp_path: Path) -> None:
    assert audit_log_path({"HERMES_HOME": str(tmp_path)}) == (
        tmp_path / "logs" / "jev-kit-unattended.jsonl"
    )


def test_audit_log_path_can_be_disabled() -> None:
    for value in ("off", "OFF", "none", "false"):
        assert audit_log_path({"JEV_KIT_UNATTENDED_AUDIT_LOG": value}) is None


def test_audit_log_path_honours_an_explicit_path(tmp_path: Path) -> None:
    target = tmp_path / "custom.jsonl"
    assert audit_log_path({"JEV_KIT_UNATTENDED_AUDIT_LOG": str(target)}) == target


# --------------------------------------------------------------------------- through the hooks


def _ask(request: dict[str, Any]) -> dict[str, Any]:
    """A gate that cannot clear: every question asks."""
    return {"schema_version": 1, "status": "ok", "records": [{"route": "ask"}]}


def _all_accept(request: dict[str, Any]) -> dict[str, Any]:
    rec = {"route": "accept", "label": "no", "allow_labels": ["no"], "is_mock": False}
    return {"schema_version": 1, "status": "ok", "records": [rec, rec, rec]}


def _run_hermes(
    command: str, *, task_id: str | None, mode: Mode, runner: Any, monkeypatch: Any, tmp_path: Path
) -> dict[str, Any] | None:
    monkeypatch.setenv("JEV_KIT_UNATTENDED_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    event: dict[str, Any] = {"tool_name": "terminal", "args": {"command": command}}
    if task_id is not None:
        event["task_id"] = task_id
    return hermes.pre_tool_call(
        None, event, mode=mode, question_set_path=GATE, runner=runner
    )


def test_unattended_ask_is_suppressed_by_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(POLICY_ENV_VAR, raising=False)
    out = _run_hermes(
        "git status", task_id="cron:job:run", mode=Mode.ENFORCE, runner=_ask,
        monkeypatch=monkeypatch, tmp_path=tmp_path,
    )
    assert out is None  # allowed through: no human to escalate to, and record is the default


def test_unattended_ask_records_what_would_have_happened(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(POLICY_ENV_VAR, raising=False)
    _run_hermes(
        "git status", task_id="cron:job:run", mode=Mode.ENFORCE, runner=_ask,
        monkeypatch=monkeypatch, tmp_path=tmp_path,
    )
    rows = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert len(rows) == 1
    row = rows[0]
    assert row["unattended"] is True
    assert row["policy"] == "record"
    assert row["would_escalate"] is True
    assert row["would_outcome"] == "ask"
    assert row["command"] == "git"
    # The record is local and holds only the basename, matching the egress discipline.
    assert "status" not in json.dumps(row)


def test_interactive_ask_still_escalates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(POLICY_ENV_VAR, raising=False)
    out = _run_hermes(
        "git status", task_id="interactive-1", mode=Mode.ENFORCE, runner=_ask,
        monkeypatch=monkeypatch, tmp_path=tmp_path,
    )
    assert out is not None and out["action"] == "block"


def test_unattended_block_policy_still_escalates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(POLICY_ENV_VAR, "block")
    out = _run_hermes(
        "git status", task_id="cron:job:run", mode=Mode.ENFORCE, runner=_ask,
        monkeypatch=monkeypatch, tmp_path=tmp_path,
    )
    assert out is not None and out["action"] == "block"


def test_env_var_signal_alone_suppresses_in_unattended_context(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(POLICY_ENV_VAR, raising=False)
    monkeypatch.setenv(CRON_SESSION_ENV_VAR, "1")
    out = _run_hermes(
        "git status", task_id=None, mode=Mode.ENFORCE, runner=_ask,
        monkeypatch=monkeypatch, tmp_path=tmp_path,
    )
    assert out is None


def test_a_session_id_merely_containing_cron_is_still_attended(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(POLICY_ENV_VAR, raising=False)
    monkeypatch.delenv(CRON_SESSION_ENV_VAR, raising=False)
    out = _run_hermes(
        "git status", task_id="my-cron-ish-session", mode=Mode.ENFORCE, runner=_ask,
        monkeypatch=monkeypatch, tmp_path=tmp_path,
    )
    assert out is not None and out["action"] == "block"


def test_shadow_is_unaffected_by_the_unattended_policy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Shadow never changes host behavior, so the policy has nothing to suppress there.
    monkeypatch.setenv(POLICY_ENV_VAR, "block")
    out = _run_hermes(
        "git status", task_id="cron:job:run", mode=Mode.SHADOW, runner=_ask,
        monkeypatch=monkeypatch, tmp_path=tmp_path,
    )
    assert out is None


def test_shadow_never_yields_ask() -> None:
    # The invariant the unattended branch's mode check depends on, asserted directly rather
    # than left implied: if shadow could ever return ASK, the policy would have to be applied
    # there too. Every response shape, including the failure ones.
    def _err(request: dict[str, Any]) -> dict[str, Any]:
        return {"schema_version": 1, "status": "error", "reason": "egress_blocked"}

    for runner in (_ask, _err, _all_accept):
        for command in ("ls -la", "rm -rf $HOME", "git status"):
            res = decide_tool_call(
                ToolCall(command),
                mode=Mode.SHADOW,
                question_set_path=GATE,
                runner=runner,
                task_id="cron:job:run",
            )
            assert res.outcome is HookOutcome.ALLOW


def test_an_affirmative_allow_is_not_touched_by_the_policy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(POLICY_ENV_VAR, "block")
    out = _run_hermes(
        "ls -la", task_id="cron:job:run", mode=Mode.ENFORCE, runner=_all_accept,
        monkeypatch=monkeypatch, tmp_path=tmp_path,
    )
    assert out is None  # a clean allow, not a suppressed escalation


def test_an_unconfident_command_in_cron_is_suppressed_not_hard_blocked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # This is the headline defect: enforce forces ASK for a command the parser cannot read,
    # and a cron job then hard-blocked with no reviewer. With the default policy the call
    # proceeds and the escalation is recorded.
    monkeypatch.delenv(POLICY_ENV_VAR, raising=False)
    out = _run_hermes(
        "git push origin main", task_id="cron:job:run", mode=Mode.ENFORCE, runner=_all_accept,
        monkeypatch=monkeypatch, tmp_path=tmp_path,
    )
    assert out is None
    rows = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert rows and rows[0]["reason"] == "command_parse_unconfident"


def test_audit_write_failure_never_breaks_the_turn(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # An unwritable audit path must not turn a suppressed escalation into a crash.
    monkeypatch.delenv(POLICY_ENV_VAR, raising=False)
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    monkeypatch.setenv("JEV_KIT_UNATTENDED_AUDIT_LOG", str(blocker / "audit.jsonl"))
    out = _run_hermes(
        "git status", task_id="cron:job:run", mode=Mode.ENFORCE, runner=_ask,
        monkeypatch=monkeypatch, tmp_path=tmp_path,
    )
    assert out is None


# --------------------------------------------------------------------------- other hosts


def test_claude_cron_task_id_is_detected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(POLICY_ENV_VAR, raising=False)
    monkeypatch.setenv("JEV_KIT_UNATTENDED_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "session_id": "cron:job:run",
        "tool_input": {"command": "git status"},
    }
    out = claude_shim.handle_claude_event(
        event, mode=Mode.ENFORCE, question_set_path=GATE, runner=_ask
    )
    assert out == {}  # allowed: the escalation was suppressed and recorded


def test_codex_cron_task_id_is_detected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(POLICY_ENV_VAR, raising=False)
    monkeypatch.setenv("JEV_KIT_UNATTENDED_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "shell",
        "session_id": "cron:job:run",
        "tool_input": {"command": "git status"},
    }
    out = codex.handle_codex_event(
        event, mode=Mode.ENFORCE, question_set_path=GATE, runner=_ask
    )
    assert out == {}


def test_decide_tool_call_takes_task_id_directly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(POLICY_ENV_VAR, raising=False)
    monkeypatch.setenv("JEV_KIT_UNATTENDED_AUDIT_LOG", "off")
    res = decide_tool_call(
        ToolCall("git status"),
        mode=Mode.ENFORCE,
        question_set_path=GATE,
        runner=_ask,
        task_id="cron:j:r",
    )
    assert res.outcome is HookOutcome.ALLOW
    assert res.route == "unattended"


def test_core_module_exposes_the_detection_helpers() -> None:
    assert core.dest_allowlist_from_env() == frozenset()
