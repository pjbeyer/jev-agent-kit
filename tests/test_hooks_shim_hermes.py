"""Hermes host shim tests (Phase 3): allow maps to `None`, ask maps to a Hermes block payload,
shadow never blocks (even on a slow runner), and `register` wires the plugin hook contract. All
use an injected fake runner (via the core's `runner` param); no engine, no network."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from jev_kit.hooks import hermes
from jev_kit.types import Mode

QS = str(
    Path(__file__).resolve().parents[1]
    / "skills"
    / "jev-runtime"
    / "questions"
    / "tool-call-gate.json"
)

TOOL_CALL: dict[str, Any] = {
    "tool_name": "terminal",
    "args": {"command": "rm -rf /data", "target": "db01"},
    "task_id": "prod",
}


class FakeCtx:
    """A minimal stand-in for a Hermes plugin context."""

    def __init__(self) -> None:
        self.hooks: dict[str, Any] = {}

    def register_hook(self, event: str, callback: Any) -> None:
        self.hooks[event] = callback


def ok(records: list[dict[str, Any]]) -> Any:
    return lambda req: {"schema_version": 1, "status": "ok", "records": records}


def test_enforce_all_accept_allows() -> None:
    runner = ok([{"route": "accept", "label": "no", "allow_labels": ["no"], "is_mock": False}])
    result = hermes.pre_tool_call(
        FakeCtx(), TOOL_CALL, mode=Mode.ENFORCE, question_set_path=QS, runner=runner
    )
    assert result is None


def test_enforce_ask_escalates_to_approve() -> None:
    # Owner decision 2026-10-30: a real (non-mock) ask escalates to Hermes' human
    # approval gate instead of a silent block. rule_key is scoped to the exact
    # command, never the tool name (Hermes' own default would grant terminal-wide).
    runner = ok([{"route": "ask", "fail_reason": "uncalibrated", "is_mock": False}])
    result = hermes.pre_tool_call(
        FakeCtx(), TOOL_CALL, mode=Mode.ENFORCE, question_set_path=QS, runner=runner
    )
    assert result is not None
    assert result["action"] == "approve"
    assert "uncalibrated" in result["message"]
    assert result["rule_key"].startswith("jev:rm")
    assert result["rule_key"] != "terminal"


def test_enforce_ask_message_carries_hazards_and_inventory() -> None:
    # The rubber-stamp fix: the approval card's only operator-readable content is the
    # plugin's message, so it must name the affirmative hazard facts (plain English)
    # and the egress-reduced command inventory — never argument text (no leak onto
    # the card).
    runner = ok([{"route": "ask", "fail_reason": "uncalibrated", "is_mock": False}])
    result = hermes.pre_tool_call(
        FakeCtx(), TOOL_CALL, mode=Mode.ENFORCE, question_set_path=QS, runner=runner
    )
    message = result["message"] if result else ""
    assert "flagged:" in message  # rm -rf -> recursive delete + force flag
    assert "recursive delete" in message
    assert "force flag" in message
    assert "commands: rm" in message
    assert "/data" not in message  # argument text never reaches the card
    assert "db01" not in message


def test_enforce_mock_ask_still_blocks() -> None:
    # A mock (test/stub) ask never escalates to a human: it blocks, as before.
    runner = ok([{"route": "ask", "fail_reason": "uncalibrated", "is_mock": True}])
    result = hermes.pre_tool_call(
        FakeCtx(), TOOL_CALL, mode=Mode.ENFORCE, question_set_path=QS, runner=runner
    )
    assert result == {
        "action": "block",
        "message": "jev-kit gate: blocked for human review. (reason: uncalibrated)",
    }


def test_rule_key_is_stable_for_identical_commands_narrow_across_different() -> None:
    assert hermes._rule_key("git push origin main") == hermes._rule_key("git push origin main")
    assert hermes._rule_key("git push origin main") != hermes._rule_key("git push origin dev")


def test_shadow_never_blocks_even_when_gate_would_ask() -> None:
    runner = ok([{"route": "ask", "fail_reason": "uncalibrated", "is_mock": False}])
    result = hermes.pre_tool_call(
        FakeCtx(), TOOL_CALL, mode=Mode.SHADOW, question_set_path=QS, runner=runner
    )
    assert result is None


def test_shadow_never_blocks_even_on_slow_runner_past_self_deadline() -> None:
    def slow(req: dict[str, Any]) -> dict[str, Any]:
        time.sleep(2.0)
        return {"schema_version": 1, "status": "ok", "records": [{"route": "accept"}]}

    result = hermes.pre_tool_call(
        FakeCtx(),
        TOOL_CALL,
        mode=Mode.SHADOW,
        question_set_path=QS,
        runner=slow,
        self_deadline_s=0.2,
    )
    assert result is None


def test_enforce_slow_runner_past_self_deadline_escalates() -> None:
    # A timeout ask is a real (non-mock) ask: it escalates to the human gate. The
    # core's own self-deadline produce the ask; Hermes' approval gate then enforces
    # its own timeout, so a hung gate still fails closed.
    def slow(req: dict[str, Any]) -> dict[str, Any]:
        time.sleep(2.0)
        return {"schema_version": 1, "status": "ok", "records": [{"route": "accept"}]}

    result = hermes.pre_tool_call(
        FakeCtx(),
        TOOL_CALL,
        mode=Mode.ENFORCE,
        question_set_path=QS,
        runner=slow,
        self_deadline_s=0.2,
    )
    assert result is not None
    assert result["action"] == "approve"


def test_unparseable_event_shadow_allows() -> None:
    result = hermes.pre_tool_call(
        FakeCtx(), object(), mode=Mode.SHADOW, question_set_path=QS, runner=ok([])
    )
    assert result is None


def test_unparseable_event_enforce_blocks() -> None:
    result = hermes.pre_tool_call(
        FakeCtx(), {"nothing": "useful"}, mode=Mode.ENFORCE, question_set_path=QS, runner=ok([])
    )
    assert result == {
        "action": "block",
        "message": "jev-kit gate: blocked for human review. (reason: unparseable_event)",
    }


def test_register_wires_pre_tool_call_hook() -> None:
    ctx = FakeCtx()
    hermes.register(ctx, mode=Mode.ENFORCE, question_set_path=QS,
                    runner=ok([{"route": "accept", "label": "no", "allow_labels": ["no"]}]))
    assert "pre_tool_call" in ctx.hooks

    result = ctx.hooks["pre_tool_call"](TOOL_CALL)
    assert result is None


def test_register_hook_accepts_kwarg_calling_convention() -> None:
    ctx = FakeCtx()
    runner = ok([{"route": "ask", "fail_reason": "uncalibrated", "is_mock": False}])
    hermes.register(ctx, mode=Mode.ENFORCE, question_set_path=QS, runner=runner)

    handler = ctx.hooks["pre_tool_call"]
    result = handler(tool_name="terminal", args={"command": "rm -rf /data"}, task_id="prod")
    assert result is not None
    assert result["action"] == "approve"


def test_register_defaults_to_shadow_and_never_blocks(monkeypatch: Any) -> None:
    monkeypatch.delenv("JEV_KIT_HOOK_MODE", raising=False)
    ctx = FakeCtx()
    runner = ok([{"route": "ask", "fail_reason": "uncalibrated", "is_mock": False}])
    hermes.register(ctx, question_set_path=QS, runner=runner)

    result = ctx.hooks["pre_tool_call"](TOOL_CALL)
    assert result is None


# ---------------------------------------------------------------------------
# jak-baw scope 2: non-shell tool extraction. A bare tool name used to land in
# ToolCall.command (unparseable -> blind ask on 4,459/4,460 measured calls).
# Reader-class tools now map their defining argument to a parser-modeled
# pseudo-command; writers and unmapped tools keep the bare name (fail-closed).
# ---------------------------------------------------------------------------


def test_read_file_maps_to_modeled_reader_pseudo_command() -> None:
    call = hermes._extract_tool_call(
        {"tool_name": "read_file", "args": {"path": "/Users/x/.hermes/config.yaml"}}
    )
    assert call is not None
    assert call.command == "cat /Users/x/.hermes/config.yaml"
    assert hermes._parse_confident(call.command) is True


def test_search_files_maps_pattern_to_grep() -> None:
    call = hermes._extract_tool_call(
        {"tool_name": "search_files", "args": {"pattern": "JEV_KIT", "path": "/Users/x/p"}}
    )
    assert call is not None
    assert call.command == "grep JEV_KIT"


def test_skill_view_maps_name_to_cat() -> None:
    call = hermes._extract_tool_call(
        {"tool_name": "skill_view", "args": {"name": "memory"}}
    )
    assert call is not None
    assert call.command == "cat memory"


def test_writer_tools_keep_bare_name_and_fail_closed() -> None:
    # write_file's `content` is the file BODY, not a command; it must never become
    # ToolCall.command. The call keeps the bare tool name and stays unparseable.
    call = hermes._extract_tool_call(
        {"tool_name": "write_file", "args": {"path": "/tmp/x", "content": "rm -rf /"}}
    )
    assert call is not None
    assert call.command == "write_file"
    assert hermes._parse_confident(call.command) is False


def test_execute_code_body_never_becomes_command() -> None:
    call = hermes._extract_tool_call(
        {"tool_name": "execute_code", "args": {"code": "import os; os.system('rm -rf /')"}}
    )
    assert call is not None
    assert call.command == "execute_code"


def test_unmapped_tool_keeps_bare_name() -> None:
    call = hermes._extract_tool_call({"tool_name": "delegate_task", "args": {"tasks": []}})
    assert call is not None
    assert call.command == "delegate_task"


def test_shell_command_extraction_unchanged() -> None:
    call = hermes._extract_tool_call(
        {"tool_name": "terminal", "args": {"command": "git status"}}
    )
    assert call is not None
    assert call.command == "git status"


def test_non_simple_argument_keeps_bare_name() -> None:
    # quoted / shell-syntax args must NOT be embedded in a pseudo-command
    call = hermes._extract_tool_call(
        {"tool_name": "read_file", "args": {"path": "a;rm -rf /tmp"}}
    )
    assert call is not None
    assert call.command == "read_file"


def test_semantic_hazard_still_detected_through_mapping() -> None:
    # A hostile path arg cannot smuggle a hazard: cat treats everything as filenames.
    call = hermes._extract_tool_call(
        {"tool_name": "read_file", "args": {"path": "rm -rf /tmp"}}
    )
    assert call is not None
    assert call.command == "cat rm -rf /tmp"
    props = hermes._command_properties(call.command)
    assert props.parse_confident is True
    # no HAZARD facts fire (the lone positive is targets_absolute_path, a true statement
    # about a filename in the line, not a hazard); the questions still judge the call.
    from jev_kit.command_properties import PROPERTY_NAMES  # noqa: I001

    hazards = [
        v for k, v in props.values.items() if v and k != "targets_absolute_path"
    ]
    assert not hazards
