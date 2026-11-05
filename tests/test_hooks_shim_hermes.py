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
# jak-baw full coverage: non-shell tool extraction into the `hermes.<tool>`
# pseudo-program namespace. A bare tool name used to land in ToolCall.command
# (unparseable -> blind ask on 4,459/4,460 measured calls). Modeled tools now
# emit `hermes.<tool> [naming args]`; the parser (command_properties +
# hermes_tools) models each tool's true effect class. Unmapped tools (MCP
# bridges, cron) keep the bare name and fail closed.
# ---------------------------------------------------------------------------


def test_read_file_emits_namespaced_reader() -> None:
    call = hermes._extract_tool_call(
        {"tool_name": "read_file", "args": {"path": "/Users/x/.hermes/config.yaml"}}
    )
    assert call is not None
    assert call.command == "hermes.read_file /Users/x/.hermes/config.yaml"
    assert hermes._parse_confident(call.command) is True


def test_search_files_emits_pattern_only() -> None:
    call = hermes._extract_tool_call(
        {"tool_name": "search_files", "args": {"pattern": "JEV_KIT", "path": "/Users/x/p"}}
    )
    assert call is not None
    assert call.command == "hermes.search_files JEV_KIT"


def test_skill_view_emits_name() -> None:
    call = hermes._extract_tool_call(
        {"tool_name": "skill_view", "args": {"name": "memory"}}
    )
    assert call is not None
    assert call.command == "hermes.skill_view memory"


def test_writer_emits_namespaced_writer_with_dest_exists() -> None:
    # write_file is MODELED as a writer now: the path is the destination and
    # target_stat must stat it so overwrites_data can discriminate.
    import tempfile
    from pathlib import Path

    from jev_kit import target_stat

    with tempfile.NamedTemporaryFile(suffix=".txt") as tf:
        existing = str(Path(tf.name))
        call = hermes._extract_tool_call(
            {"tool_name": "write_file", "args": {"path": existing, "content": "x"}}
        )
        assert call is not None
        assert call.command.startswith("hermes.write_file ")
        assert hermes._parse_confident(call.command) is True
        stat = target_stat.resolve_dest_exists(call.command)
        assert stat.dest_exists is True  # the temp file existed at judge time


def test_writer_payload_never_becomes_command() -> None:
    call = hermes._extract_tool_call(
        {"tool_name": "write_file", "args": {"path": "/tmp/x", "content": "rm -rf /"}}
    )
    assert call is not None
    assert call.command == "hermes.write_file /tmp/x"
    assert "rm -rf" not in call.command


def test_execute_code_emits_code_exec_head() -> None:
    # execute_code is MODELED (code-exec class): the head fires runs_unseen_code
    # (unconfident by design) even though the script body is never embedded.
    call = hermes._extract_tool_call(
        {"tool_name": "execute_code", "args": {"code": "import os; os.system('rm -rf /')"}}
    )
    assert call is not None
    assert call.command == "hermes.execute_code"
    props = hermes._command_properties(call.command)
    assert props.parse_confident is False
    assert props.reason == "runs_unseen_code"


def test_delegate_task_emits_code_exec_head() -> None:
    call = hermes._extract_tool_call({"tool_name": "delegate_task", "args": {"tasks": []}})
    assert call is not None
    assert call.command == "hermes.delegate_task"


def test_mcp_bridge_stays_bare_and_fail_closed() -> None:
    call = hermes._extract_tool_call(
        {"tool_name": "mcp__local_mcp_aggregator__call_tool", "args": {"calls": []}}
    )
    assert call is not None
    assert call.command == "mcp__local_mcp_aggregator__call_tool"
    assert hermes._parse_confident(call.command) is False


def test_web_search_fires_network_upload_fact() -> None:
    call = hermes._extract_tool_call(
        {"tool_name": "web_search", "args": {"query": "jev kit", "limit": 5}}
    )
    assert call is not None
    assert call.command == "hermes.web_search jev kit"
    props = hermes._command_properties(call.command)
    assert props.parse_confident is True
    assert props.values.get("network_upload") is True


def test_shell_command_extraction_unchanged() -> None:
    call = hermes._extract_tool_call(
        {"tool_name": "terminal", "args": {"command": "git status"}}
    )
    assert call is not None
    assert call.command == "git status"


def test_non_simple_argument_keeps_head_only() -> None:
    # quoted / shell-syntax args must NOT be embedded in the pseudo-command;
    # the modeled head still carries the effect facts.
    call = hermes._extract_tool_call(
        {"tool_name": "read_file", "args": {"path": "a;rm -rf /tmp"}}
    )
    assert call is not None
    assert call.command == "hermes.read_file"


def test_semantic_hazard_cannot_smuggle_through_path_arg() -> None:
    call = hermes._extract_tool_call(
        {"tool_name": "read_file", "args": {"path": "rm -rf /tmp"}}
    )
    assert call is not None
    assert call.command == "hermes.read_file rm -rf /tmp"
    props = hermes._command_properties(call.command)
    assert props.parse_confident is True
    # `rm` here is a FILENAME the reader would open, not a program: no hazard
    # facts fire (only path truths), and the questions still judge the call.
    hazards = [
        v for k, v in props.values.items() if v and k != "targets_absolute_path"
    ]
    assert not hazards


def test_spoofed_namespace_head_in_shell_stays_unmodeled() -> None:
    # A typed `hermes.unknown_tool` in a SHELL line must not gain confidence
    # from the namespace: only modeled tool names are in the allowlist.
    assert hermes._parse_confident("hermes.unknown_tool /tmp/x") is False
    assert hermes._parse_confident("hermes.read_file /etc/passwd") is True


def test_bare_tool_name_without_prefix_stays_unconfident() -> None:
    # The bare name (extraction failure / spoof) must never parse confidently.
    assert hermes._parse_confident("read_file") is False
    assert hermes._parse_confident("execute_code") is False


def test_writer_to_auto_run_path_fires_the_autorun_fact() -> None:
    # write_file to a LaunchAgent dir fires targets_autorun_path. Same semantics
    # as `cp x ~/Library/LaunchAgents/e.plist`: a FACT the questions judge, not a
    # parse-unsure (the planted-code unsures cover auto-run FILE NAMES, not dirs).
    call = hermes._extract_tool_call(
        {"tool_name": "write_file", "args": {"path": "/Users/x/Library/LaunchAgents/e.plist"}}
    )
    assert call is not None
    props = hermes._command_properties(call.command)
    assert props.values.get("targets_autorun_path") is True


def test_writer_to_auto_run_file_name_is_unconfident() -> None:
    # Writing a file whose NAME tools auto-run (Makefile, package.json...) stays
    # unconfident via the planted-code rule, same as cp.
    call = hermes._extract_tool_call(
        {"tool_name": "write_file", "args": {"path": "/Users/x/proj/package.json"}}
    )
    assert call is not None
    props = hermes._command_properties(call.command)
    assert props.parse_confident is False
    assert props.reason == "writes_auto_run_file"


# ---------------------------------------------------------------------------
# jak-baw full coverage: extended taxonomy (writers without paths, persistence,
# authority, deferred dispatch). Effect facts must be TRUE statements.
# ---------------------------------------------------------------------------


def test_cron_create_fires_autorun_fact() -> None:
    call = hermes._extract_tool_call(
        {"tool_name": "cronjob_manage", "args": {"action": "create"}}
    )
    assert call is not None
    assert call.command == "hermes.cronjob_manage create"
    props = hermes._command_properties(call.command)
    assert props.parse_confident is True
    assert props.values.get("targets_autorun_path") is True


def test_cron_list_is_clean() -> None:
    call = hermes._extract_tool_call(
        {"tool_name": "cronjob_manage", "args": {"action": "list"}}
    )
    assert call is not None
    props = hermes._command_properties(call.command)
    assert props.parse_confident is True
    assert not any(v for v in props.values.values() if v)


def test_cron_run_is_unseen_code() -> None:
    call = hermes._extract_tool_call(
        {"tool_name": "cronjob_manage", "args": {"action": "run"}}
    )
    assert call is not None
    props = hermes._command_properties(call.command)
    assert props.parse_confident is False
    assert props.reason == "runs_unseen_code"


def test_blind_write_never_parses_confidently() -> None:
    # skill_manage/memory operate via payload dicts (no path operand): a blind
    # write must stay unconfident — writer_target_unknown.
    for tool in ("skill_manage", "memory"):
        call = hermes._extract_tool_call(
            {"tool_name": tool, "args": {"operations": [{"action": "create"}]}}
        )
        assert call is not None
        assert call.command == f"hermes.{tool}"
        props = hermes._command_properties(call.command)
        assert props.parse_confident is False
        assert props.reason == "writer_target_unknown"


def test_connection_grant_fires_authority_fact() -> None:
    call = hermes._extract_tool_call(
        {"tool_name": "manage_connections", "args": {"action": "connect"}}
    )
    assert call is not None
    props = hermes._command_properties(call.command)
    assert props.parse_confident is True
    assert props.values.get("grants_authority") is True


def test_deferred_dispatch_is_unseen_code() -> None:
    call = hermes._extract_tool_call({"tool_name": "tool_call", "args": {"calls": []}})
    assert call is not None
    props = hermes._command_properties(call.command)
    assert props.parse_confident is False
    assert props.reason == "runs_unseen_code"


def test_browser_exec_is_unseen_code_not_network() -> None:
    # browser_exec drives JS in a real browser: code-exec class outranks network.
    call = hermes._extract_tool_call(
        {"tool_name": "browser_exec", "args": {"code": "x=1"}}
    )
    assert call is not None
    assert call.command == "hermes.browser_exec"
    props = hermes._command_properties(call.command)
    assert props.parse_confident is False
    assert props.reason == "runs_unseen_code"


# ---------------------------------------------------------------------------
# jak-b8n: MCP bridge coverage. Discovery heads read-only; dispatch classified
# per mcp_tools inventory; unmodeled targets fail closed; payloads never ride.
# ---------------------------------------------------------------------------


def test_mcp_discovery_heads_are_readers() -> None:
    for tool in (
        "mcp__local_mcp_aggregator__search_tools",
        "mcp__local_mcp_aggregator__get_tool_schema",
    ):
        call = hermes._extract_tool_call({"tool_name": tool, "args": {}})
        assert call is not None
        assert call.command == f"hermes.{tool}"
        props = hermes._command_properties(call.command)
        assert props.parse_confident is True
        assert not any(v for v in props.values.values() if v)


def test_mcp_dispatch_reader_target_confident_with_egress_fact() -> None:
    call = hermes._extract_tool_call(
        {
            "tool_name": "mcp__local_mcp_aggregator__call_tool",
            "args": {
                "calls": [
                    {"name": "slack-slack_search_public", "arguments": {"query": "x"}}
                ]
            },
        }
    )
    assert call is not None
    assert call.command == "hermes.mcp_call_tool slack-slack_search_public"
    props = hermes._command_properties(call.command)
    assert props.parse_confident is True
    assert props.values.get("network_upload") is True


def test_mcp_dispatch_writer_target_stays_unconfident() -> None:
    call = hermes._extract_tool_call(
        {
            "tool_name": "mcp__local_mcp_aggregator__call_tool",
            "args": {
                "calls": [
                    {
                        "name": "slack-slack_send_message",
                        "arguments": {"channel_id": "C1"},
                    }
                ]
            },
        }
    )
    assert call is not None
    assert call.command == "hermes.mcp_call_tool slack-slack_send_message"
    props = hermes._command_properties(call.command)
    assert props.parse_confident is False
    assert props.reason == "remote_state_write"


def test_mcp_dispatch_code_exec_and_authority_fail_closed() -> None:
    for target, reason in (
        ("aws_mcp-aws___run_script", "runs_unseen_code"),
        ("aws_mcp-aws___get_presigned_url", "mcp_grants_authority"),
        ("obscura-browser_click", "runs_unseen_code"),
    ):
        call = hermes._extract_tool_call(
            {
                "tool_name": "mcp__local_mcp_aggregator__call_tool",
                "args": {"calls": [{"name": target, "arguments": {}}]},
            }
        )
        assert call is not None
        props = hermes._command_properties(call.command)
        assert props.parse_confident is False
        assert props.reason == reason


def test_mcp_dispatch_navigator_is_download() -> None:
    call = hermes._extract_tool_call(
        {
            "tool_name": "mcp__local_mcp_aggregator__call_tool",
            "args": {
                "calls": [
                    {"name": "obscura-browser_navigate", "arguments": {"url": "u"}}
                ]
            },
        }
    )
    assert call is not None
    props = hermes._command_properties(call.command)
    assert props.parse_confident is True
    assert props.values.get("network_download") is True


def test_mcp_dispatch_unknown_target_fails_closed() -> None:
    call = hermes._extract_tool_call(
        {
            "tool_name": "mcp__local_mcp_aggregator__call_tool",
            "args": {"calls": [{"name": "newserver-future_tool", "arguments": {}}]},
        }
    )
    assert call is not None
    assert call.command == "hermes.mcp_call_tool newserver-future_tool"
    props = hermes._command_properties(call.command)
    assert props.parse_confident is False
    assert props.reason == "mcp_dispatch_target_unknown"


def test_mcp_dispatch_never_embeds_payload() -> None:
    # The nested arguments payload must not ride; a missing name, non-dict
    # member, or un-simple (hostile) name keeps the bare bridge name
    # (unmodeled, fail-closed).
    for args in (
        {},
        {"calls": []},
        {"calls": [{"arguments": {"name": "no-name-key"}}]},
        {"calls": [{"name": "slack-slack_send_message; rm -rf /", "arguments": {}}]},
        {"calls": [{"name": "a", "arguments": {}}, "not-a-dict"]},
    ):
        call = hermes._extract_tool_call(
            {"tool_name": "mcp__local_mcp_aggregator__call_tool", "args": args}
        )
        assert call is not None
        assert call.command == "mcp__local_mcp_aggregator__call_tool"
        assert hermes._parse_confident(call.command) is False
        assert not call.command.startswith("hermes.")


def test_mcp_batch_judged_by_worst_member() -> None:
    # jak-b8n multi-call (2026-11-05): a batch dispatches several named tools;
    # every member name rides, and the parse is judged by the WORST member.
    reader = {"name": "slack-slack_search_public", "arguments": {}}
    writer = {"name": "slack-slack_send_message", "arguments": {}}
    exec_ = {"name": "aws_mcp-aws___run_script", "arguments": {}}
    unknown = {"name": "newserver-future_tool", "arguments": {}}

    def extract(calls):
        call = hermes._extract_tool_call(
            {"tool_name": "mcp__local_mcp_aggregator__call_tool",
             "args": {"calls": calls}}
        )
        assert call is not None
        return call

    # all readers: confident, egress fact fires once
    call = extract([reader, reader])
    assert call.command.startswith("hermes.mcp_call_tool slack-slack_search_public")
    props = hermes._command_properties(call.command)
    assert props.parse_confident is True
    assert props.values.get("network_upload") is True

    # reader + writer: the writer fail-closes the whole batch
    props = hermes._command_properties(extract([reader, writer]).command)
    assert props.parse_confident is False
    assert props.reason == "remote_state_write"

    # writer is outranked by code-exec
    props = hermes._command_properties(extract([reader, writer, exec_]).command)
    assert props.parse_confident is False
    assert props.reason == "runs_unseen_code"

    # any unknown member fail-closes even if the rest are readers
    props = hermes._command_properties(extract([reader, unknown]).command)
    assert props.parse_confident is False
    assert props.reason == "mcp_dispatch_target_unknown"


def test_mcp_batch_reader_navigator_fires_both_facts() -> None:
    reader = {"name": "slack-slack_search_public", "arguments": {}}
    nav = {"name": "obscura-browser_navigate", "arguments": {}}
    call = hermes._extract_tool_call(
        {"tool_name": "mcp__local_mcp_aggregator__call_tool",
         "args": {"calls": [reader, nav]}}
    )
    assert call is not None
    props = hermes._command_properties(call.command)
    assert props.parse_confident is True
    assert props.values.get("network_upload") is True
    assert props.values.get("network_download") is True


def test_mcp_spoofed_dispatch_head_gains_nothing() -> None:
    # A hermes.mcp_call_tool line from any path other than the shim's single-
    # target extraction would have to be a typed line — but the parser's own
    # grammar makes such a head impossible from a shell, and even a forced
    # one gains nothing: writer/exec/unknown targets fail closed, reader
    # targets fire the true network_upload fact.
    props = hermes._command_properties("hermes.mcp_call_tool slack-slack_send_message")
    assert props.parse_confident is False
    props = hermes._command_properties("hermes.mcp_call_tool newserver-future_tool")
    assert props.parse_confident is False
