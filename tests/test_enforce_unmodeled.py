"""Enforce mode stops treating every unreadable command as a wall.

Measured before this change: `git push`, `git status`, `gh issue comment` and `pytest -q`
all returned `parse_confident=False`, and in enforce an unconfident parse forces ASK
regardless of what the gate answered. Since `git` and `gh` are deliberately off the
confidence allowlist, enforce blocked every routine git and gh call by code rule rather
than by the gate's judgment. The repository's own guide conceded it: "Everything is
blocked in enforce."

The conservatism was never the bug: refusing to treat an unreadable command as safe is
correct. The defect was that the only available response was a hard block, so conservatism
became a wall.

The fix narrows the gap from the other side. A git subcommand that only reads, on a plain
invocation, has nothing this module fails to model, so it is confident. Every subcommand
that runs repository hooks, updates refs, or changes config stays unknown, and the hazard
properties still fire on the read-only set.

The invariant that must never regress is asserted in both directions below: an unreadable
command never reaches ALLOW in enforce, whatever the gate answers.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from jev_kit.command_properties import extract_command_properties
from jev_kit.hooks import claude as claude_shim
from jev_kit.hooks import codex, hermes
from jev_kit.hooks.core import HookOutcome
from jev_kit.types import Mode

REPO = Path(__file__).resolve().parents[1]
GATE = str(REPO / "skills" / "jev-runtime" / "questions" / "tool-call-gate.json")

#: Every gate answer is a clean, allow-listed accept. Used to prove that an unreadable
#: command cannot reach ALLOW even when the gate would clear it.
def _all_accept(request: dict[str, Any]) -> dict[str, Any]:
    rec = {"route": "accept", "label": "no", "allow_labels": ["no"], "is_mock": False}
    return {"schema_version": 1, "status": "ok", "records": [rec, rec, rec]}


def _run(host: str, command: str, mode: Mode, runner: Any) -> HookOutcome:
    if host == "claude":
        out = claude_shim.handle_claude_event(
            {"hook_event_name": "PreToolUse", "tool_name": "Bash",
             "tool_input": {"command": command}},
            mode=mode, question_set_path=GATE, runner=runner,
        )
        decision = out.get("hookSpecificOutput", {}).get("permissionDecision")
        return HookOutcome.ASK if decision == "ask" else HookOutcome.ALLOW
    if host == "codex":
        out = codex.handle_codex_event(
            {"hook_event_name": "PreToolUse", "tool_name": "shell", "turn_id": "t1",
             "tool_input": {"command": command}},
            mode=mode, question_set_path=GATE, runner=runner,
        )
        decision = out.get("hookSpecificOutput", {}).get("permissionDecision")
        return HookOutcome.ASK if decision == "deny" else HookOutcome.ALLOW
    result = hermes.pre_tool_call(
        None, {"tool_name": "terminal", "args": {"command": command}, "task_id": "t"},
        mode=mode, question_set_path=GATE, runner=runner,
    )
    return HookOutcome.ALLOW if result is None else HookOutcome.ASK


HOSTS = ("claude", "codex", "hermes")


# --------------------------------------------------------------------------- the fix


@pytest.mark.parametrize(
    "command",
    [
        "git status",
        "git status --short",
        "git diff",
        "git diff HEAD",
        "git log --oneline -5",
        "git show HEAD",
        "git rev-parse HEAD",
        "git ls-files",
        "git describe --tags",
        "git blame file.py",
        "git shortlog -sn",
        "git cat-file -p HEAD",
        "git merge-base main HEAD",
        "git rev-list --count HEAD",
        "git check-ignore -v x",
        "git version",
        "git -C /srv/repo log",
    ],
)
def test_git_read_only_is_modeled(command: str) -> None:
    assert extract_command_properties(command).parse_confident is True


@pytest.mark.parametrize(
    "command",
    [
        "git commit -m wip",
        "git checkout main",
        "git switch main",
        "git merge x",
        "git pull",
        "git push origin main",
        "git push --force origin main",
        "git rebase main",
        "git am patch",
        "git reset --hard HEAD~1",
        "git clean -fd",
        "git config core.hooksPath /tmp/h",
        "git update-ref refs/heads/x HEAD",
        "git stash drop",
        "git filter-branch --all",
        "git submodule update",
        "git nuke",  # an unknown subcommand may be a user alias
    ],
)
def test_git_that_can_run_hooks_refs_or_config_stays_unknown(command: str) -> None:
    # The original reason git was off the allowlist entirely: repository config can name
    # programs (core.fsmonitor, diff.external, textconv, filters, pager), and these
    # subcommands run hooks or rewrite refs.
    assert extract_command_properties(command).parse_confident is False


def test_bare_git_is_confident_because_it_only_prints_usage() -> None:
    # No subcommand means no hook, no ref update and no config read: git prints its usage and
    # exits non-zero. There is nothing here the parser fails to model, so confident with no
    # hazards is the accurate reading rather than a hole.
    props = extract_command_properties("git")
    assert props.parse_confident is True
    assert not any(value is True for value in props.values.values())


@pytest.mark.parametrize(
    "command",
    [
        "git diff --ext-diff",
        "git diff --ext-diff HEAD",
        "git show --textconv HEAD",
        "git log --textconv",
        "git grep -O x",
        "git diff -O pager",
    ],
)
def test_a_read_only_subcommand_that_can_run_a_program_stays_unknown(command: str) -> None:
    # Read-only is not the whole test: an option that hands control to a program named by
    # configuration puts it back in the unknown bucket.
    assert extract_command_properties(command).parse_confident is False


@pytest.mark.parametrize(
    ("command", "flags"),
    [
        ("git clean -fd", {"recursive_delete", "force_flag"}),
        ("git push --force origin main", {"git_history_rewrite", "force_flag"}),
    ],
)
def test_a_confident_git_command_still_carries_its_hazards(command: str, flags: set[str]) -> None:
    # Confidence is about whether the parser read the command, never about whether it is
    # safe. A hazardous git command must be both confident and flagged.
    props = extract_command_properties(command)
    for name in flags:
        assert props.values[name] is True, name


# --------------------------------------------------------------------------- the invariant


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize(
    "command",
    [
        "git push origin main",
        "git commit -m wip",
        "git clean -fd",
        "git config core.hooksPath /tmp/h",
        "git nuke",
        "bash -c ls",
        "rm -rf $HOME",
        "x" * 5000,
    ],
)
def test_an_unreadable_command_never_reaches_allow_in_enforce(
    host: str, command: str
) -> None:
    # The safety property this change must not weaken. Every gate answer is a clean accept,
    # and the command still cannot be allowed, because the parser could not read it.
    assert _run(host, command, Mode.ENFORCE, _all_accept) is HookOutcome.ASK


@pytest.mark.parametrize("host", HOSTS)
def test_a_read_only_git_command_now_follows_the_gate_in_enforce(host: str) -> None:
    # The other direction, and the point of the issue: a routine read-only call is judged by
    # the gate instead of being blocked by a code rule.
    assert _run(host, "git status", Mode.ENFORCE, _all_accept) is HookOutcome.ALLOW


@pytest.mark.parametrize("host", HOSTS)
def test_a_read_only_git_command_still_asks_when_the_gate_asks(host: str) -> None:
    # Confidence is not permission. The gate still decides.
    def _ask(request: dict[str, Any]) -> dict[str, Any]:
        return {"schema_version": 1, "status": "ok", "records": [{"route": "ask"}]}

    assert _run(host, "git status", Mode.ENFORCE, _ask) is HookOutcome.ASK


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("command", ["git status", "git push origin main", "rm -rf $HOME"])
def test_shadow_is_still_unaffected(host: str, command: str) -> None:
    assert _run(host, command, Mode.SHADOW, _all_accept) is HookOutcome.ALLOW


# --------------------------------------------------------------------------- outgoing state


def _state(host: str, command: str) -> dict[str, Any]:
    captured: list[dict[str, Any]] = []

    def _capture(request: dict[str, Any]) -> dict[str, Any]:
        captured.append(request)
        return {"schema_version": 1, "status": "ok", "records": [{"route": "ask"}]}

    _run_with(host, command, _capture)
    assert len(captured) == 1
    state: dict[str, Any] = captured[0]["state"]
    return state


def _run_with(host: str, command: str, runner: Any) -> None:
    _run(host, command, Mode.SHADOW, runner)


@pytest.mark.parametrize("host", HOSTS)
def test_read_only_git_state_is_confident_and_all_false(host: str) -> None:
    state = _state(host, "git status --short")
    assert state["cmd_parse_confident"] is True
    assert state["cmd_recursive_delete"] is False
    assert state["cmd_git_history_rewrite"] is False


@pytest.mark.parametrize("host", HOSTS)
def test_unreadable_git_state_is_null_never_false(host: str) -> None:
    state = _state(host, "git push origin main")
    assert state["cmd_parse_confident"] is False
    assert state["cmd_git_history_rewrite"] is None  # unknown, never a confident false


@pytest.mark.parametrize("host", HOSTS)
def test_the_raw_command_arguments_still_never_leave(host: str, tmp_path: Path) -> None:
    # The egress invariant is untouched by this change.
    from jev_kit.engine import EngineConfig, decide
    from jev_kit.ratebudget import RateBudget
    from jev_kit.receipts import ReceiptWriter
    from jev_kit.transport import MockTransport

    key = base64.urlsafe_b64decode("ZGVtby1rZXktZGVtby1rZXktZGVtby1rZXktZGVtby0=")
    reply = {
        "model": "jev-1.13.0",
        "answers": {
            "destructive": {"type": "noul", "noul": 0.5},
            "exfiltrates": {"type": "noul", "noul": 0.5},
            "widens_permission": {"type": "noul", "noul": 0.5},
        },
    }
    sent: list[bytes] = []

    def _engine(request: dict[str, Any]) -> dict[str, Any]:
        mock = MockTransport.replying(200, json.dumps(reply).encode(), {})
        response = decide(
            request, transport=mock,
            config=EngineConfig(
                hmac_key=key,
                source_allowlist=frozenset({"agent_context"}),
                writer=ReceiptWriter(directory=tmp_path / "receipts"),
                rate_budget=RateBudget(),
            ),
        )
        sent.extend(mock.requests)
        return response

    _run_with(host, "git -C /srv/acme-secret-project log --oneline", _engine)
    assert len(sent) == 1
    body = sent[0].decode("utf-8")
    assert "acme-secret" not in body
    assert "/srv" not in body
    assert "--oneline" not in body
