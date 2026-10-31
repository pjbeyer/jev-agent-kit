"""Hermes host shim for the `pre_tool_call` hook (Phase 3).

A Hermes plugin registers a callback via `ctx.register_hook("pre_tool_call", fn)`. The callback
allows a tool call by returning `None`, blocks it by returning `{"action": "block",
"message": ...}`, or escalates it to Hermes' human-approval gate by returning
`{"action": "approve", "message": ..., "rule_key": ...}`.

The ask→approve mapping (owner decision 2026-10-30) replaces the earlier block-only stance.
Hermes' plugin `approve` reaches `tools.approval.request_tool_approval`: the same human gate as
Tier-2 dangerous shell patterns (once/session/always/deny, native approval buttons on gateway
platforms, denial/timeout/gate-error fail closed). `rule_key` scopes the `[a]lways` allowlist
grain to the exact command text — Hermes' own default would key it by tool name, one grant
covering every later call of that tool, which would silently retire the gate. Mock asks never
escalate: a test/stub decision must not summon a human. Unattended contexts (cron et al.) never
see this mapping either: the core's unattended policy resolves the escalation first. Under YOLO
or `approvals.mode: off` Hermes auto-approves escalations — that is the operator's standing
consent, and `block` (which YOLO does not swallow) remains the mapping for everything else.
Hermes fails closed at `plugins.hook_callback_timeout` (default 30s) plus a 60s suppression
window on timeout or an uncaught exception (`docs/research/06-reverified-facts.md` section 9).

This shim holds no decision logic of its own: it extracts a `ToolCall` from the Hermes event and
delegates entirely to `hooks.core.decide_tool_call`, which owns the self-deadline and the
shadow/enforce mapping. Per the phase 3/4 safety amendments
(`docs/specs/phase-3-4-plan.md`), shadow must never accidentally block on Hermes, so this shim
always runs with the core's default self-deadline (well under Hermes' 30s) and never waits on
the host timeout to fail closed.

The Hermes `pre_tool_call` event shape is not pinned by a verified schema (see the "Unverified"
note in `docs/research/06-reverified-facts.md` section 9), so the event is read defensively: a
mapping-like object exposing a tool name/command and its arguments. An event that cannot be
parsed fails closed to ask in enforce and allow in shadow, and this shim never raises.
"""

from __future__ import annotations

import os
from typing import Any, Protocol

from jev_kit.hooks.core import (
    DEFAULT_QUESTION_SET_PATH as DEFAULT_QUESTION_SET_PATH,
)
from jev_kit.hooks.core import (
    DEFAULT_SELF_DEADLINE_S,
    HookOutcome,
    Runner,
    ToolCall,
    decide_tool_call,
    dest_allowlist_from_env,
    producer_id,
    question_set_path_from_env,
)
from jev_kit.types import Mode

_MODE_ENV_VAR = "JEV_KIT_HOOK_MODE"

_BLOCK_MESSAGE = "jev-kit gate: blocked for human review."


class HermesContext(Protocol):
    """The slice of the Hermes plugin context this shim depends on."""

    def register_hook(self, event: str, callback: Any) -> None: ...

# Identity of this hook's state preprocessing; part of every gate fingerprint.
_PRODUCER = producer_id("hermes", __file__)


def _mode_from_env() -> Mode:
    raw = os.environ.get(_MODE_ENV_VAR, Mode.SHADOW.value).strip().lower()
    try:
        return Mode(raw)
    except ValueError:
        # An unrecognized value must not silently arm enforce.
        return Mode.SHADOW




def _resolve(mode: Mode | None, question_set_path: str | None) -> tuple[Mode, str]:
    resolved_mode = mode if mode is not None else _mode_from_env()
    resolved_path = (
        question_set_path if question_set_path is not None else question_set_path_from_env()
    )
    return resolved_mode, resolved_path


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def _extract_tool_call(event: Any) -> ToolCall | None:
    """Build a `ToolCall` from a Hermes `pre_tool_call` event.

    The event is expected to behave like a mapping carrying a tool name (or command) and its
    arguments. Hermes event shapes are not pinned by a verified schema, so this reads
    defensively (`.get`, never attribute access) and returns `None` for anything unrecognized
    rather than raising; the caller fails closed (or allows, in shadow) on `None`.
    """
    get = getattr(event, "get", None)
    if not callable(get):
        return None
    try:
        args = event.get("args")
        args_map: dict[str, Any] = args if isinstance(args, dict) else {}

        command = (
            args_map.get("command")
            or args_map.get("content")
            or event.get("command")
            or event.get("tool_name")
            or event.get("name")
            or event.get("tool")
        )
        command_str = _as_str(command)
        if not command_str:
            return None

        target = args_map.get("target") or args_map.get("path") or args_map.get("file")
        context = event.get("context") or event.get("task_id")

        return ToolCall(command=command_str, target=_as_str(target), context=_as_str(context))
    except Exception:
        return None


def _task_id_from(event: Any) -> str | None:
    """The host's task id, if the event carries one. Used only for unattended detection."""
    try:
        if not isinstance(event, dict):
            return None
        for key in ("task_id", "session_id", "task"):
            value = event.get(key)
            if isinstance(value, str) and value:
                return value
        args = event.get("args")
        if isinstance(args, dict):
            for key in ("task_id", "session_id"):
                value = args.get(key)
                if isinstance(value, str) and value:
                    return value
    except Exception:
        return None
    return None


def _block(reason: str | None) -> dict[str, str]:
    if reason is None:
        return {"action": "block", "message": _BLOCK_MESSAGE}
    return {"action": "block", "message": f"{_BLOCK_MESSAGE} (reason: {reason})"}


_APPROVE_MESSAGE_PREFIX = "jev-kit gate: a decision could not be made locally"


def _approve_reason_text(reason: str | None) -> str:
    """The description shown on the approval card / persisted as the grant grain."""
    detail = reason if reason else "the gate could not reach a calibrated answer"
    return f"{_APPROVE_MESSAGE_PREFIX} ({detail})"


def _rule_key(command: str) -> str:
    """The `[a]lways` allowlist grain Hermes keys plugin approvals by.

    Deliberately NOT tool_name (Hermes' default when the hook omits rule_key): one
    grant on `terminal` would cover every later terminal call and the gate stops
    mattering. The grain is the first whitespace token of the command plus the first
    12 hex chars of the FULL command's sha256 — stable across repeated identical
    commands (one "always" covers the repeated loop the model actually runs), narrow
    across different commands (a new line asks again). Never raises.
    """
    try:
        import hashlib

        head = command.split()[:1]
        head = head[0] if head else "unknown"
        digest = hashlib.sha256(command.encode("utf-8", "replace")).hexdigest()[:12]
        return f"jev:{head}:{digest}"
    except Exception:
        return "jev:unknown"


def pre_tool_call(
    ctx: Any,
    tool_call: Any,
    *,
    mode: Mode | None = None,
    question_set_path: str | None = None,
    runner: Runner | None = None,
    self_deadline_s: float = DEFAULT_SELF_DEADLINE_S,
    dest_allowlist: frozenset[str] | None = None,
    workdir: str | None = None,
) -> dict[str, str] | None:
    """Hermes `pre_tool_call` callback: allow (`None`) or block (a Hermes block payload).

    `ctx` is accepted but unused beyond being part of the Hermes callback shape; this shim keeps
    no state on it. All decision logic lives in `hooks.core.decide_tool_call`. `mode` and
    `question_set_path` default from the environment when not given (`JEV_KIT_HOOK_MODE`,
    default shadow; `JEV_KIT_HOOK_QUESTION_SET_PATH` or its deprecated alias
    `JEV_KIT_QUESTION_SET_PATH`, default the tool-call-gate set). `dest_allowlist` defaults
    from `JEV_KIT_DEST_ALLOWLIST`; when it is empty, destination trust is unknown for every
    call, which is the same behaviour as not having the feature.

    Returns the host directive: `None` (allow), `{"action": "block", ...}`, or
    `{"action": "approve", ...}` when the gate's answer is ASK and the host can plausibly
    put a human on the approval path.

    The ask→approve mapping (owner decision 2026-10-30): Hermes' plugin `approve` reaches
    `tools.approval.request_tool_approval`, the same human gate as Tier-2 dangerous shell
    patterns (once/session/always/deny, native buttons on gateway platforms, denial or
    timeout fails closed). `rule_key` scopes the `[a]lways` grain to the exact command
    (see `_rule_key`), never the tool name. What still maps to `block` — the original
    rationale for block-only, intact:

    - cron and every other unattended context: the core's unattended policy resolves the
      escalation BEFORE the shim sees an ASK (default policy: record + allow), so an ASK
      here means a human is plausibly present;
    - `is_mock` responses (test/stub traffic): never escalate a mock decision to a human;
    - YOLO / `approvals.mode: off`: Hermes auto-approves plugin escalations in those
      modes, so a mock- or fail-closed ask must not become a silent allow — those map to
      block, which the YOLO bypass does NOT swallow;
    - a non-dict, YOLO-like environment cannot be detected here, so the shim is
      conservative: ASK escalates only when the core says a human decision is the right
      next step, i.e. `is_mock` is False.

    Never raises: an unparseable event or any internal failure fails closed to a block in
    enforce and to allow in shadow, matching the core's own fail-closed behavior.
    """
    del ctx
    resolved_mode, resolved_path = _resolve(mode, question_set_path)
    allowlist = (
        dest_allowlist if dest_allowlist is not None else dest_allowlist_from_env()
    )

    call = _extract_tool_call(tool_call)
    if call is None:
        return None if resolved_mode is Mode.SHADOW else _block("unparseable_event")

    try:
        result = decide_tool_call(
            call,
            mode=resolved_mode,
            question_set_path=resolved_path,
            producer=_PRODUCER,
            runner=runner,
            self_deadline_s=self_deadline_s,
            dest_allowlist=allowlist,
            workdir=workdir,
            task_id=_task_id_from(tool_call),
        )
    except Exception:
        # decide_tool_call never raises for runtime conditions; this is a last-resort net so the
        # shim itself can never crash a Hermes turn.
        return None if resolved_mode is Mode.SHADOW else _block("internal")

    if result.outcome is HookOutcome.ALLOW:
        return None
    if (
        resolved_mode is Mode.ENFORCE
        and result.outcome is HookOutcome.ASK
        and not result.is_mock
    ):
        # A real ask with a human plausibly present: escalate to the human gate, not a
        # silent block. The gate itself fails closed (denial, timeout, gate error), and
        # unattended contexts never reach this line (core resolves them first).
        return {
            "action": "approve",
            "message": _approve_reason_text(result.reason),
            "rule_key": _rule_key(call.command),
        }
    return _block(result.reason)


def register(
    ctx: HermesContext,
    *,
    mode: Mode | None = None,
    question_set_path: str | None = None,
    runner: Runner | None = None,
) -> None:
    """Register the gate as a Hermes `pre_tool_call` plugin hook.

    Resolves mode and the question-set path once, at registration time, from the given
    arguments or the environment, then wires a closure over `ctx` so the registered callback
    matches Hermes' calling convention (the event only; `ctx` is captured, not re-passed).
    Accepts either a single event argument or Hermes' keyword form
    (`tool_name=...`, `args=...`, `task_id=...`) since the exact calling convention is not
    pinned by a verified schema.
    """
    resolved_mode, resolved_path = _resolve(mode, question_set_path)

    def _on_pre_tool_call(tool_call: Any = None, **kwargs: Any) -> dict[str, str] | None:
        event = tool_call if tool_call is not None else kwargs
        return pre_tool_call(
            ctx,
            event,
            mode=resolved_mode,
            question_set_path=resolved_path,
            runner=runner,
        )

    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
