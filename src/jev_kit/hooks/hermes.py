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

# Test-facing helpers (jak-baw): thin, stable aliases so tests exercise the REAL parser
# and confidence rule without reaching into jev_kit.command_properties internals per test.


def _parse_confident(command: str) -> bool:
    """Whether the local parser proves this command line safe to read."""
    from jev_kit.command_properties import extract_command_properties

    return extract_command_properties(command).parse_confident


def _command_properties(command: str):
    """The full property set of one command line (test-facing passthrough)."""
    from jev_kit.command_properties import extract_command_properties

    return extract_command_properties(command)

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

    Non-shell tools (jak-baw scope 2, measured 2026-11-04): Hermes passes the full `args`
    dict, and for tools whose operation-defining argument is NOT `command`/`content` the old
    fallback chain landed on the bare tool NAME as `ToolCall.command` — an opaque token the
    parser can never prove safe, which fail-closed to ask on 4,459 of 4,460 measured calls
    (61% of all would-asks were blind). The extractor table below maps known non-shell tools
    to a parseable pseudo-command (`<verb> <arg>`) built from the argument that defines the
    operation. Discipline (measured, not assumed):

    - Only `str` args that are simple (non-empty, no quotes/redirects/expansion, one line,
      within the parser's MAX_COMMAND_CHARS) are mapped; anything else keeps the bare tool
      name, so the fail-closed behaviour for exotic payloads is unchanged.
    - The table stays conservative and small: reader-class tools only, each mapped to a
      parser-MODELED head word with the same effect class (`cat` for path readers, `grep`
      for search, `ls` for listing). Writer-class tools (write_file, patch) are deliberately
      NOT mapped: the parser models no honest overwrite verb, and a wrong mapping would let
      a call allow that the questions should have judged — those calls keep the bare name
      and stay fail-closed. Tools with richer payloads (execute_code script bodies, MCP
      bridges, delegate_task) are likewise unmapped pending reviewed per-tool semantics.
    """
    get = getattr(event, "get", None)
    if not callable(get):
        return None
    try:
        args = event.get("args")
        args_map: dict[str, Any] = args if isinstance(args, dict) else {}

        tool_name = event.get("tool_name") or event.get("name") or event.get("tool")
        # `content` is a COMMAND only for message-like tools; for writer tools (write_file)
        # it is the PAYLOAD body, which must never become ToolCall.command (it would be
        # judged as a command line and misparse). Reader-class extraction below decides.
        from jev_kit import hermes_tools

        modeled = _as_str(tool_name) in hermes_tools.MODELED
        command = (
            args_map.get("command")
            or event.get("command")
            or (args_map.get("content") if not modeled else None)
            or tool_name
        )
        command_str = _as_str(command)
        if not command_str:
            return None

        # jak-baw: the bare tool name is a non-shell tool's opaque stand-in. If the
        # operation-defining argument is a simple string, map it to a pseudo-command the
        # local parser can prove safe (e.g. `read_file /path` reads like a reader verb).
        tool_name_str = _as_str(tool_name)
        if tool_name_str and command_str == tool_name_str:
            command_str = _nonshell_pseudo_command(tool_name_str, args_map) or command_str

        target = args_map.get("target") or args_map.get("path") or args_map.get("file")
        context = event.get("context") or event.get("task_id")

        return ToolCall(command=command_str, target=_as_str(target), context=_as_str(context))
    except Exception:
        return None


#: Modeled Hermes tools and their extraction sources live in hermes_tools (jak-baw
#: full coverage): one source of truth for the shim's emission and the parser's
#: modeling. The pseudo-program namespace is `hermes.<tool>` — `.` is not a valid
#: shell program word in the parser's own grammar, so the head can only have come
#: from this emission path, never from a typed shell line or a bare tool name.


def _simple_arg(value: Any) -> str | None:
    """A string argument safe to embed in a pseudo-command, else None.

    Mirrors the parser's own confidence discipline: quotes, redirects, expansions, control
    characters, non-ASCII and oversized values are NOT mapped (the call keeps its bare tool
    name and fails closed as before). Never raises.
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped or "\n" in stripped or "\r" in stripped:
        return None
    if not stripped.isascii():
        return None
    if any(ch in stripped for ch in "\"'`\\$<>|;&(){}[]"):
        return None
    return stripped


def _execute_code_pseudo_command(args_map: dict[str, Any]) -> str:
    """(jak-47d) Payload-aware pseudo-command for execute_code.

    Analyzes the `code` argument statically. Clean payload + all extracted
    child command lines judged confident by the property parser:
    `hermes.execute_code <children joined by ' ;; '>`. Anything else: the
    bare `hermes.execute_code` head (fail-closed runs_unseen_code as before).
    Never raises; never embeds payload text — only extracted child commands,
    each re-judged by the parser independently of this function's verdict.
    """
    from jev_kit import hermes_tools
    from jev_kit.code_payload import analyze_code_payload
    from jev_kit.command_properties import extract_command_properties

    head = hermes_tools.PREFIX + "execute_code"
    code = args_map.get("code")
    if not isinstance(code, str) or not code.strip():
        return head
    try:
        clean, children, _reason = analyze_code_payload(code)
    except Exception:
        return head  # never raise; opaque by rule
    if not clean:
        return head
    # Children must survive the simple filter AND independent re-judgment:
    # every child line must parse confident with no hazard fact. The parser
    # does the judging; this function only decides what to hand it.
    safe_children: list[str] = []
    for child in children:
        if not child or not _simple_arg(child):
            return head  # a child line that cannot even be embedded: opaque
        props = extract_command_properties(child)
        if not props.parse_confident:
            return head
        if any(value is True for value in props.values.values()):
            return head  # hazard fact on a child: let the questions judge it
        safe_children.append(child)
    if not safe_children:
        return f"{head} _clean"  # proven-local computation, no child commands
    return f"{head} " + " ;; ".join(safe_children)


def _nonshell_pseudo_command(tool_name: str, args_map: dict[str, Any]) -> str | None:
    """Emit `hermes.<tool> [simple naming args...]` for a MODELED Hermes tool.

    Returns None for tools not in hermes_tools.MODELED — the caller keeps the bare
    tool name and the call fails closed exactly as before. Payload arguments are
    never embedded; only arguments that NAME the operation's object (per
    hermes_tools.ARG_SOURCES) are, and only when they pass the simple-string
    filter. A modeled tool with no mappable argument still emits the bare
    `hermes.<tool>` head: its effect facts (network, code-exec) fire without
    any argument text leaving the machine beyond the names.
    """
    from jev_kit import hermes_tools

    if tool_name == "mcp__local_mcp_aggregator__call_tool":
        # jak-b8n: the dispatched target's `name` NAMES the operation's object
        # (the same rule that maps read_file's `path`), so it rides as the
        # operand; the nested `arguments` payload is never embedded. A payload
        # dict or an un-simple name keeps the bare bridge name (unmodeled,
        # fail-closed).
        #
        # jak-b8n (multi-call, 2026-11-05): a batch dispatches several named
        # tools in one call. Each member is emitted as its own pseudo-command
        # operand line joined by ` ;; ` (a separator the parser treats as a
        # compound line, so the parser alone fail-closes it); but the batch
        # rule is: judge by the WORST member. The parser therefore also
        # accepts the single-token form for batches: every member's name
        # rides, and command_properties routes on the worst class present.
        # Canonical aggregator form (skill: hermes-plugin-and-mcp-customizations):
        # {"tool_id": "<opaque hex>", "arguments": {...}}. The tool_id NAMES the
        # target, but it is an opaque catalog ID -- classification by name is
        # impossible offline, and a cached id->name map would be server state
        # (stale-misclassification risk). Emit the id as the operand; the parser
        # fail-closes opaque ids with an honest reason (mcp_dispatch_target_id).
        tool_id = _simple_arg(args_map.get("tool_id"))
        if tool_id:
            return f"{hermes_tools.PREFIX}mcp_call_tool {tool_id}"
        # Batch form (Hermes deferred dispatcher shape): every member's name
        # rides, judged by the worst member in command_properties.
        calls = args_map.get("calls")
        if not isinstance(calls, list) or not calls:
            return None
        names: list[str] = []
        for entry in calls:
            if not isinstance(entry, dict):
                return None
            target = _simple_arg(entry.get("name"))
            if not target:
                return None
            names.append(target)
        return f"{hermes_tools.PREFIX}mcp_call_tool " + " ".join(names)
    if tool_name not in hermes_tools.MODELED:
        return None
    # Payload-aware CODE_EXEC modeling (jak-47d): for execute_code only, the
    # shim statically analyzes the `code` argument locally (never executes it,
    # never embeds it). A payload proven clean, whose extracted child command
    # lines all judge confident-benign in the property parser, is emitted as
    # `hermes.execute_code <child lines joined by ' ;; '>` — the parser judges
    # the children and, when all are confident and hazard-free, treats the
    # call as proven local computation. Anything opaque (dynamic argv, eval,
    # unknown imports...) keeps the bare `hermes.execute_code` head and fails
    # closed to runs_unseen_code exactly as before. The payload text itself
    # NEVER rides: only extracted child command lines do, and only after the
    # parser independently re-judges them — the shim's claim is not trusted,
    # it is verified.
    if tool_name == "execute_code":
        return _execute_code_pseudo_command(args_map)
    arg_names = hermes_tools.ARG_SOURCES.get(tool_name, ())
    parts: list[str] = [hermes_tools.PREFIX + tool_name]
    for arg_name in arg_names:
        simple = _simple_arg(args_map.get(arg_name))
        if simple:
            parts.append(simple)
            break  # first naming argument only: one object per call, no payload drift
    return " ".join(parts)


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

#: Plain-English rendering of the hazard facts for the approval card. Kept short — the
#: card is one line of description; the goal is that the operator can judge the call
#: without rubber-stamping, not a full report.
_HAZARD_LABELS: dict[str, str] = {
    "cmd_recursive_delete": "recursive delete",
    "cmd_force_flag": "force flag",
    "cmd_targets_root_or_system_path": "targets a system path",
    "cmd_uses_elevation": "uses elevation (sudo)",
    "cmd_network_download": "downloads from the network",
    "cmd_pipes_to_shell": "pipes data into a shell",
    "cmd_modifies_permissions": "changes permissions",
    "cmd_git_history_rewrite": "rewrites git history",
    "cmd_package_install": "installs a package",
    "cmd_network_upload": "sends data to the network",
    "cmd_grants_write_access": "grants write access",
    "cmd_targets_autorun_path": "writes an auto-run path",
    "cmd_grants_authority": "grants authority",
    "cmd_grants_privileged_group": "grants a privileged group",
    "cmd_grants_setuid": "sets setuid",
}


def _approve_reason_text(
    reason: str | None, hazards: tuple[str, ...] = (), command: str | None = None
) -> str:
    """The description shown on the approval card / persisted as the grant grain.

    Carries the decision-relevant content the Hermes card has room for: the fail
    reason AND the affirmative hazard facts in plain English (the rubber-stamp fix —
    "a decision could not be made locally" alone gives the operator nothing to
    judge). The card paints the command itself as a synthetic `<terminal>` label, so
    this description line IS the operator's context; `command` contributes the
    egress-reduced segment inventory (basenames only — no argument text, so nothing
    sensitive leaks onto the card).
    """
    detail = reason if reason else "the gate could not reach a calibrated answer"
    if not hazards:
        return f"{_APPROVE_MESSAGE_PREFIX} ({detail})"
    labels = [_HAZARD_LABELS.get(name, name) for name in hazards]
    parts = [
        _APPROVE_MESSAGE_PREFIX,
        f"({detail})",
        f"flagged: {', '.join(labels)}",
    ]
    if command:
        from jev_kit.egress import command_inventory

        parts.append(f"commands: {command_inventory(command)}")
    return "; ".join(parts)


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
            "message": _approve_reason_text(
                result.reason, result.hazard_facts, call.command
            ),
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
