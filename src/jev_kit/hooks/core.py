"""The shared hook core: tool-call event -> decision -> host-neutral outcome (Phase 3).

Two outcomes, never a raw allow-on-uncertainty: `ALLOW` or `ASK` (there is no BLOCK; a gate
fails to ASK, which a host maps to its human-approval path). Safety rules baked in here so
every host shim inherits them:

- Shadow mode never changes host behavior: it always returns ALLOW, even on failure or
  timeout, so it can never accidentally block (Hermes fails closed at 30s).
- The core owns its own deadline. It runs the engine through the injected runner in a worker
  and abandons a result that misses the deadline, synthesizing the fail-closed outcome, so it
  never depends on a host hook timeout to fail closed (Codex fails open at 600s).
- Enforce fails closed to ASK on any failure, timeout, or gate that did not clear.
- Command properties (ADR 0005) are computed here, in code, and added to state as keyed
  booleans. They are evidence only and can never allow a call. When the command cannot be
  parsed confidently, enforce never allows: unknown is treated as risky.
- Destination trust (the shared gate augmentation contract) is computed here too: the
  `dest_*` fields name where a command sends data, which the local `cmd_*` facts cannot
  describe. They are evidence only, like the command properties, and are computed with the
  same tri-state discipline. Their polarity is inverted on purpose: `dest_allowlisted`
  unknown is not permission, so it is never read as allowlisted.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from jev_kit import command_properties, destination, target_stat
from jev_kit import sidelog
from jev_kit import unattended as unattended_mod
from jev_kit.command_properties import extract_command_properties
from jev_kit.types import Mode

# The default self-deadline, chosen to sit well under Hermes' 30s fail-closed hook timeout.
DEFAULT_SELF_DEADLINE_S = 8.0

#: Canonical environment variable naming the question set a hook uses. Matches the
#: `JEV_KIT_HOOK_MODE` prefix.
QUESTION_SET_PATH_ENV_VAR = "JEV_KIT_HOOK_QUESTION_SET_PATH"

#: Deprecated alias for QUESTION_SET_PATH_ENV_VAR, still read by every shim. When both are
#: set to a non-empty value, the canonical name wins.
QUESTION_SET_PATH_ENV_VAR_ALIAS = "JEV_KIT_QUESTION_SET_PATH"

# The skill's gate question set lives in the repository (it is not packaged into the wheel),
# at <repo>/skills/jev-runtime/questions/tool-call-gate.json, where this module sits at
# <repo>/src/jev_kit/hooks/core.py. Resolved from this module's own path, never from the
# host's working directory. If the file is not there (for example, an installed wheel without
# the repository), the path simply does not exist and the call fails the normal way: no
# decision in shadow, ask in enforce.
DEFAULT_QUESTION_SET_PATH = str(
    Path(__file__).resolve().parents[3]
    / "skills"
    / "jev-runtime"
    / "questions"
    / "tool-call-gate.json"
)


def question_set_path_from_env() -> str:
    """The hook question-set path: canonical env var, then the alias, then the default."""
    for name in (QUESTION_SET_PATH_ENV_VAR, QUESTION_SET_PATH_ENV_VAR_ALIAS):
        raw = os.environ.get(name, "").strip()
        if raw:
            return raw
    return DEFAULT_QUESTION_SET_PATH


#: Canonical environment variable naming the destination allowlist. Comma-separated hosts.
#: Empty by default: an empty allowlist is the absence of a policy, and yields
#: `dest_allowlisted = null` for every call rather than a deny.
DEST_ALLOWLIST_ENV_VAR = "JEV_KIT_DEST_ALLOWLIST"


def dest_allowlist_from_env() -> frozenset[str]:
    """The operator's destination allowlist, from the environment. Never raises."""
    raw = os.environ.get(DEST_ALLOWLIST_ENV_VAR, "")
    return frozenset(item.strip() for item in raw.split(",") if item.strip())


# A runner takes a JSON decision request and returns a JSON response. The default is a
# child-process runner (watchdog); tests inject a fake.
Runner = Callable[[dict[str, Any]], dict[str, Any]]


class HookOutcome(StrEnum):
    ALLOW = "allow"
    ASK = "ask"


@dataclass(frozen=True)
class ToolCall:
    command: str
    target: str | None = None
    context: str | None = None


@dataclass(frozen=True)
class HookResult:
    outcome: HookOutcome
    route: str | None  # the engine route behind the outcome, for logging (may be None)
    reason: str | None  # fail reason when the outcome is a failure
    is_mock: bool
    timed_out: bool = False


def _default_runner(request: dict[str, Any], timeout_s: float) -> dict[str, Any]:
    from jev_kit.hooks.watchdog import run_child

    # The child gets slightly less than the core deadline so its own kill fires first.
    return run_child(request, timeout_s=max(0.1, timeout_s - 0.5))


def _fail_closed(
    mode: Mode, reason: str, *, is_mock: bool = False, timed_out: bool = False
) -> HookResult:
    # Shadow never changes behavior; enforce fails closed to ask.
    outcome = HookOutcome.ALLOW if mode is Mode.SHADOW else HookOutcome.ASK
    return HookResult(outcome, None, reason, is_mock, timed_out)


PRODUCER_UNAVAILABLE = "unavailable"


def producer_id(name: str, shim_file: str) -> str:
    """Identity of a hook's state preprocessing: its own source, this module's, the
    command-property extractor's (ADR 0005), and the destination extractor's.

    Sent as the request's `producer`, which the engine binds into every fingerprint, so any
    change to how a hook builds state invalidates calibration made with the old code. Never
    raises: if the source cannot be read, returns PRODUCER_UNAVAILABLE, and the hook then
    fails the call through its normal path (allow in shadow, ask in enforce).
    """
    try:
        source = (
            Path(shim_file).read_bytes()
            + bytes(1)
            + Path(__file__).read_bytes()
            # The property extractors shape state too, so their sources are part of the
            # identity.
            + bytes(1)
            + Path(command_properties.__file__).read_bytes()
            + bytes(1)
            + Path(destination.__file__).read_bytes()
        )
    except OSError:
        return PRODUCER_UNAVAILABLE
    # Normalize line endings so CRLF and LF checkouts of the same revision agree.
    normalized = source.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return f"hook.{name}@src:{hashlib.sha256(normalized).hexdigest()[:28]}"


#: The cmd_ facts that, when True, mean the model must judge even though the line's
#: syntax is unparseable: any affirmative hazard keeps the call on the normal path.
#: Facts left out (targets_absolute_path, targets_regenerable_path, validates_only) are
#: not hazards by themselves.
_LOCAL_HAZARD_FACTS = (
    "cmd_recursive_delete",
    "cmd_force_flag",
    "cmd_targets_root_or_system_path",
    "cmd_uses_elevation",
    "cmd_network_download",
    "cmd_pipes_to_shell",
    "cmd_modifies_permissions",
    "cmd_git_history_rewrite",
    "cmd_package_install",
    "cmd_network_upload",
    "cmd_grants_write_access",
    "cmd_targets_autorun_path",
    "cmd_grants_authority",
    "cmd_grants_privileged_group",
    "cmd_grants_setuid",
)

# `targets_home_directory` means a home path APPEARS in the line, not that the line
# writes there; reads (cat/ls/head of ~/.local/...) are ordinary agent work. For the
# fast path it counts as a hazard only when a write-shaped verb is present. sed/perl
# write only with an in-place flag (-i/-pi/-pe with -i); the bare verbs always write.
_LOCAL_WRITE_VERB = re.compile(
    r"\b(?:cp|mv|rm|rmdir|chmod|chown|chgrp|touch|install|dd|truncate|ln|mkdir|tee)\b"
)
# sed/perl write only with an in-place flag; `-pi`/`-ipe` glue the i into a combined
# short-option token, so match an `i` inside any leading dashed option of sed/perl.
_LOCAL_INPLACE_FLAG = re.compile(r"\b(?:sed|perl)\b[^&;|`]*\s-\w*i")

#: The compound-syntax shape the egress reducer refuses (egress.py `_CMD_CONTROL`,
#: minus `<`/`>` which this predicate excludes separately). Duplicated here rather
#: than imported because egress is the child's module, not the hook's, and the two
#: must agree only in the direction "control char present -> refused class".
_LOCAL_CMD_CONTROL = re.compile(r"[;&|`\n]|\$\(")

#: Reason recorded in the side-log when the local fast path decides a call.
LOCAL_FAST_PATH_REASON = "local_no_egress_fast_path"


def _local_no_egress_verdict(
    command: str, properties: Any, dest: destination.Destination
) -> bool:
    """True when the locally computed facts prove the call needs no judgment.

    For lines the egress reducer refuses (compound, quoted, escaped — ADR 0005), enforce
    asks on every call, and measured live traffic showed ~40% asking, nearly all of it
    pure-local (`cd X && bd create ...`, `ps | head`). The model cannot add anything when
    the whole line was already read locally and no hazard fact is affirmative:

    - the line is in a class the reducer refuses: compound syntax (`; & | backtick
      newline $(`) or quoting/escapes/expansion that makes the parse unconfident.
      A confident, simple command stays on the judged path so the calibrated
      population keeps flowing, and so does any OTHER unreadable line (an unreadable
      command never reaches ALLOW in enforce — the invariant in
      test_enforce_unmodeled.py): the fast path fires only on syntax the reducer
      refuses, not on every unconfident line.
    - no redirect (`<`/`>`) anywhere: a redirect is a local data flow the facts do not
      model, so it stays on the judged path;
    - no cmd_ hazard fact is True (None = unknown is accepted here only because the
      fact extractors that return None for these lines scanned the FULL line and found
      nothing affirmative);
    - a home path plus a write-shaped verb is a hazard (sed/perl only with an in-place
      flag); a home path on its own is ordinary reads and navigation;
    - no egress destination is recognized anywhere in the line (`dest.known` False):
      a URL, host or remote target would have set it True.

    Any doubt returns False and the call proceeds through the normal gate path.
    """
    if "<" in command or ">" in command:
        return False
    facts = properties.as_state()
    # Only the refused classes fast-path: compound syntax, or an unconfident parse
    # CAUSED BY quoting/escape/expansion (a quote character present). Any other
    # unconfident line (an unknown program, garbage, `bash -c`) stays judged: an
    # unreadable command never reaches ALLOW in enforce.
    refused = bool(_LOCAL_CMD_CONTROL.search(command)) or (
        not properties.parse_confident and ('"' in command or "'" in command)
    )
    if not refused:
        return False
    if any(facts.get(name) is True for name in _LOCAL_HAZARD_FACTS):
        return False
    if facts.get("cmd_targets_home_directory") is True:
        # A home path appears: reads are fine, writes are not. sed/perl write only
        # with an in-place flag; the other write verbs always write.
        if _LOCAL_WRITE_VERB.search(command) or _LOCAL_INPLACE_FLAG.search(command):
            return False
    if dest.known:
        return False
    return True


def decide_tool_call(
    call: ToolCall,
    *,
    mode: Mode,
    question_set_path: str,
    producer: str | None = None,
    runner: Runner | None = None,
    self_deadline_s: float = DEFAULT_SELF_DEADLINE_S,
    dest_allowlist: frozenset[str] = frozenset(),
    workdir: str | None = None,
    task_id: str | None = None,
) -> HookResult:
    """Judge one tool call. Returns ALLOW or ASK; never raises for runtime conditions.

    `task_id` is the host's task identifier. It is used only to detect an unattended run
    (a `cron:` prefix); it is never sent to the model.
    """
    if producer == PRODUCER_UNAVAILABLE:
        # Without an identity the call cannot be bound to its calibration; never send it
        # unbound (that would silently change the fingerprint) and never crash the host.
        return _fail_closed(mode, "producer_unavailable")
    if not Path(question_set_path).is_absolute():
        # A relative path would resolve against the host's working directory, letting the
        # project a hook runs in pick its own question and egress rules. Reject it through the
        # normal config-failure path; never resolve it and never fall back to the default.
        return _fail_closed(mode, "config")
    # Facts about the full command line, computed locally (ADR 0005). Only a question set that
    # declares these fields (kind `flag`) sends them; others drop them as undeclared.
    properties = extract_command_properties(call.command)
    # Where the data would go, also computed locally. An empty allowlist yields unknown for
    # every call, which is the same behaviour as not having this feature at all.
    dest = destination.resolve_destination(
        call.command, allowlist=dest_allowlist, workdir=workdir
    )
    # Whether the copy/move destination already holds data, stat'ed now (runtime fact,
    # not parseable from the line). Only the tri-state verdict is transmitted; the path
    # itself stays local for the same egress-invariant reason as `dest_host`.
    tstat = target_stat.resolve_dest_exists(call.command, workdir=workdir)
    tstat_facts = target_stat.as_state(tstat)
    # The opt-in local side-log: the only place the judged command text is written
    # down, joined to receipts by the call id computed below. Off by default; a
    # record must never break a turn, so every failure here is swallowed.
    sidelog_path = sidelog.path_from_env()
    # Local fast path (owner decision 2026-10-30, option B): when the whole line was
    # read locally and proves no hazard and no egress channel, decide here without a
    # model call. This is the fix for the enforce ask-storm on compound pure-local
    # commands the egress reducer refuses. It is an ALLOW, so the unattended policy is
    # not consulted (an allow is not an escalation). Both modes take it: shadow's
    # outcome is allow either way, and the side-log records the fast path as the
    # reason in both, keeping the shadow corpus an honest measurement.
    if _local_no_egress_verdict(call.command, properties, dest):
        # In shadow the would-be enforce outcome is this same fast path, so record it
        # as would_outcome/would_reason too — the shadow corpus must measure enforce
        # including the fast path, not show a bare allow with no reason.
        _record_sidelog(
            sidelog_path, call, mode, HookOutcome.ALLOW.value,
            LOCAL_FAST_PATH_REASON, producer, properties, dest,
            target_facts=tstat_facts,
            would_outcome=HookOutcome.ALLOW if mode is Mode.SHADOW else None,
            would_reason=LOCAL_FAST_PATH_REASON if mode is Mode.SHADOW else None,
        )
        return HookResult(HookOutcome.ALLOW, None, LOCAL_FAST_PATH_REASON, False)
    request = {
        "schema_version": 1,
        "op": "decide",
        "question_set_path": question_set_path,
        "mode": mode.value,
        **({"producer": producer} if producer else {}),
        "state": {
            "command": call.command,
            "target": call.target,
            "context": call.context,
            **properties.as_state(),
            **dest.as_state(),
            **target_stat.as_state(tstat),
        },
    }
    run: Callable[[dict[str, Any]], dict[str, Any]]
    run = runner if runner is not None else (lambda req: _default_runner(req, self_deadline_s))

    # Own the deadline independently of the runner: on a miss, abandon the worker without
    # joining it (a plain `with` block would join on exit and defeat the bound), so the core
    # itself returns within self_deadline even if the runner hangs. The watchdog child is also
    # killed on its own shorter timeout (finding Phase3/4 MAJOR-2).
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        future = pool.submit(run, request)
        try:
            response = future.result(timeout=self_deadline_s)
        except concurrent.futures.TimeoutError:
            pool.shutdown(wait=False, cancel_futures=True)
            _record_sidelog(
                sidelog_path, call, mode, "ask", "timeout", producer,
                properties, dest, target_facts=tstat_facts,
            )
            return _fail_closed(mode, "timeout", timed_out=True)
        except Exception:
            pool.shutdown(wait=False, cancel_futures=True)
            _record_sidelog(
                sidelog_path, call, mode, "ask", "internal", producer,
                properties, dest, target_facts=tstat_facts,
            )
            return _fail_closed(mode, "internal")
    finally:
        # Do not block on a still-running worker; a hung runner must not hang the hook.
        pool.shutdown(wait=False, cancel_futures=True)

    result = _map_response(response, mode)
    # Shadow rehearses enforce honestly: compute the outcome enforce would have produced
    # for this same response, including its post-map rules, and write it to the side-log
    # while still allowing (shadow never changes host behavior). Before this, the shadow
    # collapse discarded fail reasons, so a sidelog showed ~100% allow even when enforce
    # would have asked on nearly every non-trivial command — the blind spot that let an
    # unstable enforce configuration ship. `would_outcome`/`would_reason` make the
    # shadow corpus a direct measurement of the enforce ask-rate.
    would_outcome: HookOutcome | None = None
    would_reason: str | None = None
    if mode is Mode.SHADOW:
        would = _map_response(response, Mode.ENFORCE)
        if would.outcome is HookOutcome.ALLOW and not properties.parse_confident:
            # Mirror the enforce-only rule below: unknown is risky, never safe.
            would = HookResult(
                HookOutcome.ASK, "ask", "command_parse_unconfident", would.is_mock
            )
        would_outcome, would_reason = would.outcome, would.reason
    _record_sidelog(
        sidelog_path, call, mode, result.outcome.value, result.reason, producer,
        properties, dest, target_facts=tstat_facts,
        call_id=next(
            (r.get("call_id") for r in response.get("records", [])
             if isinstance(r, dict) and r.get("call_id")),
            None,
        ),
        would_outcome=would_outcome,
        would_reason=would_reason,
    )
    if mode is Mode.ENFORCE and not properties.parse_confident and result.outcome is not (
        HookOutcome.ASK
    ):
        # Unknown is risky, never safe: a command the property parser could not read never
        # reaches ALLOW in enforce, whatever the gate answered. The call still runs so the
        # decision leaves its receipt. Shadow never changes host behavior.
        result = HookResult(HookOutcome.ASK, "ask", "command_parse_unconfident", result.is_mock)

    # An ASK is an escalation that presumes a human. Where there is no human, the unattended
    # policy decides instead. Only ASK reaches this branch: a gate that affirmatively judged
    # the call dangerous is not an escalation and never passes through here.
    #
    # The mode check is defense in depth rather than the operative guard: shadow mode always
    # yields ALLOW (both in _fail_closed and in _map_response), so this branch is already
    # unreachable there. It is kept because it states the intent at the point of use instead of
    # relying on that invariant holding somewhere else. `test_shadow_never_yields_ask` pins the
    # invariant this depends on.
    if (
        mode is Mode.ENFORCE
        and result.outcome is HookOutcome.ASK
        and unattended_mod.is_unattended(task_id)
    ):
        policy = unattended_mod.policy_from_env()
        outcome = unattended_mod.resolve_escalation(
            would_escalate=True, unattended=True, policy=policy
        )
        if outcome.proceed:
            _record_suppressed_escalation(call, result, policy, dest)
            return HookResult(HookOutcome.ALLOW, "unattended", None, result.is_mock)
    return result


def _record_suppressed_escalation(
    call: ToolCall,
    result: HookResult,
    policy: unattended_mod.UnattendedPolicy,
    dest: destination.Destination,
) -> None:
    """Write down an escalation the unattended policy suppressed.

    This is what separates the default policy from doing nothing. The suppression is not
    silent: it lands in a local audit file an operator can count and review, with the action
    that would have been taken. Only the command basename is recorded, matching the egress
    discipline, and the file never leaves the machine.
    """
    try:
        path = unattended_mod.audit_log_path()
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        words = (call.command or "").split()
        entry = {
            "ts": datetime.now(UTC).isoformat(timespec="seconds"),
            "unattended": True,
            "policy": policy.value,
            "would_escalate": True,
            "would_outcome": result.outcome.value,
            "reason": result.reason,
            "command": words[0] if words else "",
            "dest_known": dest.known,
            "dest_allowlisted": dest.allowlisted,
        }
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
    except Exception:  # a record must never break a turn
        pass


def _record_sidelog(
    path: Path | None,
    call: ToolCall,
    mode: Mode,
    outcome: str,
    reason: str | None,
    producer: str | None,
    properties: Any,
    dest: Any,
    call_id: str | None = None,
    target_facts: dict | None = None,
    would_outcome: HookOutcome | None = None,
    would_reason: str | None = None,
) -> None:
    """Write one side-log line after the decision. Never raises."""
    cmd_facts = properties.as_state() if properties is not None else {}
    if target_facts:
        # The runtime destination-existence verdict rides with the cmd_ facts so the
        # calibration join (command -> verdict) stays a single lookup.
        cmd_facts = {**cmd_facts, **target_facts}
    try:
        sidelog.record(
            path=path,
            call_id=call_id or "",
            command=call.command,
            target=call.target,
            context=call.context,
            mode=mode.value,
            outcome=outcome,
            reason=reason,
            cmd_facts=cmd_facts,
            dest_facts=dest.as_state() if dest is not None else {},
            producer=producer,
            would_outcome=would_outcome.value if would_outcome else None,
            would_reason=would_reason,
        )
    except Exception:  # a record must never break a turn
        pass


def _map_response(response: dict[str, Any], mode: Mode) -> HookResult:
    if not isinstance(response, dict) or response.get("status") != "ok":
        reason = response.get("reason") if isinstance(response, dict) else None
        return _fail_closed(mode, reason or "error")

    records = response.get("records")
    if not isinstance(records, list) or not records:
        return _fail_closed(mode, "no_records")

    is_mock = any(bool(r.get("is_mock")) for r in records if isinstance(r, dict))

    if mode is Mode.SHADOW:
        # Shadow never changes behavior: allow regardless, but surface the would-be route.
        would = next(
            (r.get("would_route") for r in records if isinstance(r, dict) and r.get("would_route")),
            None,
        )
        return HookResult(HookOutcome.ALLOW, would, None, is_mock)

    # Enforce: any gate not clearing to accept means ask (fail closed). The tool-call-gate set
    # is all gate questions, so a single non-accept route escalates.
    # ALLOW only if EVERY record is a clean accept whose accepted label is explicitly listed
    # safe (kit.gate.allow_labels). accept alone is calibrated-and-clear, not permission; a
    # confident dangerous answer (label not in allow_labels) escalates (finding H1). Missing
    # allow_labels on an accept is a fail-closed backstop (asks).
    dict_records = [r for r in records if isinstance(r, dict)]
    if len(dict_records) != len(records) or not dict_records:
        return _fail_closed(mode, "malformed_records")

    def _may_allow(rec: dict[str, Any]) -> bool:
        if rec.get("route") != "accept":
            return False
        allow_labels = rec.get("allow_labels")
        if not isinstance(allow_labels, list):
            return False  # backstop: an accept without a declared allow-list never allows
        return rec.get("label") in allow_labels

    if all(_may_allow(rec) for rec in dict_records):
        return HookResult(HookOutcome.ALLOW, "accept", None, is_mock)
    reason = next(
        (r.get("fail_reason") for r in dict_records if r.get("fail_reason")),
        None,
    )
    return HookResult(HookOutcome.ASK, "ask", reason, is_mock)
