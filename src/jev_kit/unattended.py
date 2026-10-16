"""Unattended (cron) session semantics for a gate.

A gate fails closed to "ask", which a host maps to its human-approval path. In a scheduled
or otherwise unattended run there is no human on that path, so the same escalation becomes
a hard block with nobody to review it, and the run stalls or fails.

Neither the kit nor its sibling gate had any unattended awareness: `HERMES_CRON_SESSION`
appeared nowhere, and no code read any session-type variable. This module supplies the
detection and the policy, following the shared augmentation contract in
`docs/upstream/gate-augmentation-contract-v1.md`.

Detection is deliberately narrow. Either signal is sufficient:

- the task id starts with ``cron:``, or
- ``HERMES_CRON_SESSION`` is set to a true-ish value.

The task-id test is a **prefix** match, never a substring match. A substring match would
exempt an interactive session whose id merely contains ``cron``, which is a silent safety
hole in the direction of "allowed", so the contract forbids it.

The policy applies to escalations that presume a human. It does **not** apply to an
affirmative danger verdict: a gate that judges a call dangerous still blocks in unattended
context, because that verdict is a judgement rather than a request for a person. That
distinction is the whole point of the module and is covered by tests in both directions.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

#: The environment variable Hermes exports for a cron run.
CRON_SESSION_ENV_VAR = "HERMES_CRON_SESSION"

#: The task-id namespace a cron run uses.
CRON_TASK_ID_PREFIX = "cron:"

#: Values of CRON_SESSION_ENV_VAR that mean "yes". Anything else, including the empty
#: string, means no.
_TRUEISH = frozenset({"1", "true", "yes", "on"})


class UnattendedPolicy(StrEnum):
    """What a gate does with an escalation when no human is present."""

    #: Do not escalate; continue. Record what would have been escalated, marked unattended.
    RECORD = "record"
    #: Hard-block. For installations that prefer broken automation over an unreviewed action.
    BLOCK = "block"
    #: Continue with no record of the suppressed escalation. The weakest option.
    ALLOW = "allow"


#: The default. It satisfies both halves of the requirement: automation keeps working, and
#: the suppressed escalation is still written down for an operator to count and review.
DEFAULT_POLICY = UnattendedPolicy.RECORD

POLICY_ENV_VAR = "JEV_KIT_UNATTENDED_POLICY"


def is_unattended(
    task_id: object = None, environ: object = None
) -> bool:
    """Whether this call is running with no human to answer an escalation.

    Either signal suffices. ``environ`` exists so tests and callers can supply a mapping
    instead of the process environment; it defaults to ``os.environ``.
    """
    if isinstance(task_id, str) and task_id.startswith(CRON_TASK_ID_PREFIX):
        return True
    env = os.environ if environ is None else environ
    raw = ""
    if hasattr(env, "get"):
        value = env.get(CRON_SESSION_ENV_VAR, "")
        raw = value if isinstance(value, str) else ""
    return raw.strip().lower() in _TRUEISH


def policy_from_env(environ: object = None) -> UnattendedPolicy:
    """The configured policy, or the default. An unreadable value never raises."""
    env = os.environ if environ is None else environ
    raw = ""
    if hasattr(env, "get"):
        value = env.get(POLICY_ENV_VAR, "")
        raw = value if isinstance(value, str) else ""
    candidate = raw.strip().lower()
    for policy in UnattendedPolicy:
        if policy.value == candidate:
            return policy
    return DEFAULT_POLICY


#: Where a suppressed escalation is written down. A local file, never transmitted.
AUDIT_LOG_ENV_VAR = "JEV_KIT_UNATTENDED_AUDIT_LOG"

#: Default location, relative to the Hermes home, matching the sibling gate's log convention.
DEFAULT_AUDIT_LOG = "logs/jev-kit-unattended.jsonl"


def audit_log_path(environ: object = None) -> Path | None:
    """Where to record a suppressed escalation, or None to record nothing.

    ``JEV_KIT_UNATTENDED_AUDIT_LOG`` wins when set; the value ``off`` disables the record.
    Otherwise the default sits under ``$HERMES_HOME`` (or ``~/.hermes``). Never raises.
    """
    env = os.environ if environ is None else environ
    raw = ""
    if hasattr(env, "get"):
        value = env.get(AUDIT_LOG_ENV_VAR, "")
        raw = value if isinstance(value, str) else ""
    explicit = raw.strip()
    if explicit.lower() in {"off", "none", "false"}:
        return None
    if explicit:
        try:
            return Path(explicit).expanduser()
        except (TypeError, ValueError):
            return None
    home = ""
    if hasattr(env, "get"):
        value = env.get("HERMES_HOME", "")
        home = value if isinstance(value, str) else ""
    base = Path(home).expanduser() if home.strip() else Path.home() / ".hermes"
    return base / DEFAULT_AUDIT_LOG


@dataclass(frozen=True)
class UnattendedOutcome:
    """What the gate decided to do with a would-be escalation."""

    #: True when the call may proceed.
    proceed: bool
    #: The policy that was applied.
    policy: UnattendedPolicy
    #: The action that would have been taken with a human present, for the record.
    would_escalate: bool


def resolve_escalation(
    *,
    would_escalate: bool,
    unattended: bool,
    policy: UnattendedPolicy = DEFAULT_POLICY,
) -> UnattendedOutcome:
    """Apply the unattended policy to a would-be escalation.

    Called only for escalations that presume a human. A caller holding an affirmative danger
    verdict must not route it through here: that verdict blocks regardless.
    """
    if not would_escalate or not unattended:
        return UnattendedOutcome(proceed=False, policy=policy, would_escalate=would_escalate)
    if policy is UnattendedPolicy.BLOCK:
        return UnattendedOutcome(proceed=False, policy=policy, would_escalate=True)
    return UnattendedOutcome(proceed=True, policy=policy, would_escalate=True)
