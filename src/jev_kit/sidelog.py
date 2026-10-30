"""Opt-in, local-only side-log joining judged commands to their decision ids.

The receipts deliberately carry no command text: the egress invariant is that
no raw command argument leaves the machine unmodeled, and a receipt is written
before anything is sent. The cost of that discipline is that a shadow corpus
cannot be re-labeled offline — the calibration guide's fit/confirm workflow
needs the judged input, not just the verdict.

The side-log restores the missing half, deliberately:

- **Opt-in**: `JEV_KIT_SIDELOG_PATH` must be set to a path, or the value `off`.
  Unset or `off` means nothing is written and behavior is byte-identical to
  before.
- **Local only**: the file sits where the operator points it. Nothing in this
  module transmits, and the record carries exactly what the hook already
  computed locally: the command text the host already displayed, the computed
  facts, and the decision metadata.
- **Never breaks a turn**: every failure (unwritable path, disk full, anything)
  is swallowed. The side-log is evidence, not control flow.

The join key is the `call_id` receipts already carry, so a side-log line joins
to its receipt batch without parsing any command text out of a receipt.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from typing import Any

#: Environment variable naming the side-log file. Unset, empty, or `off` means
#: the side-log is disabled: nothing is written, ever.
SIDELOG_PATH_ENV_VAR = "JEV_KIT_SIDELOG_PATH"

#: Environment variable labelling the traffic class of the running process.
#: Test suites and calibration batteries set it to `test`; production sessions
#: leave it unset and records fall back to `real`. Written on every record so
#: suite traffic that reaches an operator log by accident stays greppable and
#: excludable — the enforce-era forensics were poisoned by exactly such leak.
TRAFFIC_ENV_VAR = "JEV_KIT_TRAFFIC"
TRAFFIC_REAL = "real"

_OFF = frozenset({"off", "none", "false"})


def traffic_from_env(environ: Any = None) -> str:
    """The traffic class label for this process. Never raises."""
    try:
        env = os.environ if environ is None else environ
        if hasattr(env, "get"):
            value = env.get(TRAFFIC_ENV_VAR, "")
            if isinstance(value, str) and value.strip():
                return value.strip()
    except Exception:
        pass
    return TRAFFIC_REAL


def path_from_env(environ: Any = None) -> Path | None:
    """The side-log path, or None when disabled. Never raises."""
    env = os.environ if environ is None else environ
    raw = ""
    if hasattr(env, "get"):
        value = env.get(SIDELOG_PATH_ENV_VAR, "")
        raw = value if isinstance(value, str) else ""
    explicit = raw.strip()
    if not explicit or explicit.lower() in _OFF:
        return None
    try:
        return Path(explicit).expanduser()
    except (TypeError, ValueError):
        return None


def record(
    *,
    path: Path | None,
    call_id: str,
    command: str,
    target: str | None,
    context: str | None,
    mode: str,
    outcome: str,
    reason: str | None,
    cmd_facts: dict,
    dest_facts: dict,
    producer: str | None = None,
    traffic: str | None = None,
    would_outcome: str | None = None,
    would_reason: str | None = None,
) -> None:
    """Append one side-log line. Never raises.

    Written after the decision, so `outcome`/`reason` reflect what the gate
    actually did, and the line joins to the receipt batch via `call_id`.
    In shadow mode `would_outcome`/`would_reason` carry the outcome enforce
    would have produced for the same response, so a shadow corpus measures the
    enforce ask-rate directly instead of recording a vacuous all-allow log.
    """
    if path is None:
        return
    try:
        entry = {
            "ts": datetime.now(UTC).isoformat(timespec="seconds"),
            "call_id": call_id,
            "command": command,
            "target": target,
            "context": context,
            "mode": mode,
            "outcome": outcome,
            "reason": reason,
            "cmd_facts": cmd_facts,
            "dest_facts": dest_facts,
            **({"producer": producer} if producer else {}),
            "traffic": traffic if traffic else traffic_from_env(),
            **({"would_outcome": would_outcome} if would_outcome else {}),
            **({"would_reason": would_reason} if would_reason else {}),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
    except Exception:  # a record must never break a turn
        return