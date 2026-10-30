"""Destination-existence: does the copy/move target already hold data?

Computed at judge time, in code. The `overwrites_data` question asks whether a
command replaces content on an EXISTING path, but the `cmd_*` facts are computed
from the command line alone, so nothing in the state can distinguish `cp report
/tmp/` (new file) from `cp report /tmp/report` (existing file replaced). Measured
twice (batches 6 and the 2026-10-28 registry build): the overwrite confirm band
cannot be closed by cp/mv volume because force_flag discriminates INTENT, not
destination. The missing dimension is whether the destination exists right now.

This module supplies that dimension the way `destination.py` supplies dest trust,
following `docs/upstream/gate-augmentation-contract-v1.md` (Contract 1 pattern):

- `dest_exists` tri-state: true / false / null.
- The raw destination path is computed here and deliberately NOT transmitted.
  A path from the command line is a raw command argument; sending it would break
  the kit's central egress invariant (no raw command argument leaves the machine).
  Only the boolean verdict goes on the wire.

Tri-state polarity matches the `cmd_*` hazard facts: unknown (`None`) is read as
possibly-true (possibly overwriting). An affirmative `false` (destination absent,
nothing to overwrite) is only ever sent when the parse was confident enough to
identify exactly one destination operand and the stat could be performed.

Scope is deliberately narrow: the copy/move/link family (`cp`, `mv`, `ln`,
PowerShell copy/move). Every other shape yields null; the question falls back to
its existing weighing. Remote specs (`user@host:path`) yield null: a remote path's
existence is not this machine's to stat.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

#: The single field this module computes (wire name, prefixed like the cmd_ facts
#: so a question set declares it with kind `flag`).
DEST_EXISTS = "dest_exists"
WIRE_FIELD = "cmd_dest_exists"

#: Programs whose LAST non-option operand is a destination path on this machine.
#: `rsync`/`scp` are excluded: their operands may be remote specs, and the last
#: operand of a push is a remote. `install` is included (copy semantics).
_COPY_PROGRAMS = frozenset({"cp", "mv", "install", "copy-item", "cpi", "move-item", "mi"})

#: `ln -sf` replaces a link target only with the force flag; plain `ln` fails when
#: the target exists, so existence is not an overwrite for it.
_LINK_PROGRAM = "ln"

#: Options that take a value, so the token after them is NOT an operand.
_VALUE_OPTIONS = frozenset({
    "-t", "--target", "--target-directory",   # cp/mv/install: DESTINATION option form
    "-S", "--suffix", "-Z", "--context",
    "-T" if False else "--no-target-directory",  # -T IS a flag, handled below
})
_FLAGS = frozenset({"-T", "--no-target-directory", "-f", "--force", "-i", "--interactive",
                    "-n", "--no-clobber", "-b", "--backup", "-p", "-a", "-r", "-R",
                    "--recursive", "-d", "-P", "--no-dereference", "-L", "-H", "-v",
                    "-u", "--update", "-l", "-s", "--symbolic", "-h", "--help"})


@dataclass(frozen=True)
class TargetStat:
    """The computed verdict plus local diagnostics that never go on the wire."""

    dest_exists: bool | None
    reason: str | None  # why null; local diagnostics only
    dest_path: str | None  # local only; never transmitted


def resolve_dest_exists(command: object, workdir: str | None = None) -> TargetStat:
    """Stat the copy/move destination operand, computed before any network call.

    Pure with respect to the wire: returns a tri-state plus local-only fields.
    Never raises.
    """
    if not isinstance(command, str) or not command.strip():
        return TargetStat(None, "no_command", None)
    tokens = command.split()
    if not tokens or len(tokens) > 128:
        return TargetStat(None, "token_limit", None)
    program = tokens[0].rsplit("/", 1)[-1].lower()
    operands: list[str] = []
    link_force = False
    if program == _LINK_PROGRAM:
        rest = tokens[1:]
        i = 0
        while i < len(rest):
            tok = rest[i]
            if tok in _FLAGS or (tok.startswith("-") and len(tok) > 1
                                 and all(c in "fs" for c in tok.lstrip("-"))):
                if "f" in tok.lstrip("-"):
                    link_force = True
                i += 1
                continue
            if tok.startswith("-"):
                return TargetStat(None, "unmodeled_option", None)
            operands.append(tok)
            i += 1
        if not link_force or len(operands) != 2:
            # Without force the link call fails rather than overwriting; with a
            # different operand count the destination is not identifiable.
            return TargetStat(None, "ln_without_force_or_ambiguous", None)
        dest = operands[1]
    elif program in _COPY_PROGRAMS:
        rest = tokens[1:]
        i = 0
        optioned_dest: str | None = None
        while i < len(rest):
            tok = rest[i]
            if tok in ("-t", "--target-directory") and i + 1 < len(rest):
                optioned_dest = rest[i + 1]
                i += 2
                continue
            if tok.startswith("-") and len(tok) > 1:
                # Clustered short flags are fine; an unknown long option is not.
                if tok.startswith("--"):
                    return TargetStat(None, "unmodeled_option", None)
                if any(c not in "abinoprfvHLPRTuxZ" for c in tok.lstrip("-")):
                    return TargetStat(None, "unmodeled_option", None)
                i += 1
                continue
            operands.append(tok)
            i += 1
        if optioned_dest is not None:
            dest = optioned_dest
            if not operands:
                return TargetStat(None, "no_source", None)
        elif len(operands) >= 2:
            # N-ary copy: the last operand is the destination directory (or file
            # for exactly two operands). Both read as "exists?".
            dest = operands[-1]
        else:
            return TargetStat(None, "missing_operands", None)
    else:
        return TargetStat(None, "not_copy_family", None)

    if _REMOTE_RE.search(dest):
        return TargetStat(None, "remote_spec", None)
    # Reject anything that is not a plain path: globs, variables, redirects inside
    # a token. The parser's unconfident-character rule, applied to the operand.
    if any(ch in dest for ch in "*?[]$`\\\"'&|;<>(){}"):
        return TargetStat(None, "unresolved_path", None)
    if not dest or dest == "-" or dest.startswith("&"):
        return TargetStat(None, "unresolved_path", None)

    base = Path(workdir) if workdir else None
    target = Path(dest)
    if base is not None and not target.is_absolute():
        target = base / target
    try:
        exists = os.path.lexists(target)
    except OSError:
        return TargetStat(None, "stat_failed", None)
    return TargetStat(True if exists else False, None, dest)


_REMOTE_RE = re.compile(r"^[A-Za-z0-9._-]+@[^:]*:|^[A-Za-z0-9.-]+:[A-Za-z0-9/._-]+")


def as_state(stat: TargetStat) -> dict[str, bool | None]:
    """The wire shape: one prefixed tri-state field. Raw path stays local."""
    return {WIRE_FIELD: stat.dest_exists}