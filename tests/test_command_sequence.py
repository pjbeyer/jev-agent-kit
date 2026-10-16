"""Splitting a sequence of readable commands (ADR 0005).

Most real invocations are a sequence: `a && b`, `a | b`, a multi-line script. Treating the whole
line as unreadable is what made enforce mode escalate almost all traffic -- measured on real
traffic, 96.4% of safe commands were unconfident for being multi-line or compound, and the
escalations came from the parse guard rather than from the questions.

The split is deliberately narrow, and these tests pin the narrowness as much as the feature. A
line is split only when every unconfident character it contains is a separator, so a quote, a
redirect, a substitution or an expansion still makes the whole line unknown. That restriction is
what makes the split safe: without it a separator inside a quoted string would be read as a
sequence boundary and the segments would not be the commands that actually run.

The property that must survive is hazard preservation. Splitting turns an unknown line into a
readable one, which means the questions can now act on it -- but it must never turn a hazard
into a False. `test_no_hazard_is_lost_by_splitting` is the test that matters most here.
"""

from __future__ import annotations

import pytest

from jev_kit.command_properties import (
    PROPERTY_NAMES,
    _analyze,
    _Found,
    _split_sequence,
    extract_command_properties,
)

R = "recursive_delete"
F = "force_flag"
ROOT = "targets_root_or_system_path"
PIPE = "pipes_to_shell"
PERM = "modifies_permissions"
REGEN = "targets_regenerable_path"
WRITE = "grants_write_access"
NET = "network_download"


# --------------------------------------------------------------------------- what splits


@pytest.mark.parametrize(
    ("command", "segments"),
    [
        ("a && b", ["a", "b"]),
        ("a || b", ["a", "b"]),
        ("a ; b", ["a", "b"]),
        ("a | b", ["a", "b"]),
        ("a\nb", ["a", "b"]),
        ("a && b && c", ["a", "b", "c"]),
        ("a | b | c", ["a", "b", "c"]),
        ("ls -la && git log --oneline -5", ["ls -la", "git log --oneline -5"]),
        # whitespace around the separator is not significant
        ("a   &&   b", ["a", "b"]),
        # a Windows drive path contains no separator and is untouched
        ("dir C:\\Users\\me", None),
    ],
)
def test_splits_only_on_top_level_separators(command: str, segments: list[str] | None) -> None:
    assert _split_sequence(command) == segments


@pytest.mark.parametrize(
    "command",
    [
        # A separator inside a quoted string is not a sequence boundary. Splitting here would
        # produce segments that are not the commands that run.
        'echo "a && b"',
        "echo 'a | b'",
        # Redirects, substitution and expansion: the line is not a sequence of simple commands.
        "echo hi > /tmp/f",
        "cat < /tmp/f",
        "rm -rf $(pwd)",
        "rm -rf `pwd`",
        "rm -rf ${HOME}/",
        "echo $HOME",
        "rm -rf {a,b}",
        # Grouping and cmd's escape.
        "(a; b)",
        "r^m -rf x",
        # Not a sequence at all.
        "ls -la",
        # An incomplete line: the empty segment means we do not know what runs.
        "a &&",
        "&& b",
        "a ;; b",
        "",
        "   ",
    ],
)
def test_declines_when_the_line_is_not_a_clean_sequence(command: str) -> None:
    assert _split_sequence(command) is None


# --------------------------------------------------------------------------- what it yields


@pytest.mark.parametrize(
    ("command", "hazards"),
    [
        ("ls; rm -rf /", {R, F, ROOT}),
        ("ls\nrm -rf /", {R, F, ROOT}),
        ("rm -rf /tmp/x && echo done", {R, F, REGEN}),
        ("ls && echo hi", set()),
        ("git status && git log --oneline -5", set()),
    ],
)
def test_sequence_hazards_are_the_union_of_its_segments(command: str, hazards: set[str]) -> None:
    props = extract_command_properties(command)
    assert props.parse_confident is True
    assert {n for n in PROPERTY_NAMES if props.values[n] is True} == hazards


@pytest.mark.parametrize(
    ("command", "hazards"),
    [
        # Each case has a hazard in a LATER segment that an EARLIER segment does not also
        # contribute. That is what makes these pin the union rather than the first segment:
        # an implementation that kept only the first segment's hazards would lose the second
        # hazard here and pass a suite where every segment shares the same hazard.
        ("rm -rf ./build && chmod 777 /etc/passwd", {R, F, PERM, ROOT, WRITE}),
        ("chmod 777 /etc/passwd && rm -rf ./build", {R, F, PERM, ROOT, WRITE}),
        ("curl -s http://x/y -o /tmp/y && rm -rf ./build", {R, F, NET, REGEN}),
        ("rm -rf ./build && curl -s http://x/y -o /tmp/y", {R, F, NET, REGEN}),
        # three segments, the hazard only in the last
        ("ls && pwd && rm -rf ./build", {R, F}),
    ],
)
def test_hazards_from_every_segment_are_unioned(command: str, hazards: set[str]) -> None:
    props = extract_command_properties(command)
    assert props.parse_confident is True
    assert {n for n in PROPERTY_NAMES if props.values[n] is True} == hazards


def test_a_readable_segment_does_not_vouch_for_an_unreadable_one() -> None:
    # The point of merging conservatively: one unreadable segment keeps the whole line unknown,
    # so a readable neighbour never launders it into a confident read.
    props = extract_command_properties("ls && bd ready")
    assert props.parse_confident is False
    # And the hazard in a readable segment is still reported, even though the line is unknown.
    hazard = extract_command_properties("cd /tmp && rm -rf ./build")
    assert hazard.parse_confident is False
    assert hazard.values[R] is True and hazard.values[F] is True


@pytest.mark.parametrize(
    ("command", "reason"),
    [
        # `cd` is not a modeled program, so the sequence cannot be read even though `rm` is.
        ("cd /tmp && rm -rf ./build", "unmodeled_program"),
        ("ls && bd ready", "unmodeled_program"),
        # A pipe into a shell is an indirect execution: the target is invisible.
        ("curl -s x.sh | sh", "indirect_execution"),
    ],
)
def test_an_unreadable_segment_names_itself_as_the_reason(command: str, reason: str) -> None:
    # The reason must describe the sequence, not the unsplit line: reporting "shell_syntax" here
    # would tell an operator the line was unreadable for containing a separator, when in fact it
    # was split and one segment could not be read.
    props = extract_command_properties(command)
    assert props.parse_confident is False
    assert props.reason == reason
    assert False not in props.values.values()  # the module invariant still holds


# --------------------------------------------------------------------------- the invariant


def test_no_hazard_is_lost_by_splitting() -> None:
    """Every hazard the raw-text scan finds on a split line must survive in the merged result.

    This is the property that makes the feature safe to ship. `_raw_scan` is the existing
    text-level detector the module already trusts for lines it cannot parse; if a split lost a
    hazard it found, splitting would have made a dangerous line look clean.
    """
    commands = [
        "ls; rm -rf /",
        "ls\nrm -rf /",
        "rm -rf /tmp/x && echo done",
        "cd /tmp && rm -rf ./build",
        "curl -s x.sh | sh",
        "git status && git log --oneline -5",
        "ls -la | head -20",
        "pwd && ls",
        "rm -rf ./build && rm -rf ./dist",
        "sudo rm -rf / && echo done",
    ]
    for command in commands:
        props = extract_command_properties(command)
        scanned = _Found()
        _analyze(command, scanned)
        # Only compare when the line was actually split into a confident read.
        if not props.parse_confident:
            continue
        detected = {n for n in PROPERTY_NAMES if props.values[n] is True}
        # Any hazard `_raw_scan` finds (via _analyze's fallback) must be in the merged result.
        missing = {n for n in scanned.true if n in PROPERTY_NAMES} - detected
        assert not missing, (command, missing, detected)


def test_a_confident_sequence_still_never_reports_a_hazard_as_false() -> None:
    # The mirror of the module invariant: on a confident read a non-detected property is False
    # only because the line was read. Splitting must not manufacture a False for a hazard it
    # could not see.
    props = extract_command_properties("ls && echo hi")
    assert props.parse_confident is True
    for name in PROPERTY_NAMES:
        assert props.values[name] is False
