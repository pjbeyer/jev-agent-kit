"""Hermes host-tool semantics for the local property parser (jak-baw full coverage).

Hermes tools are not shell programs, but the gate judges every tool call as a
command line. Historically the shim let the bare tool NAME land in
ToolCall.command — an opaque token that parses as `unmodeled_program` and
fail-closes to ask, measured at 4,459 of 4,460 such calls (61% of all shadow
would-asks were blind, 2026-11-04).

This module is the modeling half of the fix (the shim's extraction half lives in
`hooks/hermes.py`): the shim emits a pseudo-command `hermes.<tool> <args...>`
whose args are the call's own simple string arguments, and this module tells the
parser what each Hermes tool actually does. Effects are copied from the Hermes
source (agent/tool_executor.py and the tool schemas), not guessed:

- readers (read_file, skills_list, tool_search, ...) — pure reads;
- writers (write_file, patch) — create/overwrite at `path`, and their
  destination existence is stat-able (target_stat's `dest_exists` fact), which
  is what lets `overwrites_data` discriminate a new file from a replacement;
- network (web_search, web_extract, browser_exec) — outbound;
- code-exec (execute_code, jupyter, delegate_task) — run unseen code, unconfident
  by design, same rule as interpreters;
- MCP bridges (mcp__*) and cron (cronjob_manage) — arbitrary effects, unconfident.

Trust boundary: the `hermes.` prefix is only ever emitted by the shim, and only
from arguments that passed the shim's simple-string filter (ASCII, one line, no
quotes/expansion/redirects). A bare tool name without a prefix — an extraction
failure, a spoof, or an actual shell word — stays unmodeled. Nothing in this
module inspects payloads: script bodies, diffs and query text are never mapped;
tools whose effect is not honestly expressible in the property vocabulary are
left unmodeled and fail closed.
"""

from __future__ import annotations

#: The pseudo-program namespace the shim emits. `.` is not a valid shell program
#: character in the parser's own program-name grammar, which is the point: a
#: typed `hermes.read_file` cannot be confused with a shell word, and no shell
#: line can accidentally carry a `hermes.` head.
PREFIX = "hermes."

#: Tools whose call only reads: no file, permission or auth state changes. The
#: args (paths, patterns, names) are still path-checked by the parser, so
#: `read_file /etc/passwd` still carries targets_absolute_path etc.
READERS = frozenset({
    "read_file",           # reads a text file (local files; binary refused)
    "search_files",        # ripgrep content/file search — read-only
    "skill_view",          # loads a skill's SKILL.md — read-only
    "skills_list",         # lists skills — read-only
    "tool_search",         # searches the deferred tool catalog — read-only
    "tool_describe",       # loads tool schemas — read-only
    "session_search",      # reads session history (FTS5) — read-only
    "vision_analyze",      # loads an image for the model — read-only
    "clarify",             # asks the user a question — no file/system effect
})

#: Tools that create or overwrite files at a `path` argument. Modeled as writers
#: so the planted-code check runs (writing .plist/.launchd/pyproject.toml must
#: fire targets_autorun_path) and target_stat can resolve `dest_exists` for the
#: overwrites_data question.
WRITERS = frozenset({
    "write_file",          # full-file overwrite (refuses to clobber unread files)
    "patch",               # targeted find-and-replace edits in a file
    "skill_manage",        # creates/patches/deletes skill SKILL.md files on disk
    "memory",              # writes MEMORY.md / USER.md profile stores
    "todo_list",           # writes/mutates the task list store
})

#: Tools whose primary effect is an outbound network request.
NETWORK = frozenset({
    "web_search",          # search backend call
    "web_extract",         # fetches URLs
    "text_to_speech",      # provider TTS call (payload text IS the egress)
})

#: Tools that execute code the parser cannot see. Same verdict as interpreters
#: (runs_unseen_code): unconfident by design; positive detections still count.
CODE_EXEC = frozenset({
    "execute_code",        # arbitrary Python in the session kernel
    "jupyter",             # live kernel execution
    "delegate_task",       # spawns subagents that use tools of their own
    "computer_use",        # drives the desktop (mouse/keyboard = arbitrary effect)
    "browser_exec",        # drives a real browser: JS execution + network + local state
    "tool_call",           # dispatches deferred tools (browser, computer_use, ...)
    "process_manage",      # writes to a live process's stdin / signals it: arbitrary effect
})

#: Tools whose effect is a scheduled/persistent action: what they create runs
#: LATER, on a schedule or at next session. Fires the persistence hazard fact.
PERSISTENCE = frozenset({
    "cronjob_manage",      # creates/edits Hermes cron jobs (code that runs later)
})

#: Tools that change standing authorization state (account links, grants).
AUTHORITY = frozenset({
    "manage_connections",  # connect/disconnect/rename app accounts (OAuth grants)
})

#: Every modeled Hermes tool name, for the parser's allowlist.
MODELED = READERS | WRITERS | NETWORK | CODE_EXEC | PERSISTENCE | AUTHORITY

#: Tools modeled but with NO mappable naming argument: the effect head alone is
#: honest (the facts fire), so a bare hermes.<tool> head is emitted confidently
#: for reader/network/persistence/authority classes, but WRITERS without their
#: path operand stay unconfident (writer_target_unknown) — a blind write must
#: never parse confidently.

#: Extraction sources (shim half): tool -> argument names whose simple string
#: values are embedded in the pseudo-command, in this order. Payload arguments
#: (script bodies, diffs, message text) are deliberately absent: only arguments
#: that NAME the object of the operation are mapped. A tool present in MODELED
#: but absent here emits `hermes.<tool>` with no args (facts still fire:
#: network, code-exec); a tool absent from MODELED keeps its bare name.
ARG_SOURCES: dict[str, tuple[str, ...]] = {
    "read_file": ("path",),
    "clarify": ("questions",),  # naming only; question text is payload-shaped
    "cronjob_manage": ("action",),
    "manage_connections": ("action",),
    "search_files": ("pattern", "path"),
    "skill_view": ("name",),
    "skills_list": ("category",),
    "tool_search": ("queries",),
    "tool_describe": ("names",),
    "write_file": ("path",),
    "patch": ("path",),
    "web_search": ("query",),
    "web_extract": ("urls",),
    "session_search": ("query",),
    "vision_analyze": ("image_url",),
}