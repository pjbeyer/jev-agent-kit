"""Destination trust: which host a command sends data to, computed in code.

The exfiltration question cannot be answered from local effects alone. The `cmd_*`
properties in `command_properties.py` describe what a command does *on this machine*
(recursive delete, force flag, pipe to shell). None of them describes *where the data
goes*, so a question about sending data out is judging a dimension the state never
supplies, and `git push` reads as a push.

This module supplies that dimension as code-computed fields, following the shared
augmentation contract in `docs/upstream/gate-augmentation-contract-v1.md`:

- `dest_host`: the normalized destination hostname, or None when there is not one.
- `dest_known`: whether a destination could be determined at all.
- `dest_allowlisted`: whether that host is on the operator's allowlist, or None.

**`dest_host` is computed here but is deliberately NOT transmitted.** The measured result
is that the allowlist verdict is what separates intended egress from exfiltration
(allowlisted <= 0.08, not allowlisted >= 0.98); the hostname itself adds nothing to that
decision. Transmitting it would break this kit's central egress invariant, that no raw
command argument leaves the machine, and a hostname taken from the command line is exactly
such an argument. So the wire state carries the two flags, and the host stays local for
receipts, diagnostics and operator tooling. See `WIRE_FIELDS` and `LOCAL_FIELDS`.

Tri-state polarity is the opposite of the `cmd_*` facts and this is deliberate. A `cmd_*`
fact is a hazard, so unknown (`None`) is read as hazardous. `dest_allowlisted` is a
permission, so unknown (`None`) must be read as **not permitted**. The rule this module
enforces:

- `dest_known=False` means no destination was determined. It is not a claim of safety.
- `dest_allowlisted=None` means unknown, never "allowlisted".
- `dest_allowlisted=False` is the only affirmative negative, and is only ever set when a
  host was determined and the allowlist is non-empty.
- An empty or unreadable allowlist yields None for every call. An empty allowlist is the
  absence of a policy, not a deny-list.

The extractor is deliberately conservative: when it cannot determine exactly one host it
says so, and says so in the direction that cannot suppress a warning. More than one
distinct host in a command yields unknown, never the friendly one.
"""

from __future__ import annotations

import configparser
import re
from dataclasses import dataclass
from pathlib import Path

#: The three fields this module computes.
DEST_HOST = "dest_host"
DEST_KNOWN = "dest_known"
DEST_ALLOWLISTED = "dest_allowlisted"

#: Every field this module computes, in order.
LOCAL_FIELDS: tuple[str, ...] = (DEST_HOST, DEST_KNOWN, DEST_ALLOWLISTED)

#: The fields that go into the request state. `dest_host` is not among them: it is a raw
#: command argument, and transmitting it would break the egress invariant. The two flags
#: carry the whole decision the question needs.
WIRE_FIELDS: tuple[str, ...] = (DEST_KNOWN, DEST_ALLOWLISTED)

#: Longest host this module will report. Not arbitrary: it is the bound of the `metric`
#: content kind in the egress policy (`_METRIC_TOKEN`, 64 chars), and `dest_host` is sent
#: as a metric. A longer host is refused rather than truncated, because a truncated host
#: is a different host and could be the allowlisted one.
MAX_HOST_CHARS = 64

_HOST_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST_RE = re.compile(rf"^(?:{_HOST_LABEL})(?:\.{_HOST_LABEL})*$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

#: Schemes whose host is worth reporting. Anything else (for example `file:`) is not egress.
_URL_SCHEMES = ("http://", "https://", "ssh://", "git://", "git+ssh://", "ftp://", "ftps://")

#: `scp`-style remote, `user@host:path`. The leading `user@` is what distinguishes this from a
#: Windows drive path (`C:\x`), which has no `@` and never reaches this pattern. The token must
#: contain no whitespace and exactly one `@`, so a shell line naming several files cannot match.
_SCP_RE = re.compile(r"^[A-Za-z0-9._-]+@([A-Za-z0-9.-]+):[^\s@]*$")

#: Quote characters stripped from the ends of a token before it is examined. A quoted URL
#: is still a URL; the command-property parser treats quoting as low confidence, which is
#: a separate judgement from this one.
_QUOTES = "\"'`"

#: git subcommands that name a remote or a URL and therefore have a destination.
_GIT_REMOTE_SUBCOMMANDS = frozenset(
    {"push", "pull", "fetch", "clone", "ls-remote", "remote", "submodule", "archive"}
)

#: git global options that consume the next argument, so it is not the subcommand.
_GIT_GLOBAL_WITH_ARG = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"}
)


@dataclass(frozen=True)
class Destination:
    """Tri-state destination trust for one command line."""

    host: str | None
    known: bool
    allowlisted: bool | None

    def as_state(self) -> dict[str, bool | None]:
        """The wire fields: the two flags, never the host."""
        return {DEST_KNOWN: self.known, DEST_ALLOWLISTED: self.allowlisted}

    def as_local(self) -> dict[str, str | bool | None]:
        """Every field including the host, for local receipts and diagnostics only."""
        return {DEST_HOST: self.host, DEST_KNOWN: self.known, DEST_ALLOWLISTED: self.allowlisted}


UNKNOWN = Destination(host=None, known=False, allowlisted=None)


def normalize_host(value: object) -> str | None:
    """A hostname, lowercased and validated, or None if it is not one.

    Strips a scheme, userinfo, port, path, query and fragment. Never truncates: a host too
    long to report returns None, because a shortened host is a different host.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    # scheme, if any. Everything after "://" is the authority plus path.
    if "://" in text:
        text = text.split("://", 1)[1]
    # userinfo
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    # bracketed IPv6 is not supported in this version and must not be guessed at
    if text.startswith("["):
        return None
    # port, path, query, fragment
    for sep in ("/", "?", "#"):
        text = text.split(sep, 1)[0]
    if ":" in text:
        head, _, tail = text.partition(":")
        # a trailing port is numeric; anything else is not a host:port form
        if tail.isdigit():
            text = head
        else:
            return None
    text = text.rstrip(".")
    text = text.lower()
    if not text or len(text) > MAX_HOST_CHARS:
        return None
    if _IPV4_RE.match(text):
        return text if all(int(part) <= 255 for part in text.split(".")) else None
    if not _HOST_RE.match(text):
        return None
    # A single label with no dot is not a destination on the public internet; `localhost`
    # is a destination but a loopback one, and reporting it as a host would let an
    # allowlist entry cover it. Both are left unknown.
    if "." not in text:
        return None
    return text


def _tokens(command: str) -> list[str]:
    return command.split()


def _unquote(token: str) -> str:
    return token.strip(_QUOTES)


def _host_from_token(token: str) -> str | None:
    """The host a single token names, if it names one."""
    text = _unquote(token)
    lowered = text.lower()
    for scheme in _URL_SCHEMES:
        if lowered.startswith(scheme):
            # normalize_host strips the scheme, the port and any path.
            return normalize_host(text)
    if "://" in text:
        # a scheme this module does not treat as egress, for example file://
        return None
    scp = _SCP_RE.match(text)
    if scp:
        return normalize_host(scp.group(1))
    return None


def _git_destination(args: list[str], workdir: Path | None) -> str | None:
    """Resolve the destination of a git command that names a remote.

    Reads the repository's own config file. It never runs git, so it cannot execute
    anything the repository configures (the same reason `git` is off the confidence
    allowlist in `command_properties.py`).
    """
    repo_dir = workdir
    index = 0
    while index < len(args):
        token = args[index]
        if token == "-C" and index + 1 < len(args):
            repo_dir = Path(args[index + 1]).expanduser()
            index += 2
            continue
        if token in {"--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"}:
            # The repository location is being redirected in a way this reader does not
            # follow. Saying so is safer than guessing the wrong repository.
            return None
        if token in _GIT_GLOBAL_WITH_ARG:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        break
    subcommand = args[index] if index < len(args) else ""
    if subcommand not in _GIT_REMOTE_SUBCOMMANDS:
        return None
    rest = [t for t in args[index + 1:] if not t.startswith("-")]
    # An explicit URL wins over a remote name.
    for token in rest:
        host = _host_from_token(token)
        if host is not None:
            return host
    if subcommand == "clone":
        return None
    remote = rest[0] if rest else "origin"
    return _remote_url_host(repo_dir, remote)


def _remote_url_host(repo_dir: Path | None, remote: str) -> str | None:
    if repo_dir is None:
        return None
    config = repo_dir / ".git" / "config"
    if not config.is_file():
        return None
    parser = configparser.RawConfigParser()
    try:
        parser.read(config, encoding="utf-8")
    except (configparser.Error, OSError, UnicodeDecodeError):
        return None
    section = f'remote "{remote}"'
    if not parser.has_section(section) or not parser.has_option(section, "url"):
        return None
    url = parser.get(section, "url")
    for scheme in _URL_SCHEMES:
        if url.lower().startswith(scheme):
            return normalize_host(url[len(scheme):])
    scp = _SCP_RE.match(url)
    if scp:
        return normalize_host(scp.group(1))
    # A local path or a relative path: a push with no host is not egress.
    return None


def resolve_destination(
    command: object,
    *,
    allowlist: frozenset[str] = frozenset(),
    workdir: str | None = None,
) -> Destination:
    """Compute destination trust for one command line. Pure; never raises.

    Exactly one distinct host must be determined for `dest_known` to be True. A command
    naming two hosts is reported as unknown rather than as whichever host looks friendly,
    so a decoy cannot talk the gate out of a warning.
    """
    if not isinstance(command, str) or not command.strip():
        return UNKNOWN
    try:
        tokens = _tokens(command)
        hosts: set[str] = set()
        for token in tokens:
            host = _host_from_token(token)
            if host is not None:
                hosts.add(host)
        program = _unquote(tokens[0]).rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        if program == "git":
            host = _git_destination([_unquote(t) for t in tokens[1:]], _workdir_path(workdir))
            if host is not None:
                hosts.add(host)
        if len(hosts) != 1:
            return UNKNOWN
        host = next(iter(hosts))
        return Destination(host=host, known=True, allowlisted=is_allowlisted(host, allowlist))
    except Exception:  # a bug here must mean unknown, never a wrong host or a False
        return UNKNOWN


def _workdir_path(workdir: str | None) -> Path | None:
    if not workdir:
        return None
    try:
        return Path(workdir).expanduser()
    except (TypeError, ValueError):
        return None


def is_allowlisted(host: str, allowlist: frozenset[str]) -> bool | None:
    """Whether *host* is on *allowlist*, or None when there is no policy to apply.

    Matching is case-insensitive and on label boundaries only, so `github.com` matches
    `api.github.com` and does not match `notgithub.com` or `github.com.evil.example`.
    """
    if not allowlist:
        return None
    return any(host_matches(host, entry) for entry in allowlist)


def host_matches(host: str, entry: str) -> bool:
    candidate = entry.strip().strip(".").lower()
    if not candidate:
        return False
    subject = host.lower()
    return subject == candidate or subject.endswith("." + candidate)
