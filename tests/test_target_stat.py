"""Unit tests for target_stat.resolve_dest_exists - no network, no model."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "/Users/pjbeyer/Projects/pjbeyer/jev-agent-kit/src")
from jev_kit.target_stat import resolve_dest_exists, as_state  # noqa: E402

tmp = tempfile.mkdtemp()
existing = Path(tmp) / "report.txt"
existing.write_text("data")
existing_dir = Path(tmp) / "subdir"
existing_dir.mkdir()

CASES = [
    # (command, workdir, expected tri-state, label)
    (f"cp a.txt {existing}", None, True, "cp onto existing file"),
    (f"cp a.txt {tmp}/nonexistent-path.txt", None, False, "cp to absent dest"),
    (f"cp -f a.txt {existing}", None, True, "cp -f onto existing"),
    (f"mv src {existing}", None, True, "mv onto existing"),
    (f"cp a b {existing_dir}", None, True, "n-ary cp into existing dir"),
    (f"cp -t {existing_dir} a b", None, True, "cp -t dest option"),
    ("cp a.txt /tmp/definitely-not-here-12345/x", None, False, "absent nested dest"),
    ("ln -sf /a /etc/hosts", None, True, "ln -sf onto existing"),
    ("ln -s /a /etc/hosts", None, None, "ln WITHOUT force -> null"),
    (f"cp -i a {tmp}/not-there.txt", None, False, "two operands, absent dest -> False"),
    ("cp a --unknown-opt b", None, None, "unknown long opt -> null"),
    ("cp a b user@host:/x", None, None, "remote spec in operands -> null (dest is local a b?)"),
    ("git push origin main", None, None, "non-copy family -> null"),
    ("echo hello", None, None, "no operands -> null"),
    ("cp a 'quoted dest'", None, None, "quote chars -> null"),
    ("cp a b*", None, None, "glob -> null"),
    (f"cp a b $HOME/x", None, None, "variable -> null"),
    (f"copy-item a {existing}", None, True, "PS copy-item"),
]

fails = 0
for cmd, wd, want, label in CASES:
    got = resolve_dest_exists(cmd, wd).dest_exists
    ok = got == want
    if not ok:
        fails += 1
    print(("PASS" if ok else "FAIL"), label, "->", got, "(want", str(want) + ")")
print("wire shape:", as_state(resolve_dest_exists("cp /x /y")))
print("FAILURES:", fails)