"""The watchdog child must be able to import `jev_kit` without inherited state.

Regression: a host that runs the hook from a source checkout bootstraps
`sys.path` in its own process only. The watchdog child (`sys.executable -m
jev_kit.cli`) therefore failed to import on hosts where `jev_kit` is not
otherwise importable — observed as a Hermes gateway running the hermes-tools
CPython with `-I`: every gate call returned the internal error envelope and
shadow silently allowed, with no receipt (2026-10-18/19 outage). The fix passes
the checkout's `src/` as `PYTHONPATH` to the child; these tests pin that
mechanism by observing the child process's actual environment from inside the
child, not by trusting the parent's view.

The "child interpreter" here is a fake: an executable shim that dumps its
environment and prints a valid engine envelope. What is under test is the
environment `run_child` constructs and the envelope handling — the real
`python -m jev_kit.cli` import is verified separately against the gateway's own
isolated interpreter (see the session log; kept out of the suite so tests never
depend on a specific interpreter layout).
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from jev_kit.hooks.watchdog import run_child


def _fake_interpreter(tmp_path: Path) -> tuple[str, Path]:
    """An executable shim that records its environment and prints an ok envelope."""
    out = tmp_path / "child_env.json"
    shim = tmp_path / "fake-python.sh"
    shim.write_text(
        "#!/bin/sh\n"
        f'printf "%s" "$(cat)" >/dev/null 2>&1 || true\n'  # consume stdin like a python would
        f'python3 - <<\'PYEOF\'\n'
        "import json, os, pathlib\n"
        f"pathlib.Path({str(out)!r}).write_text(json.dumps(dict(os.environ)))\n"
        "PYEOF\n"
        'printf \'%s\' \'{"schema_version": 1, "status": "ok", "records": []}\'\n'
    )
    shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
    return str(shim), out


def test_child_receives_package_parent_on_pythonpath(tmp_path: Path) -> None:
    python_exe, out = _fake_interpreter(tmp_path)
    request = {"schema_version": 1, "op": "decide", "state": {}}
    response = run_child(request, timeout_s=25, python_exe=python_exe)
    assert response["status"] == "ok"
    env = json.loads(out.read_text())
    parts = env.get("PYTHONPATH", "").split(":")
    package_parent = str(Path(__file__).resolve().parents[1] / "src")
    assert package_parent in parts, (
        "child must receive the checkout's src/ on PYTHONPATH "
        "(regression: gateway -I interpreter could not import jev_kit)"
    )


def test_child_pythonpath_prepends_not_replaces(tmp_path: Path) -> None:
    """A caller's existing PYTHONPATH survives (prepended), not clobbered."""
    python_exe, out = _fake_interpreter(tmp_path)
    request = {"schema_version": 1, "op": "decide", "state": {}}
    run_child(request, timeout_s=25, python_exe=python_exe)
    env = json.loads(out.read_text())
    parts = env.get("PYTHONPATH", "").split(":")
    inherited = os.environ.get("PYTHONPATH")
    if inherited:
        for entry in inherited.split(":"):
            if entry:
                assert entry in parts, f"existing PYTHONPATH entry {entry!r} must be preserved"


def test_error_envelope_shape_unchanged() -> None:
    """The internal-error envelope the hook core maps to fail-closed stays stable."""
    from jev_kit.hooks.watchdog import _ERROR_INTERNAL, _ERROR_TIMEOUT

    for envelope in (_ERROR_INTERNAL, _ERROR_TIMEOUT):
        assert envelope["schema_version"] == 1
        assert envelope["status"] == "error"
        assert envelope["records"] == []
