"""Suite-wide test isolation for anything the tests write outside tmp_path.

Two classes of leakage this conftest prevents (both observed):

1. The production side-log. The hook shims fall back to the operator's real
   ``JEV_KIT_SIDELOG_PATH`` (exported for the *production* Hermes process and
   inherited by any test run from that shell) when a test does not point the
   path somewhere else. Suite traffic then lands in the operator's audit
   corpus disguised as real decisions — exactly what corrupted the enforce-era
   forensics. Every test gets an explicit path; a test that needs the real
   environment can delete the override deliberately (monkeypatch.delenv).

2. Production receipts. ``JEV_KIT_RECEIPTS_DIR`` is likewise redirected per
   test session, so no probe receipt can ever reach the operator's receipts
   directory.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from jev_kit import sidelog

_SIDECLOG_ENV_VAR = "JEV_KIT_SIDELOG_PATH"
_RECEIPTS_ENV_VAR = "JEV_KIT_RECEIPTS_DIR"


@pytest.fixture(autouse=True)
def _isolate_local_writes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # autouse session isolation: the shim never sees the operator's paths, and
    # anything that slips through anyway is labelled `test` in the sidelog.
    monkeypatch.setenv(_SIDECLOG_ENV_VAR, str(tmp_path / "sidelog.jsonl"))
    monkeypatch.setenv(_RECEIPTS_ENV_VAR, str(tmp_path / "receipts"))
    monkeypatch.setenv(sidelog.TRAFFIC_ENV_VAR, "test")
