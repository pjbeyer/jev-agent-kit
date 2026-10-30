"""Tests for the decision side-log (opt-in command/decision join key).

The receipts deliberately carry no command text (egress discipline), so a shadow
corpus cannot be re-labeled offline. The side-log restores that capability as a
LOCAL-ONLY, OPT-IN record: when `JEV_KIT_SIDELOG_PATH` is unset or `off`,
nothing is written and behavior is unchanged; when set to a path, one JSONL line
per judged call records the command text and facts alongside the `call_id` that
receipts already carry.
"""

from __future__ import annotations

import json
from pathlib import Path

from jev_kit.hooks.core import HookResult, ToolCall, decide_tool_call, producer_id
from jev_kit.types import Mode

SHIM = Path(__file__).resolve().parents[1] / "src" / "jev_kit" / "hooks" / "hermes.py"
QSET = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "jev-runtime"
    / "questions"
    / "tool-call-gate.json"
)


def _run_failing_runner_call() -> HookResult:
    """One real decision under a raising runner; returns the HookResult."""
    return decide_tool_call(
        ToolCall(command="echo hello", target=None, context="sidelog-test"),
        mode=Mode.SHADOW,
        question_set_path=str(QSET),
        producer=producer_id("hermes", str(SHIM)),
        runner=lambda request: (_ for _ in ()).throw(RuntimeError("runner down")),
    )


def _read(path: Path | None) -> list[dict]:
    if path is None or not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_default_off_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("JEV_KIT_SIDELOG_PATH", raising=False)
    side = tmp_path / "sidelog.jsonl"
    # The resolver contract is part of the default-off guarantee: with the env
    # unset it must resolve to None, not to some fallback path. (A mutation
    # returning a hardcoded default would otherwise escape this fixture.)
    from jev_kit import sidelog

    assert sidelog.path_from_env() is None
    result = _run_failing_runner_call()
    assert result.outcome is not None
    assert _read(side) == []


def test_opt_in_writes_join_record(tmp_path, monkeypatch):
    side = tmp_path / "sidelog.jsonl"
    monkeypatch.setenv("JEV_KIT_SIDELOG_PATH", str(side))

    # A succeeding runner returning a real envelope with call_ids, so the
    # positive control proves the join key lands when the engine supplied one.
    def runner(request):
        return {"schema_version": 1, "status": "ok", "records": [
            {"question_id": q, "route": "no_advice", "noul": 0.05, "call_id": f"act_{q}"}
            for q in ("destructive", "exfiltrates", "widens_permission")
        ]}

    result = decide_tool_call(
        ToolCall(command="echo hello", target=None, context="sidelog-test"),
        mode=Mode.SHADOW, question_set_path=str(QSET),
        producer=producer_id("hermes", str(SHIM)), runner=runner,
    )
    assert result.outcome is not None
    lines = _read(side)
    assert len(lines) == 1
    rec = lines[0]
    # The join key receipts carry, from the engine's response.
    assert rec["call_id"].startswith("act_")
    # The judged input, so calibration history is replayable.
    assert rec["command"] == "echo hello"
    assert rec["context"] == "sidelog-test"
    # The decision metadata.
    assert rec["mode"] == "shadow"
    assert rec["outcome"] == result.outcome.value
    assert rec["reason"] == result.reason
    # The computed facts, exactly what the state carried.
    assert isinstance(rec["cmd_facts"], dict)
    assert "dest_known" in rec["dest_facts"]


def test_runner_failure_still_records_without_call_id(tmp_path, monkeypatch):
    # A runner that dies before a response exists: no call_id can be known,
    # but the judged input is still written down (a timeout or crash on the
    # engine path is exactly the case calibration needs visibility into).
    side = tmp_path / "sidelog.jsonl"
    monkeypatch.setenv("JEV_KIT_SIDELOG_PATH", str(side))
    result = _run_failing_runner_call()
    assert result.outcome is not None
    lines = _read(side)
    assert len(lines) == 1
    rec = lines[0]
    assert rec["command"] == "echo hello"
    assert rec["call_id"] == ""
    assert rec["outcome"] == "ask"


def test_record_never_raises_and_never_breaks_turn(tmp_path, monkeypatch):
    # An unwritable side-log location must not break the decision. The record
    # creates parent directories by design (same as the unattended audit log),
    # so the assertion is that the turn completed, not that the file is absent.
    side = tmp_path / "no-such-dir" / "sidelog.jsonl"
    monkeypatch.setenv("JEV_KIT_SIDELOG_PATH", str(side))
    result = _run_failing_runner_call()
    assert result.outcome is not None
    assert side.exists()


def test_parser_accepts_explicit_off(tmp_path, monkeypatch):
    from jev_kit import sidelog

    monkeypatch.setenv("JEV_KIT_SIDELOG_PATH", "off")
    assert sidelog.path_from_env() is None
    monkeypatch.setenv("JEV_KIT_SIDELOG_PATH", "")
    assert sidelog.path_from_env() is None
    monkeypatch.delenv("JEV_KIT_SIDELOG_PATH")
    assert sidelog.path_from_env() is None
    target = tmp_path / "log.jsonl"
    monkeypatch.setenv("JEV_KIT_SIDELOG_PATH", str(target))
    assert sidelog.path_from_env() == target.expanduser()

def test_traffic_label_defaults_to_real(tmp_path, monkeypatch):
    """Without the env var a record is labelled real production traffic."""
    from jev_kit import sidelog

    monkeypatch.delenv(sidelog.TRAFFIC_ENV_VAR, raising=False)
    assert sidelog.traffic_from_env() == "real"

    side = tmp_path / "sidelog.jsonl"
    monkeypatch.setenv("JEV_KIT_SIDELOG_PATH", str(side))
    result = _run_failing_runner_call()
    assert result.outcome is not None
    lines = _read(side)
    assert lines
    assert all(rec.get("traffic") == "real" for rec in lines)


def test_traffic_labelled_test_when_env_set(tmp_path, monkeypatch):
    """Test/corpus processes label their rows, keeping leakage greppable."""
    from jev_kit import sidelog

    monkeypatch.setenv(sidelog.TRAFFIC_ENV_VAR, "test")
    assert sidelog.traffic_from_env() == "test"

    side = tmp_path / "sidelog.jsonl"
    monkeypatch.setenv("JEV_KIT_SIDELOG_PATH", str(side))
    result = _run_failing_runner_call()
    assert result.outcome is not None
    lines = _read(side)
    assert lines
    assert all(rec.get("traffic") == "test" for rec in lines)
