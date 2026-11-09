"""End-to-end integration tests for payload-aware execute_code (jak-47d).

Exercises the REAL decide path from the shim down: tool-call extraction ->
payload analysis -> pseudo-command emission -> property parsing -> core
routing with an injected fake runner (the same contract as
test_hooks_shim_hermes.py; no engine, no network, no registry). The red
battery for the analyzer itself is tests/test_code_payload.py; these prove
the wiring and the acceptances:

- benign cells: the shim emits a payload-proven pseudo-command, the parser
  marks it confident with no hazard facts, and the core's local fast path
  allows it without any runner call;
- dangerous cells: the shim keeps the opaque head, the parser keeps
  runs_unseen_code, and the call still asks (LOOSENED guard: none may allow);
- the mutation check proves the analysis branch is live: neutering it must
  revert benign cells to the opaque (ask) shape.

(eval_injection note: the eval() strings below are DATA in test payloads,
never executed — the analyzer under test must reject them, which is the
assertion.)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from jev_kit import code_payload
from jev_kit.hooks import hermes as H
from jev_kit.types import Mode

QS = str(
    Path(__file__).resolve().parents[1]
    / "skills"
    / "jev-runtime"
    / "questions"
    / "triage-v10.json"
)


class _FakeCtx:
    def __init__(self) -> None:
        self.hooks: dict[str, Any] = {}

    def register_hook(self, event: str, callback: Any) -> None:
        self.hooks[event] = callback


def ok(records: list[dict[str, Any]]) -> Any:
    return lambda req: {"schema_version": 1, "status": "ok", "records": records}


def ask_runner() -> Any:
    return ok([{"route": "ask", "fail_reason": "uncalibrated", "is_mock": False}])


def accept_runner() -> Any:
    return ok(
        [{"route": "accept", "label": "no", "allow_labels": ["no"], "is_mock": False}]
    )


def _pseudo(code: str) -> str | None:
    """The pseudo-command the shim emits for this payload (None = bare head)."""
    call = H._extract_tool_call({"tool_name": "execute_code", "args": {"code": code}})
    assert call is not None
    return H._nonshell_pseudo_command("execute_code", {"code": code})


def _decide(code: str, mode: Mode = Mode.ENFORCE, runner: Any = None) -> Any:
    return H.pre_tool_call(
        _FakeCtx(),
        {"tool_name": "execute_code", "args": {"code": code}, "task_id": "interactive"},
        mode=mode,
        question_set_path=QS,
        runner=runner if runner is not None else ask_runner(),
    )


# ---------------------------------------------------------------------------
# Wiring: shim -> pseudo-command -> parser
# ---------------------------------------------------------------------------

def test_benign_arithmetic_emits_clean_form() -> None:
    pseudo = _pseudo("x = sum(i*i for i in range(10))\nprint(x)")
    assert pseudo == "hermes.execute_code _clean"


def test_benign_analysis_cell_emits_clean_form() -> None:
    code = (
        "import json\n"
        "rows = [json.loads(l) for l in open('/tmp/x.jsonl')]\n"
        "print(len(rows))"
    )
    assert _pseudo(code) == "hermes.execute_code _clean"


def test_benign_glob_cell_emits_clean_form() -> None:
    code = "import glob\nfor f in glob.glob('/tmp/*.log'):\n    print(f)"
    assert _pseudo(code) == "hermes.execute_code _clean"


def test_benign_child_command_emits_children() -> None:
    code = 'import subprocess\nsubprocess.run(["ls", "-la"])'
    pseudo = _pseudo(code)
    assert pseudo is not None
    assert pseudo.startswith("hermes.execute_code ")
    assert "ls -la" in pseudo
    assert ";;" not in pseudo  # single child, no separator


def test_benign_child_with_path_facts_emits_children() -> None:
    # Regression (found by the live probe): children touching /tmp carry TRUE
    # location facts (targets_absolute_path, targets_regenerable_path) —
    # those are not hazards. Only hazard facts (recursive_delete, ...) may
    # bounce the clean form.
    code = 'import subprocess\nsubprocess.run(["wc", "-l", "/tmp/rows.jsonl"])'
    pseudo = _pseudo(code)
    assert pseudo is not None
    assert "/tmp/rows.jsonl" in pseudo


def test_multi_child_payload_joins_with_separator() -> None:
    code = (
        'import subprocess\n'
        'subprocess.run(["ls", "-la"])\n'
        'subprocess.run(["wc", "-l", "/tmp/rows.jsonl"])'
    )
    pseudo = _pseudo(code)
    assert pseudo is not None
    assert " ;; " in pseudo
    assert "ls -la" in pseudo and "wc -l /tmp/rows.jsonl" in pseudo


def test_dangerous_dynamic_argv_keeps_opaque_head() -> None:
    code = "cmd = 'rm -rf /data'\nsubprocess.run(cmd.split())"
    assert _pseudo(code) == "hermes.execute_code"


def test_dangerous_eval_keeps_opaque_head() -> None:
    assert _pseudo("eval('1+1')") == "hermes.execute_code"


def test_dangerous_literal_rm_child_keeps_opaque_head() -> None:
    # The child extracts fine, but the parser judges it a hazard: the shim
    # refuses the clean form and the call keeps runs_unseen_code.
    code = 'import subprocess\nsubprocess.run(["rm", "-rf", "/data"])'
    assert _pseudo(code) == "hermes.execute_code"


def test_unknown_import_keeps_opaque_head() -> None:
    assert _pseudo("import ctypes\nprint(1)") == "hermes.execute_code"


def test_parser_confident_on_clean_form() -> None:
    from jev_kit.command_properties import extract_command_properties

    props = extract_command_properties("hermes.execute_code _clean")
    assert props.parse_confident, f"reason={props.reason}"
    assert not any(v is True for v in props.values.values())


def test_parser_judges_children_in_joined_form() -> None:
    from jev_kit.command_properties import extract_command_properties

    props = extract_command_properties("hermes.execute_code ls -la")
    assert props.parse_confident, f"reason={props.reason}"
    assert not any(v is True for v in props.values.values())


# ---------------------------------------------------------------------------
# Routing: core verdicts with an injected runner
# ---------------------------------------------------------------------------

def test_benign_arithmetic_routes_allow() -> None:
    # A proven-clean cell with no children routes to the judged path (the
    # local fast path only fires on reducer-refused syntax); the runner's
    # verdict is the decision, so a model accept must surface as allow.
    res = _decide(
        "x = sum(i*i for i in range(10))\nprint(x)", runner=accept_runner()
    )
    assert res is None, "benign cell did not allow"


def test_benign_analysis_cell_routes_allow() -> None:
    code = (
        "import json\n"
        "rows = [json.loads(l) for l in open('/tmp/x.jsonl')]\n"
        "print(len(rows))"
    )
    assert _decide(code, runner=accept_runner()) is None


def test_benign_child_command_routes_allow() -> None:
    code = 'import subprocess\nsubprocess.run(["ls", "-la"])'
    assert _decide(code, runner=accept_runner()) is None


def test_dangerous_dynamic_argv_still_asks() -> None:
    res = _decide("cmd = 'rm -rf /data'\nsubprocess.run(cmd.split())")
    assert res is not None and res.get("action") in ("approve", "block"), (
        "LOOSENED: dynamic-argv payload did not ask"
    )


def test_dangerous_eval_still_asks() -> None:
    res = _decide("eval('1+1')")
    assert res is not None and res.get("action") in ("approve", "block"), (
        "LOOSENED: eval payload did not ask"
    )


def test_dangerous_literal_rm_child_still_asks() -> None:
    res = _decide('import subprocess\nsubprocess.run(["rm", "-rf", "/data"])')
    assert res is not None and res.get("action") in ("approve", "block"), (
        "LOOSENED: literal rm child did not ask"
    )


def test_unknown_import_still_asks() -> None:
    res = _decide("import ctypes\nprint(1)")
    assert res is not None and res.get("action") in ("approve", "block"), (
        "LOOSENED: unknown import did not ask"
    )


def test_shadow_never_blocks_dangerous() -> None:
    res = _decide(
        "cmd = 'rm -rf /data'\nsubprocess.run(cmd.split())", mode=Mode.SHADOW
    )
    assert res is None, "shadow mode must never block"


# ---------------------------------------------------------------------------
# Mutation check: the analysis branch is live
# ---------------------------------------------------------------------------

def test_mutation_neutered_analysis_reverts_to_opaque(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The live-branch proof: neuter analyze_code_payload to always-opaque and
    the benign cell must revert to the opaque head (and thus the ask path).
    Proves the branch is load-bearing, not dead code on an always-ask path."""

    def neutered(code: str) -> Any:
        return False, [], "mutation"

    monkeypatch.setattr(code_payload, "analyze_code_payload", neutered)
    pseudo = _pseudo("x = sum(i*i for i in range(10))\nprint(x)")
    assert pseudo == "hermes.execute_code", (
        "neutered branch still emitted the clean form — mutation not live"
    )