"""Shadow pilot: measure the kit's gate on real traffic, changing nothing.

Run:  python3 tools/calibration/shadow_pilot/run_pilot.py --corpus commands.json
      python3 tools/calibration/shadow_pilot/run_pilot.py --corpus commands.json --live --limit 250

WHY

`hook_fp/measure.py` establishes a floor: 99.4% of safe commands are parse-unconfident and can
therefore never be allowed in enforce, whatever the model answers. That floor needs no model to
measure, and it says the escalations are mostly the parse guard rather than the questions.

What it cannot say is what the QUESTIONS would do on their own, on the commands the parser did
understand. That is the number a go/no-go on enforce has to rest on, and it needs real answers.
This harness produces it and separates the two causes:

  guard escalations     the parse was unconfident, so enforce could never allow it
  question escalations  the parse was confident and a question still refused

Only the second is addressable by calibration or threshold work. If it is small, the gate's
problem is the parser and no threshold setting will help; if it is large, the questions are
miscalibrated and a threshold is the right instrument.

HOW IT OBSERVES WITHOUT CHANGING ANYTHING

Every decision runs through the real `decide_tool_call` path, with `Mode.SHADOW` passed
unconditionally and not configurable here. Shadow never changes host behaviour, which is what
makes this safe against a live agent; turning on enforce is a separate decision with its own
evidence requirements, and is deliberately not reachable from this tool.

The runner is the designed injection seam: the real one spawns the CLI child, and this harness
substitutes its own so it can both choose the transport and read back the full response, which
`HookResult` does not carry. The request body is the one the hook built, so the state assembly
under test is the shipped one.

COST

`--live` makes one model call per examined command and spends money. It is off by default.
Without it no request leaves the machine at all and the run reports the guard split only, which
is free. Use `--limit` to bound the spend.

A live run also needs an attestation (`JEV_KIT_ATTESTATION`) and an API key, and the attestation
is a compliance record: it asserts that TypeSafe is in the owner's data-flow inventory and, when
a sent field may carry personal data, that a DPA is in place. This tool will not write one.
Produce it yourself with your real status and date.

The corpus is not committed. See `hook_fp/measure.py` for why: it is this machine's real
command history, and the tools write aggregates only.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "src"))

from jev_kit.command_properties import extract_command_properties  # noqa: E402
from jev_kit.hooks.core import Mode, ToolCall, decide_tool_call  # noqa: E402

QUESTION_SET = REPO_ROOT / "skills" / "jev-runtime" / "questions" / "tool-call-gate.json"


def confident_commands(commands: list[str]) -> list[str]:
    """The subset the parser understood, which is the only subset the questions get to judge."""
    return [c for c in commands if extract_command_properties(c).parse_confident]


class Recorder:
    """A runner that records what the engine answered, and optionally makes a live call.

    With ``live=False`` it returns the unavailable envelope without touching the network, which
    exercises the harness and the fail-closed path at no cost. With ``live=True`` it sends the
    hook's own request through the same `run_json` entry point the CLI child uses, so nothing
    about the request differs from production.
    """

    def __init__(self, *, live: bool) -> None:
        self.live = live
        self.responses: list[dict[str, Any]] = []
        self._transport: Any = None

    def _build_transport(self) -> Any:
        from jev_kit.engine import _config_from_env
        from jev_kit.secrets import resolve_api_key
        from jev_kit.transport import LiveTransport

        config = _config_from_env()
        api_key = config.api_key or resolve_api_key(timeout=config.deadline_seconds)
        if api_key is None:
            raise SystemExit(
                "no API key: set TYPESAFE_API_KEY or TYPESAFE_API_KEY_COMMAND before --live"
            )
        return LiveTransport(
            api_key, base_url=config.base_url, endpoint_allowlist=config.endpoint_allowlist
        )

    def __call__(self, request: dict[str, Any]) -> dict[str, Any]:
        if not self.live:
            response = {"status": "error", "records": [], "fail_reason": "offline"}
        else:
            from jev_kit.engine import run_json

            if self._transport is None:
                self._transport = self._build_transport()
            response = run_json(request, transport=self._transport)
        self.responses.append(response)
        return response


def run(
    commands: list[str], *, live: bool, limit: int | None, skip: int = 0
) -> dict[str, Any]:
    selected = confident_commands(commands)
    total_confident = len(selected)
    # `skip` exists because the engine shares one rate budget per process (RateBudget defaults
    # to max_calls=100, and the default budget is process-wide). A corpus larger than that must
    # be walked in chunks across processes; each chunk is an honest subset rather than a run that
    # silently reports the throttled remainder as failures.
    selected = selected[skip:]
    if limit is not None:
        selected = selected[:limit]

    recorder = Recorder(live=live)
    outcomes: collections.Counter = collections.Counter()
    reasons: collections.Counter = collections.Counter()
    per_question: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    routes: collections.Counter = collections.Counter()
    # The raw probability per question, which is the calibration datum. The kit ships no
    # registry, so every question routes `no_advice` and `label` is null: the probability is
    # the only thing a run can compare against an independent label. Collecting it is the
    # point of the pilot, not the collapsed route.
    rows: list[dict[str, Any]] = []

    for command in selected:
        result = decide_tool_call(
            ToolCall(command=command),
            mode=Mode.SHADOW,
            question_set_path=str(QUESTION_SET),
            runner=recorder,
        )
        outcomes[result.outcome.value] += 1
        routes[str(result.route)] += 1
        if result.reason:
            reasons[result.reason] += 1
        # Per-question detail comes from the response the runner saw, not from HookResult, which
        # carries only the collapsed outcome.
        row: dict[str, Any] = {"command": command}
        response = recorder.responses[-1] if recorder.responses else {}
        for record in (response.get("records") or []):
            if not isinstance(record, dict):
                continue
            qid = str(record.get("question_id"))
            per_question[qid][str(record.get("label"))] += 1
            row[qid] = {
                "noul": record.get("noul"),
                "value": record.get("value"),
                "label": record.get("label"),
                "route": record.get("route"),
                "fail_reason": record.get("fail_reason"),
            }
        rows.append(row)

    return {
        "live": live,
        "corpus_size": len(commands),
        "confident_total": total_confident,
        "confident_examined": len(selected),
        "outcomes": dict(outcomes),
        "would_route": dict(routes),
        "reasons": dict(reasons.most_common()),
        "per_question_labels": {k: dict(v) for k, v in sorted(per_question.items())},
        "rows": rows,
    }


def report(result: dict[str, Any]) -> None:
    corpus = result["corpus_size"]
    confident = result["confident_total"]
    share = f"{100 * confident / corpus:.2f}%" if corpus else "n/a"
    print(f"corpus: {corpus} commands")
    print(f"parse-confident: {confident} ({share} of the corpus)")
    print("  ^ the only commands the questions judge; the rest never reach them")
    print(f"examined: {result['confident_examined']}"
          f"{'  (LIVE)' if result['live'] else '  (offline: no request left the machine)'}\n")
    print(f"outcomes:    {result['outcomes']}")
    print(f"would_route: {result['would_route']}")
    if result["reasons"]:
        print("\nreasons:")
        for reason, count in list(result["reasons"].items())[:10]:
            print(f"  {reason:<34}{count:>7}")
    if result["per_question_labels"]:
        print("\nper-question labels (what the model answered):")
        for qid, labels in result["per_question_labels"].items():
            print(f"  {qid:<20}{labels}")
    rows = result.get("rows") or []
    if rows:
        print("\nprobability spread per question (the calibration datum):")
        for qid in sorted({k for row in rows for k in row if k != "command"}):
            values = [
                row[qid]["noul"] for row in rows
                if isinstance(row.get(qid), dict) and isinstance(row[qid].get("noul"), (int, float))
            ]
            if not values:
                continue
            values.sort()
            mid = values[len(values) // 2]
            print(f"  {qid:<20} n={len(values):<5} min={values[0]:.3f} "
                  f"median={mid:.3f} max={values[-1]:.3f}")
    if not result["live"]:
        print("\nEvery outcome above is the fail-closed path, so this run says nothing about")
        print("the gate. It confirms the harness works. Add --live and an attestation for a")
        print("real answer.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Shadow pilot for the kit's gate.")
    parser.add_argument("--corpus", required=True, help="JSON list of commands")
    parser.add_argument("--live", action="store_true", help="make real model calls (costs money)")
    parser.add_argument("--limit", type=int, help="cap the number of calls")
    parser.add_argument("--skip", type=int, default=0, help="skip the first N confident commands")
    parser.add_argument("--json", help="write the aggregate result here")
    parser.add_argument("--out", help="write per-command rows (JSONL) here")
    args = parser.parse_args()

    raw = json.loads(Path(args.corpus).expanduser().read_text(encoding="utf-8"))
    commands = [r["command"] if isinstance(r, dict) else r for r in raw]
    result = run(commands, live=args.live, limit=args.limit, skip=args.skip)
    report(result)
    if args.out:
        # Per-command probabilities, kept local: this is the calibration input, and it carries
        # command text. Never committed.
        with Path(args.out).open("w", encoding="utf-8") as fh:
            for row in result.pop("rows", []):
                fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
        print(f"\nper-command rows written to {args.out}")
    else:
        result.pop("rows", None)
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"aggregate written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
