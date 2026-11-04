"""Confident-command probe set: build + native-pattern classification (jak-baw).

Offline stage. No model calls, no network. Produces the probe corpus the live
scoring stage (run_pilot.py --live) consumes:

  probes_confident.json   [{"command": str, "label": kit-detector label,
                            "native_flagged": bool, "native_reason": str}]

Method (per jak-baw):
- Commands come from this machine's real history via the kit's own builder
  (hook_fp/measure.py commands_from_session_store) — never committed; the
  corpus carries real paths (local-only discipline, see measure.py).
- Keep distinct commands whose jev_kit parse is CONFIDENT — the only
  population the calibrated questions can judge in enforce.
- Classify each against NATIVE Hermes patterns (approval_detection:
  DANGEROUS_PATTERNS 110 / HARDLINE 12) offline — no Hermes runtime needed.
- Also classify with the kit's deterministic detector (measure.label) so the
  novel-hazard band can later be split into: kit-yes + native-unflagged
  (the plugin's unique coverage) vs kit-yes + native-flagged (double coverage).

Usage: python3 tools/calibration/shadow_pilot/build_probes.py [--out DIR]
Self-test: --self-test (pure logic, no DB, no network).
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "src"))

HERMES_SRC = Path(os.environ.get("HERMES_SRC", Path.home() / ".hermes" / "hermes-agent"))

DEFAULT_DB = Path.home() / ".hermes" / "state.db"
# Probe budget: distinct confident commands to live-score. Rule-of-three target
# is 150 distinct for a >=2% novel-hazard bound; we take more to survive
# transport failures and allow per-question coverage.
PROBE_LIMIT = 400


def build_probe_set(db: Path, limit: int = PROBE_LIMIT) -> list[dict]:
    from jev_kit.command_properties import extract_command_properties

    sys.path.insert(0, str(HERMES_SRC))
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "measure", REPO_ROOT / "tools" / "calibration" / "hook_fp" / "measure.py"
    )
    assert spec is not None and spec.loader is not None
    measure = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(measure)

    import tools.approval_detection as ad  # native Hermes patterns

    out: list[dict] = []
    seen: set[str] = set()
    for cmd in measure.commands_from_session_store(str(db)):
        if cmd in seen:
            continue
        seen.add(cmd)
        if not extract_command_properties(cmd).parse_confident:
            continue
        danger, danger_reason, _ = ad.detect_dangerous_command(cmd)
        hardline, hardline_reason = ad.detect_hardline_command(cmd)
        out.append(
            {
                "command": cmd,
                "label": measure.label(cmd),
                "native_flagged": bool(danger or hardline),
                "native_reason": danger_reason or hardline_reason,
            }
        )
        if len(out) >= limit:
            break
    return out


def _self_test() -> int:
    # Pure-logic checks: classification semantics on synthetic commands.
    sys.path.insert(0, str(HERMES_SRC))
    import tools.approval_detection as ad

    checks = [
        ("rm -rf /", True),          # hardline
        ("rm -rf ./build", True),     # dangerous pattern
        ("ls -la /tmp", False),
        ("git push --force origin main", True),
    ]
    failed = 0
    for cmd, expect in checks:
        d, _, _ = ad.detect_dangerous_command(cmd)
        h, _ = ad.detect_hardline_command(cmd)
        got = bool(d or h)
        if got != expect:
            print(f"SELF-TEST FAIL: {cmd!r} native_flagged={got} expected {expect}")
            failed += 1
    # probe shape sanity
    probe = {"command": "ls", "label": "safe", "native_flagged": False, "native_reason": None}
    if set(probe) != {"command", "label", "native_flagged", "native_reason"}:
        print("SELF-TEST FAIL: probe shape")
        failed += 1
    print("self-test: ok" if not failed else f"self-test: {failed} failures")
    return 0 if not failed else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=str(DEFAULT_DB))
    ap.add_argument("--out", default=str(Path(__file__).parent), help="output dir")
    ap.add_argument("--limit", type=int, default=PROBE_LIMIT)
    args = ap.parse_args()
    probes = build_probe_set(Path(args.db), args.limit)
    out_path = Path(args.out) / "probes_confident.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(probes, fh, indent=1)
    stats = collections.Counter(
        (p["label"], "native_flagged" if p["native_flagged"] else "native_clean") for p in probes
    )
    print(f"probes: {len(probes)} -> {out_path}")
    for k, v in sorted(stats.items()):
        print(f"  {k[0]:12s} {k[1]}: {v}")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv or "--test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())