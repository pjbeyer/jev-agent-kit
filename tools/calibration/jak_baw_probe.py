#!/usr/bin/env python3
"""jak-baw criterion 1: confident-command probe-set measurement.

Offline classification of the shadow corpus's parse-confident commands against
Hermes' NATIVE approval patterns (DANGEROUS_PATTERNS / HARDLINE), joined to the
live would-ask rehearsal already in the shadow side-log. The novel-hazard band =
parse-confident + NOT native-flagged + gate would-ask — the calls where the
jev-gate plugin (not native approvals) is the only thing asking.

Local-only: the corpus carries real command text; results printed as aggregates
plus command basenames, never full command lines with paths.

Usage: jak_baw_probe.py [--since 2026-11-08]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path.home() / ".hermes" / "hermes-agent"))

SIDELOG = Path.home() / "Library/Application Support/jev-agent-kit/sidelog.jsonl"


def load_native_patterns() -> tuple[list, list]:
    from tools.approval_detection import (  # type: ignore
        DANGEROUS_PATTERNS_COMPILED,
        HARDLINE_PATTERNS,
    )

    # DANGEROUS_PATTERNS_COMPILED is already [(compiled_pattern, description)];
    # HARDLINE_PATTERNS is [(raw_pattern, description)].
    compiled = [p for p, _ in DANGEROUS_PATTERNS_COMPILED]
    hardline = [re.compile(p, re.IGNORECASE) for p, _ in HARDLINE_PATTERNS]
    return compiled, hardline


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", default="2026-11-08")
    ap.add_argument("--top", type=int, default=15)
    args = ap.parse_args()

    compiled, hardline = load_native_patterns()

    rows = [json.loads(l) for l in SIDELOG.read_text().splitlines() if l.strip()]
    win = [r for r in rows if r["ts"] >= args.since]
    confident = [r for r in win if (r.get("cmd_facts") or {}).get("cmd_parse_confident") is True]

    # Distinct commands, keeping the latest rehearsal per command.
    latest: dict[str, dict] = {}
    for r in confident:
        latest[r["command"]] = r

    flagged_native = 0
    novel_ask: list[dict] = []
    novel_allow: list[dict] = []
    for cmd, r in latest.items():
        native_hit = any(p.search(cmd) for p in compiled) or any(
            p.search(cmd) for p in hardline
        )
        if native_hit:
            flagged_native += 1
            continue
        (novel_ask if r.get("would_outcome") == "ask" else novel_allow).append(r)

    total = len(latest)
    print(f"since {args.since}: parse-confident distinct commands: {total}")
    print(f"  native-flagged (DANGEROUS_PATTERNS/HARDLINE): {flagged_native}")
    print(f"  NOT native-flagged: {total - flagged_native}")
    print(f"    would-ask (NOVEL-HAZARD BAND): {len(novel_ask)}"
          f" ({100 * len(novel_ask) / max(1, total - flagged_native):.1f}% of unflagged)")
    print(f"    would-allow: {len(novel_allow)}")

    # Novel-band asks by head word + reason (basenames only, no paths).
    print("\nnovel-band asks by command head:")
    heads = Counter(c["command"].split()[0] for c in novel_ask)
    for head, n in heads.most_common(args.top):
        print(f"  {n:4d}  {head}")
    print("\nnovel-band asks by would_reason:")
    for reason, n in Counter(
        (r.get("would_reason") or "engine-calibrated") for r in novel_ask
    ).most_common(args.top):
        print(f"  {n:4d}  {reason}")

    # 95% CI (rule of three / Wilson) on the novel-band ask rate.
    import math

    n = total - flagged_native
    k = len(novel_ask)
    if n:
        p = k / n
        z = 1.96
        denom = 1 + z * z / n
        centre = (p + z * z / (2 * n)) / denom
        half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
        print(f"\nnovel-band ask rate: {p:.3f}  (95% CI {max(0, centre - half):.3f}–{min(1, centre + half):.3f}, n={n})")

    out = REPO / "tools/calibration/_jak_baw_novel_band.json"
    out.write_text(json.dumps(
        {
            "since": args.since,
            "distinct_confident": total,
            "flagged_native": flagged_native,
            "novel_band_asks": len(novel_ask),
            "novel_band_allows": len(novel_allow),
            "ask_heads": dict(heads.most_common(50)),
        },
        indent=1,
    ))
    print(f"aggregate written: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
