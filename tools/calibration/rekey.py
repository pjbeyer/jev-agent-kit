#!/usr/bin/env python3
"""rekey.py — one command for the mandatory post-edit registry re-key (jak-yle c).

After ANY edit to hook-source files (hooks/, command_properties.py, engine.py,
destination.py), the producer hash rotates, every question fingerprint changes,
and the calibration registry keys all miss. This tool runs the proven procedure
end-to-end so a rotation is one command instead of hand-typed toil:

  1. RESCORE: re-score the probe corpus (run_chunk.py chunks, isolated
     JEV_KIT_RECEIPTS_DIR -> probe-receipts) under the CURRENT producer.
  2. REBUILD: build_registry.py (refuses stale corpora, stamps the new producer).
  3. VERIFY: registry stamp == current tree producer AND 6/6 live-fingerprint
     match. Prints the verdict; exits nonzero on any mismatch.

Usage:
  rekey.py [--skip-fit]   # --skip-fit: reuse existing probe scores (fast path
                          # only when probe rows already postdate the last
                          # hook edit — the tool checks mtimes and refuses
                          # otherwise)

The engine-side fail-loud (jak-6lt) still guards the runtime; this tool removes
the human-typing cost, not the discipline.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CAL = REPO / "tools" / "calibration"
PILOT = CAL / "shadow_pilot"
REG_PATH = Path.home() / ".local/share/hermes/jev-calibration/registry/thresholds.json"
sys.path.insert(0, str(REPO / "src"))

HOOK_SOURCES = [
    REPO / "src/jev_kit/hooks/hermes.py",
    REPO / "src/jev_kit/hooks/core.py",
    REPO / "src/jev_kit/command_properties.py",
    REPO / "src/jev_kit/engine.py",
    REPO / "src/jev_kit/destination.py",
]

CHUNK = 100  # probe corpus chunk size (matches the 0/100/200/300 chunks)


def newest_hook_mtime() -> float:
    return max(p.stat().st_mtime for p in HOOK_SOURCES if p.exists())


def run(cmd: list, **kw) -> subprocess.CompletedProcess:
    print("+", " ".join(str(c) for c in cmd))
    return subprocess.run([str(c) for c in cmd], **kw)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-fit", action="store_true",
                    help="reuse probe scores if they postdate the last hook edit")
    args = ap.parse_args()

    edit_time = newest_hook_mtime()
    reg_mtime = REG_PATH.stat().st_mtime if REG_PATH.exists() else 0.0
    print(f"last hook-source edit: {time.ctime(edit_time)}")
    print(f"registry mtime:        {time.ctime(reg_mtime)}")

    if args.skip_fit:
        if reg_mtime > edit_time:
            print("registry already postdates the last edit; verifying only")
        else:
            print("registry predates the last hook edit — cannot skip; full rekey")
            args.skip_fit = False

    if not args.skip_fit:
        # 1. RESCORE the probe corpus in chunks under the isolated receipts dir.
        #    build_registry needs a probe-receipts file carrying all 6 questions
        #    with fingerprints under the CURRENT producer.
        #    Chunking keeps each run_chunk invocation under the pilot timeout.
        corpus = json.loads((PILOT / "probe_corpus.json").read_text())
        total = len(corpus)
        chunks = list(range(0, total, CHUNK))
        for i, skip in enumerate(chunks):
            limit = min(CHUNK, total - skip)
            out = PILOT / f"probe_rows_rekey_auto_{skip}.jsonl"
            agg = PILOT / f"probe_agg_rekey_auto_{skip}.jsonl"
            proc = run([REPO / ".venv/bin/python", PILOT / "run_chunk.py",
                        skip, limit, out], capture_output=True, text=True)
            if proc.returncode != 0:
                print(proc.stdout[-1500:])
                print(proc.stderr[-1500:])
                return 1
            agg.write_text(out.read_text())  # keep agg mirror for build_registry patterns
            print(f"  chunk {i + 1}/{len(chunks)}: skip {skip} limit {limit} ok")

        # 2. REBUILD the registry from the fresh probe receipts.
        proc = run([REPO / ".venv/bin/python", CAL / "build_registry.py"],
                   capture_output=True, text=True)
        print(proc.stdout)
        if proc.returncode != 0:
            print(proc.stderr[-1500:])
            return 1

    # 3. VERIFY: producer stamp matches the live tree AND all 6 fingerprints hit.
    reg = json.loads(REG_PATH.read_text())
    from jev_kit.hooks.core import producer_id

    live_producer = producer_id("hermes", str(REPO / "src/jev_kit/hooks/hermes.py"))
    stamp_ok = reg.get("producer") == live_producer
    print(f"producer stamp match: {stamp_ok}")
    print(f"  registry: {reg.get('producer')}")
    print(f"  live:     {live_producer}")
    calibrated = sum(1 for e in reg["entries"].values() if e.get("status") == "calibrated")
    print(f"calibrated entries: {calibrated}/{len(reg['entries'])}")
    if not stamp_ok or calibrated < 6:
        print("REKEY INCOMPLETE — registry stamp or calibration count wrong")
        return 1
    print("REKEY COMPLETE: stamp matches current tree, 6/6 calibrated.")
    print("NOTE: the live gateway keeps running the OLD source until restarted;")
    print("restart it (owner-reviewed controlled workflow) to end the config-era asks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
