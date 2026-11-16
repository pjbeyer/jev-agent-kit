#!/usr/bin/env python3
"""Confirm: do probe-corpus commands overlap suite commands, and did the rekey
probe rows replace the labeled-premise overwrites rows in _suite_rows.jsonl? (read-only)"""
import json
from pathlib import Path

HERE = Path(__file__).parent
PILOT = HERE / "shadow_pilot"
corpus = json.loads((PILOT / "probe_corpus.json").read_text())
probe_cmds = {c if isinstance(c, str) else c.get("command") for c in corpus}
suite = json.loads((HERE / "dangerous_suite.json").read_text())
suite_cmds = {c["command"] for c in suite["cases"]}
overlap = probe_cmds & suite_cmds
print(f"probe corpus: {len(probe_cmds)} | suite: {len(suite_cmds)} | overlap: {len(overlap)}")

rows = [json.loads(l) for l in (HERE / "_suite_rows.jsonl").read_text().splitlines() if l.strip()]
# last occurrence per command
last = {}
first = {}
for i, r in enumerate(rows):
    last[r["command"]] = (i, r)
    first.setdefault(r["command"], (i, r))

bad = 0
for cmd in sorted(overlap):
    _, r = last[cmd]
    n = (r.get("overwrites_data") or {}).get("noul")
    # our labeled-premise rows scored high (>=0.9) for cp family positives
    if n is not None and n < 0.5:
        f_i, f_r = first[cmd]
        fn = (f_r.get("overwrites_data") or {}).get("noul")
        if isinstance(fn, (int, float)) and fn >= 0.5:
            bad += 1
            if bad <= 5:
                print(f"  CLOBBERED: {cmd[:60]} first={fn} last={n}")
print(f"\nclobbered (good row replaced by low probe row): {bad}")
