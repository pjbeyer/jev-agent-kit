#!/usr/bin/env python3
"""Final driver analysis: per friction-bucket, which question asked and at what noul (read-only)."""
import json
from collections import Counter, defaultdict
from pathlib import Path
import statistics

SIDELOG = Path.home() / "Library/Application Support/jev-agent-kit/sidelog.jsonl"
RECEIPTS = Path.home() / "Library/Application Support/jev-agent-kit/receipts"
SUFFIX = "4ad3fda7ffd1bdf6b21b26296151"

rows = [json.loads(l) for l in SIDELOG.read_text().splitlines() if l.strip()]
post = [r for r in rows if (r.get("producer") or "").endswith(SUFFIX)
        and r.get("would_reason") != "config"]
asks = [r for r in post if r.get("would_outcome") == "ask"]
want_ids = {r["call_id"] for r in asks}
cmd_by_id = {r["call_id"]: r["command"] for r in asks}

found = defaultdict(dict)
for f in sorted(RECEIPTS.glob("*.jsonl"), reverse=True):
    for line in f.read_text().splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        cid = r.get("call_id")
        if cid in want_ids and r.get("question_id"):
            found[cid][r["question_id"]] = r
    if not (want_ids - set(found)):
        break


def bucket(c: str) -> str:
    h = c.split()[0]
    if h.startswith("hermes."):
        return h[7:]
    if ".venv" in c[:80] or "python" in c[:100]:
        return "venv-python"
    if c[:4] == "grep" or c[:3] == "ls ":
        return "reader-shell"
    return "other-shell"


# per bucket: which questions ask, with noul values
by_bucket = defaultdict(lambda: defaultdict(list))
for cid, qs in found.items():
    b = bucket(cmd_by_id[cid])
    for q, r in qs.items():
        if (r.get("would_route") or r.get("route")) == "ask":
            by_bucket[b][q].append(r.get("noul"))

print("ASK DRIVERS by friction bucket (noul values at ask):")
for b in sorted(by_bucket, key=lambda x: -sum(len(v) for v in by_bucket[x].values())):
    print(f"\n[{b}]")
    for q, vals in sorted(by_bucket[b].items(), key=lambda kv: -len(kv[1])):
        vals = [v for v in vals if isinstance(v, (int, float))]
        med = statistics.median(vals) if vals else None
        print(f"  {q}: {len(vals)} asks | noul median {med} | values {sorted(vals)[:6]}")

# what the asks' thresholds are vs values, for the top driver question
print("\nthresholds (from receipts):")
th = {}
for cid, qs in found.items():
    for q, r in qs.items():
        th[q] = r.get("threshold")
for q, t in th.items():
    print(f"  {q}: {t}")
