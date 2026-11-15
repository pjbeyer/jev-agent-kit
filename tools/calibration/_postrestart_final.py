#!/usr/bin/env python3
"""Final checklist numbers: distinct-command ask rate with Wilson CI (read-only)."""
import json
import math
from collections import Counter
from pathlib import Path

SIDELOG = Path.home() / "Library/Application Support/jev-agent-kit/sidelog.jsonl"
SUFFIX = "4ad3fda7ffd1bdf6b21b26296151"

rows = [json.loads(l) for l in SIDELOG.read_text().splitlines() if l.strip()]
post = [r for r in rows if (r.get("producer") or "").endswith(SUFFIX)
        and r.get("would_reason") != "config"]

cmds = {r["command"] for r in post}
askc = {r["command"] for r in post if r.get("would_outcome") == "ask"}
n, k = len(cmds), len(askc)
p = k / n
z = 1.96
lo = p - z * math.sqrt(p * (1 - p) / n)
hi = p + z * math.sqrt(p * (1 - p) / n)
print(f"distinct: {n}, ask: {k} -> {100*p:.1f}% CI [{100*lo:.1f}%, {100*hi:.1f}%]")


def bucket(c: str) -> str:
    h = c.split()[0]
    if h.startswith("hermes."):
        return h[7:]
    if ".venv" in c[:80] or "python" in c[:100]:
        return "venv-python"
    if c[:4] == "grep" or c[:3] == "ls ":
        return "reader-shell"
    return "other-shell"


b = Counter(bucket(c) for c in askc)
print("ask buckets:", b.most_common())

destructive = [c for c in askc if "rm " in c or "rmtree" in c]
print("genuinely-destructive asks (rm-family):", len(destructive))
for c in destructive:
    print("   ", c[:90])
