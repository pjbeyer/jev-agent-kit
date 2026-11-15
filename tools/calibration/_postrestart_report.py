#!/usr/bin/env python3
"""Post-restart clean ask-rate report (jak-7c9 final checklist item).

Reads the live side-log, isolates rows on the CURRENT producer stamp,
excludes the mid-rekey `config` transient, and reports:
  - overall and distinct-command ask rates
  - ask breakdown by head bucket
  - reader-class dispatch behavior (the refit's target class)
Pure read-only analysis; prints only.
"""
import json
from collections import Counter
from pathlib import Path

SIDELOG = Path.home() / "Library/Application Support/jev-agent-kit/sidelog.jsonl"
PRODUCER_SUFFIX = "4ad3fda7ffd1bdf6b21b26296151"
READER_TOOLS = ("read_file", "skill_view", "skills_list", "tool_search",
                "tool_describe", "session_search", "search_files",
                "vision_analyze", "clarify")

rows = [json.loads(l) for l in SIDELOG.read_text().splitlines() if l.strip()]
post = [r for r in rows if (r.get("producer") or "").endswith(PRODUCER_SUFFIX)]
clean = [r for r in post if r.get("would_reason") != "config"]

print(f"rows on producer {PRODUCER_SUFFIX[:12]}: {len(post)} "
      f"({len(post)-len(clean)} config-transient excluded)")
print(f"clean-window rows: {len(clean)}")
out = Counter(r.get("would_outcome") for r in clean)
print(f"outcomes: {dict(out)}")
asks = [r for r in clean if r.get("would_outcome") == "allow" and False]  # placeholder
asks = [r for r in clean if r.get("would_outcome") == "ask"]
print(f"row ask-rate: {100*len(asks)/len(clean):.1f}%")

cmds = {r["command"] for r in clean}
ask_cmds = {r["command"] for r in asks}
print(f"distinct commands: {len(cmds)} | distinct asks: {len(ask_cmds)} "
      f"({100*len(ask_cmds)/len(cmds):.1f}%)")


def bucket(c: str) -> str:
    head = c.split()[0]
    if head.startswith("hermes."):
        return head.split(".", 1)[1]
    return "shell"


print("\nask buckets (distinct commands):", Counter(bucket(c) for c in ask_cmds).most_common())

rd = [r for r in clean if r["command"].split()[0].startswith("hermes.")
      and r["command"].split()[0][7:].split()[0] in READER_TOOLS]
print(f"\nreader-class rows: {len(rd)} {dict(Counter(r.get('would_outcome') for r in rd))}")
for r in [x for x in rd if x.get("would_outcome") == "ask"][:5]:
    print("  ASK", r["ts"][11:19], r["command"][:60], "|", r.get("would_reason"))

mcp = [r for r in clean if r["command"].startswith("hermes.mcp_call_tool")]
tc = [r for r in clean if r["command"].startswith("hermes.tool_call")]
print(f"\nmcp_call_tool rows: {len(mcp)} {dict(Counter(r.get('would_outcome') for r in mcp))}")
print(f"tool_call rows:     {len(tc)} {dict(Counter(r.get('would_outcome') for r in tc))}")
