#!/usr/bin/env python3
"""Launch one shadow-pilot probe chunk with the correct isolated env.

Usage: run_chunk.py <skip> <limit> <out-file>

Extracts ONLY lines starting with JEV_KIT_ or TYPESAFE_ from ~/.hermes/.env
(values are never printed), overrides JEV_KIT_RECEIPTS_DIR to the isolated
probe dir, sets JEV_KIT_TRAFFIC=test, then runs run_pilot.py --live as a
subprocess with that environment.
"""
import os
import subprocess
import sys
from pathlib import Path

REPO = Path("/Users/pjbeyer/Projects/pjbeyer/jev-agent-kit")
PILOT = REPO / "tools" / "calibration" / "shadow_pilot"
PROBE_RECEIPTS = Path("/Users/pjbeyer/.local/share/hermes/jev-calibration/probe-receipts")


def parse_env_line(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if "=" not in line:
        return None
    key, _, value = line.partition("=")
    key = key.strip()
    value = value.strip()
    # strip one layer of matching quotes if present
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return key, value


def build_env() -> dict:
    env = dict(os.environ)  # inherit PATH etc.
    env.pop("JEV_KIT_RECEIPTS_DIR", None)
    extracted = []
    for line in Path.home().joinpath(".hermes", ".env").read_text().splitlines():
        if line.startswith("JEV_KIT_") or line.startswith("TYPESAFE_"):
            parsed = parse_env_line(line)
            if parsed:
                env[parsed[0]] = parsed[1]
                extracted.append(parsed[0])
    # Overrides for probe isolation (task-mandated)
    env["JEV_KIT_RECEIPTS_DIR"] = str(PROBE_RECEIPTS)
    env["JEV_KIT_TRAFFIC"] = "test"
    print(f"env: extracted {len(extracted)} JEV_KIT_/TYPESAFE_ keys "
          f"(names only), receipts_dir overridden, traffic=test", file=sys.stderr)
    return env


def main() -> int:
    skip, limit, out_name = sys.argv[1], sys.argv[2], sys.argv[3]
    out_path = PILOT / out_name
    json_path = PILOT / out_name.replace("rows_", "agg_").replace(".jsonl", ".json")
    cmd = [
        str(REPO / ".venv" / "bin" / "python"),
        str(PILOT / "run_pilot.py"),
        "--corpus", str(PILOT / "probe_corpus.json"),
        "--live",
        "--skip", skip,
        "--limit", limit,
        "--out", str(out_path),
        "--json", str(json_path),
    ]
    print(f"launching chunk: skip={skip} limit={limit} out={out_name}", file=sys.stderr)
    proc = subprocess.run(cmd, env=build_env(), cwd=str(PILOT))
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
