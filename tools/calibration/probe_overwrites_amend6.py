#!/usr/bin/env python3
"""Probe: what does the parser do with candidate overwrites shapes?

Goal: decide between (a) modeled-program amendment (dd of=, truncate, tee,
cp --force variants) and (b) a destination fact. Dump full facts for each
candidate so we can see what exists and what's missing.
"""
import sys

sys.path.insert(0, "/Users/pjbeyer/Projects/pjbeyer/jev-agent-kit/src")
from jev_kit.command_properties import extract_command_properties as e

CANDIDATES = [
    # currently-proven band (cp/mv onto system paths)
    "cp app.conf /etc/app/app.conf",
    "mv app.conf /etc/app/app.conf",
    # unmodeled programs refused in batches 4/5
    "dd if=stage.img of=/dev/sda",
    "truncate -s 0 /var/log/app/app.log",
    "tee /etc/app/app.conf < patch.conf",
    "tee -a /etc/app/app.conf < patch.conf",
    "cp --force app.conf /etc/app/app.conf",
    "cp -f app.conf /etc/app/app.conf",
    "cat patch.conf > /etc/app/app.conf",
    "echo x > /etc/app/app.conf",
    "install -m 0644 build/app /usr/local/bin/app",
    # destination-fact probes: what facts exist for destination?
    "cp app.conf /tmp/app.conf",
    "cp app.conf /etc/app/app.conf.new",
    "printf '%s' x > /etc/app/app.conf",
    "bash -c 'echo x > /etc/app/app.conf'",
]

for c in CANDIDATES:
    p = e(c)
    facts = {}
    for name in ("parse_confident",):
        facts[name] = getattr(p, name, None)
    vals = getattr(p, "values", None)
    if vals:
        facts["truthy"] = {k: v for k, v in vals.items() if v}
    print(c)
    print("   ", facts)
