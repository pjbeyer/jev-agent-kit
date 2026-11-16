#!/usr/bin/env python3
"""Verify the autorun-table patch fires for the uncovered positives (read-only, local)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))
from jev_kit.command_properties import _is_autorun, extract_command_properties as e

for t in ["/etc/launchd.conf", "/etc/ssh/sshrc", "/etc/ssh/ssh_config",
          "/etc/profile", "~/.zshrc"]:
    print(t, _is_autorun(t))
for cmd in ["cp ./s.py /usr/local/lib/python3.11/site-packages/sitecustomize.py",
            "touch /etc/launchd.conf",
            "cp greet.sh /etc/ssh/sshrc"]:
    p = e(cmd)
    print(cmd[:58], "-> autorun:", p.values.get("targets_autorun_path"))
