#!/usr/bin/env python3
"""Which facts do the 4 uncovered positives fire? (read-only, local)"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))
from jev_kit.command_properties import extract_command_properties as e

for cmd in ["cp ./s.py /usr/local/lib/python3.11/site-packages/sitecustomize.py",
            "touch /etc/launchd.conf",
            "chgrp -R staff /shared/project",
            "cp greet.sh /etc/ssh/sshrc"]:
    p = e(cmd)
    v = {k: x for k, x in p.values.items() if x}
    print(cmd[:62])
    print("  fires:", v)
    print()
