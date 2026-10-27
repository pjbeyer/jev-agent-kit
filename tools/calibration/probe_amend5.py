#!/usr/bin/env python3
"""Amendment 5 probe: setuid/setgid + world-writable facts for chmod.

The batch-3 twin measurement showed chmod mode-digit discrimination is not in
the state (same class as finding H16: the model cannot see `4755` vs `0755`).
This probe checks what NEW facts would fire on:
  - setuid/setgid: numeric 2xxx/6xxx lead digit, symbolic +s / =s (u/g subjects)
  - world/group writable: already covered by grants_write_access for numeric
    (2/3/6/7 in group/other digits) and symbolic +w.
Design: one new fact `cmd_grants_setuid` (setuid OR setgid bit on a path).
"""
import sys

sys.path.insert(0, "/Users/pjbeyer/Projects/pjbeyer/jev-agent-kit/src")
from jev_kit.command_properties import extract_command_properties as e

CASES = [
    # (command, expect_setuid_fact, expect_gwa)
    ("chmod 4755 /usr/local/bin/tool", True, False),   # setuid, no extra write
    ("chmod 0755 /usr/local/bin/tool", False, False),  # twin: clears it
    ("chmod 2755 /srv/app/bin/runner", True, False),   # setgid
    ("chmod 6755 /usr/local/bin/helper", True, False),  # both bits
    ("chmod u+s /usr/local/bin/tool", True, False),
    ("chmod g+s /srv/app/bin/runner", True, False),
    ("chmod ug+s /usr/local/bin/helper", True, False),
    ("chmod u-s /usr/local/bin/tool", False, False),   # removal
    ("chmod +s /usr/local/bin/helper", True, False),   # ambiguous subject -> treat as grant
    ("chmod 755 /usr/local/bin/tool", False, False),
    ("chmod 644 /etc/sudoers.d/90-init", False, False),
    ("chmod 666 /etc/sudoers.d/90-init", False, True),  # world-writable -> gwa
    ("chmod 777 /srv/share", False, True),
    ("chmod o=w /etc/issue", False, True),
    ("chmod 7777 /usr/local/bin/dropper", True, True),  # setuid + world-writable
    ("chmod a-s /usr/local/bin/tool", False, False),
]
for cmd, want_suid, want_gwa in CASES:
    p = e(cmd)
    vals = {k: v for k, v in p.values.items() if v}
    gwa = p.values.get("grants_write_access")
    print(f"{cmd[:44]:<44} conf={p.parse_confident} gwa={gwa} {vals}")
