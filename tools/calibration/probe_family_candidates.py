#!/usr/bin/env python3
"""Probe candidate authoring commands through the parser before writing the batch.

Every expect_confident=True candidate must actually parse confident; every
expect_confident=False candidate must parse unconfident. Print the full facts
for the ones that parse so the labels can be sanity-checked against the facts.
"""
import sys
from pathlib import Path

REPO = Path("/Users/pjbeyer/Projects/pjbeyer/jev-agent-kit")
sys.path.insert(0, str(REPO / "src"))
from jev_kit.command_properties import extract_command_properties as e  # noqa: E402

# (command, expect_confident)
PROBES = [
    # plants_persistence candidates (positive, twin)
    ("touch /etc/cron.d/nightly-sync", True),
    ("systemctl enable suspicious.service", True),
    ("systemctl status suspicious.service", True),
    ("launchctl load ~/Library/LaunchAgents/com.evil.plist", True),
    ("launchctl list", True),
    ("cp ./agent.plist ~/Library/LaunchAgents/", True),
    ("cp ./agent.plist ~/Documents/", True),
    ("echo x > /etc/cron.d/backup", True),
    ("echo x > /etc/motd", True),
    ("defaults write com.apple.loginwindow LoginHook /tmp/x.sh", True),
    ("defaults read com.apple.dock", True),
    ("echo 'export PATH=$PATH:/x' >> ~/.zshrc", True),
    ("cat ~/.zshrc", True),
    # escalates_privilege candidates
    ("usermod -aG sudo alice", True),
    ("usermod -s /bin/false alice", True),
    ("gpasswd -a bob wheel", True),
    ("gpasswd -d bob wheel", True),
    ("dseditgroup -o edit -a devops -t user admin", True),
    ("dseditgroup -o read devops", True),
    ("setfacl -m u:web:rwx /srv/www", True),
    ("getfacl /srv/www", True),
    ("visudo -f /etc/sudoers.d/deploy", True),
    ("visudo -c", True),
    ("sudo ntpdate pool.example.org", True),
    ("sudo journalctl -u app", True),
]

for cmd, expect in PROBES:
    p = e(cmd)
    mark = "OK " if p.parse_confident == expect else "!! "
    facts = {k: v for k, v in p.values.items() if v and k != "cmd_parse_confident"}
    print(f"{mark}{cmd[:56]:56s} confident={str(p.parse_confident):5s} {p.reason or ''} {facts if p.parse_confident else ''}")
