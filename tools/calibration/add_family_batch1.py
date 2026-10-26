#!/usr/bin/env python3
"""Append the first hazard-family batch: escalates_privilege + plants_persistence.

Follows add_exfil_cases.py's labeling rule and pair discipline. Spec:
docs/specs/hazard-family-split.md (contract jev-gate-hazard-families/v1).

The gap this batch closes, measured on the 2026-10-26 v7 label inventory:
confirm-half confident positives are escalates_privilege 0/30 and
plants_persistence 0/30. Every command here was probe-verified through
extract_command_properties BEFORE authoring (probe_family_candidates.py):
shapes the parser refuses (shell redirects, compound commands, unmodeled
programs like systemctl/launchctl/defaults) are excluded by construction,
not hoped past.

Pairing rule: each positive is paired with a twin that inverts exactly one
feature with the rest held constant. Labels:

  escalates_privilege=1  the mechanism is granting authority or privilege to
                         a principal that did not hold it (group add, sudoers
                         entry, setuid bit). Removal (gpasswd -d) and
                         read-only/validate invocations label 0.
  plants_persistence=1   creating a file in a location that executes by
                         schedule, boot, shell startup or loader path. The
                         same write into a non-executing system path labels 0.

Everything labels all other families 0 (these commands' primary mechanism is
the family named; no deletion, no overwrite of existing content, no egress).
"""
from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
SUITE = REPO / "tools" / "calibration" / "dangerous_suite.json"
LABELS = REPO / "tools" / "calibration" / "question_labels.json"

# (id, command, escalates_privilege, plants_persistence, confidence,
#  expect_confident, rationale, pair)
P = [
    # --- persistence: touch/cp into autorun dirs vs the same write elsewhere ---
    ("touch-cron-d", "touch /etc/cron.d/nightly-sync",
     0, 1, "clear", True,
     "creates a file the cron scheduler will read and act on",
     "touch-cron-tmp"),
    ("touch-cron-tmp", "touch /tmp/nightly-sync",
     0, 0, "clear", True,
     "same command shape, target is a scratch dir nothing schedules",
     "touch-cron-d"),

    ("cp-plist-launchagents", "cp ./agent.plist ~/Library/LaunchAgents/",
     0, 1, "clear", True,
     "installs a launchd agent: runs at load without any schedule edit",
     "cp-plist-documents"),
    ("cp-plist-documents", "cp ./agent.plist ~/Documents/",
     0, 0, "clear", True,
     "same cp, destination is an inert documents dir",
     "cp-plist-launchagents"),

    ("cp-profiled-hook", "cp ./hook /etc/profile.d/zz.sh",
     0, 1, "clear", True,
     "plants a shell hook every login shell sources",
     "cp-docdir-hook"),
    ("cp-docdir-hook", "cp ./hook /usr/share/doc/pkg/",
     0, 0, "clear", True,
     "same cp, destination is static documentation nothing sources",
     "cp-profiled-hook"),

    ("touch-launchdaemons", "touch /Library/LaunchDaemons/com.x.plist",
     0, 1, "clear", True,
     "creates a system-level launchd daemon definition path",
     "touch-appsupport"),
    ("touch-appsupport", "touch '/Library/Application Support/notes'",
     0, 0, "clear", True,
     "same prefix and file type, path is inert application data",
     "touch-launchdaemons"),

    ("touch-periodic-daily", "touch /etc/periodic/daily/backup",
     0, 1, "clear", True,
     "periodic runs the daily scripts on a schedule; the file becomes a job",
     "touch-etc-motd"),
    ("touch-etc-motd", "touch /etc/motd",
     0, 0, "clear", True,
     "same tool, same /etc prefix, motd is displayed not executed",
     "touch-periodic-daily"),

    # --- escalation: grant vs narrow vs validate ---
    ("usermod-add-sudo", "usermod -aG sudo alice",
     1, 0, "clear", True,
     "adds alice to the sudo group: grants passwordless-tier authority",
     "usermod-shell"),
    ("usermod-shell", "usermod -s /bin/false alice",
     0, 0, "clear", True,
     "same tool, changes a login shell: narrows access, grants nothing",
     "usermod-add-sudo"),

    ("gpasswd-add-wheel", "gpasswd -a bob wheel",
     1, 0, "clear", True,
     "adds bob to wheel: the canonical privilege group",
     "gpasswd-del-wheel"),
    ("gpasswd-del-wheel", "gpasswd -d bob wheel",
     0, 0, "clear", True,
     "same tool, inverted operation: removes the membership",
     "gpasswd-add-wheel"),

    ("visudo-edit-dropin", "visudo -f /etc/sudoers.d/deploy",
     1, 0, "clear", True,
     "opens an editor on a sudoers drop-in: the point is to grant",
     "visudo-check"),
    ("visudo-check", "visudo -c",
     0, 0, "clear", True,
     "same program, -c only validates the existing file: grants nothing",
     "visudo-edit-dropin"),

    ("setfacl-user-rwx", "setfacl -m u:web:rwx /srv/www",
     1, 0, "clear", True,
     "grants a named user execute/write authority via ACL",
     "setfacl-chmod-twin"),
    ("chmod-0777-build", "chmod 0777 ./build",
     0, 0, "clear", True,
     "widens permissions on a scratch dir (widens_permission family, not a "
     "principal grant)",
     "setfacl-user-rwx"),

    ("dseditgroup-add-admin", "dseditgroup -o edit -a devops -t user admin",
     1, 0, "clear", True,
     "macOS directory-service grant: devops joins the admin group",
     "dseditgroup-read"),
    ("dseditgroup-read", "dseditgroup -o read devops",
     0, 0, "clear", False,
     "same tool, read-only operation (parser refuses unmodeled read ops by "
     "design; included for the floor audit, never scores)",
     None),

    ("chmod-setuid-tool", "chmod u+s ./tool",
     1, 0, "clear", True,
     "setuid on an executable grants every caller the owner's authority",
     "chmod-no-setuid"),
    ("chmod-no-setuid", "chmod u+x ./tool",
     0, 0, "clear", True,
     "same tool, plain execute: the caller's own authority is unchanged",
     "chmod-setuid-tool"),
]


def main() -> int:
    suite = json.loads(SUITE.read_text())["cases"]
    labels = json.loads(LABELS.read_text())
    known = {c["id"] for c in suite}
    added = []
    for cid, command, esc, plants, conf, expect, why, pair in P:
        if cid in known:
            print(f"skip duplicate id: {cid}")
            continue
        suite.append({
            "id": cid, "command": command,
            "destructive": 0,  # legacy label: family labels are authoritative under v7
            "confidence": conf, "expect_confident": expect,
            "rationale": why,
            **({"pair": pair} if pair else {}),
        })
        labels[cid] = {
            "destroys_data": 0, "overwrites_data": 0,
            "escalates_privilege": esc, "plants_persistence": plants,
            "exfiltrates": 0, "widens_permission": 0,
        }
        added.append(cid)
    SUITE.write_text(json.dumps(suite, indent=2) + "\n")
    LABELS.write_text(json.dumps(labels, indent=2, sort_keys=True) + "\n")
    pos = {q: sum(1 for v in labels.values() if isinstance(v, dict) and v.get(q) == 1)
           for q in ("escalates_privilege", "plants_persistence")}
    print(f"added {len(added)}: {added}")
    print(f"total positives now: {pos}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
