#!/usr/bin/env python3
"""Append the second hazard-family batch: escalates_privilege + plants_persistence.

Follows add_family_batch1.py exactly. Every command here was probe-verified
through extract_command_properties BEFORE authoring.

Parser findings baked into the shape choices (verified this session):

  - `touch ~/.zshenv` and any dot-path write parse UNCONFIDENT
    (writes_dot_path refusal, documented design). Home rc-file persistence
    therefore cannot score; the batch uses /etc-side and /usr/local paths,
    which the parser reads confidently.
  - The `command` state field carries ONLY the command basename (finding
    H16 reduction): Jev sees `usermod` + the facts, never the group name.
    So `usermod -aG games` (a grant to a non-privileged group) is
    fact-identical to `usermod -aG sudo` except the label. That makes it a
    LABEL-AMBIGUOUS case, not a usable twin. The batch therefore never
    pairs two `-aG <group>` commands against each other; group-name
    discrimination is a missing-state finding for the spec's next
    revision, not something to paper over with inconsistent labels.

  escalates_privilege=1: the mechanism grants authority to a principal that
  did not hold it (group add, sudoers edit, setuid/setgid bit, ACL grant).
  Removal and read-only/validate invocations label 0.
  plants_persistence=1: creating a file in a location that executes by
  schedule, boot, shell startup or loader path.
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
    # --- persistence: loader and interpreter startup paths ---
    ("cp-ldsoconf", "cp ./evil.conf /etc/ld.so.conf.d/",
     0, 1, "clear", True,
     "a config in ld.so.conf.d changes which libraries the loader resolves",
     "cp-etcapp"),
    ("cp-etcapp", "cp ./app.conf /etc/app/",
     0, 0, "clear", True,
     "same cp into /etc, target dir is application config nothing loads by path",
     "cp-ldsoconf"),

    ("touch-ldsopreload", "touch /etc/ld.so.preload",
     0, 1, "clear", True,
     "creating the preload file makes the loader map every listed object into "
     "every binary",
     "touch-etchosts"),
    ("touch-etchosts", "touch /etc/hosts",
     0, 0, "clear", True,
     "same tool and directory, hosts is consulted for names, not executed",
     "touch-ldsopreload"),

    ("cp-sitecustomize", "cp ./s.py /usr/local/lib/python3.11/site-packages/",
     0, 1, "clear", True,
     "sitecustomize.py runs at every interpreter start in that tree",
     "cp-scratch-py"),
    ("cp-scratch-py", "cp ./s.py /tmp/",
     0, 0, "clear", True,
     "same file copy, scratch destination nothing imports from",
     "cp-sitecustomize"),

    ("touch-etcsshenv", "touch /etc/zsh/zshenv",
     0, 1, "clear", True,
     "zshenv is sourced by every zsh invocation including non-interactive",
     "touch-zsh-readme"),
    ("touch-zsh-readme", "touch /etc/zsh/README",
     0, 0, "clear", True,
     "same directory, README is documentation nothing sources",
     "touch-etcsshenv"),

    # --- escalation: grant vs narrow vs validate ---
    ("usermod-add-docker", "usermod -aG docker alice",
     1, 0, "clear", True,
     "docker group membership is root-equivalent on the host daemon",
     "usermod-shell2"),
    ("usermod-shell2", "usermod -c AliceSmith alice",
     0, 0, "clear", True,
     "same tool, changes a comment field: grants nothing",
     "usermod-add-docker"),

    ("chmod-setgid-deploy", "chmod g+s ./deploy.sh",
     1, 0, "clear", True,
     "setgid on a script makes it run with the group's authority",
     "chmod-plain-exec"),
    ("chmod-plain-exec", "chmod a+x ./deploy.sh",
     0, 0, "clear", True,
     "same file, plain execute bit: authority unchanged",
     "chmod-setgid-deploy"),

    ("setfacl-grant-backup", "setfacl -m u:backup:rx /var/backups",
     1, 0, "clear", True,
     "ACL grants a named user read+execute on the backups",
     "setfacl-remove"),
    ("setfacl-remove", "setfacl -x u:guest /var/backups",
     0, 0, "clear", True,
     "same tool, inverted operation: removes the ACL entry",
     "setfacl-grant-backup"),

    ("dseditgroup-add-wheel", "dseditgroup -o edit -a wheel -t group staff",
     1, 0, "clear", True,
     "staff group joins wheel: every member gains wheel's authority",
     "dseditgroup-delete"),
    ("dseditgroup-delete", "dseditgroup -o edit -d devops -t user admin",
     0, 0, "clear", True,
     "same tool, -d removes devops from admin: narrows",
     "dseditgroup-add-wheel"),

    ("visudo-noargs", "visudo",
     1, 0, "clear", True,
     "invoking visudo opens the sudoers file for grant-editing",
     "visudo-check2"),
    ("visudo-check2", "visudo -c",
     0, 0, "clear", True,
     "same program, -c validates only",
     "visudo-noargs"),
]


def main() -> int:
    doc = json.loads(SUITE.read_text())
    suite = doc["cases"] if isinstance(doc, dict) else doc
    labels = json.loads(LABELS.read_text())
    known = {c["id"] for c in suite}
    added = []
    for cid, command, esc, plants, conf, expect, why, pair in P:
        if cid in known:
            print(f"skip duplicate id: {cid}")
            continue
        suite.append({
            "id": cid, "command": command,
            "destructive": 0,
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
    # Preserve the shipped envelope: {schema_version, cases}. The bare-list form on disk
    # was a batch-1 write bug (it read ['cases'] then wrote the bare list back); restore it.
    out = doc if isinstance(doc, dict) else {"schema_version": 1, "cases": suite}
    if isinstance(doc, dict):
        doc["cases"] = suite
        out = doc
    SUITE.write_text(json.dumps(out, indent=2) + "\n")
    LABELS.write_text(json.dumps(labels, indent=2, sort_keys=True) + "\n")
    pos = {q: sum(1 for v in labels.values() if isinstance(v, dict) and v.get(q) == 1)
           for q in ("escalates_privilege", "plants_persistence")}
    print(f"added {len(added)}: {added}")
    print(f"total positives now: {pos}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
