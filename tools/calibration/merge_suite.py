"""Merge the dangerous-command suite parts into one validated file.

The parts were written by hand across two files, and hand-written JSON drifts: a rationale that
spilled onto a second line became a `reason` or `note` key, and those keys are not part of the
case schema. Merge them into `rationale` rather than discarding the prose -- the reasoning is the
part a reviewer needs in order to disagree with a label.

Validation is strict and fails loudly. A suite that silently loses a case, or references a pair
partner that does not exist, would produce a calibration number from a smaller or different set
than the one described.
"""

from __future__ import annotations

import collections
import json
from pathlib import Path

HERE = Path(__file__).parent
PARTS = [HERE / "dangerous_suite.json", HERE / "dangerous_suite_part2.json"]
OUT = HERE / "dangerous_suite.json"

# keys a case may carry
ALLOWED = {"id", "command", "destructive", "confidence", "pair", "expect_confident", "rationale"}
# keys that are continuation prose, folded into rationale
CONTINUATIONS = ("reason", "note")
CONFIDENCE = {"clear", "borderline"}

# The pair map is authoritative and overrides whatever `pair` field the hand-written parts carry.
# It is 1:1 and reciprocal by construction: a near-miss pair is only meaningful if each side is
# the other's counterpart. Where no partner differs in exactly one feature, the case is unpaired
# rather than given a loose one -- a forced pair would claim a controlled comparison that is not
# actually controlled.
PAIRS: dict[str, str | None] = {
    # rm: the flag is held constant and the target decides
    "rm-root": "rm-scoped-build",
    "rm-root-glob": "rm-scoped-glob",
    "rm-usr": "rm-node-modules",
    "rm-etc": "rm-single-file",
    "rm-var-log": "rm-tmp",
    "rm-home": "rm-cache",
    "rm-home-hermes": "rm-pytest-cache",
    "rm-home-ssh": None,
    "rm-abs-project": "rm-in-tree-then-echo",
    "rm-abs-other-user": None,
    "rmdir-empty": None,
    # elevation is held constant and the effect decides
    "sudo-rm-var": "sudo-ls",
    "sudo-rm-root": "sudo-whoami",
    "sudo-rm-hermes": None,
    "sudo-chmod-root": "chmod-scoped",
    # permissions: the mode and the target decide
    "chmod-777-etc-passwd": "chmod-x-script",
    "chmod-777-root": "chmod-644-file",
    "chmod-777-etc": None,
    "chown-self": None,
    # git history
    "git-push-force-main": "git-push-normal",
    "git-push-force-with-lease": None,
    "git-reset-hard": "git-reset-soft",
    "git-clean-fdx": "git-clean-dry-run",
    "git-filter-branch": "git-log",
    "git-checkout-dot": "git-status",
    "git-branch-D": "git-branch-delete-safe",
    # download and execute
    "curl-pipe-sh": "curl-download",
    "curl-upload-file": "curl-head",
    "curl-pipe-python": None,
    "curl-pipe-sudo-bash": None,
    "wget-pipe-sh": None,
    # packages
    "install-brew-global": "install-npm-global",
    "pip-install-user": "pip-install-broken-env",
    # devices
    "dd-to-device": "dd-to-file",
    "truncate-device": "truncate-log",
    "mkfs-usb": None,
    "diskutil-erase": None,
    # databases
    "drop-database": "select-query",
    "delete-no-where": "delete-with-where",
    "drop-table": None,
    "truncate-table": None,
    # redirects and filesystem
    "redirect-truncate-config": "redirect-append",
    "mv-overwrite-system": "mv-in-tree",
    "unlink-system": "unlink-temp",
    "redirect-overwrite-source": None,
    # interpreter strings
    "python-rmtree": "python-print",
    "perl-inline-unlink": "perl-print",
    "python-rmtree-root": None,
    # obfuscation
    "base64-decode-pipe-sh": "base64-encode",
    # find
    "find-exec-rm": "find-print",
    "find-root-delete": None,
    # safe controls, unpaired
    "ls-safe": None,
    "pwd-safe": None,
    "grep-safe": None,
    "cat-safe": None,
    "pytest-safe": None,
    "mkdir-safe": None,
    "touch-safe": None,
    "git-commit-safe": None,
    "sequence-safe": None,
}


def load_parts() -> list[dict]:
    cases: list[dict] = []
    for path in PARTS:
        doc = json.loads(path.read_text())
        block = doc.get("cases")
        if not isinstance(block, list):
            raise SystemExit(f"{path.name}: no 'cases' list")
        for case in block:
            extra = set(case) - ALLOWED - set(CONTINUATIONS)
            if extra:
                raise SystemExit(f"{path.name}: case {case.get('id')!r} has unknown keys {extra}")
            folded = [case["rationale"]]
            for key in CONTINUATIONS:
                if key in case:
                    folded.append(case.pop(key))
            case["rationale"] = " ".join(folded)
            cases.append(case)
    return cases


def main() -> None:
    cases = load_parts()

    # ---- the pair map is authoritative, and symmetrised here rather than duplicated by hand
    # (hand-duplicating both directions is what produced the non-reciprocal pairs this check
    # exists to catch).
    symmetric: dict[str, str | None] = {}
    for case_id, partner_id in PAIRS.items():
        symmetric[case_id] = partner_id
        if partner_id is not None:
            symmetric[partner_id] = case_id

    known = {c["id"] for c in cases}
    for case_id, partner_id in symmetric.items():
        if case_id not in known:
            raise SystemExit(f"PAIRS names unknown case {case_id!r}")
        if partner_id is not None and partner_id not in known:
            raise SystemExit(f"PAIRS[{case_id!r}] names unknown partner {partner_id!r}")
        if partner_id is not None and symmetric.get(partner_id) != case_id:
            raise SystemExit(f"PAIRS is not reciprocal: {case_id!r} -> {partner_id!r}")
    for case in cases:
        case["pair"] = symmetric.get(case["id"])
    for case_id in known - set(symmetric):
        raise SystemExit(f"case {case_id!r} is not declared in PAIRS")

    # ---- required fields and types
    for case in cases:
        for field in ("id", "command", "destructive", "confidence", "expect_confident",
                      "rationale"):
            if field not in case:
                raise SystemExit(f"case {case.get('id')!r} missing {field!r}")
        if not isinstance(case["destructive"], bool):
            raise SystemExit(f"{case['id']}: destructive must be a bool")
        if not isinstance(case["expect_confident"], bool):
            raise SystemExit(f"{case['id']}: expect_confident must be a bool")
        if case["confidence"] not in CONFIDENCE:
            raise SystemExit(f"{case['id']}: confidence {case['confidence']!r} not in {CONFIDENCE}")
        if case["pair"] is not None and not isinstance(case["pair"], str):
            raise SystemExit(f"{case['id']}: pair must be a string or null")

    # ---- unique ids
    ids = [c["id"] for c in cases]
    dupes = [i for i, n in collections.Counter(ids).items() if n > 1]
    if dupes:
        raise SystemExit(f"duplicate ids: {dupes}")

    # ---- unique commands (a repeated command is a labelling contradiction waiting to happen)
    commands = [c["command"] for c in cases]
    cmd_dupes = [c for c, n in collections.Counter(commands).items() if n > 1]
    if cmd_dupes:
        raise SystemExit(f"duplicate commands: {cmd_dupes}")

    # ---- pair references resolve, and are reciprocal
    by_id = {c["id"]: c for c in cases}
    for case in cases:
        if case["pair"] is None:
            continue
        partner = by_id.get(case["pair"])
        if partner is None:
            raise SystemExit(f"{case['id']}: pair {case['pair']!r} does not exist")
        if partner["pair"] != case["id"]:
            raise SystemExit(f"{case['id']}: pair {case['pair']!r} does not point back")

    by_label = collections.Counter(c["destructive"] for c in cases)
    by_conf = collections.Counter(c["confidence"] for c in cases)

    # ---- pairs, split by whether the two sides differ in label
    paired = {c["id"] for c in cases if c["pair"]}
    discriminators, same_label = [], []
    for case in cases:
        if case["pair"] is None or case["id"] > case["pair"]:
            continue
        partner = by_id[case["pair"]]
        (discriminators if case["destructive"] != partner["destructive"]
         else same_label).append((case["id"], partner["id"]))

    print(f"cases: {len(cases)}   destructive={by_label[True]}  safe={by_label[False]}")
    print(f"confidence: {dict(by_conf)}")
    print(f"paired cases: {len(paired)}/{len(cases)}")
    print(f"  discriminating pairs (sides differ in label): {len(discriminators)}")
    for a, b in discriminators:
        print(f"    {a}  vs  {b}")
    print(f"  same-label pairs (both sides the same): {len(same_label)}")
    for a, b in same_label:
        print(f"    {a}  vs  {b}")

    clear = [c for c in cases if c["confidence"] == "clear"]
    clear_pos = sum(1 for c in clear if c["destructive"])
    print(f"\ncalibration subset (confidence=clear): {len(clear)}  "
          f"destructive={clear_pos}  safe={len(clear) - clear_pos}")

    OUT.write_text(json.dumps(
        {"_readme": json.loads(PARTS[0].read_text())["_readme"], "cases": cases},
        indent=2) + "\n")
    print(f"\nwrote {OUT}  ({len(cases)} cases)")

    part2 = PARTS[1]
    if part2.exists() and part2 != OUT:
        part2.unlink()
        print(f"removed {part2.name} (merged)")


if __name__ == "__main__":
    main()
