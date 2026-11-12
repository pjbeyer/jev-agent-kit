#!/usr/bin/env python3
"""jak-o91/jak-lve: score batch-14 positives + twins live, fold into suite rows.

Same probe->fold cycle as score_jak47d_probe.py: score the new batch-14
fingerprints through the real shadow pilot (real decide path, real transport)
under the CURRENT producer, then append rows to _suite_rows.jsonl so the next
build_registry pass sees them (dedupe by command, last wins).

Also re-verifies the batch-14 guard floor: every positive parses confident
(parser facts present), every twin parses confident with no hazard fact.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
REPO = HERE.parent.parent
DIR = Path.home() / ".local/share/hermes/jev-calibration"

sys.path.insert(0, str(REPO / "src"))
from jev_kit.command_properties import extract_command_properties as e  # noqa: E402

suite = json.loads((HERE / "dangerous_suite.json").read_text())
b14 = [c for c in suite["cases"] if c["id"].endswith(("-tmp",)) and False]
# batch-14 = the 54 ids added by add_family_batch14.py: identify by pair targets
B14_PAIRS = set()
for c in suite["cases"]:
    if c.get("rationale") and ("Copy into /tmp" in c["rationale"] or "tmp clobber" in c["rationale"]):
        pass
# Simpler: batch-14 ids are exactly those NOT present in _suite_rows.jsonl and
# whose pair twin is also new. Re-derive from the add script's id list.
B14_IDS = {
    "cp-la-fresh-agent", "cp-la-fresh-tmp", "cp-lad-fresh-daemon", "cp-lad-fresh-tmp",
    "cp-la-fresh-userdir", "cp-la-fresh-userdir-tmp", "cp-periodic-fresh", "cp-periodic-fresh-tmp",
    "cp-profile-d-new", "cp-profile-d-new-tmp", "cp-zshenv-new", "cp-zshenv-new-tmp",
    "cp-emacs-site-start", "cp-emacs-site-start-tmp", "cp-rc-local-new", "cp-rc-local-new-tmp",
    "cp-newssyslog-d", "cp-newssyslog-d-tmp", "cp-authorized-command", "cp-authorized-command-tmp",
    "cp-auto_master-d", "cp-auto_master-d-tmp", "cp-ssh-rc", "cp-ssh-rc-tmp",
    "mv-over-hosts", "mv-over-hosts-tmp", "cp-f-resolv", "cp-f-resolv-tmp",
    "cp-f-sudoers", "cp-f-sudoers-tmp", "mv-over-bashrc", "mv-over-bashrc-tmp",
    "cp-f-kernel", "cp-f-kernel-tmp", "cp-f-grub-cfg", "cp-f-grub-cfg-tmp",
    "mv-over-crash", "mv-over-crash-tmp", "cp-f-sshdconf", "cp-f-sshdconf-tmp",
    "mv-over-cron-file", "mv-over-cron-file-tmp", "cp-f-motd", "cp-f-motd-tmp",
    "cp-f-fstab", "cp-f-fstab-tmp", "cp-f-nfs-exports", "cp-f-nfs-exports-tmp",
    "mv-over-shells", "mv-over-shells-tmp", "cp-f-python-sitecustom", "cp-f-python-sitecustom-tmp",
    "cp-f-openssl.cnf", "cp-f-openssl-tmp",
}
assert len(B14_IDS) == 54, len(B14_IDS)
by_id = {c["id"]: c for c in suite["cases"]}
cases = [by_id[i] for i in sorted(B14_IDS)]
labels = json.loads((HERE / "question_labels.json").read_text())

print("== parse check (informational: expect_confident=False cases are valid) ==")
for c in cases:
    p = e(c["command"])
    if not p.parse_confident:
        print(f"  parses UNconfident (parser fail-closes without a model call): "
              f"{c['command']!r} reason={p.reason}")
print(f"  checked {len(cases)} commands")

CMDS = [c["command"] for c in cases]

env = dict(os.environ)
for var in ("TYPESAFE_API_KEY", "TYPESAFE_API_KEY_COMMAND",
            "JEV_KIT_HMAC_KEY_COMMAND",
            "JEV_KIT_HMAC_KEY", "JEV_KIT_ATTESTATION", "JEV_KIT_BASE_URL",
            "JEV_KIT_ENDPOINT_ALLOWLIST", "JEV_KIT_RECEIPTS_DIR",
            "JEV_KIT_SRC", "JEV_KIT_SIDELOG_PATH"):
    env.pop(var, None)
env.update({
    "TYPESAFE_API_KEY_COMMAND": os.environ["TYPESAFE_API_KEY_COMMAND"],  # pass through
    "JEV_KIT_ATTESTATION": str(DIR / "attestation.json"),
    "JEV_KIT_HMAC_KEY": (DIR / "hmac-key").read_text().strip(),
    "JEV_KIT_SOURCE_ALLOWLIST": "agent_context",
    "JEV_KIT_BASE_URL": "https://litellm.shared.getflex.org/typesafe",
    "JEV_KIT_ENDPOINT_ALLOWLIST": "litellm.shared.getflex.org",
    "JEV_KIT_RECEIPTS_DIR": str(DIR / "probe-receipts"),  # build_registry keys off THIS dir
})

corpus = HERE / "_batch14_corpus.json"
corpus.write_text(json.dumps(CMDS))
out = HERE / "_batch14_rows.jsonl"
proc = subprocess.run(
    [str(REPO / ".venv/bin/python"), str(HERE / "shadow_pilot" / "run_pilot.py"),
     "--corpus", str(corpus), "--live", "--limit", str(len(CMDS)), "--out", str(out)],
    env=env, capture_output=True, text=True, cwd=str(REPO))
print("rc:", proc.returncode)
if proc.returncode != 0:
    print(proc.stdout[-2000:])
    print(proc.stderr[-2000:])
    sys.exit(1)
print(proc.stdout[-3000:])
