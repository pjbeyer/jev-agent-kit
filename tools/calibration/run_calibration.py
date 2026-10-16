"""Run the kit's documented calibration procedure over the real answers.

Procedure: docs/guides/calibration.md, steps 3-5. The steps that matter for the result:

- Split by SESSION, not by item. Items from one session are not independent, so the confirm half
  must not share a session with the fit half.
- Pre-register the label rule, and decide ambiguous cases by the rule, not by the model.
- Use the kit's own `select_bounds` evaluator rather than inventing a threshold, so the result is
  the kit's judgement of its own question.
- Apply the walkthrough's sufficiency rule: 30 items of each class in the confirm half. The
  walkthrough declines on 14, so this declines on fewer without apology.

Writes only aggregates plus a per-item join, which stays local (it carries command text).
"""

from __future__ import annotations

import collections
import json
import random
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src"))

from jev_kit.calibration.metrics import brier_score, expected_calibration_error  # noqa: E402
from jev_kit.calibration.pav import pav_fit  # noqa: E402
from jev_kit.calibration.promotion import select_bounds  # noqa: E402

DIR = Path.home() / ".local/share/hermes/jev-calibration"
SEED = 20261016
MIN_PER_CLASS_CONFIRM = 30  # the walkthrough's own sufficiency rule

dataset = json.loads(Path("/tmp/calib_dataset.json").read_text())
labels = {d["command"]: (d["label"], d["session_id"]) for d in dataset}

rows = [json.loads(line) for line in (DIR / "calib-rows-20261016.jsonl").read_text().splitlines()]
print(f"answers: {len(rows)}   labelled items: {len(labels)}")

# ------------------------------------------------------------------ join answer to label
joined = []
for row in rows:
    command = row["command"]
    if command not in labels:
        continue
    label, session = labels[command]
    destructive = row.get("destructive")
    if not isinstance(destructive, dict):
        continue
    noul = destructive.get("noul")
    if not isinstance(noul, (int, float)):
        continue
    joined.append({"session": session, "command": command, "label": label, "noul": float(noul)})
print(f"joined with a usable probability: {len(joined)}")

counts = collections.Counter(item["label"] for item in joined)
print(f"labels: destructive={counts[1]}  safe={counts[0]}")

# ------------------------------------------------------------------ split by session
sessions = sorted({item["session"] for item in joined})
rng = random.Random(SEED)
rng.shuffle(sessions)
half = len(sessions) // 2
fit_sessions = set(sessions[:half])
fit = [(i["noul"], i["label"]) for i in joined if i["session"] in fit_sessions]
confirm = [(i["noul"], i["label"]) for i in joined if i["session"] not in fit_sessions]
fit_pos = sum(1 for _, y in fit if y == 1)
confirm_pos = sum(1 for _, y in confirm if y == 1)
print(f"\nsessions: {len(sessions)}  (seed {SEED}, split by session)")
print(f"  fit     n={len(fit):<6} positives={fit_pos}")
print(f"  confirm n={len(confirm):<6} positives={confirm_pos}")

if not fit or not confirm:
    print("\ninsufficient_data: one half is empty")
    raise SystemExit(0)

# ------------------------------------------------------------------ metrics
print(f"\nBrier raw:  {brier_score(confirm):.4f}")
print(f"ECE raw:    {expected_calibration_error(confirm):.4f}")
model = pav_fit(fit)
print(f"ECE isotonic: {expected_calibration_error([(model.predict(p), y) for p, y in confirm]):.4f}")

# ------------------------------------------------------------------ the kit's evaluator
print("\n=== the kit's promotion evaluator (reference_accuracy=0.95, tolerance=0.0) ===")
result = select_bounds(fit, confirm, reference_accuracy=0.95, tolerance=0.0)
print(f"  promotable={result.promotable}  reason={result.reason}")
print(f"  no_bound={result.no_bound}  yes_bound={result.yes_bound}")
print(f"  confirm coverage={result.coverage}  accuracy={result.accuracy}")

# ------------------------------------------------------------------ sufficiency
smaller = min(confirm_pos, len(confirm) - confirm_pos)
print(f"\n=== sufficiency (the walkthrough's own rule) ===")
print(f"  confirm items in the smaller class: {smaller}  (this procedure requires "
      f"{MIN_PER_CLASS_CONFIRM})")

print("\n=== decision ===")
if not result.promotable:
    print(f"  do not promote: evaluator says {result.reason}")
elif smaller < MIN_PER_CLASS_CONFIRM:
    print("  do not promote: not enough labelled items of the smaller class.")
    if result.no_bound is not None and result.yes_bound is not None:
        gap = abs(result.yes_bound - result.no_bound)
        print(f"  bounds {gap:.3f} apart answering {result.coverage:.0%} of the confirm half: "
              f"too few to tell")
else:
    print("  recommendation stands; promotion is still a human decision")

out = {
    "answers": len(rows),
    "joined": len(joined),
    "labels": dict(counts),
    "fit_n": len(fit), "fit_positives": fit_pos,
    "confirm_n": len(confirm), "confirm_positives": confirm_pos,
    "brier_raw": brier_score(confirm),
    "ece_raw": expected_calibration_error(confirm),
    "evaluator": {"promotable": result.promotable, "reason": result.reason,
                  "no_bound": result.no_bound, "yes_bound": result.yes_bound,
                  "coverage": result.coverage, "accuracy": result.accuracy},
    "confirm_smaller_class": smaller,
    "min_per_class_required": MIN_PER_CLASS_CONFIRM,
}
(DIR / "calibration-result-20261016.json").write_text(json.dumps(out, indent=2) + "\n")
print(f"\nresult written to {DIR / 'calibration-result-20261016.json'}")
