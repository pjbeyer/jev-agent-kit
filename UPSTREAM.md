# Upstream tracking

This repository is a fork of [`nanoDBA/jev-agent-kit`](https://github.com/nanoDBA/jev-agent-kit).
It exists to develop a small set of augmentations and, where they are general, offer them
upstream. It is not a redistribution.

## Baseline

| | |
|---|---|
| Upstream repository | `https://github.com/nanoDBA/jev-agent-kit` |
| Baseline commit | `b9789c01fbefbab2650d8d06694d9d4363cf4f4e` |
| Baseline date | 2026-10-13 |
| Baseline subject | Merge pull request #28 from nanoDBA/feat/implementer-policy |
| License | MIT (see `LICENSE`) |
| Requires Python | `>=3.11` |
| Runtime dependencies | none (ADR 0003) |

The `main` branch of this fork is the baseline and carries **no** augmentation. Every
augmentation is a separate commit on a branch named `aug/<topic>`, rebased onto
`upstream/main`. Nothing is squashed into the baseline.

## Remotes

```
origin    https://github.com/pjbeyer/jev-agent-kit.git   (this fork)
upstream  https://github.com/nanoDBA/jev-agent-kit.git   (the project)
```

## Local baseline verification

Recorded on macOS 26.7.1 (arm64), Python 3.13.16, at the baseline commit, in a virtual
environment with `pytest`, `ruff` and `mypy` installed:

| gate | command | result |
|---|---|---|
| tests | `python -m pytest -o addopts=""` | `1647 passed, 2 skipped in 27.56s` |
| lint | `python -m ruff check src tests scripts tools` | `All checks passed!` (rc 0) |
| types | `python -m mypy` | `Success: no issues found in 69 source files` (rc 0) |

The 2 skips are environmental and are skipped at the baseline, not introduced here.

Two notes for anyone reproducing this, both of which cost time if missed:

- The package must be installed first (`uv pip install -e .`), or collection fails with
  `ModuleNotFoundError: No module named 'jev_kit'`. A bare `pytest` in a fresh clone does
  not work.
- `pyproject.toml` sets `addopts = "-q"`. Adding another `-q` on the command line
  suppresses the summary line entirely while still exiting 0, which looks like a clean run
  with no evidence. Use `-o addopts=""` when you want the counts.

## Update procedure

Prefer a rebase over a merge, so upstream history stays linear and the augmentation set
stays a readable patch series.

```sh
git fetch upstream --prune --tags
git checkout main
git merge --ff-only upstream/main          # main is always exactly upstream
git push origin main
```

Then, for each augmentation branch:

```sh
git checkout aug/<topic>
git rebase upstream/main                   # resolve, then re-run the gates below
```

Re-run the full gate set after every rebase. A rebase that leaves the gates red is not
finished.

### Exercising the procedure

The procedure above was exercised once at fork creation: `git fetch upstream --tags`
succeeded, `main` was confirmed `--ff-only`-able against `upstream/main` (both at
`b9789c0`), and a no-op rebase of an augmentation branch onto `upstream/main` reported
`up to date`. Recorded in the fork-creation issue.

## Divergence inventory

Each row is one independently upstreamable change. The column records whether the change
is general (a candidate to offer upstream) or specific to this installation.

| branch | change | upstreamable |
|---|---|---|
| `aug/baseline` | This file, plus the shared gate augmentation contract under `docs/upstream/`. | No. Fork bookkeeping. |
| `aug/dest-trust` | Compute destination trust in code and supply it to the question set as state. | Yes. General. |
| `aug/unattended` | Detect unattended (cron) sessions and stop emitting escalations that presume a human. | Yes. General. |
| `aug/enforce-unmodeled` | In `enforce`, an unreadable command no longer hard-blocks routine work, without ever reaching ALLOW. | Yes. General. |
| `aug/hook-calibration` | Measure the hook's false-positive floor on real traffic, with the corpus built locally. | Yes. General. |
| `aug/flex-gateway` | Let an operator route live calls through their own gateway, without relaxing finding C23. | Yes. General. |
| `aug/parse-split` | Read a sequence of readable commands (`a && b`, `a | b`, a script) instead of refusing the line. | Yes. General, and the highest-value change here. |
| `aug/calibration` | Reproduce the documented calibration procedure, and record what it returns on real traffic. | Yes. General. |
| `aug/state-facts` | Add the consequence, direction and write-access facts the questions were missing. | Yes. General, and it measurably fixes the separation problem. |
| `aug/absolute-fact` | The absolute-path fact, plus the ensemble measured end to end. | Yes. General. |

The receipt-replay idea below is **not implemented** and has no branch. It is recorded as a
candidate rather than a change, because this file must not claim work that does not exist:

| candidate (no branch) | Persist enough state in receipts to re-judge recorded traffic offline. | Probably. Design not settled. |

Nothing in this fork hardcodes an installation-specific host, path or credential. The
destination allowlist is operator configuration with no shipped default, which is what
keeps the destination-trust change upstreamable.

## Why this fork has an update discipline

The failure this file exists to prevent is concrete and was observed on this machine: a
catalog-installed plugin with no `.git` directory fell 36 commits behind upstream while
local fixes were re-implemented by hand, so upstream improvements and local fixes had to be
reconciled twice. A fork that is not rebased on a schedule silently becomes that again.

## Contributing back

Upstream's rules are in `CONTRIBUTING.md` and `CLAUDE.md`, and they apply to this fork's
changes too. The ones that shaped the augmentations here:

- Standard library only at runtime; a new runtime dependency needs an ADR.
- Tests for behavior through a public path, plus a clean control, so a fix is not simply
  blocking everything.
- No new `type: ignore` or `noqa`.
- Docs stay honest; `tests/test_docs_examples.py` runs the examples and fails on drift.
- Prose style: plain language, no em dashes.
- Changes to egress, receipts, host hooks or calibration get an extra review pass.
