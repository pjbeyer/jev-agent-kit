# jev-gate — Hermes plugin (in-repo, upstreamable)

A Hermes `pre_tool_call` plugin that routes every judged tool call through the
[jev-agent-kit](../../) question engine (three calibrated questions:
`destructive` / `exfiltrates` / `widens_permission`).

This directory is the distributable form of the shim that runs on the author's
machine at `~/.hermes/plugins/jev-gate/`. The deployed copy predates it; keep
the two in sync or replace the deployed copy with a checkout of this directory.

## Install (from a checkout of this repo)

```sh
hermes plugins install <git-url-or-path>   # once this repo (or a fork) is fetchable
# or for local testing:
ln -s "$PWD/plugins/hermes" ~/.hermes/plugins/jev-gate
hermes plugins validate ~/.hermes/plugins/jev-gate
```

## Configuration

| env | default | meaning |
|---|---|---|
| `JEV_KIT_HOOK_MODE` | `shadow` | `shadow` logs and allows everything; `enforce` escalates |
| `JEV_KIT_HOOK_QUESTION_SET_PATH` | the kit's default set | absolute path to `tool-call-gate.json` |
| `JEV_KIT_SRC` | `~/jev-agent-kit/src` | where the kit source lives |
| `JEV_KIT_*` | — | the kit's own runtime config (base URL, allowlists, receipts dir, side-log) |

## Design constraints (do not relax casually)

- **Shadow never changes host behavior.** Every runtime condition resolves to
  allow in shadow and ask in enforce.
- **`block` is the only escalation response.** Hermes' `approve` action is
  keyed by tool name and bypassed under YOLO/approvals-off; only `block` holds
  on every surface (`src/jev_kit/hooks/hermes.py` docstring, phase 3/4 plan).
- **The kit source is imported from a checkout, not site-packages.** The Hermes
  runtime python has dropped third-party editable installs before; a source
  import is durable and keeps the producer fingerprint bound to the code that
  actually runs.
- **Enforcement readiness is a calibration state, not a flag.** The registry
  must contain per-question entries with promotion evidence before
  `JEV_KIT_HOOK_MODE=enforce` is meaningful. See `docs/specs/` and the
  calibration guides.
