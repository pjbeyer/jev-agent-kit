# jev-agent-kit Handoff — 2026-11-01 session → next session

**Repo:** `/Users/pjbeyer/Projects/pjbeyer/jev-agent-kit` (branch `aug/dest-exists-fact`, pushed through `f810cb8`)
**Beads:** prefix `jak`, contributor mode, central Dolt server db `jev_agent_kit` on port 3307, remote = Phil's fork (`pjbeyer/jev-agent-kit`). Manifest entry (31-repo manifest at `~/.hermes/scripts/beads_cron_manifest.json`) added; cron-coverage audit passes with 0 findings.

## Session state (what was done)

1. **Calibration re-score** — 6-chunk pilot over 594 parser-confident suite commands; registry re-keyed to production-verified fingerprints. Registry now (all dated 2026-11-01, at `~/.local/share/hermes/jev-calibration/registry/thresholds.json`):
   - `9757ec6ab576` destroys_data — calibrated, no 0.80 / yes 0.81
   - `0f66b13ab364` exfiltrates — calibrated, no 0.20 / yes 0.21
   - `3ad6bfd180ca` escalates_privilege — calibrated, no 0.42 / yes 0.71
   - `6947b4503f6df` widens_permission — calibrated, no 0.70 / yes 0.92
   - `30fe1d245505` and `6947b450…` companions: **overwrites_data** and **plants_persistence remain UNCALIBRATED** (fail-closed ask)
2. **Egress fail-closed verified** — `curl | sh` probe confirmed `egress_blocked` path works end to end.
3. **Beads unblocked** — stale `routing.contributor` / `routing.mode` rows deleted from the central config table (documented as jak-597).
4. **Beads prefix renamed** `jev-agent-kit` → `jak` (bd rename-prefix + central Dolt commit `b55mtliikbf3vjts1jr2f5d6vgt8u61a`, pushed with head-parity verified). Old prefix now resolves `unknown_prefix`.
5. **metadata.json repaired** — added `dolt_server_port: 3307`; `hermes-beads-resolve jak-*` went `verification_failed` → `resolved`.
6. **bd 1.3.2 housekeeping** — hooks/.gitignore/agent-file blocks committed (`930d758`, `f810cb8`) and pushed.

## Open Beads issues (work for the next session)

| ID | What | Notes |
|---|---|---|
| **jak-lve** | overwrites_data: deliberate positive collection | Need 30+ real destructive-overwrite commands w/ confident parser state + matched negatives, scored through the live path, then refit. Currently forces fail-closed asks. |
| **jak-o91** | plants_persistence: deliberate positive collection | Same shape; suite had ~no true positives. Collect launchd plists, cron entries, shell-profile edits, Login Items commands, refit. |
| **jak-8oj** | Shadow `would_route` skips the H1 label check | hooks surface the engine's would_route (ACCEPT whenever candidate clears) without the enforce-only `_may_allow` label check — shadow telemetry overstates accept-rate. Fix in hooks/core.py or routing.py. **Blocks jak-ehc.** |
| **jak-597** | Routing-config incident record | Root cause + fix documented; close after a final `bd config list` sanity pass. |
| **jak-7c9** | Spec audit + Hermes comparison + ask-rate | See breakdown below — three deliverables, one still missing. |
| **jak-ehc** | Enforce-flip checklist | Depends on jak-8oj. Blocked until 8oj lands. |

## jak-7c9 deliverable status

1. **Spec** — ANSWERED: no standalone spec exists; contract lives across 8 governed docs (`docs/upstream/gate-augmentation-contract-v1.md`, `docs/guides/hermes.md`, `docs/guides/calibration.md`, `docs/adr/0002-egress-policy.md`, `docs/specs/hazard-family-split.md`, question set v12, `skills/jev-runtime/SKILL.md`, plugin manifest). Recommended: write `docs/specs/jev-gate-plugin.md` as an INDEX binding them, adding only the promote-to-enforce checklist, per-family calibration requirements, and a failure-mode matrix (transport fail / model mismatch / egress_blocked / uncalibrated).
2. **Ask-rate** — ANSWERED from suite data: all-6-gate = 100% ask (2 uncalibrated fail closed); calibrated-4-gate = 46% on the suite (hazard-heavy; only 9.7% true hazard-yes). **Real-traffic ask-rate is NOT measured** — that is jak-ehc's shadow week.
3. **Hermes comparison** — NOT DONE. This is the main open analysis item for the next session. A systematic write-up comparing jev-gate against Hermes's native approval flow: permission modes, allowlists, PreToolUse hooks, native receipt/audit story. Delta to document: jev-gate adds calibrated statistical gating, durable receipts, default-fail-closed egress posture; Hermes natively provides deterministic policy. Identify double-coverage and whether the plugin's egress cost earns its keep.

## jak-ehc (enforce flip) — sequence for the next session

1. Fix jak-8oj first (would-route must mirror enforce exactly, else shadow week data is wrong).
2. Run ~1 week of shadow over real Hermes traffic (not the suite), logging would-be routes.
3. Measure real ask-rate; review a sample of asks for actionability.
4. Decide on the two uncalibrated questions: finish jak-lve / jak-o91 collection, or demote them to advisory (document the choice).
5. Phil's explicit go required — enforce changes host behavior. `JEV_KIT_HOOK_MODE=shadow` currently set in `~/.hermes/.env` (line 36); do not touch the LaunchAgent plist.

## Environment facts the next session needs

- `JEV_KIT_HOOK_MODE=shadow` in `~/.hermes/.env`; receipts dir overridden via `JEV_KIT_RECEIPTS_DIR` (never let receipts reach the production receipts dir).
- `bd dolt status` in this repo spuriously reports "server not running" (port 3307 is actually up); use `bd --readonly status` or direct SQL against `~/.local/share/dolt/data/jev_agent_kit`.
- Run coverage/audit scripts with `env -u PYTHONPATH python3` from `~/.hermes/scripts/`.
- Never rely on bare `python3` (Xcode 3.9.6 vs Homebrew 3.14 conflict).
- Never `eval "$(direnv export bash)"` in the persistent shell (drops 1Password-sourced git creds); direnv `use_sourceop` leaves literal `op://` tokens in env.
- Registry fingerprints in `~/.local/share/hermes/jev-calibration/registry/thresholds.json` are keyed to out-of-process child fingerprints — do not re-key from hook envelopes; production-verified keys are the ones listed above.
- `bd config set` is available if any routing keys reappear; check `dolt sql -q "SELECT * FROM config"` in the central db if `bd` commands start failing with PROJECT IDENTITY MISMATCH again.
