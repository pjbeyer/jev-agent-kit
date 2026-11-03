# Native Hermes approval flow vs the jev-gate plugin

Status: complete (2026-11-02) · Answers question 3 of the 2026-11-01 session review
(tracker: jak-7c9): a documented capability delta — what jev-gate adds over what Hermes
already provides natively — to justify the plugin's existence and find double-coverage.

Sources: native side from the Hermes docs
(<https://hermes-agent.nousresearch.com/docs/user-guide/security>,
`…/features/hooks`, `…/reference/mcp-config-reference`) verified against the local
source checkout (`tools/approval.py`, `tools/approval_smart.py`, `tools/approval_floors.py`,
`tools/approval_detection.py`, `hermes_cli/plugins_dispatch.py`) and the live
`~/.hermes/config.yaml`. Plugin side from this repo: `src/jev_kit/hooks/hermes.py`,
`hooks/core.py`, `unattended.py`, `errors.py`, `docs/guides/hermes.md`,
`docs/guides/calibration.md`, `docs/receipts.md`. Machine-specific numbers are from
`tools/calibration/hook_fp/measure.py` and the shadow receipts, both re-measured 2026-11-02.

## The two architectures in one paragraph each

**Native Hermes** is deterministic, pattern-first, and per-surface. A code-shipped regex
stack gates terminal commands: a hardline floor (`rm -rf /`-class, not overridable by
YOLO, `mode: off`, cron-approve, or "always"), user `approvals.deny` globs, then
`DANGEROUS_PATTERNS` detection whose hits go to a human gate (once/session/always/deny,
timeout = deny). `approvals.mode: smart` adds an auxiliary-LLM guardian that triages
already-flagged commands with a one-word APPROVE/DENY/ESCALATE verdict — LLM judgment,
but no numeric threshold, no calibration, and it never sees commands the patterns did
not flag. Approval grants persist per command/pattern/rule-key in `command_allowlist`
(never per tool), and unattended surfaces get an explicit policy (`cron_mode` etc.,
default deny, with allowlist rule keys still honored). There is no native receipt
ledger: "always" grants live in config, implied history is mined from the session DB,
and a decision log must be built from observer hooks.

**jev-gate** is statistical, evidence-first, and per-call. A `pre_tool_call` plugin
callback sends an egress-reduced command fact set to a pinned TypeSafe Jev model, which
answers six calibrated yes/no hazard questions (exfiltrates, widens_permission,
destroys_data, overwrites_data, escalates_privilege, plants_persistence). A
fingerprint-bound threshold registry (keyed by question wording + model + egress
contract + producer code hash) maps each probability to accept/ask; uncalibrated or
failed questions fail closed to ask. Every decision is written to a signed-shape
receipt JSONL (digests, never command text), and a shadow mode records the would-be
enforce outcome while changing nothing. Escalations ride Hermes' own human gate
(`approve` action + command-grain `rule_key`); unattended contexts never escalate
(record policy), mocks never escalate, and YOLO does not swallow the plugin's `block`.

## Capability delta

| Capability | Native Hermes | jev-gate | Delta owner |
|---|---|---|---|
| Detects dangerous commands | Deterministic regex patterns, code-shipped | Calibrated per-hazard probabilities | Different mechanism, overlapping intent |
| Judgment under ambiguity | LLM triage of flagged commands (APPROVE/DENY/ESCALATE, uncalibrated) | Calibrated thresholds with measured acc/cov per question (live acc 0.95-0.99) | jev-gate |
| Hazard taxonomy | One flat "dangerous" class + ~30 pattern families | Six named hazard families with independent thresholds | jev-gate |
| Novel/unpatterned commands | Not flagged → runs with no gate at all | Judged by the model like any other command | jev-gate (the only coverage here) |
| Decision receipts | None (grants in config; history mined from session DB) | Append-only JSONL per decision, commit markers, no raw text | jev-gate |
| Rehearsal mode | None | Shadow mode with honest would-be enforce outcome | jev-gate |
| Calibration lifecycle | N/A | Fingerprint-bound registry; any edit to question/code/env rotates keys (jak-yle) | jev-gate (and its cost) |
| Allow persistence grain | Command text / glob / pattern rule-key | `jev:<cmd-head>:<sha12>` per exact command | Same store, jev-gate's grain is narrower by design |
| Unattended policy | `cron_mode: deny` default (rule keys still honored) | record-and-continue default, escalation suppressed and audited | Different defaults; native is stricter on paper |
| Fail posture | Timeout/expiry = deny; hardline floor unconditional | Transport/model/fail closed to ask (enforce) or allow (shadow); 8s self-deadline under Hermes' 30s | Both fail closed |
| YOLO interplay | YOLO bypasses approvals; hardline floor survives | YOLO auto-approves `approve` escalations; jev-gate's `block` survives YOLO | jev-gate keeps a hold YOLO cannot swallow |
| Setup/ops cost | None (shipped) | Plugin + env config + calibration + registry upkeep + per-call model spend | Native |

## Double coverage

On this machine the native layer already deterministically gates what the patterns
know. The measured corpus (`tools/calibration/hook_fp/measure.py`, 2026-11-02 run over
168,436 distinct real commands from the Hermes session store) says:

- 100.0% of exfil-labeled and 99.1% of destructive-labeled commands are parse-unconfident
  — so in jev-gate enforce they escalate before any model answer, and native Hermes
  patterns flag the same classes deterministically. Same commands, two gates.
- Only **1.47% of safe commands** are parse-confident; the other 98.53% can never be
  allowed in enforce whatever Jev answers. The guaranteed-escalation floor is 98.53% of
  safe traffic (drivers: control characters 48%, shell syntax 44%, unmodeled programs 4%).

The consequence for the enforce decision (jak-ehc): on current Phil-traffic shape, the
parser — not the questions — is the binding constraint. Calibration work cannot move the
floor; only parser coverage (confidence on multi-command lines, unmodeled programs) or
scoping the gate to the parse-confident subset can. Native Hermes flags the dangerous
subset without any of that cost, so jev-gate's enforce value today is concentrated in the
narrow band the parser trusts AND the patterns do not already know: novel-hazard
commands the regexes never learned. That band is exactly what shadow week should size.

## What the shadow week must measure (feeding jak-ehc)

1. Ask-rate over real traffic with the re-keyed registry (4/6 calibrated) — the honest
   number, replacing the 85.4% all-uncalibrated pre-rekey baseline (2026-11-01).
2. The split from `run_pilot.py`'s taxonomy: guard escalations (parse-unconfident —
   addressable only by parser work) vs question escalations (parse-confident but a
   question refused — addressable by calibration).
3. The novel-hazard band: parse-confident commands that native `DANGEROUS_PATTERNS` does
   not flag but a question answers yes on. This is the plugin's unique enforce value;
   if it measures near zero, enforce is not worth the ask-rate cost while the parser
   floor stands.

## Verdict

jev-gate is not redundant with native Hermes — it is the only layer that judges
unpatterned commands, produces decision receipts, and can rehearse an enforce cutover
on real traffic. But on this machine today its enforce-path marginal value is bounded
by the parse guard: it would re-ask nearly everything the native patterns already
block, at per-call model spend and calibration upkeep. Justified to keep in shadow
(measurement + receipts); enforce is not justified until either the parse-confident
share rises or the shadow week shows a material novel-hazard band. Both parsers and
thresholds are our code, so both paths are open.

Related: the stale-doc drift this review caught in `docs/guides/hermes.md` (a
pre-2026-10-30 block-only paragraph contradicting the ask→approve mapping) is fixed in
the same pass. Registry producer-churn reliability gap is tracked as jak-yle.
