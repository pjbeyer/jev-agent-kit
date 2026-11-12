# Spec: the `jev-gate` Hermes plugin

- Tracker: Beads `jak-7c9` (parts 1 and 3; part 2's measurement lives in the shadow
  corpus, summarized below). This file is the plugin-level contract.
- Status: implemented (matches `aug/dest-exists-fact` through `330f817`).
- Sources this spec consolidates (not replaces): `docs/upstream/gate-augmentation-contract-v1.md`
  (the upstream hook contract), `docs/adr/0002` (egress policy), `docs/adr/0005`
  (command properties), `docs/adr/0006` (implementer-owned policy), `docs/guides/calibration.md`
  (calibration procedure), `skills/jev-runtime/questions/tool-call-gate.json` (question set).

## 1. Hook surface

The plugin registers one Hermes `pre_tool_call` hook (`hooks/hermes.py::register`).
Hermes passes an event mapping (`tool_name`, `args`, `task_id`); the event shape is
not pinned by a verified schema, so the shim reads defensively and returns `None`
(allow) on anything unparseable in shadow, and a block payload in enforce.

Extraction contract (jak-baw, jak-47d, jak-77q, jak-a2p):

- Shell tools (`terminal`): the `command` string is the judged line.
- Modeled non-shell tools: the shim emits `hermes.<tool> <naming args>` pseudo-commands.
  Only simple strings ride (ASCII, one line, no quotes/expansion/redirects); payload
  bodies never leave the machine.
- `execute_code`: the `code` payload is statically analyzed locally (never executed);
  a proven-clean payload with confidently-judged child lines emits
  `hermes.execute_code <children joined by ' ;; '>`. Anything opaque keeps the bare
  head (fail-closed `runs_unseen_code`).
- MCP aggregator dispatch (`mcp__local_mcp_aggregator__call_tool`): single canonical
  form emits `hermes.mcp_call_tool <tool_id>`; provisioned ids (mcp_tools.TOOL_IDS,
  each verified live via `get_tool_schema`) resolve to names. Batch form rides member
  names.
- Native dispatcher (`tool_call`): member NAMEs ride as
  `hermes.tool_call <members...>`; un-simple members keep the bare name.
- Dispatch batches (both bridges) are judged by the WORST member: unknown >
  code_exec/persistence > authority > writer > navigator > network > reader.

## 2. Shadow vs enforce semantics

- Shadow: never changes host behavior; records `would_outcome`/`would_reason` (the
  enforce rehearsal) in the local side-log. Shadow's `outcome` is always allow.
- Enforce: ALLOW/ASK; a real ASK escalates to the human approval gate (never a silent
  block); fail-closed paths (`timeout`, `internal`, `config`, `producer_unavailable`)
  become blocks in enforce — never silent allows. Mock/test traffic never escalates.
- Parse confidence is an allowlist (ADR 0005): an unreadable command never reaches
  ALLOW in enforce, whatever the gate answered (`command_parse_unconfident`).
- Local no-egress fast path: refused-class lines (compound/quoted) with no hazard
  fact and no egress destination allow without a model call, in both modes, recorded
  honestly in the side-log.
- Unattended contexts (cron) never escalate to a human; the unattended policy decides.

## 3. Calibration requirements

- The registry (`$JEV_KIT_REGISTRY`, default `~/.local/share/hermes/jev-calibration/
  registry/thresholds.json`) maps question fingerprint → calibrated bounds. Six
  questions: destroys_data, overwrites_data, escalates_privilege, plants_persistence,
  exfiltrates, widens_permission.
- Producer binding (jak-6lt, jak-yle): the registry root carries a `producer` stamp;
  the engine compares it to the runtime producer and fails the whole request loudly
  (CONFIG) on mismatch. An unstamped registry keeps working (pre-stamp format).
- Registry keys must come from the isolated probe-receipts corpus (run_chunk.py),
  never the ambient receipts dir. Re-key procedure after any hook-source edit:
  1. re-score probe corpus: `run_chunk.py <skip> <limit> <out>` (fresh receipts under
     the current producer),
  2. rebuild: `build_registry.py` (refuses corpora that predate the current source),
  3. verify: stamp == current tree producer, 6/6 fingerprints live-match.
- Calibration sufficiency: 30+ per class in the confirm half; currently
  plants_persistence (jak-o91) and overwrites_data (jak-lve) do NOT meet it and every
  gate decision touching them fail-closes to ask.

## 4. Promote-to-enforce checklist

- [x] Shadow week over real traffic closed (2026-11-10).
- [x] Registry binding verified fail-loud (jak-6lt), re-key procedure proven twice.
- [ ] All six questions calibrated (jak-o91, jak-lve outstanding).
- [ ] Confident-band ask-rate on real traffic ≤ target (measurement: the shadow
      side-log's `would_outcome` column; current headline slice: reader-egress
      dispatches ask at calibrated exfiltrates ≥0.21 bound — the egress-band
      threshold itself is the open calibration question, affects named and id
      dispatches equally).
- [ ] Enforce profile reviewed (run_enforce_profile.py) and signed off.

## 5. What the gate adds over Hermes' native approval flow (part 3)

Hermes natively provides: permission modes (YOLO/approvals off/ask), command
allowlists, PreToolUse hooks (this plugin rides one), and smart approvals (pattern
matching on the command text with saved always/never rules — visible in this
session's own terminal approvals).

jev-gate adds what none of those do:

- **Calibrated statistical gating**: per-question fitted bounds from a scored corpus,
  so a verdict is "0.87 exfiltrates ≥ 0.21 yes-bound" — measurable, refittable —
  rather than a static pattern match. Smart approvals cannot express "this class of
  reader egress is fine, this near-identical one is not."
- **Receipts**: every judged call leaves a durable signed record (fingerprint,
  threshold, verdict, call id) — an audit trail; native approvals leave at best a log
  line.
- **Fail-closed by default**: unparseable, unmodeled, timed-out, misconfigured — all
  block in enforce. Native allowlists fail open (an unlisted command just runs unless
  a rule says otherwise).
- **Producer-bound calibration**: behavior changes invalidate calibration loudly
  (CONFIG), not silently.
- **Batch dispatch judgment**: native approvals see one tool name; the gate sees the
  dispatched member names and judges the worst.

Double-coverage note: the gate deliberately does NOT replicate native allowlists or
the approval UX; it composes — the gate's ASK feeds Hermes' native approval card,
which is the human gate the plugin escalates to.

## 6. Known open contracts

- jak-yle: producer decoupling (hook-source edit still rotates all fingerprints; re-key
  is manual toil, now loud instead of silent).
- exfiltrates egress band: every `network_upload=True` reader dispatch scores ≥0.85
  against a 0.21 yes-bound — asks are calibrated but constant; the threshold needs a
  refit on a reader-egress-rich corpus (relates to jak-baw's question-definition
  review).
- jak-baw: confident-command probe set + non-shell question-definition review.
