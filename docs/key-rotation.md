# Jev (jev-agent-kit) API Key Rotation

Scope: the Jev question-engine API key (`TYPESAFE_API_KEY`) used by the
`jev-gate` Hermes plugin's judge children. This is the key that authorizes
calls from the gate to the Jev model endpoint (`litellm.shared.getflex.org`
gateway).

## Where the key lives (three surfaces, one source of truth)

| surface | location | role |
|---|---|---|
| **Source of truth** | 1Password item **Flex AI Model Gateway** (`op://3g2pzzvrog6jeuxmcrmaowzn5i/iud54wgauipabvz6efnpfj7jcm/credential`), vault `3g2pzzvrog6jeuxmcrmaowzn5i` | the one place the key is stored |
| **Offline-proof resolver** | `~/.config/jev/get-jev-api-key.sh`, wired via `TYPESAFE_API_KEY_COMMAND` in `~/.hermes/.env` | resolves via 1Password service-account token in the login keychain; survives desktop-app lock (commute-class outage, 2026-10-22) |
| **Gateway runtime env** | `TYPESAFE_API_KEY` injected by Hermes `secrets.onepassword` at gateway start (from the `config.yaml` op:// ref) | the direct-var fast path; resolution order is direct-else-command (`secrets.resolve_secret`) |

The resolver's precedence means both paths read the same 1Password item — a
rotation is a 1Password edit only. No other file ever stores the key.

## Resolution order (verified)

`resolve_secret("TYPESAFE_API_KEY", "TYPESAFE_API_KEY_COMMAND")`:
1. direct env var `TYPESAFE_API_KEY` if set (the gateway-injected value),
2. else run the command in `TYPESAFE_API_KEY_COMMAND` (the shim),
3. else `None` → judge child returns `config` → fail-open in shadow.

Setting both direct and command simultaneously is a hard config error
(`both_key_sources`), so never export a literal `TYPESAFE_API_KEY` in
`~/.hermes/.env`.

## Rotation procedure (key compromise / scheduled rotation)

1. **Generate** the new key in the Jev admin surface (out of band).
2. **Update 1Password first**: edit item *Flex AI Model Gateway*, field
   `credential`. This is the single write; everything else reads.
3. **Verify old-key invalidation timing** with the Jev admin: confirm whether
   the old key stops working immediately or after a grace period. The
   rotation is not complete until the old key is dead.
4. **Bounce the gateway** (`launchctl kickstart -k gui/$(id -u)/ai.hermes.gateway`)
   so Hermes re-materializes the new key into the runtime env.
5. **Verify** (all three, in order):
   - `env -i HOME="$HOME" bash ~/.config/jev/get-jev-api-key.sh | wc -c` →
     nonzero, single line (shim path works with the new key).
   - `curl -s -o /dev/null -w '%{http_code}' "$JEV_KIT_BASE_URL/health/liveliness"`
     with a one-off call using the new key (or simply: the next judged call
     in the side-log shows `reason: None`).
   - `grep -c config ~/.hermes/.../sidelog.jsonl` deltas stay flat after the
     restart (no new `config` class rows — a burst here means the rotation
     left a surface stale).
6. **Record** the rotation date in the 1Password item's `notesPlain` field
   (date + triggering reason). Do not store key material in notes.

## Emergency rotation (suspected compromise)

Same as above, but before step 2: revoke the old key in the Jev admin
**first**, then update 1Password, then bounce. Accept the brief judge outage
(fail-open in shadow, fail-closed-ask in enforce) — a dead key during
rotation is the correct, safe state; a live compromised key is not.

## Failure signatures to know

- `config` rows in the side-log with empty `call_id` = key resolution failed
  at judge time. With the shim installed this should only happen when the
  key is *actually dead* (rotation mid-flight) — which is the design working.
- `both_key_sources` in gateway logs = someone set the literal env var
  alongside the command; remove the literal.

## History

- 2026-10-25: resolver shim installed (`get-jev-api-key.sh`), wired via
  `TYPESAFE_API_KEY_COMMAND`; trigger: commute-class outage (1Password
  desktop lock) on 2026-10-22, 105 unjudged calls.
