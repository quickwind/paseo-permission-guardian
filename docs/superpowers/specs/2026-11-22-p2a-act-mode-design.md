# P2a: `act` Mode with Evidence Gate — Design

- **Date**: 2026-11-22
- **Status**: Draft (builder check done; pending independent review by neon)
- **Milestone**: P2a (safety core). P2b (shadow dashboard screen, timeline rows, prompt guidance,
  mode policy) is a separate design.
- **Related**: [DESIGN.md](../../DESIGN.md) §10.4, §12, §13, §16;
  [ADR-0002](../../adr/0002-session-context-taint-and-cache-invalidation.md),
  [ADR-0003](../../adr/0003-paseo-integration-and-config-source-of-truth.md). A new ADR-0008 records
  the decisions marked **[ADR]** below.

## 1. Intent

Until now the plugin only classifies and records (`shadow`). P2a makes it actually answer routine
permission prompts for the user (`act`), but only after the user's own history shows that the
plugin's "would allow" judgement has never disagreed with a human denial. The point is to remove
prompt fatigue for clearly routine actions without ever becoming the reason a risky action ran.

### Goals

1. `act` mode that auto-answers **L0 → allow-once** and, only when `denyAsAsk` is off,
   **L3 → deny with a message**. Everything else stays with the human.
2. An **evidence gate** that keeps the effective mode at `shadow` until enough human-resolved
   evidence exists, with a visible reason.
3. **Replay**: re-evaluate recorded history with the current engine so the gate reflects the code
   and policy actually running, not the version that produced the history.
4. **Explicit override** ("I accept the risk") that skips only the sample-count requirement, is
   audited, and stays visible.
5. Settings-screen section for gate parameters and live gate status.

### Non-goals (P2a)

- Full shadow dashboard screen, disagreement browser, timeline rows (P2b).
- `agent.open.before` prompt guidance and `agent.create.before` mode policy (P2b).
- LLM judge for L1 (P3). L1 is always `ask` in P2a.
- Layered YAML policy loading (not implemented yet; see §9).
- Selecting "always allow"/persistent permission options. Never.

### Anti-goals (failure even if it "works")

- Any path where an internal error, unknown provider payload, or ambiguous option leads to an
  automatic **allow** or **deny**.
- Misattributing a human answer to the plugin, which would hide false-allows from the gate.
- The agent being able to lower the gate (edit settings/state files) and then benefit from it.
- Gate state silently surviving an engine/policy change that would have changed decisions.

## 2. Decisions taken with the user

| Topic | Decision |
| --- | --- |
| Packaging | Split P2 into P2a (this doc) and P2b |
| Gate style | Hard gate + explicit override |
| Sample definition | Human-resolved requests the **current engine** judges `allow` |
| Minimum samples | 200 (user-configurable, floor 20, max 5000) |
| Window | 30 days (configurable 1–365) |
| False-allow | Must be 0 in window; on any false-allow, fall back to `shadow` — **also when overridden** (configurable, default on) |
| Override | Allowed (configurable, default on); skips only the sample-count requirement |
| Configuration | All gate parameters editable in the plugin settings screen |
| Unit of counting | One permission request (one prompt card), not individual sub-commands; the request's level is the max over its parsed sub-commands |
| Gate scope | **Global**: one sample pool and one gate for all providers and all command kinds. The gate measures whether the engine's L0 judgement agrees with this user; it is not a per-command allow-list. New, never-seen L0 requests are auto-answered once the gate is open |
| Human denials of L0 | Count as false-allow by default; the user can **annotate** an individual denial as "not a safety issue" in the settings screen (audited); annotated denials are excluded |
| Not answered / redirected | A prompt the user never answered (e.g. they sent a new prompt instead) is never a false-allow (§3.3) |

## 3. Behaviour

### 3.1 Effective mode

```
settings.mode = off     -> effective off
settings.mode = shadow  -> effective shadow
settings.mode = act     -> effective act    iff gate.state == "passed"
                                            or (override.accepted && gate.falseAllowCount == 0)
                           effective shadow otherwise, with gate.reason
```

`falseAllowCount` here is computed over the window by replay (§3.3). The override never applies
while the gate is `replaying` or `unavailable` (false-allow count unknown ⇒ `shadow`). With
`autoFallbackOnFalseAllow = false` an override keeps `act` even with false-allows; this is the only
way to run `act` with a known false-allow and is shown as a persistent warning.

`getStatus()` returns `effectiveMode: "off" | "shadow" | "act"` plus a `gate` object (state, reason,
samples x/N, false-allow count, last replay time, engine fingerprint, override info).

### 3.2 Gate states

| State | Meaning |
| --- | --- |
| `collecting` | `samples < minSamples`, no false-allow |
| `passed` | `samples >= minSamples` and `falseAllow == 0` |
| `failed_false_allow` | at least one false-allow in window (lists up to 5 request ids) |
| `replaying` | a replay for the current engine fingerprint has not finished; effective mode is `shadow` until it finishes |
| `unavailable` | audit history unreadable or replay error; effective mode `shadow` (fail to human) |

**[ADR] Latch.** Once in `act`, the plugin answers L0 itself, so new human-resolved allow samples
stop arriving and the 30-day window would eventually drain below 200. Therefore:

- **Entering** `act` requires the full condition (samples ≥ N, false-allow = 0).
- **Staying** in `act` requires only false-allow = 0 over the window, re-checked on every
  reconciliation and every replay. The latch is stored in `gate-state.json` (§5.4) together with the
  engine fingerprint it was earned under.
- An **engine fingerprint change** (plugin version, engine data version, policy hash) clears the
  latch: a replay over the window must pass the full entry condition again. If, after an upgrade, the
  window has fewer than N human samples because the plugin had been answering, the user sees
  `collecting` and can use the override; this is intentional — a new engine has not earned trust on
  this user's data.

### 3.3 Samples and false-allows (replay)

Input set: audit records whose `requestedAt` is within the window, that have both a decision and a
resolution, and whose resolution actor is `human` (not `plugin`, not `unknown`).

**Human vs. cancelled resolutions** *(builder-review call)*. Paseo cancels pending permissions in
bulk when a turn is interrupted, the user sends a new prompt, the agent is closed, or the ACP
transport exits (`acp-internal/connection.js` resolves them as `cancelled`). Such a resolution is not
a judgement about safety. Rule:

- `allow` resolutions: human if not plugin-attributed (§3.6).
- `deny` resolutions count as a **human denial** only if `selectedActionId` is present and equals a
  deny action offered by that request (as recorded in the raw request). Otherwise the record is
  `actor = "unknown"`, category `unclassified_deny`: never a sample, never a false-allow, never
  triggers fallback, but listed (count + up to 5 ids) in the status card so it is not hidden.
- A request with no `after` event stays pending and is ignored.
- The exact Paseo payload for "user sent a new prompt while a permission was pending" must be
  confirmed during implementation and captured as a fixture.

**Annotations.** `guardian.gate.annotate({ requestId, annotation: "not_safety" | null })` stores an
annotation as an audit `event: "annotation"` line (latest wins). Annotated human denials are removed
from the false-allow count (they are not samples either). Annotations are made only from the
settings UI; the RPC is not exposed as an agent tool.

For each record the replay computes `replayVerdict` with the current engine:

- **Sample** ⇔ `replayVerdict == "allow"` and `resolution.behavior == "allow"` .
- **False-allow** ⇔ `replayVerdict == "allow"` and `resolution.behavior == "deny"`.
- Records whose action cannot be re-evaluated (missing `action`, unknown kind, decide error) are
  skipped and counted in `replaySkipped`; they never count as samples.

**[ADR] Context fidelity.** Decisions depend on session context (secret/untrusted taint, modified
entrypoints). From P2a on, `recordBefore` stores a `contextSnapshot`
`{ secretTaint, untrustedTaint, modifiedEntrypoints[] }` (paths redacted like other paths) and replay
feeds it to `decideAction`. For older records without a snapshot, replay uses
`max(recordedLevel, replayLevel)` so that missing context can only make a record *less* likely to be
a sample, never more.

**Redaction.** Replay runs on redacted actions. Redaction replaces secret values with placeholders;
the classifier works on structure (commands, paths, hosts), so this is acceptable, but any record
whose replay verdict differs from its recorded verdict *only* because of redaction cannot be
detected. This is accepted and documented; it errs toward fewer samples in the known cases
(placeholders are unknown tokens → opaque → not allow).

**When replay runs.** On daemon start, on engine-fingerprint change, and on settings change to the
gate parameters. Reconciliation of a new record updates the counters incrementally (the live
decision was produced by the current engine, so no re-evaluation is needed). Replay runs in the
background, yields between records, uses the same PowerShell host pool with its normal timeouts,
and is bounded (default 20 000 records; beyond that the oldest are ignored and `replayTruncated` is
reported).

**Not a decision cache.** Replay results are used only for gate metrics and are never consulted
when answering a live request. Live requests are always evaluated fresh (DESIGN §10.4 invariant).

### 3.4 Answering a request in `act`

In `handlePermissionBefore`, after `decideAction` and `recordBefore`:

1. If effective mode is not `act`, stop (shadow behaviour).
2. If `decision.neverAutoAnswer`, or kind ∈ {question, plan, mode}, stop.
3. Map the verdict:
   - `allow` (L0 only) → resolve an **allow-once action** (§3.5). If none can be resolved, stop.
   - `deny` (L3 with `denyAsAsk = false`) → resolve a **deny-once action**; response
     `{ behavior: "deny", selectedActionId?, message }` where `message` is a short, redacted
     explanation the agent can act on (reasons joined, max 500 chars). `interrupt` is not set.
   - `ask` → stop.
4. Check `context.signal`; if aborted, stop.
5. `markAnsweredByPlugin(requestId, { verdict, selectedActionId, behavior })` **before** calling
   Paseo, so an `after` event that arrives first is attributed correctly.
6. Call `context.paseo.agents.ref(agentId).respondToPermission({ requestId, response })`.
7. On error (already resolved by a human, agent gone, network): `unmarkAnsweredByPlugin`, log at
   debug level, record `actOutcome: "lost_race" | "error"` in the audit record. Never retry.

Latency budget: the whole path must stay well inside Paseo's 30 s hook timeout; the existing warm
pwsh timeout (1.5 s) and cold timeouts (10 s / 20 s on 5.1) apply. A cold-start timeout yields
`opaque` → L1 → ask, as today.

### 3.5 Allow-once / deny-once resolution **[ADR]**

Per-provider explicit mapping; anything not matched ⇒ do not answer.

| Provider (observed) | Allow-once | Deny-once |
| --- | --- | --- |
| `agy` | action `id == "allow"`, `behavior == "allow"`, and no other allow action exists | `id == "deny"` |
| `devin` (ACP) | candidate `id == "allow_once"` (seen only as a resolution, no raw request yet) | candidate `id == "reject_once"` |
| `claude` | candidate `id == "accept"` (seen only as a resolution, no raw request yet) | — |

*(builder-review call)* Fixtures come from the user's local shadow audit (`includeRawInAudit`
defaults to on). At design time only `agy` has raw request payloads (16 records, actions
`[allow, deny]`). **P2a enables auto-answering for `agy` only.** `devin` and `claude` stay
shadow-only until real raw payloads are captured into fixtures; enabling them is a follow-up change
that adds fixtures plus the mapping row.

Generic rules applied to every provider:

- Never select an action whose id or label matches `/always|session|remember|forever|all|persist/i`.
- If more than one candidate allow action remains, do not answer.
- Never send `updatedInput` or `updatedPermissions`.
- The mapping lives in one module (`server/act/actions.ts`) with fixtures from real payloads for each
  provider; a provider without fixtures is not auto-answered.

### 3.6 Attribution and the race with humans

`agent.permission.before` is a notification; the human sees the prompt at the same time. Paseo's
`after` event has no actor. Attribution rule:

- `actor = "plugin"` only if `answeredByPlugin` has the request **and** the resolution matches what
  the plugin sent (`behavior` equal and, if the plugin sent one, `selectedActionId` equal).
- If the plugin marked the request but the resolution differs → `actor = "human"`,
  `actOutcome = "lost_race"`. This keeps human denials visible to the gate.
- If `respondToPermission` rejects, the mark is removed (step 7) and the `after` event is attributed
  to the human.

Residual risk: a human clicking the *same* allow-once option in the same instant as the plugin is
attributed to the plugin. Both chose allow, so no false-allow is hidden.

### 3.7 False-allow while in `act`

A false-allow can only be observed from human-resolved records. While in `act`, L0 requests are
answered by the plugin, so new false-allows mostly surface via (a) lost races where the human denied,
(b) replay after an engine change, (c) humans resolving requests the plugin chose not to answer
(e.g. option not resolvable) that the engine judges allow. On any false-allow with
`autoFallbackOnFalseAllow = true`, the effective mode drops to `shadow` immediately (in-memory
first, then persisted), and the latch is cleared.

## 4. Settings (Paseo Settings, host scope)

Additive fields on `GuardianSettingsSchema`:

```ts
actGate: z.object({
  minSamples: z.number().int().min(20).max(5000).default(200),
  windowDays: z.number().int().min(1).max(365).default(30),
  autoFallbackOnFalseAllow: z.boolean().default(true),
  allowOverride: z.boolean().default(true),
}).default({}),
actOverride: z.object({
  accepted: z.boolean().default(false),
  acceptedAt: z.string().nullable().default(null),
}).default({}),
```

- Setting `actOverride.accepted = true` is ignored unless `actGate.allowOverride` is true and
  `acceptedAt` is set; the plugin writes an audit `gate_event` when it observes the change.
- Settings are edited only through the Paseo settings UI. The agent must not be able to change them
  through a request the plugin auto-allows *(builder-review call)*:
  - Path Model: the plugin data dir (audit, `gate-state.json`) and Paseo's settings storage
    location for this plugin are `write_protected` (L2). The builder locates the real settings file
    path for host-scope settings and adds it; `PASEO_GUARDIAN_DATA_DIR` overrides must be covered.
  - Command/MCP: `paseo` CLI invocations that write settings, reload/disable/remove plugins, or
    respond to permissions, and Paseo MCP tools with the same effects (e.g. `respond_to_permission`,
    settings/plugin management), are classified L2.
  - Vector tests assert all of the above are never L0.

## 5. Components and contracts

### 5.1 New / changed modules (server)

| Module | Responsibility |
| --- | --- |
| `server/act/actions.ts` | Provider allow-once / deny-once resolution (§3.5) |
| `server/act/responder.ts` | Steps 1–7 of §3.4; owns `answeredByPlugin` matching data |
| `server/gate/gate.ts` | Gate state machine, latch, effective-mode computation |
| `server/gate/replay.ts` | Reads audit JSONL within window, re-evaluates, produces counts (samples, false-allows, unclassified denials, annotated, skipped) |
| `server/gate/fingerprint.ts` | Engine fingerprint = hash(pluginVersion, engine data versions, policy hash or `"builtin"`) |
| `server/audit/store.ts` | Add `contextSnapshot`, `actOutcome`, `gate_event` entries; add a streaming reader for replay; rebuild in-memory metrics from disk on start |
| `server/guardian.ts` | Wire responder and gate; attribution rule §3.6 |
| `index.server.ts` | Pass `context.paseo` / `context.signal` into the before-hook path |

### 5.2 Shared

- `shared/settings.ts`: fields in §4.
- `shared/rpc.ts`: `guardian.status` output gains `effectiveMode: "off" | "shadow" | "act"` and
  `gate`; new RPCs `guardian.gate.replay` (manual "re-run replay now") and `guardian.gate.annotate`.
- `shared/types.ts`: `GateStatus`, `ActOutcome`, `ContextSnapshot`.

### 5.3 Client

Settings screen gains an "Automatic answering" section: mode selector (existing), gate parameters,
override checkbox with a confirmation dialog, and a read-only status card (state, reason, samples
x/N, false-allows with up to 5 entries showing the command and per-sub-command effects and an
"not a safety issue" annotate button, unclassified denials count, last replay, engine fingerprint
short hash). React
Native primitives only; strings in `client/i18n.ts` (en, zh-CN).

### 5.4 Files

- `gate-state.json` in the plugin data dir: `{ latched, fingerprint, latchedAt, lastReplay }`,
  written atomically (tmp + rename). Unreadable/corrupt ⇒ treated as not latched.
- Audit JSONL gains `event: "gate"` lines for: latch, unlatch (with reason), override accepted /
  revoked, fallback on false-allow, replay summary.

## 6. Error handling (fail to human)

| Failure | Result |
| --- | --- |
| Replay error / audit unreadable | gate `unavailable`, effective `shadow` |
| `gate-state.json` corrupt | not latched → full entry condition required |
| Unknown provider / unresolvable action | do not answer |
| `respondToPermission` throws | unmark, `actOutcome` recorded, human flow continues |
| Any exception in act path | caught; no answer; logged |
| Settings invalid | defaults (effective `shadow` because `mode` default is `shadow`) |

## 7. Testing

- Unit: action resolution per provider with real fixtures (agy, devin, claude), including
  "always"-style options and multiple-allow ambiguity → no answer.
- Unit: gate state machine (collecting → passed → latched; false-allow → fallback; fingerprint
  change → unlatch; override paths with fallback on/off).
- Unit: replay counting, context snapshot use, `max(recorded, replay)` for legacy records,
  skipped/truncated accounting.
- Unit: attribution rule incl. lost race, after-before-before ordering, mismatched resolution.
- Integration: `handlePermissionBefore` in `act` with a fake `paseo.agents.ref().respondToPermission`
  — L0 answered once, L1/L2 untouched, L3 only with `denyAsAsk=false`, errors never answer.
- Security vectors: writes to settings, gate-state, audit dir never L0.
- Daemon smoke: extend `smoke:daemon` to assert `guardian.status` reports `effectiveMode: "shadow"`
  and gate `collecting` with `mode: act` on an empty data dir.

## 8. Exit criteria for P2a

- All tests above pass on the CI matrix; typecheck and boundary checks pass.
- With `mode: act` on a fresh install, effective mode is `shadow` and the settings screen shows
  `collecting 0/200`.
- With a synthetic audit history meeting the gate, L0 requests are answered allow-once on `agy`
  fixtures and never on providers without fixtures; replaying a history containing one human-denied
  L0 request shows `failed_false_allow` and no auto-answers; annotating it `not_safety` restores
  `passed`; a cancelled (no `selectedActionId`) denial never changes the gate.
- DESIGN.md (§10.4, §11, §12, §13, §16) and ADR-0008 updated.

## 9. Left to the builder

- Exact streaming JSONL reader and how metrics are rebuilt on start (must handle rotated files and
  out-of-order before/after pairs).
- Concurrency control between replay and live reconciliation (single-writer queue is acceptable).
- Engine data version source (e.g. a constant bumped when rules/registry change) — must change
  whenever classification can change.
- Policy hash: layered YAML policy is not loaded yet; use `"builtin"` until it is, and include the
  hash once policy loading lands.
- Confirming the `claude` provider's action shape from real raw payloads before enabling it.

## 10. Approaches considered

1. **P2 as one project** — one design, one review; rejected because the act engine is the first
   time the plugin decides on the user's behalf and deserves a focused review, and UI work would
   delay collecting real samples.
2. **P2a safety core + P2b experience layer (chosen)**.
3. **UI first** — rejected; a dashboard without gate/act does not move the P2 exit criterion.

Gate variants considered: advisory only (rejected: easy to enable by mistake), hard gate without
override (rejected: new or low-volume users could never enable it), **hard gate + explicit override
(chosen)**. Gate on live recorded decisions only (rejected: every upgrade would reset the evidence)
vs **replay with the current engine (chosen)**.
