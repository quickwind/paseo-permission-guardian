# P2a: `act` Mode with Evidence Gate — Design

- **Date**: 2026-11-22
- **Status**: Approved (v3, 2026-11-22) — builder check and two independent review rounds (neon) incorporated
- **Milestone**: P2a (safety core). P2b (shadow dashboard screen, timeline rows, prompt guidance,
  mode policy) is a separate design.
- **Related**: [DESIGN.md](../../DESIGN.md) §10.4, §12, §13, §14, §16;
  [ADR-0002](../../adr/0002-session-context-taint-and-cache-invalidation.md),
  [ADR-0003](../../adr/0003-paseo-integration-and-config-source-of-truth.md),
  [ADR-0008](../../adr/0008-act-mode-evidence-gate.md) (records the decisions marked **[ADR]**).

## 1. Intent

Until now the plugin only classifies and records (`shadow`). P2a makes it actually answer routine
permission prompts for the user (`act`), but only after the user's own history shows that the
plugin's "would allow" judgement has never disagreed with a human denial. The point is to remove
prompt fatigue for clearly routine actions without the plugin becoming the reason a risky action ran.

### Goals

1. `act` mode that auto-answers **L0 → allow-once** and, only when `denyAsAsk` is off,
   **L3 → deny-once with a message**. Everything else stays with the human.
2. An **evidence gate** that keeps the effective mode at `shadow` until enough human-resolved
   evidence exists, with a visible reason.
3. **Replay**: re-evaluate recorded history with the current engine so the gate reflects the code
   and configuration actually running.
4. **Explicit override** ("I accept the risk") that skips only the sample-count requirement, is
   bound to the current engine, audited, and always visible.
5. Settings-screen section for gate parameters, live gate status, and false-allow annotation.
6. **Prerequisite hardening** (§3.9): close existing classification gaps that are harmless in
   `shadow` but would become wrong auto-allows in `act`.

### Non-goals (P2a)

- Full shadow dashboard screen, disagreement browser, timeline rows (P2b).
- `agent.open.before` prompt guidance and `agent.create.before` mode policy (P2b).
- LLM judge for L1 (P3). L1 is always `ask` in P2a.
- Layered YAML policy loading (not implemented yet; see §10).
- Selecting "always allow"/persistent permission options. Never.
- **Being a security boundary.** The plugin is a prompt reducer (DESIGN §14). In `act`, an agent can
  edit ordinary source/test files (L0) and then run a project command (L0) that executes them; this
  is accepted (decision §2) and documented. Isolation belongs to OS/provider sandboxes.

### Anti-goals (failure even if it "works")

- Any path where an internal error, unknown provider payload, or ambiguous option leads to an
  automatic **allow** or **deny**.
- Misattributing a human answer to the plugin, or a human denial to "cancelled", in a way that hides
  false-allows from the gate.
- The agent being able to lower the gate (edit settings/state/audit files, change env) through a
  request the plugin auto-answers, and then benefit from it.
- Gate state or an override silently surviving an engine/configuration change.

## 2. Decisions taken with the user

| Topic | Decision |
| --- | --- |
| Packaging | Split P2 into P2a (this doc) and P2b |
| Gate style | Hard gate + explicit override |
| Unit of counting | One permission request (one prompt card); its level is the max over its parsed sub-commands |
| Gate scope | **Global**: one sample pool and one gate for all providers and command kinds. It measures whether the engine's L0 judgement agrees with this user; it is not a per-command allow-list. New, never-seen L0 requests are auto-answered once the gate is open |
| Sample definition | Human-resolved requests the current engine judges `allow` (any mix of read/write/exec; **no coverage requirement**) |
| Minimum samples | 200 (configurable, floor 20, max 5000) |
| Window | 30 days (configurable 1–365) |
| False-allow | Must be 0 in window; on any false-allow fall back to `shadow` — also when overridden (configurable, default on) |
| Human denials of L0 | Count as false-allow; the user can **annotate** an individual one as "not a safety issue" (audited) to exclude it |
| Denials without a clicked option | **Count as false-allow (annotatable) until Paseo's cancellation payload is confirmed**; afterwards only payloads matching the confirmed cancellation signature are excluded automatically |
| Override | Allowed (configurable, default on); skips only the sample-count requirement |
| Edit code then run project command | Stays L0; documented as outside the plugin's guarantees; gate files integrity-checked; **entrypoint list extended to more ecosystems** (§3.9) |
| Configuration | All gate parameters editable in the plugin settings screen |

## 3. Behaviour

### 3.1 Engine fingerprint **[ADR]**

`fingerprint = sha256(pluginVersion, ENGINE_DATA_VERSION, policyHash ?? "builtin", denyAsAsk,
windowsDefaultShell)`. `ENGINE_DATA_VERSION` is a constant bumped whenever rules, registry data, or
classification code can change a decision. Anything that can change a live decision must be in the
fingerprint.

### 3.2 Gate states and effective mode **[ADR]**

| State | Meaning |
| --- | --- |
| `replaying` | No completed replay for the current fingerprint yet |
| `unavailable` | Replay failed, history unreadable, truncated, or a human-denied record could not be re-evaluated (§3.4) |
| `failed_false_allow` | ≥1 unannotated false-allow in window |
| `collecting` | No false-allow, `samples < minSamples`, not latched |
| `passed` | No false-allow, `samples >= minSamples` (entry condition met) |
| `latched` | Entered `act` under the current fingerprint and `minSamples`; stays while false-allow = 0 |
| `suspended` | Latched, but ≥1 unannotated false-allow appeared after latching (see Latch rules) |

```
settings invalid                               -> shadow
mode == off                                    -> off
mode == shadow                                 -> shadow
mode == act:
  state in {replaying, unavailable}            -> shadow   (nothing overrides this)
  falseAllow > 0 && autoFallbackOnFalseAllow   -> shadow   (latched ⇒ suspended; override does not help)
  falseAllow > 0 && !autoFallbackOnFalseAllow:
       latchValid || overrideValid             -> act + persistent warning
       otherwise                               -> shadow
  latchValid                                   -> act
  samples >= minSamples                        -> act, write latch (state passed → latched)
  overrideValid                                -> act      (no latch written)
  otherwise                                    -> shadow   (collecting)

latchValid    = gate-state.latched && gate-state.fingerprint == fingerprint
                && minSamples <= gate-state.minSamplesAtLatch && !suspended
overrideValid = allowOverride && actOverride.accepted && actOverride.fingerprint == fingerprint
```

`autoFallbackOnFalseAllow = false` therefore means exactly one thing in every state: false-allows are
reported but do not change the effective mode.

- **Latch.** In `act` the plugin answers L0 itself, so new human allow samples stop arriving and the
  window would drain below N. Entering needs the full condition; staying needs only
  false-allow = 0 (re-checked on every reconciliation and replay). The latch (`gate-state.json`)
  records `fingerprint` and `minSamplesAtLatch`; raising `minSamples` above the latched value
  invalidates it (lowering does not create one retroactively).
- **Suspension, not deletion.** A false-allow while latched sets `suspendedBy: [requestId…]`.
  Annotating all of them `not_safety` lifts the suspension and resumes `act` without re-earning
  samples (so a mis-counted redirect/cancellation does not cost weeks). If a suspending record ages
  out of the window unannotated, the latch is **cleared** and the full entry condition applies again
  — a real disagreement never resolves itself by time.
- **Fingerprint change** clears the latch **and invalidates the override**. A replay must pass the
  entry condition again, or the user must re-accept the override for the new fingerprint.
- **Auto-deny gate.** L3 auto-deny additionally requires false-deny = 0 in window (a human allowed a
  request the current engine would deny); otherwise L3 is left to the human even in `act`.

`guardian.status` returns `effectiveMode: "off" | "shadow" | "act"` and a `gate` object (state,
reason, samples x/N, false-allow and false-deny counts, unannotated false-allow entries (≤5),
`unconfirmed` act-answer count, data-integrity issues (corrupt lines, orphan denials), last replay
time, fingerprint short hash, override info).

### 3.3 Human vs. cancelled resolutions **[ADR]**

Paseo cancels pending permissions in bulk when a turn is interrupted, the user sends a new prompt,
the agent closes, or the ACP transport exits (`acp-internal/connection.js` resolves them as
`cancelled`). The exact shape that reaches `agent.permission.after` is **not yet confirmed**.

- `recordBefore` stores `offeredActions: [{ id, behavior }]` from the request **independently of
  `includeRawInAudit`** (ids/behaviors only, no labels needed).
- `allow` resolution not attributed to the plugin (§3.6) → human allow.
- `deny` resolution not attributed to the plugin → **human denial**, unless it matches a
  **confirmed cancellation signature**. The signature list starts **empty**; it is filled only from
  captured real payloads (fixture + test). Until then every such denial counts (and is annotatable).
- A request with no `after` event stays pending and is ignored.

### 3.4 Replay, samples and false-allows **[ADR]**

Input: records whose `requestedAt` (or, for orphan resolutions, `resolvedAt`) is in the window, with
a resolution and actor `human`.

- **Orphan human denial** (resolution without a decision, e.g. the `before` handler failed or crashed):
  cannot be replayed ⇒ gate `unavailable`, listed as an integrity issue that the user can
  acknowledge via annotation (`not_safety`), which excludes it.
- **Corrupt line** anywhere in the window ⇒ `unavailable`, listed with file + line hash; the user can
  acknowledge it (audited annotation keyed by `file#sha256(line)`).

For each record compute `replayVerdict` with the current engine, using the stored
`contextSnapshot` (§3.7) when present:

- **False-allow** ⇔ `replayVerdict == "allow"` ∧ human denial ∧ not annotated `not_safety`.
  Judged on the **replay verdict alone** (a regression that newly allows a previously denied request
  must surface).
- **Sample** ⇔ human allow ∧ `replayVerdict == "allow"` ∧ (record has a context snapshot, or the
  recorded verdict was also `allow`). Legacy records without a snapshot can only *lose* sample
  status from missing context, never gain it.
- **False-deny** ⇔ `replayLevel == "L3"` ∧ human allow (by level, so it is measured even while
  `denyAsAsk = true` maps L3 to `ask`).
- **Skipped**: action missing/unknown kind/decide error. A skipped **human-denied** record makes the
  gate `unavailable` (it might be a false-allow); skipped allows are just not samples.
- **Truncation**: replay is bounded (default 20 000 records in window). If the bound is hit the gate is
  `unavailable` — no partial result is used.
- **Isolation**: replay uses its own PowerShell host instances (separate queue and circuit breaker)
  so it can neither starve nor be starved by live requests. A pwsh timeout during replay yields the
  normal `opaque` result for that record. Any parser-host failure on a **human-denied** record
  (`timeout`, `circuit_open`, `crashed`, `spawn_error`, or any `opaque:pwsh_host_*` reason) makes the
  gate `unavailable` until that record can be evaluated.
- **Filesystem drift**: replay should not depend on the current state of paths that may no longer
  exist (deleted worktrees). The builder decides how (e.g. `skipHostRealpath` with stored resolved
  paths); the result must be deterministic for a given record and fingerprint.
- **When**: on daemon start, on fingerprint change, on gate-parameter change, on annotation change,
  and on demand (`guardian.gate.replay`). New reconciliations update counters incrementally.
- **Not a decision cache**: replay results feed only gate metrics, never a live answer.

### 3.5 Answering a request in `act`

In `handlePermissionBefore`, after normalization, context snapshot, `decideAction`, `recordBefore`:

Gate counters are updated wherever `before` and `after` are merged in the audit store, in every mode
— not inside this act path — so out-of-order events always reach the gate.

`recordBefore` updates the in-memory record first and appends to disk asynchronously; the act path
never waits for disk I/O.

1. Effective mode must be `act`; otherwise stop.
2. If the in-memory record for this `requestId` already has a resolution (the `after` event arrived
   first), stop.
3. Stop if `decision.neverAutoAnswer` or kind ∈ {question, plan, mode}.
4. Map verdict: `allow` (L0) → allow-once action (§3.8); `deny` (L3, `denyAsAsk = false`, auto-deny
   gate open) → deny-once action + message (reasons, redacted, ≤500 chars, no `interrupt`); `ask` →
   stop. If no action resolves, stop.
5. Re-check effective mode and `context.signal` immediately before sending.
6. `markAnsweredByPlugin(requestId, { behavior, selectedActionId, sentAt })`.
7. `context.paseo.agents.ref(agentId).respondToPermission({ requestId, response })`.
   **This call is fire-and-forget** (the daemon client only sends a frame; it does not report "already
   resolved"). Success or loss is determined only by the `after` event (§3.6). A thrown error (e.g.
   disconnected client) unmarks the request and records `actOutcome: "error"`.

Latency stays well inside Paseo's 30 s hook timeout. Audit writes before step 7 must not block on
slow disk beyond the existing write queue; the step 2 check uses the in-memory record.

### 3.6 Attribution

- `actor = "plugin"` only if the request is marked, the resolution matches what the plugin sent
  (`behavior` and `selectedActionId` equal), **and** it arrives within the attribution window
  (15 s after `sentAt`). A matching resolution arriving later is attributed to the human (the
  plugin's frame was evidently not applied).
- Marked but different resolution → `actor = "human"`, `actOutcome = "lost_race"`; a human denial
  here is a false-allow candidate and triggers fallback immediately.
- Marked but no `after` within the window → `actOutcome = "unconfirmed"`. Three consecutive
  `unconfirmed` outcomes ⇒ act answering pauses (effective `shadow`, reason
  `responder_unconfirmed`) until the next confirmed answer path check on daemon restart or a manual
  replay. The mark itself is kept for the existing 10 min TTL only to recognise late events.
- Residual: a human clicking the *same* option at the same instant is attributed to the plugin; both
  chose the same answer, so no false-allow is hidden.

### 3.7 Context snapshot

Taken **before** `decideAction` (so it reflects the state the decision saw, not effects of this
request): `{ secretTaint, untrustedTaint, modifiedEntrypoints[], modifiedFiles[] }`, paths redacted,
`modifiedFiles` capped at 200 entries (cap reached ⇒ flag `modifiedFilesTruncated`, and replay
treats the record as having no snapshot).

### 3.8 Allow-once / deny-once resolution **[ADR]**

Mapping by **action id** (labels may be localized and are only an extra guard).

| Provider | Allow-once | Deny-once | Enabled in P2a |
| --- | --- | --- | --- |
| `agy` | `id == "allow"`, `behavior == "allow"`, exactly one allow action offered | `id == "deny"`, exactly one deny action offered | **Yes** (16 real raw payloads in local audit, actions `[allow, deny]`) |
| `devin` (ACP) | candidate `allow_once` | candidate `reject_once` | No — resolution ids seen, no raw request yet |
| `claude` | candidate `accept` | — | No — resolution id seen, no raw request yet |

Rules for every provider: never select an id/label matching
`/always|session|remember|forever|all|persist/i`; never answer if more than one candidate remains;
**never answer without a `selectedActionId`** (no bare `{behavior}` responses); never send
`updatedInput` or `updatedPermissions`. Enabling another provider = adding real fixtures + a mapping
row + tests.

### 3.9 Prerequisite hardening (must land before `act` can be effective)

Verified gaps that are harmless in `shadow` but would be wrong auto-allows in `act`:

1. **Read with no recognised path ⇒ L0** (`server/effects.ts` adds a bare `read` when `paths` is
   empty). Change to `opaque` (L1). Add `Path` (agy's key, verified in local audit) to path keys.
2. **Timeline sync failure** in `syncFromTimeline` is swallowed and returns un-tainted state.
   For context-sensitive kinds, a failed sync must add `opaque:context_unavailable`.
3. **Invalid settings** are ignored by the subscription, so the plugin keeps the previous mode
   (possibly `act`). Invalid ⇒ effective `shadow` with reason.
4. **Plugin-self paths**: add `~/.paseo/**`, `$PASEO_HOME/**`, `$PASEO_PLUGIN_DIR/**`, and the
   resolved `PASEO_GUARDIAN_DATA_DIR` to the Path Model as `pluginSelf` (writes L3, reads
   `read_secret` for config files). Assignments to `PASEO_HOME`, `PASEO_PLUGIN_DIR`,
   `PASEO_GUARDIAN_DATA_DIR` in any shell are L2.
5. **Paseo control surface**: `paseo` CLI subcommands that write settings, manage plugins, or respond
   to permissions, and Paseo MCP tools with those effects (e.g. `respond_to_permission`, settings,
   plugin management, `send_agent_prompt` to other agents) are L2. MCP name parsing accepts the
   provider spellings actually observed; the single-underscore form (`mcp_<server>_<tool>`) is
   to be confirmed from real payloads, but the conservative rule ships in P2a regardless:
   names matching `^mcp_[a-z0-9-]+_` are parsed as MCP (server = segment after `mcp_`), and any
   `paseo` server tool is L2 unless explicitly listed read-only. `paseo` CLI detection skips leading
   global options (`--home`, `--host`, `--json`, …) before matching subcommands.
6. **Sandbox-bypass flags**: any input key matching `/^(bypass_?sandbox|dangerously.*|unsandboxed)$/i`
   with a truthy value ⇒ L2. Reported for agy as `BypassSandbox` (not yet seen in local audit); the
   rule ships in P2a regardless because it can only raise levels.
7. **Entrypoints**: extend `isBuildOrScriptEntrypoint` with `build.rs`, `conftest.py`, `setup.py`,
   `setup.cfg`, `noxfile.py`, `tox.ini`, `Taskfile.yml`/`Taskfile.yaml`, `justfile`, `build.gradle`,
   `build.gradle.kts`, `settings.gradle(.kts)`, `pom.xml`, `CMakeLists.txt`, `meson.build`,
   `Rakefile`, `Gemfile`, `composer.json`, `deno.json(c)`, `bunfig.toml`, `.cargo/config.toml`,
   `Directory.Build.props`, `*.csproj`, and `.husky/**`/`.git/hooks/**` (already protected).
8. **Unknown timeline items**: `syncFromTimeline` ignores ACP tool calls whose `detail.type` is
   `unknown`. Such items (completed tool calls of unknown type) set `untrustedTaint` for the session,
   since their output may carry untrusted content.

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
  fingerprint: z.string().nullable().default(null),
}).default({}),
```

The settings UI fills `fingerprint` from `guardian.status` when the user accepts. The plugin writes
an audit `gate` event when it observes override acceptance/revocation.

## 5. Gate integrity and tamper resistance

- `gate-state.json` (`{ version, latched, fingerprint, latchedAt, lastReplay }`) is schema-validated;
  unreadable, unknown version, or fingerprint mismatch ⇒ not latched. It is written atomically.
- Audit lines are parsed defensively; malformed lines are skipped and counted; a malformed line in a
  file that also contains human-denied records ⇒ `unavailable`.
- Annotations are audit `event: "annotation"` lines (latest wins) written only via
  `guardian.gate.annotate`.
- Plugin RPCs (`guardian.gate.annotate`, settings writes) are reachable by any local Paseo client,
  not just the UI. An agent reaching them needs either a Paseo MCP tool (L2 per §3.9.5) or an inline
  script/network client (`exec_inline`, L1), so neither is auto-answered. Same-user processes
  running already-approved project code can still forge local files; this is within the documented
  non-goal (§1).

## 6. Components and contracts

### 6.1 Server

| Module | Responsibility |
| --- | --- |
| `server/act/actions.ts` | Provider allow-once / deny-once resolution (§3.8) |
| `server/act/responder.ts` | §3.5 steps; `answeredByPlugin` payloads; attribution (§3.6) |
| `server/gate/gate.ts` | State machine, effective mode, latch, override validity (§3.2) |
| `server/gate/replay.ts` | Streaming JSONL read within window, re-evaluation, counts (§3.4) |
| `server/gate/fingerprint.ts` | §3.1 |
| `server/audit/store.ts` | `offeredActions`, `contextSnapshot`, `actOutcome`, `gate`/`annotation` events; streaming reader; rebuild in-memory metrics on start |
| `server/guardian.ts` | Wiring; snapshot before decide; invalid-settings handling |
| `server/effects.ts`, `server/paths/*`, `server/normalize/*`, `server/context/session.ts` | §3.9 hardening |
| `index.server.ts` | Pass `context.paseo` and `context.signal` into the before path; handle `invalid` settings state |

### 6.2 Shared

- `shared/settings.ts`: §4.
- `shared/rpc.ts`: `guardian.status` gains `effectiveMode: "off" | "shadow" | "act"` and `gate`;
  new `guardian.gate.replay` and `guardian.gate.annotate({ requestId, annotation: "not_safety" | null })`.
- `shared/types.ts`: `GateStatus`, `GateState`, `ActOutcome`, `ContextSnapshot`, `OfferedAction`.

### 6.3 Client

Settings screen "Automatic answering" section: mode selector, gate parameters, override checkbox
with confirmation dialog (shows what it skips and that it expires on upgrade), and a status card:
state, reason, samples x/N, false-allow entries (command + per-sub-command effects + "not a safety
issue" button), false-deny count, unconfirmed count, integrity issues with acknowledge buttons, last replay,
fingerprint short hash. React Native primitives only; strings in `client/i18n.ts` (en, zh-CN).

## 7. Error handling (fail to human)

| Failure | Result |
| --- | --- |
| Replay error, truncation, unreadable history, skipped human denial | `unavailable` ⇒ `shadow` |
| `gate-state.json` corrupt / fingerprint mismatch | not latched |
| Settings invalid | `shadow` |
| Unknown provider / unresolvable or ambiguous action | no answer |
| `after` already present before answering | no answer; evaluate immediately |
| `respondToPermission` throws | unmark, `actOutcome: "error"` |
| Any exception in act path | caught; no answer; logged |
| Timeline sync failure (context-sensitive kinds) | `opaque` ⇒ L1 |

## 8. Testing

- Action resolution per provider with real agy fixtures; always/session options, multiple
  candidates, missing ids, localized labels → no answer; devin/claude never answered.
- Gate state machine: every row of §3.2 incl. override + fingerprint change, autoFallback on/off in
  latched/override/collecting states, replaying/unavailable with override, auto-deny gate,
  `minSamples` raised after latching, suspension lifted by annotation, suspension aging out ⇒ latch
  cleared.
- Integrity: corrupt line ⇒ unavailable until acknowledged; orphan human denial ⇒ unavailable until
  annotated; parser-host failure on a human denial ⇒ unavailable.
- Responder: after-before ordering in shadow and act both reach the gate; matching resolution after
  15 s ⇒ human; three unconfirmed ⇒ paused.
- Replay: false-allow from replay verdict only; legacy sample rule; skipped human denial ⇒
  unavailable; truncation ⇒ unavailable; annotations; isolated pwsh host.
- Attribution: lost race (human deny), same-option race, after-before ordering, unconfirmed TTL,
  thrown error.
- Cancellation: unconfirmed signature ⇒ counted; a confirmed-signature fixture (once captured) ⇒
  excluded.
- §3.9 vectors: empty-path read ⇒ L1; `Path` key; timeline failure ⇒ opaque; invalid settings ⇒
  shadow; plugin-self paths and env assignments; paseo CLI/MCP control surface; new entrypoints for
  Go/Python/Rust/JVM/.NET/Ruby/PHP/Deno.
- Integration: `handlePermissionBefore` in `act` with a fake `respondToPermission`.
- Daemon smoke: `mode: act` on empty data dir ⇒ `effectiveMode: "shadow"`, state `collecting`.

## 9. Exit criteria for P2a

- All tests pass on the CI matrix; typecheck and boundary checks pass.
- Fresh install with `mode: act` ⇒ effective `shadow`, status `collecting 0/200`.
- Synthetic history meeting the gate ⇒ L0 answered allow-once on agy fixtures only; one human-denied
  L0 in history ⇒ `failed_false_allow`, no auto-answers; annotating it ⇒ `passed`.
- All §3.9 hardening items landed (items marked "to be confirmed" either confirmed with fixtures or
  shipped with the conservative behaviour described there).
- DESIGN.md (§10.4, §11, §12, §13, §14, §16) and ADR-0008 updated.

## 10. Left to the builder

- Streaming JSONL reader, metrics rebuild on start, concurrency between replay and live
  reconciliation (a single-writer queue is acceptable).
- How replay avoids filesystem drift (§3.4) deterministically.
- `ENGINE_DATA_VERSION` mechanics (must change whenever decisions can change).
- Policy hash once YAML policy loading lands (`"builtin"` until then).
- Locating Paseo's host-scope settings file path for this plugin and the exact `paseo` CLI / MCP tool
  names for §3.9.5.

## 11. Approaches considered

1. **P2 as one project** — rejected; the act engine is the first time the plugin decides on the
   user's behalf and deserves a focused review; UI work would delay collecting real samples.
2. **P2a safety core + P2b experience layer (chosen)**.
3. **UI first** — rejected; a dashboard without gate/act does not move the P2 exit criterion.

Gate variants: advisory only (rejected: easy to enable by mistake); hard gate without override
(rejected: low-volume users could never enable it); **hard gate + override bound to fingerprint
(chosen)**. Evidence from live decisions only (rejected: upgrades would reset evidence) vs **replay
with the current engine (chosen)**. Per-provider or per-category pools (rejected by user: would
starve low-volume providers/categories; the engine is provider-independent and option mapping is
gated by fixtures). Treating any code edit as making later project commands L1 (rejected by user:
would remove the edit→test loop that `act` exists to automate).

## 12. Review log

- Builder check (2026-11-22): 6 questions; 2 answered by the user (annotation, global scope), 4
  settled as design calls (cancellations, tamper scope, fixtures, override during replay).
- Independent review by neon (`agy/gemini-4-neon`, 2026-11-22): 8 findings. Verified in code:
  fire-and-forget `respondToPermission`; empty-path read ⇒ L0; `Path` key missing; invalid settings
  ignored; `mcp__`-only parsing. Not yet verified: `BypassSandbox`, single-underscore MCP names,
  cancellation payload shape (marked "to be confirmed"). All findings incorporated; #1 and #8
  decided by the user (count unclear denials until confirmed; no coverage requirement); the
  edit-then-run concern decided by the user (stay L0, document, extend entrypoints).
- Independent review round 2 by neon (2026-11-22): round-1 items 1 and 7 resolved, 2–6 partially; 5 new
  findings. Verified: ACP `detail.type: "unknown"` timeline items ignored by `session.ts`. Not found
  in local data or SDK: `BypassSandbox`, `mcp_paseo_*` (rules shipped anyway as raise-only). v3 adds:
  integrity rules (corrupt lines, orphan denials, all host failures ⇒ unavailable), latch bound to
  `minSamplesAtLatch`, suspension instead of deletion (designer's call to keep the user's
  "count until confirmed" choice from costing weeks), unified `autoFallbackOnFalseAllow` semantics,
  gate updates at the merge point in every mode, memory-first `recordBefore`, 15 s attribution
  window and unconfirmed pause, false-deny by level, mandatory raise-only MCP/sandbox rules.

## Errata (implementation)

Added 2026-11-22; earlier sections are unchanged.

- **R7 (persistence-option pattern).** §3.8's literal `/always|session|remember|forever|all|persist/i`
  also matches agy's own `allow` (it contains `all`). The implemented pattern treats `all` as a
  standalone word only; the other terms keep substring matching.
- **R10 (replay samples).** Replay never counts a human-attributed allow whose `actOutcome` is
  `unconfirmed` or `lost_race` as a sample (the outcome of the plugin's own answer is unclear, so the record is not trusted
  as human evidence).
- **R11 (Paseo self roots).** §3.9.4's literal `~/.paseo/**` also covers Paseo's default worktree
  location `~/.paseo/worktrees/...`, which made ordinary worktree edits L3 and repo `config.json`
  reads secret reads. For the Paseo home roots `~/.paseo` and `$PASEO_HOME` (POSIX and Windows,
  including `%USERPROFILE%\.paseo`, `%PASEO_HOME%` and `$env:PASEO_HOME`) only these are plugin-self:
  the root itself, `config.json`, `settings.json`, `plugin-settings/**`, `plugins/**`,
  `permission-guardian/**`, `state/**`, and root-level `*.key`, `*.pem` and `daemon*.json`. Writes to
  them are L3 plugin-self; reads of `config.json`, `settings.json` and `plugin-settings/**/*.json`
  are secret reads. `worktrees/**` and every other subpath are ordinary. `PASEO_PLUGIN_DIR`,
  `PASEO_GUARDIAN_DATA_DIR` and the plugin data dir stay whole-root. A worktree that itself lies
  inside a protected subtree (e.g. `~/.paseo/plugins/x`) keeps the protection.
