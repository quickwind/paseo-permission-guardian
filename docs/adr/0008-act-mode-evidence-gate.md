# ADR-0008: `act` Mode Behind an Evidence Gate, Replay with the Current Engine, and Provider Option Mapping

- **Status**: Proposed
- **Date**: 2026-11-22
- **Supersedes**: —
- **Superseded by**: —
- **Extends**: [ADR-0002](./0002-session-context-taint-and-cache-invalidation.md), [ADR-0003](./0003-paseo-integration-and-config-source-of-truth.md)
- **Design**: [P2a design](../superpowers/specs/2026-11-22-p2a-act-mode-design.md)

## Context

The plugin classifies permission requests deterministically (L0–L3) and so far only records them
(`shadow`). DESIGN §16 makes "false-allow = 0" the precondition for `act`, but did not define how
that evidence is measured, how it survives upgrades, or how the plugin answers safely given Paseo's
real contracts:

- `agent.permission.before` is a notification; the human sees the prompt concurrently.
- `agent.permission.after` carries no actor.
- `respondToPermission` on the plugin's Paseo client is fire-and-forget: it sends a frame and does not
  report that a request was already resolved.
- Paseo cancels pending permissions in bulk on interrupt/close/transport exit; the payload that then
  reaches `agent.permission.after` is not yet confirmed.
- Providers expose different option ids (observed: agy `allow`/`deny`; devin `allow_once`/
  `reject_once`; claude `accept`), some of which may be persistent ("always").

## Decision

1. **Evidence gate.** `act` is effective only when a global gate over the last `windowDays` (default
   30) of human-resolved requests shows `samples >= minSamples` (default 200, floor 20) and zero
   unannotated false-allows. Unit of counting is one permission request. Entering requires the full
   condition; staying (latch, bound to fingerprint and `minSamplesAtLatch`) requires only zero
   false-allows. A false-allow **suspends** the latch; annotating all suspending records resumes it;
   a suspending record that ages out unannotated clears it. Fallback to `shadow` on a false-allow is
   on by default and also applies under override; when turned off, false-allows are reported but never
   change the effective mode in any state.
2. **Replay with the current engine.** Gate metrics come from re-evaluating recorded requests with the
   engine identified by a fingerprint (plugin version, engine data version, policy hash, decision-
   affecting settings). A false-allow is judged on the replay verdict alone; legacy records without a
   context snapshot may lose but never gain sample status. Truncation, any corrupt line, an orphan
   human denial, or a human-denied record that cannot be re-evaluated (including any parser-host
   failure) make the gate unavailable (⇒ `shadow`) until resolved or acknowledged by the user.
   False-denies are judged by level (L3), independent of `denyAsAsk`. Replay results never feed live
   decisions.
3. **Fingerprint binding.** A fingerprint change clears the latch and invalidates the override.
4. **Override.** "I accept the risk" skips only the sample count, is bound to the fingerprint, never
   applies while replaying/unavailable, and is audited.
5. **Human denials.** Every non-plugin `deny` counts as a human denial unless it matches a confirmed
   cancellation signature captured from real payloads (initially none). Users may annotate an
   individual denial as "not a safety issue"; annotations are audited and excluded from false-allows.
6. **Answering.** Only L0 → allow-once and (with `denyAsAsk=false` and zero false-denies) L3 →
   deny-once. Options are selected by explicit per-provider id mapping backed by real fixtures;
   persistent-looking or ambiguous options, missing ids, or providers without fixtures ⇒ no answer.
   `updatedInput`/`updatedPermissions` are never sent. P2a enables agy only.
7. **Attribution.** The plugin marks a request before answering; an `after` event is attributed to the
   plugin only if behaviour and `selectedActionId` match what was sent and it arrives within 15 s.
   Success/loss is inferred from `after`, never from the fire-and-forget call. If `after` already
   arrived, the plugin does not answer. Three consecutive unconfirmed answers pause answering. Gate
   counters are updated at the audit merge point in every mode.
8. **Prerequisite hardening.** Gaps that would become wrong auto-allows (empty-path reads, swallowed
   timeline failures and unknown timeline items, ignored invalid settings, plugin-self and Paseo
   control paths/env/CLI/MCP including `mcp_<server>_<tool>` spellings, sandbox-bypass flags,
   multi-ecosystem entrypoints) are fixed before `act` can be effective; raise-only rules ship even
   where the provider behaviour is not yet confirmed.
9. **Not a security boundary.** Editing ordinary code (L0) and then running a project command (L0) is
   allowed in `act`; this is documented as outside the plugin's guarantees.

## Consequences

### Positive

- `act` can only be reached on evidence from the user's own decisions, measured against the code
  actually running, and is withdrawn on the first observed disagreement.
- Upgrades re-earn trust automatically from history instead of resetting it.
- Races with humans cannot hide human denials from the gate.

### Negative / Trade-offs

- Low-volume users need weeks to reach 200 samples or must use the override.
- Until the cancellation payload is confirmed, redirecting an agent by sending a new prompt may
  register as a false-allow that the user has to annotate.
- Replay costs CPU and PowerShell host time on start and after upgrades.
- Only agy is auto-answered in P2a.

### Follow-up / Guardrails

- Capture and fixture real cancellation payloads, devin/claude request payloads, and any
  single-underscore MCP naming before widening behaviour.
- `ENGINE_DATA_VERSION` must be bumped with any change that can alter a decision.
- Tests listed in the P2a design §8 are required; DESIGN.md §10.4/§11/§12/§13/§14/§16 must be updated.

## Alternatives Considered

1. **Advisory gate** — easy to enable by mistake.
2. **Hard gate without override** — low-volume users could never enable `act`.
3. **Gate on live recorded decisions only** — every upgrade would reset evidence or keep stale trust.
4. **Per-provider or per-category pools** — starves low-volume providers/categories; the engine is
   provider-independent and option mapping is already fixture-gated.
5. **Treat any code edit as making later project commands L1** — removes the edit→test loop that
   `act` exists to automate; isolation belongs to sandboxes.
6. **Exclude every denial without a clicked option** — could let a provider's genuine denials never
   count, producing a false pass.
