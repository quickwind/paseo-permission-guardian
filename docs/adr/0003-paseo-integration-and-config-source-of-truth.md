# ADR-0003: Paseo Hook Integration Boundaries and Configuration Source of Truth

- **Status**: Accepted
- **Date**: 2026-11-08
- **Supersedes**: —
- **Superseded by**: —

## Context

Verified against Paseo's plugin reference and hooks documentation (Paseo 0.16 / 0.17-beta):

- `agent.permission.before` is a non-blocking notification hook (`{ agent, request }`) with a 30 s timeout and `context.signal`. Events may overlap concurrently and completion order is not guaranteed.
- `agent.permission.after` delivers `{ agent, requestId, resolution }` where `resolution` is `AgentPermissionResponse` — it does **not** carry an `actor`/`decidedBy` field.
- `agent.open.before` supports `appendSystemPrompt`, but **the ACP adapter does not send system instructions to its providers** (and Codex requires `>= 0.121.0`).
- `paseo.agents.ref(id).timeline.append(...)` stores rows in daemon memory only (lost on daemon restart) and caps `data` at 64 KiB.
- Paseo provides `defineSettings` + `server.registerSettings` + `client.addSettingsScreen` for host-persisted JSON settings, while this plugin also supports layered YAML policy files (`policy.yaml`, team policy, pinned `.paseo-guardian.yaml`).
- The plugin targets pure Node.js with no native binaries, whereas `better-sqlite3` is a native addon.
- Registry publishing requires `OVERVIEW.md` beside `paseo-plugin.json` and an accurate `requirements.paseo` semver range.

## Decision

1. **Actor attribution & out-of-order reconciliation**: Track plugin-submitted resolutions in an in-memory map (`answeredByPlugin: Map<requestId, { decision, answeredAt }>` with TTL eviction). Reconcile `before` and `after` records by `requestId` using upsert/merge semantics so out-of-order completion (e.g., human clicks approve before analysis finishes) never corrupts audit metrics. In `shadow` mode, note that non-plugin resolutions are assumed human unless canceled.
2. **No hard reliance on `appendSystemPrompt` for ACP**: Keep `agent.open.before` prompt guidance strictly optional and document clearly that it applies to providers supporting system instructions (e.g., Claude Code, Codex >= 0.121.0) and is a no-op on ACP agents.
3. **Clear configuration Source of Truth**:
   - **Paseo Settings (`defineSettings`, host scope)**: Owns runtime UI controls — `mode` (`off | shadow | act`), `denyAsAsk`, `llm` toggle/provider/model, local policy file paths, project policy sha256 pins, and timeline verbosity.
   - **Layered YAML Policy**: Owns declarative security rules — `trusted` domains/environments/MCP, `paths` (sensitive/protected), `commands`, and `shells`. The UI never rewrites user YAML files (preserving comments and formatting); it reads and validates them.
   - **Team Policy**: Loaded from a configured local file path only (teams distribute via Git, dotfiles, or MDM), avoiding remote-fetch complexity and supply-chain/MITM surface.
4. **Low-noise timeline rows**: Do not spam a timeline row for every routine auto-allow by default. Default to appending compact timeline rows for `deny` and `shadow` disagreements (configurable to `all | notable | off`).
5. **Pure Node.js audit storage**: Use rotated append-only JSONL files plus an in-memory/compact JSON summary index for dashboard metrics. Do not depend on native SQLite addons.
6. **Signal propagation & registry readiness**: Pass `context.signal` (combined with a shorter 3–5 s abort timeout) to all external LLM calls. Maintain `OVERVIEW.md` and accurate `requirements.paseo` from P0.

## Consequences

### Positive

- Aligns 100% with Paseo's real runtime contracts and avoids subtle race conditions.
- Zero native-binary installation friction across macOS, Linux, and Windows.
- Clean separation between UI toggles and version-controlled YAML policy files.

### Negative / Trade-offs

- Without a Paseo waiting hook (`agent.permission.decide`), approval cards can briefly flash before the plugin responds, especially if the optional LLM judge is enabled.
- Large historical audit queries over JSONL require streaming/filtering rather than SQL, though daily rotation keeps dashboard windows fast.

### Follow-up / Guardrails

- Track upstream Paseo waiting-hook proposal (§12.3) and feature-detect it when available.
- Test concurrent `agent.permission.before` bursts and human-races-plugin scenarios in unit/integration tests.

## Alternatives Considered

1. **Write UI changes back into `policy.yaml`** — Rejected because YAML round-tripping destroys comments/formatting and creates race conditions with user edits.
2. **Use `better-sqlite3` for audit indexing** — Rejected because native addons break the pure Node.js cross-platform goal.
3. **Append a timeline row for every permission check** — Rejected because it clutters conversations and does not survive daemon restarts.
