# AGENTS.md

Instructions for coding agents working in `paseo-permission-guardian`.

## Project Overview

`paseo-permission-guardian` is a pure Node.js Paseo plugin that classifies the risk of agent tool
calls using deterministic AST parsing, effect tags, combination rules, and session context,
auto-answering routine permission prompts while keeping humans in the loop for risky actions.

## Required Reading Before Making Changes

- System design: `docs/DESIGN.md`
- Architecture Decision Records (ADRs): `docs/adr/README.md`
  - `docs/adr/0001-deterministic-ast-first-with-effect-tags.md`
  - `docs/adr/0002-session-context-taint-and-cache-invalidation.md`
  - `docs/adr/0003-paseo-integration-and-config-source-of-truth.md`
  - `docs/adr/0004-cross-platform-shell-and-path-strategy.md`

## Documentation & ADR Rules

1. **Major decisions require an ADR**: Any significant architectural, security-model, parser,
   configuration, or Paseo API-contract decision must be documented in `docs/adr/` before or
   alongside implementation.
   - Start from `docs/adr/0000-template.md`, use 4-digit numbering (`NNNN-short-kebab-title.md`),
     and register it in `docs/adr/README.md`.
   - Accepted ADRs are immutable. To change an accepted decision, add a new ADR that supersedes
     the old one and update both status headers.
2. **Keep `docs/DESIGN.md` current**: Update `docs/DESIGN.md` whenever module layout, contracts,
   policy schema, or milestones change.
3. **Keep `OVERVIEW.md` user-facing**: Once created at the repo root beside `paseo-plugin.json`,
   `OVERVIEW.md` follows Paseo plugin registry rules (plain factual language, no install commands
   or badges) and is separate from `docs/`.

## Non-Negotiable Engineering & Security Invariants

- **Fail to human**: Any parse error, unknown command, internal error, timeout, or unsupported
  provider payload must leave the request pending (`ask`) — never auto-allow, never auto-deny on
  error.
- **Deterministic first, never downgrade L2/L3**: Optional LLM judge is restricted to `L1` grey
  zone and may only return `allow` or `ask`.
- **No cross-state caching for deterministic decisions**: Only LLM judge results may be cached,
  keyed by `(normalizedActionHash, policyVersion, taintEpoch, worktreeMutationEpoch, scopeGrantVersion)`.
- **Path & secret checks are mandatory**: `safe-chains` matches must still pass arguments through
  the Path Model; never auto-allow writes to protected paths (`.git/`, agent configs, plugin
  policy/settings/data).
- **Pure Node.js**: Do not introduce native binary addons (e.g. `better-sqlite3`).
- **Licensing**: Do not use, reference, or port code, rules, or data from Destructive Command
  Guard (`dcg`). Keep `safe-chains` attribution in `THIRD_PARTY_NOTICES`.

## Paseo Plugin Runtime Boundaries

- Keep runtime modules strictly separated:
  - `index.client.tsx` & `client/`: React Native primitives only (`theme.colors`, `layout.compact`);
    never import `server/` or `node:*`; no raw HTML/DOM outside a `Platform.OS === "web"` guard.
  - `index.server.ts` & `server/`: Daemon subprocess; never import `client/`.
  - `shared/`: Zod schemas, `defineSettings`, `defineRpc`, and plain DTOs only (no Node or RN imports).
- Respect Paseo hook contracts (`docs/adr/0003-paseo-integration-and-config-source-of-truth.md`):
  - `agent.permission.before` / `after` may overlap concurrently and arrive out of order.
  - `agent.permission.after` does not include an actor field; track plugin-answered `requestId`s in memory.
  - `agent.open.before` `appendSystemPrompt` is ignored by Paseo's ACP adapter.
  - Always propagate `context.signal` to external requests.
- Run `npm run typecheck` and tests before reporting plugin code changes done.
