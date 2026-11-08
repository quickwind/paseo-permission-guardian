# ADR-0001: Deterministic AST-First Analysis with Effect Tags and Combination Rules

- **Status**: Accepted
- **Date**: 2026-11-08
- **Supersedes**: —
- **Superseded by**: —

## Context

Coding agents managed by Paseo issue frequent permission requests across shell execution, file access, web fetches, and MCP tool calls. Two common approaches exist in the ecosystem:

1. Regex-based allow/deny lists over raw command strings, which are brittle against quoting, chaining, pipelines, subshells, and wrapper commands.
2. LLM-only classifiers on every request, which add latency (1–3 s), cost, non-determinism, and prompt-injection exposure.

Additionally, some existing destructive-command rule sets (such as Destructive Command Guard / `dcg`) carry license riders restricting use by or for certain AI companies, making them unsuitable for a general-purpose MIT/Apache-2.0 plugin.

## Decision

1. **Deterministic AST-first pipeline**: Parse shell commands into ASTs per shell grammar (`bash`, `pwsh`, `cmd`), unwrap wrappers recursively up to depth 3, and normalize all tool calls into a single `Action` model.
2. **Effect tags + combination rules**: Map normalized actions and parsed commands to structured effect tags (`read`, `read_secret`, `write_worktree`, `net_egress`, `privilege`, `opaque`, etc.) and evaluate cross-layer combination rules to produce deterministic risk levels (`L0`–`L3`).
3. **Opaque ≠ dangerous**: Unparseable or dynamic constructs (`eval`, `iex`, dynamic command names, obfuscation, depth exceeded) emit `opaque` and route to the grey zone (`L1`), never auto-allow.
4. **Optional grey-zone LLM judge**: Disabled by default. Only consulted on `L1`, restricted to returning `allow` or `ask`, and strictly forbidden from lowering deterministic `L2`/`L3` verdicts.
5. **Command knowledge**: Vendor and interpret `safe-chains` declarative TOML definitions (MIT OR Apache-2.0) as an allow-list baseline, augmented by path inspection and dedicated Windows/PowerShell knowledge. Do not use or port anything from `dcg`.

## Consequences

### Positive

- Sub-20 ms deterministic latency for routine approvals, minimizing UI flicker on Paseo's non-blocking notification hook.
- Auditable, reproducible, and replay-testable decisions.
- Clean permissive licensing suitable for public distribution on the Paseo plugin registry.

### Negative / Trade-offs

- Requires maintaining parsers and a `safe-chains` TOML interpreter in Node.js/TypeScript.
- Unknown commands default to `ask` until covered by the registry or user/team policy.

### Follow-up / Guardrails

- Conformance test suite extracted from `safe-chains` must pass on every registry sync.
- `safe-chains` verdicts must never bypass Path Model checks on command arguments.

## Alternatives Considered

1. **Regex-only rules** — Rejected due to bypasses via quoting, pipelines, subshells, and cross-layer wrappers (`wsl`, `bash -c`, `powershell -c`).
2. **LLM-only classification** — Rejected due to latency, cost, non-determinism, and poor UX without a waiting hook in Paseo.
3. **Bundling `dcg` rules** — Rejected due to license restrictions.
