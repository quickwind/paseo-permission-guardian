# Architecture Decision Records (ADRs)

Significant architectural, security, and platform-integration decisions for `paseo-permission-guardian` are tracked here.

## Index

| ID | Title | Status | Date |
| --- | --- | --- | --- |
| [ADR-0001](./0001-deterministic-ast-first-with-effect-tags.md) | Deterministic AST-first analysis with effect tags and combination rules | Accepted | 2026-11-08 |
| [ADR-0002](./0002-session-context-taint-and-cache-invalidation.md) | Session context, taint/provenance tracking, and decision cache boundaries | Accepted | 2026-11-08 |
| [ADR-0003](./0003-paseo-integration-and-config-source-of-truth.md) | Paseo hook integration boundaries and configuration source of truth | Accepted | 2026-11-08 |
| [ADR-0004](./0004-cross-platform-shell-and-path-strategy.md) | Cross-platform shell parsing, path resolution, and phased P1 rollout | Accepted | 2026-11-08 |
| [ADR-0005](./0005-env-classification-and-bash-ast-hardening.md) | Environment variable classification, credential pattern sharing, and bash AST hardening | Accepted | 2026-11-21 |
| [ADR-0006](./0006-windows-env-classification-shell-hardening-and-static-cwd.md) | Windows environment classification, shell hardening, and cross-shell static CWD tracking | Accepted | 2026-11-21 |
| [ADR-0007](./0007-pwsh5-named-pipe-transport-and-cmdlet-free-cold-start.md) | Windows PowerShell 5.1 host transport over authenticated named pipe and cmdlet-free cold start | Accepted | 2026-11-22 |
| [ADR-0008](./0008-act-mode-evidence-gate.md) | `act` mode behind an evidence gate, replay with the current engine, and provider option mapping | Accepted | 2026-11-22 |
| [ADR-0009](./0009-uncommitted-delete-requires-human.md) | Uncommitted deletes require a human; committed files stay L0 | Accepted | 2026-11-23 |

## Creating a New ADR

1. Copy [0000-template.md](./0000-template.md) to `NNNN-short-kebab-title.md`.
2. Fill in Status (`Proposed` | `Accepted` | `Deprecated` | `Superseded by ADR-XXXX`), Context, Decision, Consequences, and Alternatives Considered.
3. Add a row to the index table above and link it from [DESIGN.md](../DESIGN.md) where relevant.
