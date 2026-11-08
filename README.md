# paseo-permission-guardian

A pure Node.js [Paseo](https://paseo.sh) plugin (`requirements.paseo: ">=0.16.0"`) that classifies
the risk of coding-agent tool calls and automatically handles routine permission prompts while
keeping humans in the loop for high-risk actions.

> **Status**: Design finalized (v0.2). Implementation starting at P0.

## Key Principles

- **Deterministic AST-first analysis**: Parses shell commands (`bash`, PowerShell 5.1/7, `cmd.exe`)
  into ASTs and recursively unwraps nested layers (`bash -c`, `wsl`, `cmd /c`, `pwsh -c`) rather
  than matching raw command strings with regexes.
- **Effect tags & combination rules**: Maps normalized tool calls (`exec`, `read`, `edit`, `fetch`,
  `mcp`) to effect tags and enforces cross-layer and cross-call rules (e.g., `read_secret` +
  `net_egress`).
- **Live session context**: Tracks same-turn untrusted taint, `secretTaint`, targeted build/script
  provenance, and user-declared scope grants.
- **Fail to human**: Parse errors, unknown commands, timeouts, or unsupported payloads always stay
  pending (`ask`) — never auto-allowed, never auto-denied on error.
- **Shadow mode by default**: Measure agreement and verify zero false-allows on replay before
  enabling `act` mode.
- **Optional grey-zone LLM judge**: Disabled by default; restricted to `L1` and can only return
  `allow` or `ask` (never overrides deterministic `L2`/`L3`).

## Non-Goals

This plugin is a **prompt reducer**, not a sandbox or security boundary. Hard red lines belong in
provider-native deny rules and OS/container isolation.

## Supported Providers (Planned)

- **P0**: Claude Code, ACP agents (priority: **Antigravity** and **Devin CLI**)
- **P3**: Codex, OpenCode

## Documentation

- [System Design (`docs/DESIGN.md`)](./docs/DESIGN.md)
- [Architecture Decision Records (`docs/adr/`)](./docs/adr/README.md)
- [Documentation Conventions (`docs/README.md`)](./docs/README.md)
- [Agent Instructions (`AGENTS.md`)](./AGENTS.md)

## Milestones

| Phase | Scope |
| --- | --- |
| **P0** | Plugin scaffold, `OVERVIEW.md`, normalizers (Claude Code, Antigravity, Devin CLI), Paseo Settings, rotated JSONL audit store, shadow mode |
| **P1a** | `bash` WASM parser, POSIX Path Model, `safe-chains` interpreter + path sweep, effect/combination rules, same-turn taint & provenance |
| **P1b** | Windows PowerShell 5.1/7 serialized parser host, `cmd.exe` tokenizer, Windows built-ins, WSL layers & bidirectional path mapping |
| **P2** | `act` mode, shadow dashboard, compact timeline renderer, optional prompt guidance & mode policy |
| **P3** | Optional LLM judge (epoch-keyed cache), Codex/OpenCode adapters, JS command handlers, upstream waiting-hook PR |

## License

Copyright 2026 blynx-hq. Licensed under the [Apache License, Version 2.0](./LICENSE) (see [NOTICE](./NOTICE)).

Command knowledge data is derived from [`safe-chains`](https://github.com/michaeldhopkins/safe-chains)
(MIT OR Apache-2.0). This project does **not** use or port any code, rules, or data from
Destructive Command Guard (`dcg`).
