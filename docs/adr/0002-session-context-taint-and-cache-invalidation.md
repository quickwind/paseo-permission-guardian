# ADR-0002: Session Context, Taint/Provenance Tracking, and Decision Cache Boundaries

- **Status**: Accepted
- **Date**: 2026-11-08
- **Supersedes**: —
- **Superseded by**: —

## Context

Three subtle correctness and security gaps arise when evaluating permission requests over a multi-step agent session:

1. **Same-turn blind spot**: An agent can execute multiple tool calls within a single turn (e.g., `WebFetch` an untrusted issue, then immediately invoke `Bash` to exfiltrate data or run a just-edited script). Relying solely on `agent.turn.after` leaves session taint and modified-file state stale during the turn. Moreover, provider-auto-approved calls (`Read`, `Edit`, `WebFetch`) never fire `agent.permission.before`.
2. **Cache bypass of dynamic state**: Caching permission decisions solely by a hash of the normalized `Action` would allow a previously approved `npm test` or `curl` call to bypass newly acquired taint or newly modified scripts/configs.
3. **Provenance vs. developer workflow**: Treating every `exec_project` as `exec_inline` whenever the worktree is dirty would force human approval on every test run after any code edit, defeating the plugin's primary goal.
4. **Split-call exfiltration & env secrets**: A single-call combination rule (`read_secret + net_egress`) misses a two-step exfiltration (step 1 reads `.env` or `env`; step 2 runs `curl`).

## Decision

1. **On-demand incremental timeline sync**: Maintain per-agent session state (`taint`, `secretTaint`, `modifiedFiles`, `lastSyncedEntryId`). When `agent.permission.before` fires for an action sensitive to context (`exec`, `net_egress`, `vcs_remote`), incrementally inspect the current turn's timeline entries since `lastSyncedEntryId` (supplemented by `agent.turn.after` cleanup), rather than waiting for turn completion.
2. **Two-tier taint**:
   - `untrustedTaint`: set when the session reads external untrusted content (web pages, fetched docs, untrusted MCP outputs); raises `net_egress`, `exec_*`, and `vcs_remote` by one level.
   - `secretTaint`: set when the session reads a sensitive path or sensitive environment variables (`env`, `printenv`, `Get-ChildItem Env:`, `$env:*_KEY/*_TOKEN/*_SECRET`); elevates subsequent `net_egress` in the session to at least `L2` (`ask`), or `L3` (`deny`) when policy opts in.
3. **Targeted provenance**: Only downgrade `exec_project` to `exec_inline` when the command executes a directly modified script/file or when build/task entrypoints (`package.json`, `Makefile`, `pyproject.toml`, `scripts/**`, test runner configs) were modified in the session — not on ordinary source-file edits.
4. **No cross-state caching for deterministic decisions**: Deterministic evaluation runs fresh on every request (typically < 20 ms). Optional caching applies **only** to LLM judge responses and must be keyed by `(normalizedActionHash, policyVersion, taintEpoch, worktreeMutationEpoch, scopeGrantVersion)`.

## Consequences

### Positive

- Closes same-turn prompt-injection and split-call secret-exfiltration gaps.
- Eliminates stale-cache security regressions when session state changes.
- Preserves smooth edit-then-test loops for coding agents.

### Negative / Trade-offs

- Adds an incremental timeline read on context-sensitive permission requests (mitigated by cursoring/tracking the latest seen entry and skipping for pure `read` calls).
- Maintaining the list of build/script entrypoint patterns requires care across ecosystems (Node, Python, Rust, Go, Make).

### Follow-up / Guardrails

- Add regression test vectors for: (a) same-turn untrusted fetch → egress, (b) edit `package.json` → `npm test`, (c) edit `src/foo.ts` → `npm test`, (d) read `.env` in call 1 → `curl` in call 2.

## Alternatives Considered

1. **Only update context in `agent.turn.after`** — Rejected because multi-tool turns are standard in Claude Code, Codex, and ACP agents.
2. **Cache all decisions by action hash** — Rejected because identical commands have different risk after taint or file modifications.
3. **Escalate all `exec_project` when `git status` is dirty** — Rejected because it causes constant approval fatigue during normal coding.
