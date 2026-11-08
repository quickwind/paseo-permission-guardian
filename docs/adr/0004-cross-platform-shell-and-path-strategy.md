# ADR-0004: Cross-Platform Shell Parsing, Path Resolution, and Phased P1 Rollout

- **Status**: Accepted
- **Date**: 2026-11-08
- **Supersedes**: —
- **Superseded by**: —

## Context

Supporting bash/zsh, PowerShell 5.1/7, cmd.exe, and WSL in a single plugin introduces major surface area and subtle edge cases:

1. **`safe-chains` argument semantics**: `safe-chains` TOML definitions classify commands and flags (`Inert`, `SafeRead`, `SafeWrite`), but do not annotate which positional or flag values are filesystem paths vs. URLs vs. plain strings. Blindly trusting `SafeRead` would allow `cat ~/.ssh/id_rsa`.
2. **PowerShell specifics**:
   - PowerShell supports unambiguous prefix matching on parameter names (`-Rec` for `-Recurse`, `-M` for `-Method`, `-Ep` for `-ExecutionPolicy`) as well as positional parameters.
   - A persistent PowerShell parser host (`Parser.ParseInput`) receives concurrent requests from Paseo's overlapping `agent.permission.before` hooks; stdin/stdout framing breaks without serialization.
   - Windows PowerShell 5.1 defaults to legacy codepages (not UTF-8) on stdio.
   - Some enterprise EDR tools flag a Node daemon spawning a persistent `powershell.exe` process.
3. **Path resolution edge cases**:
   - `fs.realpathSync.native` throws `ENOENT` on files that do not yet exist (`Write`, `mkdir`, redirection targets).
   - Calling `fs.realpathSync.native` on `\\wsl.localhost\<distro>\...` can wake a stopped WSL VM and block for seconds.
   - Protecting only `.git/hooks` and `.git/config` leaves `.git/info/attributes` and other `.git/` internals exposed.
4. **Delivery risk**: Bundling bash + PowerShell 5.1/7 + cmd + WSL + path model + `safe-chains` + rules into a single P1 milestone delays real-world shadow-mode feedback.

## Decision

1. **Mandatory path sweep over `safe-chains` commands**: Normalize command names (lowercase, strip `.exe`/`.cmd`/`.bat` on Windows). For every `SafeRead` / `SafeWrite` match, run Path Model checks (sensitive & protected path matching) across all positional arguments and path-like flag values before assigning `L0`.
2. **Hardened PowerShell analysis**:
   - Enforce a **serialized request queue** with per-request timeout (500 ms), crash auto-restart with circuit breaker, and explicit UTF-8 stdio encoding (`[Console]::InputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)`).
   - Treat any non-empty `ParseError[]` from `Parser.ParseInput` as `opaque`.
   - Implement **parameter prefix disambiguation** for known high-risk cmdlets (and treat ambiguous or unknown abbreviated flags as `opaque`).
   - Allow disabling the persistent PowerShell host via policy (`shells.pwshHost: "auto" | "disabled"`) for EDR-restricted environments; on non-Windows hosts or when the host is unavailable/disabled, fall back directly to `opaque` (no PowerShell WASM grammar bundled).
3. **Safe Path Model**:
   - For non-existent paths, walk upward to the nearest existing ancestor, call `fs.realpathSync.native` on that ancestor, and re-append the remaining segments.
   - Avoid invoking filesystem syscalls on `\\wsl$\` / `\\wsl.localhost\` paths unless the target distro is already running; rely on lexical normalization and dual-world sensitive-path matching first.
   - Protect the entire `.git/` directory by default against direct file writes.
4. **Split P1 into P1a and P1b**:
   - **P1a**: POSIX (`bash`/WASM), Path Model (POSIX + common sensitive/protected catalog), `safe-chains` interpreter + path sweep, effect tags & combination rules, shadow-mode validation.
   - **P1b**: Windows PowerShell 5.1/7 persistent host + prefix disambiguation, `cmd.exe` tokenizer, Windows built-ins, WSL recursive layers & bidirectional path mapping.

## Consequences

### Positive

- Faster time to real-world shadow-mode metrics on macOS/Linux (P1a) before tackling Windows/WSL complexity (P1b).
- Prevents symlink-escape on newly created files, PowerShell flag-abbreviation bypasses, stdio corruption under concurrency, and accidental WSL VM wakeups.

### Negative / Trade-offs

- Sweeping all positional arguments of `SafeRead` commands through the Path Model may occasionally flag a benign string that resembles a sensitive path (acceptable false-ask, never false-allow).
- Windows-first users wait for P1b for full PowerShell/WSL coverage (P0 still records all Windows requests in shadow mode).

### Follow-up / Guardrails

- Maintain separate conformance suites for P1a (`test/vectors/safe-chains/`) and P1b (`test/vectors/windows/`).

## Alternatives Considered

1. **Deliver POSIX + Windows + WSL together in one P1** — Rejected due to high integration risk and delayed feedback loop.
2. **Skip `realpath` for non-existent files** — Rejected because writing into a symlinked parent directory would escape the worktree check.
