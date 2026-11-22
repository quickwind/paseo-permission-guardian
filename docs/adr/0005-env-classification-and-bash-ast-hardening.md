# ADR-0005: Environment Variable Classification, Credential Pattern Sharing, and Bash AST Hardening

- **Status**: Accepted
- **Date**: 2026-11-21
- **Supersedes**: —
- **Superseded by**: —

## Context

End-to-end testing on `paseo-permission-guardian` surfaced a false-allow where a command carrying an inline API key assignment (`OPENAI_API_KEY=sk-proj-... rm -f /tmp/test`) was classified as `L0 allow` because `rm -f /tmp/...` resolved to non-recursive `delete_worktree` while `server/effects.ts` only inspected `$VAR` reads (`cmd.envReads`) and ignored inline variable assignments (`cmd.assignments`).

Deeper review by the committee identified three systemic issues across credential detection, environment-variable risk classification, and bash AST extraction:

1. **Unclassified environment variable risk vectors**:
   - Real credential literals in assignments or raw command text (including heredocs, headers, and URLs with embedded credentials) could bypass `read_secret` and `secretTaint`.
   - Non-secret variables can still hijack execution (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `NODE_OPTIONS`, `BASH_ENV`, `PATH`, `GIT_SSH_COMMAND`, etc.) or redirect network/package traffic and disable TLS verification (`HTTPS_PROXY`, `OPENAI_BASE_URL`, `npm_config_registry`, `GIT_SSL_NO_VERIFY`, `NODE_TLS_REJECT_UNAUTHORIZED=0`).
   - Conversely, treating every unknown assignment as `L1 ask` (or matching substrings without exclusions for `$PWD`, `TOKENIZERS_PARALLELISM`, `GIT_AUTHOR_*`, or empty-value clears) creates severe approval fatigue for routine commands (`NODE_ENV=test npm test`, `RUST_LOG=debug cargo test`, `IFS=, read -r a b`, `ls "$PWD/src"`).
2. **AST and wrapper extraction blind spots**:
   - Standalone `variable_assignment` statements (`OPENAI_API_KEY=...; ls`), `declaration_command` (`export`, `declare`, `typeset`, `readonly`, `local`), top-level `parsed.envReads` (heredocs, `[[ ... ]]`, `$((...))`, `case`, `for`), `bash -c` outer assignments/reads, `env`/`sudo` inline `KEY=VAL` arguments, `env -S` split strings, and indirect variable references (`${!ref}`, `${!prefix*}`, `declare -n`) were either dropped or bypassed.
   - `env -0`, `env -u X`, `set` (no args), `export -p`, `declare -px`, `compgen -v`, `ps eww`, and `/proc/*/environ` were not consistently treated as full-environment secret reads.
3. **Regex state & audit leakage bugs**:
   - Sharing `/g` regexes from `redact.ts` directly with `.test()` causes alternating false negatives via `lastIndex` mutation.
   - `AuditStore` only redacted `action`, leaving `decision.effects[].target` and `decision.reasons` (which can include `cmd.rawText`) unredacted on disk.

## Decision

### 1. Additive P0–P6 Environment & Credential Classification Model

All assignment and environment checks are **additive** (no early-exit): a single construct may emit multiple effect tags, the highest risk level wins (`decide.ts`), and P6 applies only when P0–P5 all miss. Secret values are **never** copied into `EffectTag.target`, `detail`, `reasons`, or `opaqueReasons` (only variable names or pattern labels).

| Priority | Condition | EffectTag | RiskLevel | Sets `secretTaint` |
| --- | --- | --- | --- | --- |
| **P0** | High-confidence credential literal anywhere in raw `exec.source` (scanned even on parse errors; only elevates risk) or in any assignment value | `read_secret` (`inline_secret_literal`) | `L2` (combines with `net_egress` → `L3 deny`) | Yes |
| **P1** | Root-level sensitive `envReads` (incl. heredocs, `[[ ... ]]`, `$((...))`) OR full-env dumps (`env`/`env -0`/`env -u` with no inner cmd, `printenv` no-positional/sensitive, no-arg `set`, `export`/`declare`/`typeset`/`readonly`/`local` without var names or with `-p`/`-x`, `compgen -v/-e`, `ps eww`/`-E`, `/proc/*/environ`) | `read_secret` (`sensitive_env_expansion` / `env_dump`) | `L2` (combines with `net_egress` → `L3 deny`) | Yes |
| **P2** | Indirect variable references (`${!ref}`, `${!prefix*}`, `declare -n`) | `opaque` (`indirect_var_ref` / `indirect_var_nameref`) | `L1` | No |
| **P3** | Non-empty execution-hijack assignment (case-insensitive prefixes/wildcards: `LD_*`, `DYLD_*`, `BASH_FUNC_*`, `NODE_OPTIONS`, `NODE_PATH`, `PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONHOME`, `PERL5LIB`, `PERL5OPT`, `RUBYOPT`, `RUBYLIB`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `BASH_ENV`, `ENV`, `ZDOTDIR`, `PROMPT_COMMAND`, `PATH`, `GIT_SSH`, `GIT_EXEC_PATH`, `GIT_TEMPLATE_DIR`, `GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`, `GIT_EDITOR`, `GIT_PAGER`, `GIT_ASKPASS`, `SSH_ASKPASS`, `GIT_PROXY_COMMAND`, `GIT_*_COMMAND`, `EDITOR`, `VISUAL`, `PAGER`, `MANPAGER`, `BROWSER`, `LESSOPEN`, `LESSCLOSE`, `RUSTC_WRAPPER`, `CARGO_BUILD_RUSTC_WRAPPER`, `CARGO_TARGET_*_RUNNER`, `npm_config_script_shell`, `npm_config_node_options`; `CC`/`CXX` only if value contains `/` or whitespace) | `exec_inline` (`env_exec_hijack:<KEY>`) | `L1` (`L2` under `untrustedTaint`) | No |
| **P4** | Non-empty redirect / proxy / TLS-disable assignment (case-insensitive: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `*_BASE_URL`, `*_API_BASE`, `*_ENDPOINT`, remaining `npm_config_*`, `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`, `PIP_TRUSTED_HOST`, `UV_INDEX_URL`, `GOPROXY`, `CARGO_REGISTRIES_*`, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_NO_VERIFY` non-empty/true, `PYTHONHTTPSVERIFY=0`, `NODE_TLS_REJECT_UNAUTHORIZED` non-empty and `!= "1"`) | `opaque` (`env_redirect_or_tls:<KEY>`) | `L1` | No |
| **P5** | Non-empty sensitive credential variable name (camelCase→SNAKE normalization + exclusions for `PWD`/`OLDPWD`/`GIT_AUTHOR_*`/`GIT_COMMITTER_*`/`TOKENIZERS_PARALLELISM`/`MAX_TOKENS`/`KEYMAP`/`KEYBOARD_*` + segment/suffix/connection-string rules) | `opaque` (`sensitive_env_assignment:<KEY>`) | `L1` | No |
| **P6** | Empty clears (`KEY=""`/`KEY=`), command-prefix `IFS=, read`, shell flags (`set -euo pipefail`, `set --`, `set -o ...`, `set +x`), or remaining normal/unknown variables (`NODE_ENV`, `RUST_LOG`, `PORT`, `CC=clang`) | None | Inherit underlying command level (logged redacted) | No |

- **Standalone `IFS` rule**: Prefix `IFS=, read -r a b` is allowed (`L0`), whereas a standalone `IFS=...;` statement emits `opaque` (`L1`).

### 2. Stateless Shared Pattern Module & Audit Redaction

- Extract stateless credential literal patterns (strictly **without** `/g` flags) and environment variable classifiers into `server/secrets/patterns.ts` as the single source of truth shared by `server/effects.ts` and `server/audit/redact.ts`.
- `server/audit/redact.ts` constructs fresh `/g` regexes per replacement pass.
- `AuditStore.recordBefore` redacts `decision` and `warnings` in addition to `action`. Future P3 LLM judge inputs must likewise pass through `redactString`/`redactValue` before leaving the host.
- `touchedSecret` in `analyzeActionEffects` is strictly derived from `effects.some(e => e.tag === "read_secret")` to prevent manual tracking drift.

### 3. Bash AST & Layer Hardening + Interim `cwd` Guard

- `server/shell/bash.ts` collects `envReads` across the entire AST root (including heredoc bodies, test commands `[[ ... ]]`, and `arithmetic_expansion` variable names) while excluding LHS names of `variable_assignment`, preserves standalone `variable_assignment` facts, extracts `declaration_command` (`export`, `declare`, `typeset`, `readonly`, `local`), and uses `web-tree-sitter.cjs` + `readFileSync` WASM loading for Paseo's `eval`-based bundle evaluator.
- `server/shell/layers.ts` propagates `assignments`, `envReads`, and `bash -c`/`env`/`sudo` outer/prefix assignments, recursively parses `env -S`, and preserves `env` without an inner command as a dump command.
- **Interim `cd` / `env -C` guard**: Until full dynamic `cwd` tracking is designed in a dedicated issue, any `cd` or `env -C` sets `cwdChanged` on subsequent commands in the layer, causing relative paths in those commands to emit `opaque` (`L1`) instead of resolving against the initial worktree.

## Consequences

### Positive

- Eliminates inline secret-literal and environment-dump bypasses (`OPENAI_API_KEY=sk-... rm`, `export -p`, `set`, `cat <<EOF` heredoc exfiltration, `bash -c` outer assignments).
- Prevents `LD_PRELOAD`, `NODE_OPTIONS`, `HTTPS_PROXY`, and `GIT_SSL_NO_VERIFY` execution/traffic hijacks from passing at `L0`.
- Preserves low-friction developer workflows (`NODE_ENV=test`, `RUST_LOG=debug`, `IFS=, read`, `set -euo pipefail`, `ls "$PWD/src"`, `CC=clang make`).
- Prevents plaintext secret leakage into `audit-*.jsonl` via `decision` targets/reasons.

### Negative / Trade-offs

- **Literal credential + `net_egress` triggers `L3 deny`**: Commands passing a plaintext literal credential directly to `curl -X POST` (even to `api.openai.com`) are classified `L3` because static analysis cannot distinguish legitimate calls from exfiltration and plaintext credentials on CLI invocations violate secret-hygiene practice. Teams wanting prompts instead of auto-deny rely on `denyAsAsk: true` (the default).
- **`PATH` assignments stay `L1`**: Commands like `PATH="$PWD/node_modules/.bin:$PATH" ...` remain `L1 ask` until provenance-aware `PATH` verification is added, because worktree `bin/` directories may contain agent-modified scripts.

### Follow-up / Guardrails

- Open a dedicated issue for full cross-command `cwd` tracking across `cd` and `env -C` (replacing the interim relative-path `opaque` guard).
- Maintain regression vectors for both bypass catches and zero-false-positive `L0` baselines in `test/env-hardening.test.ts` and `test/audit.test.ts`.

## Alternatives Considered

1. **Allowlist-only for all env assignments (unknown variables → `L1`)** — Rejected because project-specific variables (`RUST_LOG`, `PORT`, `GOOS`, `NEXT_TELEMETRY_DISABLED`, etc.) cannot be statically enumerated and would cause severe approval fatigue.
2. **Checking only `cmd.assignments` in `server/effects.ts` without AST/wrapper fixes** — Rejected because standalone assignments, `export -p`, `bash -c` outer assignments, `env KEY=VAL`, and heredoc `$VAR` expansions would continue to bypass checks.
