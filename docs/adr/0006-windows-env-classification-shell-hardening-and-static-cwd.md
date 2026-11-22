# ADR-0006: Windows Environment Classification, Shell Hardening, and Cross-Shell Static CWD Tracking

- **Status**: Accepted
- **Date**: 2026-11-21
- **Supersedes**: —
- **Superseded by**: —
- **Extends**: [ADR-0004](./0004-cross-platform-shell-and-path-strategy.md), [ADR-0005](./0005-env-classification-and-bash-ast-hardening.md)

## Context

Following [ADR-0005](./0005-env-classification-and-bash-ast-hardening.md), a dedicated cross-model security review of Windows (`PowerShell 5.1`, `PowerShell 7`, `cmd.exe`, and `WSL`) identified three platform-specific risk classes absent on POSIX, along with several POSIX omissions in ADR-0005 and a structural flaw in ADR-0005's interim `cwd` guard:

1. **Windows-only attack surfaces**:
   - **Persistent environment mutation (P7)**: `setx`, `[Environment]::SetEnvironmentVariable(..., 'User'|'Machine')`, `HKCU:\Environment` / `HKLM\...\Environment` registry writes, and `Set-ExecutionPolicy` persist across future processes rather than staying scoped to one child invocation.
   - **Pre-tokenization expansion (`cmd.exe` Phase 1)**: `cmd.exe` expands `%VAR%` *before* tokenizing `&`, `|`, `>`, and `( )`, allowing variable contents to inject command separators; additionally, bare `set PREFIX` (without `=`) dumps all variables matching that prefix.
   - **Parser-host hijacking & NTFS path quirks**: Spawning `powershell.exe`/`pwsh.exe` via `PATH` or with polluted `COR_*`/`CORECLR_*`/`DOTNET_*`/`PSModulePath`/`PSExecutionPolicyPreference` or a worktree `cwd` allows DLL/module/profile hijacking of the parser host itself; NTFS strips trailing dots/spaces (unless `\\?\`), supports Alternate Data Streams (`::$DATA`), triggers NTLMv2 auth over remote UNC/WebDAV (`\\host\share`), and searches `cwd` before `PATH` in `cmd.exe`.
   - **WSL cross-OS bridging (`WSLENV`)**: `WSLENV` exports host secrets across the Windows/WSL boundary directly into child process environments (including compiled binaries whose source does not appear in a bash AST).
2. **ADR-0005 POSIX omissions & false positives**:
   - Missing P3 execution-hijack variables (`HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `DOTNET_CLI_HOME`, `GIT_DIR`, `GIT_WORK_TREE`, `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_*`, `GIT_CONFIG_VALUE_*`).
   - `SSH_AUTH_SOCK` reads (`echo $SSH_AUTH_SOCK`) triggered a false-positive `read_secret` (`L2`) due to the `AUTH` segment, whereas only modifying `SSH_AUTH_SOCK` hijacks agent forwarding.
   - Credential flags on CLI invocations (`--password=`, `--token`, `mysql -p<val>`, `sshpass -p`, `curl -u user:pass`) and bash `alias` / `shopt -s expand_aliases` were unhandled.
   - Sharing a single pattern tier for both P0 risk escalation and audit redaction risks false `L2` escalations when adding broad redaction rules.
3. **Interim `cwdChanged` guard violates L2/L3 non-downgrade**:
   - Under ADR-0005's interim guard, `cd ~/.ssh && cat id_rsa` or `cd / && rm -rf etc` marks subsequent relative paths as `L1 opaque` instead of `L2 read_secret` or `L3 system_destructive`.
   - Once an optional LLM judge operates in the `L1` grey zone ([ADR-0001](./0001-deterministic-ast-first-with-effect-tags.md)), downgrading an `L2`/`L3` call to `L1` violates the core non-downgrade invariant. Meanwhile, benign sequences such as `cd src && npm test` produce unnecessary `L1` approval noise.

All Windows/PowerShell/cmd/NTFS/.NET/NuGet/PEP details in this ADR were verified against official Microsoft Learn, npm, Git, uv, and Python PEP documentation prior to acceptance.

## Decision

### 1. Persistent Environment Writes (P7)

Introduce priority **P7** (evaluated additively alongside P0 and P3–P5):

- `setx` (any target), `[Environment]::SetEnvironmentVariable(..., "User" | "Machine")`, writes to `HKCU:\Environment` or `HKLM\...\Environment`, and `Set-ExecutionPolicy` (any scope) emit **`write_protected` (`L2`, `detail: "env_persist:user"` or `"env_persist:machine"`)**.
- Machine-level targets (`setx /m`, `"Machine"`, `2`, `HKLM`) additionally emit **`privilege` (`L2`)**. `setx /s <host>` adds `infra_mutate`.
- Empty clears via `Remove-Item Env:X` or `$env:X = ""` in process scope remain P6 (`L0`).

### 2. Cross-Platform Extensions to P0–P6 & Two-Tier Credential Patterns

- **Case normalization split**:
  - **P3 & P4** MUST match raw ASCII uppercase (`name.trim().toUpperCase()`), NEVER `normalizeEnvVarName`, so camelCase/PascalCase names like `PSModulePath` or `MSBuildSDKsPath` are not split into `PS_MODULE_PATH`.
  - **P1 & P5** check both raw uppercase and `normalizeEnvVarName` (so `apiKey` matches `API_KEY` while `GIT_AUTHOR_*`, `PWD`, `OLDPWD`, `SSH_AUTH_SOCK` are cleanly excluded).
- **P3 (execution hijack — `exec_inline`, `L1`; `L2` under `untrustedTaint`) additions**:
  - **POSIX & Git/CLI**: `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `DOTNET_CLI_HOME`, `SSH_AUTH_SOCK` (assignment only; **reads are excluded** from `isSensitiveEnvVarName` to fix the `echo $SSH_AUTH_SOCK` false positive), `GIT_DIR`, `GIT_WORK_TREE`, `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_*`, `GIT_CONFIG_VALUE_*`.
  - **Windows & .NET/MSBuild/PowerShell**: `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `PROGRAMDATA`, `PSMODULEPATH`, `PATHEXT`, `COMSPEC`, `SYSTEMROOT`, `WINDIR`, `COR_*`, `CORECLR_*`, `DOTNET_PROFILER*`, `DOTNET_ENABLE_PROFILING`, `COMPLUS_*`, `DOTNET_STARTUP_HOOKS`, `DOTNET_ADDITIONAL_DEPS`, `DOTNET_SHARED_STORE`, `DOTNET_ROOT*`, `MSBUILD_EXE_PATH`, `MSBUILDSDKSPATH`, `MSBUILDEXTENSIONSPATH`, `__PSLOCKDOWNPOLICY`.
  - **`PSExecutionPolicyPreference`**: `Bypass` or `Unrestricted` emits **`exec_inline` (`L2`, `detail: "execution_policy_bypass"`)** (matching `-ExecutionPolicy Bypass` / `-ep Bypass` CLI flags, without overloading `privilege`); any other non-empty value emits P3 `exec_inline` (`L1`).
  - **`CC` / `CXX`**: trigger P3 when value contains `/`, `\`, whitespace, or a Windows drive prefix (`^[A-Za-z]:`).
- **P4 (redirect / proxy / TLS-disable — `opaque`, `L1`) additions**:
  - Official package/TLS controls: `UV_INSECURE_HOST`, `DOTNET_NUGET_SIGNATURE_VERIFICATION` (`false` or `0`), `NUGET_CERT_REVOCATION_MODE` (non-empty and `!= "online"`), `-SkipCertificateCheck`, `ServerCertificateValidationCallback`/`CertificatePolicy`, `netsh winhttp set proxy`.
  - Note on `PYTHONHTTPSVERIFY=0`: retained in P4 for legacy Python 2.7.12+ (PEP 493) / downstream patched runtimes; upstream Python 3 relies on `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `PIP_TRUSTED_HOST`, and `UV_INSECURE_HOST`.
  - Note on phantom variables: `NUGET_CONFIG_FILE` does not exist in NuGet CLI (NuGet uses `--configfile` / `-ConfigFile`) and is explicitly omitted.
- **Value-aware `TEMP` / `TMP` / `TMPDIR` rule**:
  - Because the Path Model computes `isTemp` against the daemon's real temp directories rather than command-mutated env vars, setting `TEMP`/`TMP`/`TMPDIR` to a static path that resolves inside non-protected worktree space or a real system temp directory (`$env:TEMP='C:\repo\.tmp'; pytest`, `TMPDIR=/tmp/test npm test`) stays **P6 (`L0`)**.
  - Dynamic expressions or paths outside worktree/temp or hitting protected/sensitive paths emit **P4 `opaque` (`L1`)**.
- **Two-tier credential patterns (`server/secrets/patterns.ts`)**:
  - High-confidence `CREDENTIAL_LITERAL_PATTERNS` (used for both **P0** escalation and redaction; strictly NO `/g` flags) adds Azure Storage `AccountKey=`, Azure SAS tokens (`sv=...&sig=`), Entra ID client secrets (`...8Q~...`), SQL connection-string passwords (`Server=...;Password=...`), and PuTTY `.ppk` private keys (`PuTTY-User-Key-File-`).
  - Low-confidence `REDACTION_ONLY_CREDENTIAL_PATTERNS` (e.g. generic `password: ...` / `secret: ...` key-value text) is used **only** by `server/audit/redact.ts` and never triggers P0 `read_secret`.
- **CLI secret flags & bash aliases**:
  - Commands passing sensitive flags (`--password=`, `--token`, `mysql -p<val>` attached, `sshpass -p`, `curl -u user:pass`; excluding bare `mysql -p`, `--key`, `--author`) are checked via `CREDENTIAL_LITERAL_PATTERNS` (P0 `L2` if high-confidence literal) and emit **P5 `opaque` (`cli_secret_flag:<flag>`, `L1`)** for non-empty ordinary values without leaking values into `EffectTag` or `AuditStore`.
  - Bash `alias` definitions and `shopt -s expand_aliases` emit `opaque` (`L1`).

### 3. PowerShell 5.1 / 7 Host Security & AST Contract (P1b)

- **Hardened host spawning**: Launch `powershell.exe` / `pwsh.exe` strictly via **verified OS system/install absolute paths** (never via `PATH` or `cwd`), set child `cwd` to the system directory (preventing DLL planting), strip `COR_*`, `CORECLR_*`, `DOTNET_*`, `COMPLUS_*`, user `PSModulePath`, and `PSExecutionPolicyPreference` from child `env`, pass `-NoProfile -NonInteractive`, pass script text exclusively over UTF-8 stdin JSON, and never echo raw command source to stderr.
- **Complete AST traversal + versioned `nodeTypeCensus`**: Walk with `$ast.FindAll({ $true }, $true)` (entering nested script blocks) and return a `nodeTypeCensus`. Node maintains separate understood-AST-node sets for **5.1** vs **7.x** (e.g. `PipelineChainAst`, `TernaryExpressionAst` exist only in 7+); any unknown node type emits `opaque` (`unknown_ast_node:<Type>`).
- **Anti-obfuscation & quoting fidelity**: Read `CommandAst.GetCommandName()`, `CommandParameterAst.ParameterName`, and `StringConstantExpressionAst.Value` rather than `.Extent.Text` (defeating backtick escapes). Handle `--%` stop-parsing tokens by forwarding the trailing slice to `cmd.exe` `%VAR%` inspection; flag `$PSNativeCommandArgumentPassing` embedded-quote / empty-string quirks on native calls as `opaque`.
- **PowerShell env reads/writes & non-env hijacks**: Inspect `$env:*` (excluding LHS of plain `=`, including both read+write on `+=`), `Env:` provider cmdlets (including `Set-Location Env:` / `New-PSDrive -PSProvider Environment`), `[Environment]::GetEnvironmentVariables` / `GetEnvironmentVariable` / `ExpandEnvironmentVariables`, `Start-Process -Environment @{...}` (PS 7.4+), `Get-Variable` (unscoped/wildcard), `Set-Alias`/`sal`, `$PSDefaultParameterValues`, `Import-Module`/`using module`/`Add-Type`, and shadowed `function` definitions (when subsequently invoked in the same input).
- **Safe L0 baselines**: Constant assignments to `$ErrorActionPreference`, `$ProgressPreference`, `[Console]::OutputEncoding`, and `$PSStyle.OutputRendering` remain `L0` (**`$WhatIfPreference = $true` MUST NEVER downgrade effect levels** — only explicit `-WhatIf` on a cmdlet previews). Unmodified `<worktree>/{.venv,venv,env}/Scripts/{Activate.ps1,activate.bat}` activation scripts stay `L0` unless `untrustedTaint` is active.

### 4. `cmd.exe` Phase-1 Expansion & Hardening (P1b)

- Run P0 literal scanning on both raw source and `^`-unescaped text.
- `set` (no args) and `set PREFIX` (without `=`, `/a`, or `/p`) emit **P1 `env_dump` (`L2`)** because `cmd.exe` dumps all variables matching the prefix.
- `set /a <expr>` emits **`opaque` (`L1`)** and scans RHS bare variable identifiers; any sensitive variable name stacks **P1 `read_secret` (`L2`)** (matching bash `$((...))`).
- **Safe system macro allowlist**: Unquoted or quoted `%VAR%` belonging to the strict system macro allowlist (`TEMP`, `TMP`, `USERPROFILE`, `LOCALAPPDATA`, `APPDATA`, `PROGRAMFILES`, `PROGRAMFILES(X86)`, `PROGRAMDATA`, `SYSTEMROOT`, `WINDIR`, `CD`, `PATH`, `ERRORLEVEL`, `USERNAME`, `COMPUTERNAME`, `OS`, `DATE`, `TIME`, `HOMEDRIVE`, `HOMEPATH`) is permitted deterministically (`L0` + Path Model sweep) ONLY when ALL guardrails hold:
  1. It appears in argument position (never command-name position);
  2. It is not inside an `if`, `for`, or `( ... )` block (where paths like `(x86)` break grouping);
  3. The variable was not reassigned earlier in the same command chain;
  4. It uses no substring/replace modifiers (`%VAR:~...%`, `%VAR:a=b%`) and its host snapshot value contains no cmd metacharacters (`& | < > ^ ( ) % ! "` when unquoted; `" % !` when quoted).
- Non-allowlisted `%VAR%` (including non-identifier `%A-B%`, `%A.B%` names matching `/^([^%\r\n=]+)$/`), `!VAR!`, `%%`, `call`, `for /f`, `set` followed by subshell `%...%`/`!`, and unknown `^`+`!` obfuscations emit `opaque` (`L1`) plus `read_secret` (`L2`) if the variable name is sensitive. Wrapper commands (`cmd /c`, `start`, `wsl`, `powershell -c`, `bash -c`, `env -S`) preserve outer `redirections` and `envReads` at the wrapper's layer before unwrapping into child layers.
- **CWD shadow binary check**: Bare command names in `cmd.exe` check `cwd` for `<bin>.{com,exe,bat,cmd}` (if modified in session → `exec_inline`; if present/unknown → `opaque`).

### 5. WSL Cross-Boundary Rules (P1b)

- **`WSLENV` classification**: Assigning or persisting `WSLENV` parses `:`-delimited entries (stripping `/p`, `/l`, `/u`, `/w` flags): sensitive var names emit **P1 `read_secret` (`L2`) + `secretTaint`** (`wslenv_secret_export`); execution-hijack var names emit **P3 `exec_inline` (`L1`)**; remaining non-empty or dynamic values emit **P4 `opaque` (`L1`)**. `setx WSLENV` stacks **P7**.
- **Outer assignment propagation**: Windows-side env assignments propagate into child `wsl` layers because user-persisted `WSLENV` cannot be observed statically.
- Parse `wsl --exec` / `-e` directly as `execve` argv, handle `wsl --cd`, `wsl --shell-type login`, evaluate default-shell `wsl <cmd...>` via dual-form reconstruction (shell-quoted preservation + raw spaced join), enforce case-insensitive sensitive/protected path checks on DrvFs (`/mnt/<drive>/`), and mark `cmd.exe` invoked under `\\wsl.localhost\...` cwd as `opaque`.

### 6. Windows Credential Dumping, Process Inspection, & NTFS Path Model (P1b)

- **`Win32_Process.CommandLine`**: `wmic process get commandline`, explicit `CommandLine` queries, and un-narrowed `Get-CimInstance` / `Get-WmiObject Win32_Process` (which select `CommandLine` by default) emit **P1 `read_secret` (`L2`)**. `Get-Process`, `gps`, and `tasklist` stay `L0`. (POSIX `ps aux` / `/proc/*/cmdline` parity is tracked separately.)
- **Explicit `credential_dump` signatures → `system_destructive` (`L3 deny`)**: `procdump -ma lsass`, `rundll32 comsvcs.dll,MiniDump`, `reg save`/`export HKLM\{SAM,SECURITY,SYSTEM}`, `ntdsutil ... ifm`, and `vssadmin create shadow` / `esentutl /vss` targeting SAM/SYSTEM/SECURITY hives. No generic `read_secret + privilege → L3` rule is added (preserving human-ask on `sudo cat <file>`).
- **Windows Path & Egress Model**: Remote UNC/WebDAV (`\\host\share`, `\\host@SSL\...`, `file://host/` excluding `localhost`/`127.0.0.1`/`wsl$`/`wsl.localhost`) emit **`net_egress`** (automatic NTLMv2 auth leak); normalize trailing dots/spaces (except `\\?\`), strip Alternate Data Streams across **all** path segments (`::$DATA`, intermediate `.git::$INDEX_ALLOCATION`, `.git:$I30:$INDEX_ALLOCATION`, `Zone.Identifier` → `opaque`), reserved device names (`NUL`, `CON`), and unresolved 8.3 short names (`~1` → `opaque`). Note: writing or deleting `isSensitive` files (`.env*`, `*.pem`, `id_rsa`) also emits `write_protected` (`L2`) while preserving `net_read` + `Invoke-Expression`/`[scriptblock]::Create` (`L3`) combination upgrades.

### 7. Cross-Shell Linear Static Literal `cwd` Tracking (Replaces Interim Bash Guard)

- Replace ADR-0005's blanket `cwdChanged` guard with deterministic **linear static literal `cwd` tracking** (`server/shell/cwd.ts`, implemented for bash immediately alongside Stage 1 hardening and extended to PowerShell/cmd/WSL in P1b):
  - Sequential chains (`;`, `&&`, `{ ... }`, PowerShell statement lists) resolve literal `cd`, `pushd`, and `popd` targets (including `~`, `$HOME`, `$PWD`) against `cwd` and stamp `effectiveCwd` on each `CommandFact`.
  - Single-command scoped directory flags (`env -C`, `git -C`, `npm --prefix`, `Start-Process -WorkingDirectory`, `wsl --cd`) resolve strictly for their target command/layer without leaking to sibling commands.
  - Subshells `( ... )`, pipelines (`|`), and child shells (`bash -c`) run on isolated `cwd` clones and never mutate outer `cwd`.
  - Conditional/ambiguous constructs (`||`, `if`, `case`, loops containing `cd`/`pushd`/`popd`, dynamic targets, `cd -`, empty `popd`, non-filesystem provider drives `Env:`/`HKLM:`, UNC, bare Windows drive switches `D:`) fall back to `cwdChanged: true` (`L1 opaque` on subsequent relative paths).

## Consequences

### Positive

- Closes persistent env writes (`setx`), `cmd.exe` Phase-1 expansion/`set PREFIX`, `WSLENV` exfiltration, NTFS path evasion, and PowerShell AST/host-hijack gaps before P1b code lands.
- Preserves the **L2/L3 non-downgrade invariant**: `cd ~/.ssh && cat id_rsa` and `cd / && rm -rf etc` now classify accurately as `L2 read_secret` and `L3 system_destructive` instead of dropping to `L1 opaque`, while `cd src && npm test` returns to `L0 allow`.
- Fixes the `echo $SSH_AUTH_SOCK` POSIX false positive and prevents future redaction-only patterns from inflating deterministic `L2` escalations.

### Negative / Trade-offs

- **`Win32_Process.CommandLine` at P1 (`L2`)**: Inspecting process command lines requires human approval unless narrowed via `-Property` (while `Get-Process`/`tasklist` stay `L0`). This is an intentional trade-off so `wmic process get commandline | curl -d @-` escalates to `L3 deny`.
- **Explicit `credential_dump` list vs generic combo**: Only explicit LSASS/SAM dump signatures trigger `L3` directly rather than `read_secret + privilege → L3`, preventing false auto-denies on admin troubleshooting commands such as `sudo grep ... .env`.
- **Linear static `cwd` scope**: Branching `cd` flows (`a || cd b`) conservatively fall back to `L1 opaque` for relative paths rather than attempting multi-path symbolic execution.
- **`TEMP` value-aware check**: Dynamic `$TEMP` expressions trigger `L1 opaque`, while static worktree/system-temp assignments remain `L0`.

### Follow-up / Guardrails

- Implement Stage 1 (`server/secrets/patterns.ts`, `server/audit/redact.ts`, cross-platform `server/paths/index.ts`, `server/shell/cwd.ts`, `bash.ts`/`layers.ts`/`effects.ts`/`decide.ts`) and cross-platform CI matrix (`ubuntu`, `macos`, `windows` + headless Paseo daemon smoke) immediately.
- Implement remaining P1b parsers (`server/shell/pwsh.ts`, `server/shell/cmd.ts`, `server/shell/wsl.ts`, Windows Path Model) against `test/vectors/windows/`.
- Track POSIX `ps aux` / `/proc/*/cmdline` alignment with `Win32_Process.CommandLine` as a follow-up evaluation item.

## Alternatives Considered

1. **Deferring static `cwd` tracking to ADR-0007** — Rejected because an interim `cwdChanged` guard downgrades `cd ~/.ssh && cat id_rsa` from `L2` to `L1`, violating the non-downgrade invariant once an LLM judge handles `L1`.
2. **Adding a generic `read_secret + privilege → L3` combination rule** — Rejected because legitimate human-approvable admin commands (`sudo cat <secret>`) would be auto-denied (`L3`).
3. **Treating `WSLENV=<secret>` as `L1` without `secretTaint`** — Rejected because compiled binaries run inside WSL (e.g. `wsl python3 app.py`) read `os.environ` without exposing `$SECRET` in bash ASTs.
