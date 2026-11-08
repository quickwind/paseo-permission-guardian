# Paseo Permission Guardian — Design

> Plugin ID: `paseo-permission-guardian`. Status: draft v0.2 (2026-11-08).
> A general-purpose Paseo plugin that classifies the risk of agent tool calls and answers
> routine permission prompts automatically, so humans only review the calls that matter.
>
> Key architectural decisions are recorded in [docs/adr/](./adr/README.md).

---

## 1. Summary

Coding agents managed by Paseo (Claude Code, Codex, OpenCode, Devin CLI and other ACP agents)
ask for permission before running commands, editing files, fetching URLs or calling MCP tools.
Teams currently choose between approving every prompt (slow, causes approval fatigue) and
bypass mode (fast, no guardrails).

This plugin sits on Paseo's permission flow and, for every pending request:

1. normalizes the provider-specific request into one `Action` model;
2. analyzes it **deterministically** — shell commands are parsed into ASTs (bash, PowerShell,
   cmd), wrapper commands such as `wsl`, `bash -c`, `cmd /c` are unwrapped recursively, and file
   paths are normalized across Windows, POSIX and WSL;
3. maps the result to **effect tags** (read, local write, delete, network egress, credential
   access, privilege, infra mutation, …) and applies **combination rules** alongside live
   session context (taint, secret taint, provenance, scope grants);
4. decides `allow`, `ask` or `deny`, optionally consulting an LLM only for the grey zone;
5. records every decision for audit, shadow-mode evaluation and replay testing.

The plugin is pure Node.js (no native binaries to install or sign), cross-platform, and
configuration-driven so it can be published to the Paseo plugin registry for any user.

## 2. Goals and non-goals

### Goals

- **Reduce human approvals** for routine, low-risk tool calls across all Paseo providers.
- **Never auto-allow** high-risk calls; keep humans in the loop where consequences are real.
- **First-class cross-platform support**: POSIX (`bash`/`sh`/`zsh` subset) first, followed by
  Windows PowerShell 5.1 & 7, `cmd.exe`, and WSL via `wsl.exe` with accurate path semantics
  ([ADR-0004](./adr/0004-cross-platform-shell-and-path-strategy.md)).
- **Deterministic first**: understand commands by parsing, not by regex over raw strings.
  LLM judgement is optional and confined to the grey zone
  ([ADR-0001](./adr/0001-deterministic-ast-first-with-effect-tags.md)).
- **Reuse proven rule data**: interpret `safe-chains`' declarative command definitions
  (MIT OR Apache-2.0) for cross-platform CLIs such as git, npm, cargo, kubectl, cloud CLIs,
  combined with mandatory path-model checks on arguments.
- **Safe rollout**: shadow mode by default, agreement metrics, replayable audit log.
- **Configurable** per user, team and (pinned) project without code changes.

### Non-goals

- Not a sandbox and not a security boundary. It reduces prompts; it cannot stop an agent that
  runs outside Paseo or a call the provider already auto-approved. Hard red lines belong in
  provider-native deny rules (Claude Code managed settings, Devin Team Settings, Codex config)
  and in OS or container isolation.
- Not a replacement for provider-native smart modes (Claude Code auto mode, Devin Smart mode).
  It complements them by handling the residual prompts with team-specific rules.
- No full coverage of every CLI in existence. Unknown commands are escalated, not guessed.

## 3. Background: what Paseo offers a plugin

Verified against Paseo plugin docs and source (`getpaseo/paseo`, server `0.16.x` / `0.17.0-beta`).
Hooks use `server.addHook(name, handler)`; this plugin targets `requirements.paseo: ">=0.16.0"`
(covering hooks, settings screens, `appendSystemPrompt`, and `agent.background`).

| Hook | Kind | Payload / Contract | Used for |
| --- | --- | --- | --- |
| `agent.permission.before` | notification (not awaited, 30 s timeout) | `{ agent, request }` | Classify the request; answer via `paseo.agents.ref(id).respondToPermission(...)` |
| `agent.permission.after` | notification | `{ agent, requestId, resolution }` (**no actor/decidedBy field**) | Reconcile final resolution with plugin's own answered map; compute agreement |
| `agent.create.before` | waiting (≤ 30 s) | `{ request: { config, env?, metadata } }` | Optional mode policy, e.g. downgrade `bypassPermissions`, strip ACP `auto_accept` |
| `agent.open.before` | waiting (≤ 30 s) | `{ request }` | Optional `appendSystemPrompt` (non-ACP providers; Codex ≥ 0.121.0) and launch `env` |
| `agent.turn.after`, timeline API | notification / SDK | `{ agent, turnId, outcome }` + `timeline.refetch(...)` | Turn cleanup and incremental session-context sync (taint, modified files) |

Permission request shape (`AgentPermissionRequest`):

```ts
{ id, provider, name, kind: "tool"|"plan"|"question"|"mode"|"other",
  title?, description?, input?, detail?, suggestions?, actions?, metadata? }
```

Response: `{ behavior: "allow", selectedActionId?, updatedInput?, updatedPermissions? }` or
`{ behavior: "deny", message?, interrupt? }`. Responding to an already-resolved request fails;
if the plugin does not respond, the request stays pending for the user.

Provider specifics and platform constraints ([ADR-0003](./adr/0003-paseo-integration-and-config-source-of-truth.md)):

- **Claude Code** (Agent SDK `canUseTool`): `name` is the tool name (`Bash`, `Write`, `Edit`,
  `WebFetch`, `mcp__server__tool`, …) and `input` is the tool input (`command`, `file_path`, `url`).
  Paseo's Claude modes include `auto` (classifier) when the Anthropic API is used.
- **ACP agents** (first-class targets: **Antigravity** and **Devin CLI** via `devin acp`;
  other ACP agents such as Cursor / Gemini CLI follow the same schema): `name` is the ACP tool
  kind (`execute`, `edit`, `read`, `fetch`, …); the raw input lives in
  `metadata.rawRequest.toolCall.rawInput`; `actions` lists the agent's options
  (`allow_once`, `allow_always`, `reject_*`). **Note**: Paseo's ACP adapter does not forward
  `appendSystemPrompt` instructions to ACP providers.
- **Codex / OpenCode**: own approval payloads; handled by dedicated adapters. Codex
  `appendSystemPrompt` requires Codex ≥ 0.121.0.
- **Concurrency & ordering**: Paseo may invoke notification hooks concurrently for parallel
  tool calls, and completion order is not guaranteed. All shared state, parser hosts, and
  audit reconciliation must be concurrency-safe.
- **Known limitation**: Because `agent.permission.before` is a notification, the approval card
  and push notification can surface before the plugin answers. See §12.3 for the upstream
  proposal.

## 4. Threat model

The plugin targets the realistic failure modes of coding agents:

| Threat | Example | Primary defence |
| --- | --- | --- |
| Overeager behaviour | Agent force-pushes to "fix" a rejected push | Effect tags + human-required rules |
| Honest mistakes | `Remove-Item -Recurse` (or `-Rec`) on the wrong directory | Path model, prefix disambiguation, reversibility rules |
| Prompt injection | Issue text instructs agent to POST `.env` to a URL (single-call or split-call) | Same-turn taint & `secretTaint` tracking + secret→egress rules |
| Self-escalation | Agent edits its own permission config, `.git/`, or this plugin's policy | Protected paths, never auto-allowed |

Out of scope: a malicious human user, a compromised Paseo daemon, and calls that never reach
Paseo's permission flow.

## 5. Architecture

```mermaid
flowchart LR
  P[Provider permission request] --> N[Normalize to Action]
  N --> A{Action kind}
  A -->|exec| S[Shell analysis\nlayers + parsers + wrappers]
  A -->|read/edit| F[Path model]
  A -->|fetch| W[URL / egress rules]
  A -->|mcp| M[MCP rules]
  S --> F2[Path & env-secret sweep]
  F2 --> E[Effect tags]
  F --> E
  W --> E
  M --> E
  C[Session context\nincremental timeline sync:\ntaint, secretTaint, provenance, grants] --> R
  E --> R[Combination rules\n+ policy]
  R --> D{Decision}
  D -->|grey zone L1| L[Optional LLM judge\n+ epoch-keyed cache]
  L --> D2[allow / ask]
  D --> O[respondToPermission\nor leave pending]
  D --> AU[(Audit JSONL store)]
```

Module layout (aligned with Paseo plugin runtime boundaries: `client/`, `server/`, `shared/`):

```text
paseo-permission-guardian/
  paseo-plugin.json
  OVERVIEW.md              # Required for Paseo plugin registry listing
  package.json
  tsconfig.json
  index.server.ts          # hook, settings, and RPC wiring
  index.client.tsx         # settings screen, shadow dashboard, timeline renderer
  docs/
    README.md
    DESIGN.md
    adr/
  shared/
    settings.ts            # defineSettings schema (UI-owned runtime controls)
    rpc.ts                 # defineRpc contracts (audit metrics, policy status, replay)
    types.ts               # shared DTOs (no Node / RN imports)
  client/
    settings-screen.tsx    # SettingsCard/SettingsSection UI
    dashboard.tsx          # Shadow dashboard & disagreements view
    timeline-row.tsx       # Compact risk/verdict timeline renderer
  server/
    normalize/             # claude.ts, acp.ts, codex.ts, opencode.ts → Action
    shell/
      layers.ts            # recursive layer analysis + wrapper unwrapping
      bash.ts              # web-tree-sitter + tree-sitter-bash (WASM)
      pwsh.ts              # serialized persistent PowerShell host (UTF-8, timeout, circuit breaker)
      pwsh-fallback.ts     # conservative opaque fallback when no PowerShell host is available
      cmd.ts               # conservative cmd.exe tokenizer
    knowledge/
      sc-registry/         # safe-chains TOML interpreter + vendored data + path sweep
      pwsh-verbs.ts        # verb taxonomy, alias table, parameter prefix disambiguation
      windows-builtins.ts  # del, rd, reg, sc, schtasks, robocopy, icacls, …
      handlers/            # JS ports for commands needing code (curl, …)
    paths/                 # normalization, ancestor realpath, WSL mapping, sensitive/protected catalogs
    context/               # incremental timeline sync, taint, secretTaint, provenance, scope grants
    effects.ts             # effect vocabulary + combination rules
    policy/                # layered YAML loading, schema, project sha256 pinning
    decide.ts              # levels, LLM grey zone, epoch-keyed LLM cache, actor tracking
    audit/                 # rotated JSONL store, redaction, in-memory metrics index, replay
  test/
    vectors/safe-chains/   # extracted conformance cases
    vectors/windows/       # PowerShell, cmd, WSL cases
    replay/                # user-supplied audit replays
```

## 6. Action model

```ts
type Shell = "bash" | "pwsh5" | "pwsh7" | "cmd" | "argv";

interface Action {
  provider: string;
  agentId: string;
  requestId: string;
  kind: "exec" | "read" | "edit" | "delete" | "fetch" | "mcp" | "plan" | "question" | "other";
  host: { os: "windows" | "darwin" | "linux"; wsl?: { distro: string; user?: string } };
  cwd: string;              // normalized
  worktreeRoot?: string;    // from Paseo workspace / git
  exec?: { shell: Shell; source: string };
  paths?: string[];         // normalized, ancestor-resolved realpath where applicable
  url?: { href: string; method?: string; hasBody?: boolean };
  mcp?: { server: string; tool: string; args: unknown };
  raw: unknown;             // original request, for redacted audit only
}
```

Shell detection: tool name (`Bash`, `PowerShell`, ACP `execute`), provider metadata, host OS
and configured defaults. When the shell cannot be determined, the plugin escalates rather than
guessing.

`question`, `plan` and `mode` requests are never auto-answered.

## 7. Shell analysis

### 7.1 Layers

A command is analyzed as a stack of **layers**, each with its own grammar and context:

```ts
analyze(layer: Shell, source: string, ctx: LayerContext): LayerResult
// LayerContext: { os, distro?, user?, cwd, home, depth, env hints }
// LayerResult : { commands: CommandFacts[], effects: EffectTag[], opaque: Reason[] }
```

Each parser produces simple commands (name, argv, redirections, assignments, env reads). Wrapper
commands produce a **child layer** with an adjusted context and `depth + 1`. Results from all
layers are merged before combination rules run, so cross-layer patterns (e.g. Windows reads a
secret, WSL sends it out) are still caught. Maximum depth: 3. Beyond that the call is opaque.

### 7.2 Parsers

| Shell | Parser | Notes |
| --- | --- | --- |
| bash / sh / zsh (subset) | `web-tree-sitter` + `tree-sitter-bash` (WASM) | Extract every simple command across `&&`, `||`, `;`, pipes, subshells, `$(...)`, backticks, process substitution, heredocs, redirections, variable expansions |
| PowerShell | Official parser in a persistent host: `System.Management.Automation.Language.Parser.ParseInput` | Exact grammar of the executing shell (5.1 vs 7). Started once (`-NoProfile -NonInteractive`) with explicit UTF-8 stdio encoding, **serialized request queue**, per-request timeout (500 ms), crash restart + circuit breaker, parse-only, never executes. Any non-empty `ParseError[]` → `opaque`. Can be disabled via policy (`shells.pwshHost: "disabled"`) for EDR-restricted hosts ([ADR-0004](./adr/0004-cross-platform-shell-and-path-strategy.md)). |
| PowerShell (fallback) | Conservative opaque fallback | Used on non-Windows hosts, under WDAC Constrained Language Mode, or when `pwshHost` is disabled; all PowerShell commands emit `opaque` (no PowerShell WASM grammar bundled) |
| cmd.exe | Conservative tokenizer | Splits on `&`, `&&`, `||`, `|` and redirections with correct quote and `^` handling. `%var%`, `!var!`, `for /f`, `call`, nested `cmd /c` → `opaque` |

The PowerShell host extracts `CommandAst` (name via `GetCommandName()`, null for dynamic names),
`CommandParameterAst`, `InvokeMemberExpressionAst` (.NET calls), `VariableExpressionAst`
(`$env:*` reads), `RedirectionAst`, `ScriptBlockAst`, and pipeline structure.

### 7.3 Wrapper unwrapping

| Wrapper | Child layer |
| --- | --- |
| `bash -c`, `sh -c`, `zsh -c` | bash, argument string |
| `cmd /c`, `cmd /k` | cmd |
| `powershell -Command`, `pwsh -c`, `-File` | pwsh (file → provenance check) |
| `powershell -EncodedCommand` (and `-ec` / `-e` / prefix forms) | opaque (escalate) |
| `wsl [opts] <cmdline>`, `wsl -- …` | bash inside the distro (default shell) |
| `wsl -e/--exec …` | argv inside the distro; recurse if it is a shell with `-c` |
| `bash.exe -c`, `<distro>.exe run` | as `wsl` |
| `Start-Process <exe> -ArgumentList` | argv / matching layer |
| `env`, `timeout`, `nice`, `nohup`, `xargs`, `find -exec`, `git -c`, `sudo` | argv; `sudo` and `wsl -u root` add `privilege` |
| `npx`, `pnpm dlx`, `uvx`, `pipx run` | `exec_network_sourced` unless pinned and allow-listed |

**WSL specifics**

- The outer AST decides argument boundaries. In PowerShell, `wsl ls | grep x` pipes into a
  Windows-side `grep`; only `wsl "ls | grep x"` pipes inside Linux.
- Options shape the child context: `-d` (distro), `-u` (user; root ⇒ `privilege`, home `/root`),
  `--cd` (cwd, Windows or Linux path).
- Management commands are classified separately: `--unregister` ⇒ deny (irreversible);
  `--mount`, `--import`, `--export`, `--set-default`, `--install`, `--shutdown`,
  `--terminate` ⇒ human.
- Inside WSL, Windows interop (`cmd.exe`, `powershell.exe`) recurses back to Windows layers.

### 7.4 Opaque constructs

Opaque is not "dangerous"; it means "cannot be understood statically". Opaque calls go to the
grey zone (LLM or human), never to auto-allow. Triggers include: parse errors; dynamic command
names (`$CMD args`, `& $x`); `eval`, `Invoke-Expression`/`iex`; `source`/dot-sourcing of
non-tracked files; inline code (`python -c`, `node -e`, `Add-Type`); `-EncodedCommand`;
obfuscation (long base64, `\x` escapes, char-code joins); splatting from unknown variables;
ambiguous PowerShell parameter abbreviations; COM objects; depth limit exceeded.

## 8. Command knowledge

### 8.1 `safe-chains` registry interpreter

`safe-chains` (`michaeldhopkins/safe-chains`, MIT OR Apache-2.0) ships ~1,268 declarative TOML
command definitions; all but 29 are fully declarative (the rest reference Rust handlers).
The plugin vendors the TOML data with attribution and implements an interpreter for the schema
documented in `commands/SAMPLE.toml`: `sub` (nested), `bare`, `bare_flags`, `standalone`,
`valued`, `max_positional`, `guard`, `first_arg`, `require_any`, `write_flags`, `wrapper`,
`delegate_*`, `allow_all`, `deny`, aliases, `tolerate_unknown_*`.

- Command names are normalized before lookup (lowercase and `.exe`/`.cmd`/`.bat` stripped on
  Windows).
- Levels map to effect baselines: `Inert` → `read`, `SafeRead` → `exec_project_readonly`,
  `SafeWrite` → `write_local`.
- **Mandatory path & env-secret sweep** ([ADR-0004](./adr/0004-cross-platform-shell-and-path-strategy.md)):
  Because `safe-chains` TOML definitions do not tag which arguments are filesystem paths, every
  `SafeRead` / `SafeWrite` match must still pass all positional arguments and path-like flag
  values (`-f`, `--file`, `-C`, `--config`, `-i`, `-o`, etc.) through the Path Model to detect
  sensitive or protected paths before assigning `L0`.
- Commands that require handlers (e.g. `curl`, `perl`) get JS handlers over time; until then
  they are treated as unknown.
- A sync script pulls new upstream data releases; conformance tests (§13) gate updates.
- The registry is an **allow-list**: a command or flag it does not list is not auto-allowed.

### 8.2 PowerShell knowledge

- **Alias resolution** first (`rm`, `del`, `ri`, `iwr`, `irm`, `iex`, `gc`, `sc`, and in 5.1
  `curl`/`wget` → `Invoke-WebRequest`).
- **Parameter prefix disambiguation & positional parameters**: Resolve PowerShell unique-prefix
  abbreviations (e.g. `-Rec` → `-Recurse`, `-M` → `-Method`, `-Ep` → `-ExecutionPolicy`) for
  known cmdlets; treat ambiguous or unrecognized abbreviated flags as `opaque`.
- **Verb taxonomy** as the baseline: `Get/Test/Measure/Select/Find/Resolve/Compare/Format/Out-Host`
  → read; `New/Set/Add/Copy/Move/Rename/Clear/Remove/Start/Stop/Restart/Invoke/Install/Uninstall/Register/Unregister/Enable/Disable`
  → write/exec, refined by noun, parameters and paths.
- **High-risk constructs**: `Remove-Item -Recurse`; provider paths `HKLM:`/`HKCU:`/`Cert:`;
  `Set-ExecutionPolicy`, `-ExecutionPolicy Bypass`; `Invoke-WebRequest`/`Invoke-RestMethod`
  with `-Method Post/Put`, `-Body`, `-InFile`; .NET calls (`[IO.File]::Delete`,
  `[Net.WebClient]`); `Start-Process -Verb RunAs`; credential cmdlets; `Get-ChildItem Env:` /
  `$env:*` secret reads.
- `-WhatIf` on cmdlets that honour it lowers the effect to a preview.

### 8.3 Windows built-ins

A small hand-written table for cmd and system tools: `del /s`, `rd /s`, `format`, `robocopy /MIR`,
`reg add/delete`, `sc`, `schtasks`, `net user`, `icacls`, `takeown`, `vssadmin`, `bcdedit`,
`diskpart`, `cmdkey`, `setx`, `winget`, `choco`, `msiexec`.

## 9. Path model

Correct paths are the foundation of "inside the worktree?" and "credential store?" decisions.

**Normalization**

- Windows: case-insensitive comparison, drive letters, `/` vs `\`, `\\?\` prefixes, UNC paths,
  8.3 short names (`PROGRA~1`), alternate data streams (`file:stream`), env expansion
  (`%USERPROFILE%`, `$env:USERPROFILE`, `~`), PowerShell provider drives (`Env:`, `HKLM:`, `Cert:`
  are not files).
- POSIX: `~`, `$HOME`, `..`, symlinks.
- **Ancestor-resolved real paths** ([ADR-0004](./adr/0004-cross-platform-shell-and-path-strategy.md)):
  Use `fs.realpathSync.native` when the path exists; when the target does not yet exist (e.g.
  `Write`, `mkdir`, redirection), walk up to the nearest existing ancestor, resolve its real
  path, and re-append the remaining segments so symlinked parent directories cannot escape the
  worktree.

**WSL mapping (both directions)**

- `C:\repo` ⇄ `/mnt/c/repo` (respecting the distro's automount root).
- `\\wsl$\<distro>\…` and `\\wsl.localhost\<distro>\…` ⇄ Linux paths in that distro.
- Home depends on the WSL user (`-u root` ⇒ `/root`).
- **Avoid waking stopped WSL VMs**: perform lexical normalization and sensitive-path matching
  first; skip `realpath` syscalls on `\\wsl$\` / `\\wsl.localhost\` unless the distro is
  already running.

**Sensitive path catalog** (policy-extensible), evaluated on the mapped path in *both* worlds:
`~/.ssh`, `~/.aws`, `~/.azure`, `~/.kube`, `~/.config/gcloud`, `~/.docker/config.json`,
`~/.npmrc`, `~/.pypirc`, `~/.netrc`, `~/.git-credentials`, `.env*`, `*.pem`, `*.pfx`, `*.key`,
`%APPDATA%\Microsoft\Credentials`, browser profiles, `/etc/shadow`, `/etc/sudoers`.

**Protected paths** (never auto-allowed for writes): agent configs (`.claude/`, `.devin/`,
`.codex/`, `.cursor/`), the entire `.git/` directory (covering hooks, config, `info/attributes`,
modules), CI configs, shell startup files, PowerShell profiles, package-manager configs
(`.npmrc`, `.pip/pip.conf`), startup folders, scheduled-task and service definitions, and this
plugin's own policy, settings, and data files.

## 10. Effects, context and decisions

### 10.1 Effect vocabulary

| Tag | Meaning |
| --- | --- |
| `read` | Reads ordinary files / metadata |
| `read_secret` | Reads a sensitive path, credential store, or sensitive env vars (`env`, `printenv`, `$env:*_KEY/*_TOKEN/*_SECRET`) |
| `write_worktree` | Creates/modifies files inside the worktree |
| `write_outside` | Writes outside the worktree (excluding temp) |
| `write_protected` | Writes a protected path |
| `delete_worktree` / `delete_outside` | Deletes files |
| `exec_project` | Runs project code (tests, builds, scripts) |
| `exec_inline` / `exec_network_sourced` | Runs inline code / code fetched from the network |
| `pkg_install` | Installs dependencies (may run install scripts) |
| `net_read` / `net_egress` | Fetches / sends data off the machine |
| `vcs_remote` | Push, force-push, remote branch deletion, releases |
| `infra_read` / `infra_mutate` | Cloud, Kubernetes, IaC, databases (with target) |
| `privilege` | sudo, `-u root`, RunAs, service/registry/system config |
| `system_destructive` | Disk, boot, shadow copies, distro unregister |
| `opaque` | Not statically understood |

Each tag carries attributes: target (path, host, context), reversibility, and source layer.

### 10.2 Context signals

See [ADR-0002](./adr/0002-session-context-taint-and-cache-invalidation.md) for rationale.

- **Incremental same-turn sync**: On context-sensitive permission requests (`exec`, `net_egress`,
  `vcs_remote`), incrementally read new entries from the agent's timeline since the last synced
  cursor so same-turn tool calls (including provider-auto-approved `Read`/`Edit`/`WebFetch`)
  are reflected immediately, not only after `agent.turn.after`.
- **Targeted provenance**: Upgrade `exec_project` to `exec_inline` when executing a directly
  modified script/file, or when build/task entrypoints (`package.json`, `Makefile`,
  `pyproject.toml`, `scripts/**`, test runner configs) were modified in the session. Ordinary
  source-file edits do not block allow-listed test commands.
- **Untrusted taint (`untrustedTaint`)**: After the session reads untrusted external content
  (web pages, issue bodies, fetched documents, MCP results from untrusted servers), raise
  `net_egress`, `exec_*` and `vcs_remote` by one level for the rest of the turn or session.
- **Secret taint (`secretTaint`)**: After the session reads a sensitive path or sensitive env
  vars (`read_secret`), elevate subsequent `net_egress` calls in the session to at least `L2`
  (`ask`) — or `L3` (`deny`) if configured — to catch split-call exfiltration.
- **Scope grants**: User-declared task scopes ("may run migrations against local postgres")
  stored in agent metadata; matching actions are downgraded, never beyond the policy ceiling.

### 10.3 Combination rules (examples)

| Rule | Result |
| --- | --- |
| `read_secret` + `net_egress` anywhere in the call (any layer) | deny |
| `secretTaint` active + `net_egress` in a later call | ask (or deny by policy) |
| `net_read` piped into an interpreter (`curl \| sh`, `iwr \| iex`) | deny |
| `infra_mutate` on a target not in `trusted.environments` | human |
| `vcs_remote` force or to a protected branch | human |
| `write_protected` | human (deny for this plugin's own files) |
| `delete_outside` with recursion | deny |
| `system_destructive` | deny |
| any `opaque` | grey zone |

### 10.4 Levels and decision

| Level | Typical effects | Decision |
| --- | --- | --- |
| L0 | `read`, `write_worktree`, `exec_project` (allow-listed, entrypoints unmodified), `net_read` to trusted domains | allow (select the provider's **allow-once** option; never "always") |
| L1 | unknown commands, opaque, `pkg_install`, `write_outside` to temp-like dirs, unlisted MCP tools | grey zone → LLM judge (if enabled) may return allow or ask; default ask |
| L2 | `vcs_remote`, `infra_mutate`, `privilege`, `write_protected`, untrusted egress, `secretTaint` egress | ask (human) |
| L3 | combination-rule denies, `system_destructive` | deny with an explanatory message the agent can act on |

Rules:

- The highest level across all effects wins; deterministic L2/L3 can never be lowered by the LLM.
- Any internal error, timeout or unsupported provider payload ⇒ leave pending (ask). The plugin
  fails *to the human*, never to allow, and never denies on error.
- **No cross-state caching for deterministic rules**: deterministic evaluation runs fresh on
  every request. Only LLM judge responses may be cached, keyed by
  `(normalizedActionHash, policyVersion, taintEpoch, worktreeMutationEpoch, scopeGrantVersion)`.
- Deny can be downgraded to ask globally by policy for teams that prefer no auto-deny.

### 10.5 Optional LLM judge

- Input: truncated/summarized user task intent, the normalized action, deterministic findings
  and reasons. Tool outputs and assistant prose are excluded to limit prompt-injection reach
  (note: user messages with pasted/attached external content remain partially untrusted, so
  the LLM can never override L2/L3 or return `deny`).
- Output: `allow` or `ask` with a one-line reason.
- Must propagate Paseo's `context.signal` combined with a short request timeout (3–5 s).
- Pluggable backends (Anthropic, OpenAI-compatible, local). Disabled by default.
- **UX note**: Until Paseo adds a waiting permission hook (§12.3), a 1–3 s LLM call can cause
  approval cards to flash and disappear. Clearly surface this trade-off in Settings.

## 11. Configuration and policy

Clear Source of Truth ([ADR-0003](./adr/0003-paseo-integration-and-config-source-of-truth.md)):

- **Paseo Settings (`defineSettings`, host scope)**: Stores runtime controls edited in the UI —
  `mode` (`off | shadow | act`), `denyAsAsk`, `llm` enable/provider/model, local policy file
  paths, pinned project sha256 hashes, and timeline verbosity (`off | notable | all`).
- **Layered YAML Policy**: Stores declarative rules; later layers override earlier ones, and
  deny/human rules from any layer cannot be relaxed by a later layer. The UI never rewrites YAML
  files:
  1. Built-in defaults (conservative).
  2. User: `~/.paseo/permission-guardian/policy.yaml`.
  3. Team: a local file path configured in Settings (distributed by teams via Git, dotfiles, or
     MDM; no remote HTTP fetch).
  4. Project: `.paseo-guardian.yaml` in the repo — **ignored unless pinned** by sha256 in
     Settings or team policy; any change un-trusts it until re-pinned.

```yaml
trusted:
  domains: [registry.npmjs.org, pypi.org, github.com, "*.internal.example.com"]
  environments:
    kube: [kind-dev, docker-desktop]
    databases: [localhost, 127.0.0.1]
  mcp:
    - { server: github, tools: [list_issues, get_issue, get_pull_request], level: L0 }
    - { server: github, tools: [merge_pull_request], level: L2 }

paths:
  sensitive: ["~/.config/acme/token", "%APPDATA%\\Acme\\*"]
  protected: ["deploy/**"]

commands:            # extra registry entries, same schema as safe-chains TOML, in YAML
  - name: acmectl
    sub:
      - { name: status, valued: [--env] }
      - { name: deploy, level: L2 }

shells:
  windowsDefault: pwsh7      # pwsh5 | pwsh7 | cmd
  pwshHost: auto             # auto | disabled (for EDR-restricted Windows hosts)
  wsl: { enforceCanonicalForm: true }
```

`enforceCanonicalForm` makes any `wsl` invocation that is not
`wsl -d <distro> -e bash -c '<command>'` a human decision, removing quoting ambiguity between
PowerShell versions.

## 12. Paseo integration

### 12.1 Hooks

- `agent.permission.before`: run the pipeline; in `act` mode record `requestId` in an in-memory
  `answeredByPlugin` map and call `respondToPermission` for allow/deny; in `shadow` mode only
  record. Tolerate "already resolved" errors (a human was faster) and remove from
  `answeredByPlugin` on failure.
- `agent.permission.after`: reconcile by `requestId` (upsert/merge to handle out-of-order
  delivery); attribute actor via `answeredByPlugin` vs. external/human resolution; compute
  agreement metrics.
- `agent.open.before` (optional, opt-in): append system-prompt guidance — one action per
  command, avoid chaining and inline scripts, prefer PowerShell over cmd on Windows, canonical
  WSL form. **Known limitation**: ignored by Paseo's ACP adapter; requires Codex ≥ 0.121.0.
- `agent.create.before` (optional, opt-in): mode policy, e.g. replace `bypassPermissions` with
  `auto`, remove ACP `auto_accept`.

### 12.2 UI

Built with React Native primitives (`theme.colors`, `layout.compact`) and Paseo host UI
components (`SettingsSection`, `SettingsCard`, `SettingsSwitch`, `SettingsSelect`, etc.):

- **Settings screen** (`addSettingsScreen`): mode, `denyAsAsk`, LLM toggle/backend, policy file
  locations, team policy load status, project pin status, timeline verbosity.
- **Shadow dashboard** (`addScreen` + sidebar item): would-allow rate, agreement with humans,
  false-allow count, disagreements list (the most important view before switching to `act`).
- **Timeline row** (`timeline.append` + `addTimelineRenderer`): compact row for notable events
  (`deny`, `shadow` disagreements) by default, configurable to `all` or `off`. Note that
  appended rows are in-memory on the daemon and do not survive daemon restart.

### 12.3 Upstream proposal

Propose a waiting hook `agent.permission.decide` (or a decision field on the existing hook)
that Paseo awaits for a bounded time (e.g. 2 s) **before** broadcasting attention and push
notifications. Timeout ⇒ normal human flow. The plugin detects and prefers it when available.

## 13. Audit, metrics and testing

### 13.1 Audit store

- Append-only JSONL under the plugin data directory, rotated daily/by size, paired with a
  lightweight in-memory / JSON summary index for dashboard metrics (pure Node.js, no native
  SQLite addon; [ADR-0003](./adr/0003-paseo-integration-and-config-source-of-truth.md)).
- Each record (keyed by `requestId` for `before`/`after` reconciliation): normalized action
  (secrets redacted), layers, effects, reasons, decision, mode, actor attribution, final
  resolution, latency, plugin and data versions.
- Redaction: known token formats, `Authorization` headers, values of `*_KEY`/`*_TOKEN`/`*_SECRET`
  env assignments, PEM blocks. Raw commands can be excluded entirely by policy.

### 13.2 Metrics

Would-allow rate, agreement rate, **false-allow count** (plugin would allow, human denied — must
be ~0 before `act`), latency p50/p95, opaque rate per shell.

### 13.3 Tests

- **Conformance vectors**: extract command → expected verdict cases from `safe-chains`' test
  suite (≈2.7k tests) for the bash layer, plus path-sweep regression tests.
- **Session & security vectors**: same-turn taint → egress, split-call `read_secret` → egress,
  entrypoint edit vs. source edit provenance, cache invalidation on state changes, concurrent
  `before`/`after` ordering.
- **Windows vectors**: PowerShell 5.1 and 7 (incl. parameter prefix abbreviations, UTF-8 stdio,
  parser host timeout/restart), cmd, WSL invocation forms, ancestor `realpath` & symlink escape.
- **Replay**: users can replay their own audit logs against a new plugin version and diff
  decisions; any new allow on a previously human-denied action fails the run.
- **Differential checks**: compare bash parse results against `bash -n` and PowerShell results
  across 5.1/7 where available.
- **CI matrix**: Linux, macOS, Windows (PowerShell 5.1 and 7), Windows + WSL.

## 14. Security considerations

- Paseo plugins are trusted, unsandboxed code running with the daemon user's permissions. Keep
  dependencies minimal and pinned; publish provenance for npm releases.
- The plugin never auto-allows writes to its own policy, settings, data, or pin files, nor to
  agent config or `.git/`.
- The PowerShell host is parse-only; it must never evaluate input. Inputs are passed as JSON
  data over UTF-8 stdin, never interpolated into scripts.
- Event delivery is best-effort; the plugin is a prompt reducer, not an enforcement point.
  Document clearly that red lines belong in provider-native deny rules and OS isolation.
- Under WDAC with PowerShell Constrained Language Mode (or EDR restrictions), the parser host
  may be blocked unless signed; the plugin detects this (or honors `pwshHost: "disabled"`) and
  falls back (§7.2).

## 15. Licensing and third-party code

- Plugin license: Apache-2.0.
- `safe-chains` TOML data: MIT OR Apache-2.0 — vendored with copyright notices and a
  `THIRD_PARTY_NOTICES` file.
- `tree-sitter`, `tree-sitter-bash`: MIT.
- **Not used**: Destructive Command Guard (`dcg`). Its license adds a rider restricting use by
  and for certain AI companies; no code, rules or data from it are used, and contributors must
  not port from it.

## 16. Milestones

Split P1 into P1a and P1b to validate shadow-mode accuracy early ([ADR-0004](./adr/0004-cross-platform-shell-and-path-strategy.md)):

| Phase | Scope | Exit criteria |
| --- | --- | --- |
| P0 | Plugin scaffold (`paseo-plugin.json`, `OVERVIEW.md`), normalizers (Claude Code, ACP: Antigravity & Devin CLI), Paseo Settings, rotated JSONL audit store, shadow mode | Installs cleanly; records and reconciles `before`/`after` requests on macOS/Linux/Windows |
| P1a | `bash` WASM parser, POSIX Path Model (incl. ancestor `realpath`), `safe-chains` interpreter + path sweep, effects/combination rules, same-turn taint & provenance (shadow only) | `safe-chains` conformance vectors + session/security vectors pass |
| P1b | PowerShell 5.1/7 serialized host + prefix disambiguation, `cmd.exe` tokenizer, Windows built-ins, WSL layers & bidirectional path mapping | Windows vectors pass on PowerShell 5.1 & 7 and Windows + WSL |
| P2 | `act` mode, shadow dashboard, compact timeline renderer, optional system-prompt guidance & mode policy | False-allow = 0 on replay corpus; agreement ≥ target |
| P3 | Optional LLM judge (with epoch-keyed cache), Codex/OpenCode adapters, JS handlers for top handler-based commands, upstream waiting-hook PR | — |

## 17. Resolved design decisions

All initial open questions for P0–P2 are resolved:

1. **License**: Apache-2.0.
2. **Minimum Paseo version**: `requirements.paseo: ">=0.16.0"`.
3. **Priority ACP agents**: Antigravity and Devin CLI.
4. **PowerShell fallback (non-Windows / no host)**: Treat all PowerShell commands as `opaque`
   (no PowerShell WASM grammar bundled).
5. **Team policy distribution**: Local file path only (teams distribute via Git, dotfiles, or
   MDM; no remote HTTPS fetching).

## 18. References

- Paseo plugin docs: hooks, reference, publishing — https://paseo.sh/docs/plugins
- Paseo source — https://github.com/getpaseo/paseo
- Claude Code auto mode (layered approvals, classifier inputs) —
  https://www.anthropic.com/engineering/claude-code-auto-mode
- Claude Code managed settings — https://code.claude.com/docs/en/managed-settings
- Devin CLI permissions and modes — https://docs.devin.ai/cli/reference/permissions
- `safe-chains` — https://github.com/michaeldhopkins/safe-chains
- Local decider (prior art, local-model approach) — https://github.com/ziptie-soft/local-decider
- PowerShell language parser API — `System.Management.Automation.Language.Parser`
