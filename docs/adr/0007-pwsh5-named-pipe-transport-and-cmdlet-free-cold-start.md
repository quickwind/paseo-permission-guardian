# ADR-0007: Windows PowerShell 5.1 Host Transport over Authenticated Named Pipe and Cmdlet-Free Cold Start

- **Status**: Accepted
- **Date**: 2026-11-22
- **Supersedes**: —
- **Superseded by**: —
- **Extends**: [ADR-0006](./0006-windows-env-classification-shell-hardening-and-static-cwd.md)

## Context

[ADR-0006](./0006-windows-env-classification-shell-hardening-and-static-cwd.md) specified a short
`-EncodedCommand` bootstrap that reads the full parser-host script from UTF-8 `stdin`. Live runs of
`powershell.exe` 5.1 on GitHub Actions `windows-latest` showed two platform-specific failures that
did not occur on PowerShell 7 or on macOS/Linux:

1. **`stdin` hand-off.** With `-EncodedCommand`, Windows PowerShell 5.1 can take over the redirected
   `stdin` pipe, so the bootstrap and the host contend for it and the request is never delivered.
2. **Cold-start stall on the first cmdlet.** The host environment is deliberately sanitized
   ([ADR-0006](./0006-windows-env-classification-shell-hardening-and-static-cwd.md)): `PSModulePath`,
   `LOCALAPPDATA`, `USERPROFILE`, `PATH`, `COR_*`/`DOTNET_*` are stripped. In that environment the
   first call to any cmdlet outside `Microsoft.PowerShell.Core` (here `New-Object`, from
   `Microsoft.PowerShell.Utility`) triggers module autoload/analysis in 5.1 and does not return
   before the cold timeout. Measured: the bootstrap printed its first marker at ~2.1 s and never
   reached the next statement within 20 s. After replacing `New-Object` with static constructors the
   live Windows PowerShell 5.1 test passes within its timeout.

A diagnostic trap also contributed to the delay: several hosts can legitimately exist for the same
shell variant with different binaries (a test parses with `pwsh5` rules against the PowerShell 7
binary), and the diagnostic accessor returned the first host with the matching prefix instead of the
host for the default binary, so reported stage markers described the wrong process.

## Decision

1. **Transport on Windows PowerShell 5.1 only**: the host connects back to a Node-side
   `net.Server` over an **authenticated Windows named pipe** `\\.\pipe\paseo-pwsh5-<pid>-<random>`
   (`PipeOptions.Asynchronous`). The child is spawned with `stdio: ["ignore", "pipe", "pipe"]`.
   - The first line on the pipe must equal a per-spawn 128-bit random token; otherwise the socket is
     destroyed. Only one authenticated connection is accepted and the server is closed right after
     authentication.
   - The host script is streamed over the pipe as one Base64 line; requests and responses use the
     same NDJSON framing, 2 MiB line limit and bounded serialized queue as before.
   - PowerShell 7 and non-Windows hosts keep the `stdin`/`stdout` transport from ADR-0006.
2. **Cmdlet-free cold path**: the 5.1 bootstrap and the shared host script must not call
   `New-Object` or any other cmdlet outside `Microsoft.PowerShell.Core` on the startup path. Use
   `[Type]::new(...)` (PowerShell 5.0+) and direct .NET types. JSON on 5.1 uses
   `System.Web.Script.Serialization.JavaScriptSerializer`; PowerShell 7 may use its JSON cmdlets.
   `buildSanitizedPwshEnv()` is **not** relaxed to work around the stall.
3. **Timeouts**: the cold timeout is 20 s for `pwsh5` and 10 s for `pwsh7`; the warm timeout stays
   1.5 s. Every timeout, connection failure or crash still resolves to `opaque` → `ask` (fail to
   human).
4. **Diagnostics**: host diagnostics select the host for the shell's default binary, include the
   binary path, and carry per-stage timestamps (`__ST:*`, `__NODE:authed`) measured from spawn.

## Consequences

### Positive

- `powershell.exe` 5.1 starts reliably under the sanitized environment on `windows-latest`; the
  Windows PowerShell 5.1 and 7 suites pass in CI.
- The named pipe is private to the spawned child by an unguessable name and token; no `stdin`
  ownership races.
- Stage timestamps make future cold-start regressions diagnosable from a single CI log.

### Negative / Trade-offs

- A second transport exists for one shell variant, increasing test surface.
- PowerShell 5.1 startup is slower than 7 in the worst case, so the cold timeout is higher.

### Follow-up / Guardrails

- A regression test fails if `New-Object` reappears in `server/shell/pwsh-host.ts`.
- New code on the 5.1 startup path must be exercised by the Windows live 5.1 suite in CI, which
  asserts the 5.1 test actually ran and passed.
- Do not weaken the sanitized environment contract asserted in `pwsh.test.ts`.

## Alternatives Considered

1. **Keep `stdin` and add `-InputFormat None`/flush workarounds** — did not remove the hand-off
   race on 5.1 and diverged between versions.
2. **Restore `PSModulePath`/`LOCALAPPDATA`/`USERPROFILE` for the 5.1 child** — would likely avoid the
   stall but re-opens the environment-injection surface closed in ADR-0006.
3. **`$PSModuleAutoLoadingPreference = 'None'` with cmdlets still in use** — breaks any remaining
   cmdlet call instead of removing the dependency.
4. **Write the host script to a temp `.ps1` and run with `-File`** — adds a writable on-disk script
   that could be tampered with and execution-policy dependencies.
