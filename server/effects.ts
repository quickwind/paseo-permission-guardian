import { existsSync, realpathSync } from "node:fs";
import { join } from "node:path";
import type { Action, EffectTag, Shell } from "../shared/types.js";
import type { SessionState } from "./context/session.js";
import {
  getDefaultSafeChainsRegistry,
  type SafeChainsRegistry,
} from "./knowledge/sc-registry/interpreter.js";
import {
  classifyPath,
  stripProviderDrive,
  type WindowsPathClassification,
  type WindowsPathContext,
} from "./paths/index.js";
import {
  classifyExecutionPolicyEnvVar,
  classifyWslEnvValue,
  detectCredentialLiterals,
  isExecHijackEnvVar,
  isRedirectOrTlsEnvVar,
  isSensitiveCliFlag,
  isSensitiveEnvVarName,
  isTempDirEnvVar,
} from "./secrets/patterns.js";
import { analyzeShellLayers } from "./shell/layers.js";
import type { PwshHostMode } from "./shell/pwsh.js";
import type { AssignmentFact, CommandFact, PipelineFact } from "./shell/types.js";

export interface EffectAnalysisResult {
  effects: EffectTag[];
  opaqueReasons: string[];
  pipelines: PipelineFact[];
  commands: CommandFact[];
  touchedSecret: boolean;
  touchedUntrusted: boolean;
}

export interface EffectAnalysisOptions {
  pathCtx: WindowsPathContext;
  registry?: SafeChainsRegistry;
  trustedDomains?: string[];
  session?: SessionState;
  pwshHost?: PwshHostMode;
  allowPosixPwshHost?: boolean;
  pwshBinaryPath?: string;
  envSnapshot?: Record<string, string | undefined>;
}

const DEFAULT_TRUSTED_DOMAINS = [
  "registry.npmjs.org",
  "pypi.org",
  "github.com",
  "crates.io",
  "pkg.go.dev",
  "developer.mozilla.org",
];

const INTERPRETER_BINARIES = new Set([
  "sh",
  "bash",
  "zsh",
  "dash",
  "ksh",
  "python",
  "python3",
  "node",
  "perl",
  "ruby",
  "php",
  "iex",
  "invoke-expression",
  "powershell",
  "pwsh",
  "cmd",
]);

const SYSTEM_DESTRUCTIVE_COMMANDS = new Set([
  "mkfs",
  "mkfs.ext4",
  "mkfs.xfs",
  "fdisk",
  "parted",
  "diskutil",
  "dd",
  "shutdown",
  "reboot",
  "halt",
  "poweroff",
  "format",
  "diskpart",
  "bcdedit",
]);

const INFRA_MUTATE_COMMANDS = new Set([
  "kubectl",
  "terraform",
  "tofu",
  "helm",
  "aws",
  "gcloud",
  "az",
  "flyctl",
  "wrangler",
]);

const DECLARATION_BUILTINS = new Set(["export", "declare", "typeset", "readonly", "local"]);

const SYSTEM_DESTRUCTIVE_ROOTS = new Set([
  "/",
  "/etc",
  "/private/etc",
  "/usr",
  "/bin",
  "/sbin",
  "/System",
]);

const CMD_INTERNAL_BUILTINS = new Set([
  "dir",
  "echo",
  "type",
  "copy",
  "move",
  "del",
  "erase",
  "rd",
  "rmdir",
  "mkdir",
  "md",
  "ren",
  "rename",
  "set",
  "cd",
  "chdir",
  "pushd",
  "popd",
  "ver",
  "rem",
  "start",
  "call",
  "goto",
  "for",
  "if",
  "setlocal",
  "endlocal",
  "assoc",
  "ftype",
  "cls",
  "exit",
]);

const LOLBIN_COMMANDS = new Set([
  "mshta",
  "wscript",
  "cscript",
  "installutil",
  "forfiles",
]);

const WINDOWS_PRIVILEGE_TOOLS = new Set(["sc", "schtasks", "net", "icacls", "takeown", "assoc", "ftype"]);
const WINDOWS_PKG_INSTALL_TOOLS = new Set(["winget", "choco", "msiexec"]);

export const PASEO_READONLY_MCP_TOOLS: ReadonlySet<string> = new Set([
  "list_agents",
  "get_agent_status",
  "get_agent_activity",
  "read_agent_conversation",
  "list_workspaces",
  "list_terminals",
  "list_providers",
  "list_models",
  "list_hosts",
  "list_pending_permissions",
  "list_schedules",
  "list_events",
  "get_run",
  "list_runs",
  "inspect_provider",
  "inspect_schedule",
  "schedule_logs",
  "list_gates",
  "list_subscriptions",
  "get_analytics",
  "capture_terminal",
  "list_workspace_scripts",
]);

const PASEO_CONTROL_SUBCOMMANDS = new Set([
  "plugin",
  "permit",
  "permission",
  "agent",
  "settings",
  "config",
  "daemon",
  "schedule",
  "workspace",
  "run",
]);
const PASEO_VALUE_FLAGS = new Set(["--home", "--host", "--server"]);

function isPaseoControlCommand(bin: string, argv: string[]): boolean {
  if (bin !== "paseo") return false;
  // argv may or may not include the command name itself.
  let i = argv[0] !== undefined && normalizeBin(argv[0]) === "paseo" ? 1 : 0;
  while (i < argv.length && argv[i].startsWith("--")) {
    const flag = argv[i];
    i += !flag.includes("=") && PASEO_VALUE_FLAGS.has(flag) ? 2 : 1;
  }
  return i < argv.length && PASEO_CONTROL_SUBCOMMANDS.has(argv[i].toLowerCase());
}

function normalizeBin(name: string): string {
  const base = (name.split(/[\\/]/).pop() ?? name).toLowerCase();
  return base.replace(/\.(?:exe|cmd|bat|ps1|com)$/, "");
}

function isRelativePath(raw: string): boolean {
  return (
    !raw.startsWith("/") &&
    !raw.startsWith("~") &&
    !raw.startsWith("$HOME") &&
    !raw.startsWith("${HOME}") &&
    !/^[A-Za-z]:/.test(raw) &&
    !raw.startsWith("\\\\") &&
    !stripProviderDrive(raw)
  );
}

function isUrlTrusted(href: string, trustedDomains: string[]): boolean {
  try {
    const host = new URL(href).hostname.toLowerCase();
    return trustedDomains.some((d) => {
      const lower = d.toLowerCase();
      return lower.startsWith("*.") ? host.endsWith(lower.slice(1)) : host === lower;
    });
  } catch {
    return false;
  }
}

function isCurlEgress(argv: string[]): boolean {
  const egressFlags = new Set([
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "-F",
    "--form",
    "-T",
    "--upload-file",
  ]);
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (egressFlags.has(tok)) return true;
    if ((tok === "-X" || tok === "--request") && argv[i + 1]) {
      const method = argv[i + 1].toUpperCase();
      if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) return true;
    }
    if (tok.startsWith("-d") && tok.length > 2) return true;
  }
  return false;
}

function extractUrlFromArgv(argv: string[]): string | undefined {
  return argv.find((a) => /^https?:\/\//i.test(a));
}

function isPsEnvDump(argv: string[]): boolean {
  for (const arg of argv) {
    if (arg === "-E") return true;
    if (!arg.startsWith("-") && /^[a-zA-Z]*e[a-zA-Z]*$/.test(arg)) {
      return true;
    }
  }
  return false;
}

function hasShortFlag(argv: string[], flagChar: string): boolean {
  for (const arg of argv) {
    if (arg === "--") break;
    if (arg.startsWith("-") && !arg.startsWith("--") && arg.slice(1).includes(flagChar)) {
      return true;
    }
  }
  return false;
}

function isCompgenEnvDump(argv: string[]): boolean {
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "-v" || arg === "-e") return true;
    if (arg.startsWith("-") && !arg.startsWith("--") && (arg.includes("v") || arg.includes("e"))) {
      return true;
    }
    if (arg === "-A" && (argv[i + 1] === "variable" || argv[i + 1] === "export")) {
      return true;
    }
  }
  return false;
}

function emitWindowsPathAlerts(
  classified: WindowsPathClassification,
  depth: number,
  effects: EffectTag[],
  opaqueReasons: string[],
): void {
  if (classified.isRemoteUnc) {
    effects.push({
      tag: "net_egress",
      layer: depth,
      target: classified.normalized,
      detail: "remote_unc_ntlm",
    });
  }
  if (classified.isDriveRelative) {
    opaqueReasons.push("drive_relative_path");
    effects.push({
      tag: "opaque",
      layer: depth,
      target: classified.raw,
      detail: "drive_relative_path",
    });
  }
  if (classified.hasUnresolvedShortName) {
    opaqueReasons.push("unresolved_short_name");
    effects.push({
      tag: "opaque",
      layer: depth,
      target: classified.normalized,
      detail: "unresolved_short_name",
    });
  }
  if (classified.adsStream) {
    if (/zone\.identifier/i.test(classified.adsStream)) {
      opaqueReasons.push("zone_identifier_ads");
      effects.push({
        tag: "opaque",
        layer: depth,
        target: classified.raw,
        detail: "zone_identifier_ads",
      });
    } else if (
      /\$index_allocation/i.test(classified.adsStream) ||
      !/^:\$data$/i.test(classified.adsStream.trim())
    ) {
      opaqueReasons.push("ntfs_ads");
      effects.push({
        tag: "opaque",
        layer: depth,
        target: classified.raw,
        detail: "ntfs_ads",
      });
    }
  }
}

const PASEO_ROOT_ENV_VARS = new Set(["PASEO_HOME", "PASEO_PLUGIN_DIR", "PASEO_GUARDIAN_DATA_DIR"]);

function evaluateAssignments(
  assignments: AssignmentFact[],
  effects: EffectTag[],
  opaqueReasons: string[],
  pathCtx: WindowsPathContext,
): void {
  const seen = new Set<string>();

  for (const a of assignments) {
    const dedupKey = `${a.name}\u0000${a.value}\u0000${a.standalone}\u0000${a.depth}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);

    if (PASEO_ROOT_ENV_VARS.has(a.name.trim().toUpperCase())) {
      effects.push({
        tag: "privilege",
        layer: a.depth,
        target: a.name,
        detail: `paseo_env_override:${a.name.trim().toUpperCase()}`,
      });
    }

    for (const kind of detectCredentialLiterals(a.value)) {
      effects.push({
        tag: "read_secret",
        layer: a.depth,
        target: a.name,
        detail: `inline_secret_literal:${kind}`,
      });
    }

    if (a.name === "IFS") {
      if (a.standalone && a.value.trim().length > 0) {
        const reason = "standalone_ifs_assignment";
        opaqueReasons.push(reason);
        effects.push({
          tag: "opaque",
          layer: a.depth,
          target: "IFS",
          detail: reason,
        });
      }
      continue;
    }

    if (a.name.trim().toUpperCase() === "WSLENV") {
      const wsl = classifyWslEnvValue(a.value);
      for (const secretVar of wsl.sensitiveVars) {
        effects.push({
          tag: "read_secret",
          layer: a.depth,
          target: secretVar,
          detail: "wslenv_secret_export",
        });
      }
      for (const hijackVar of wsl.hijackVars) {
        effects.push({
          tag: "exec_inline",
          layer: a.depth,
          target: hijackVar,
          detail: "wslenv_exec_hijack",
        });
      }
      if (wsl.hasOther) {
        const reason = "wslenv_passthrough";
        opaqueReasons.push(reason);
        effects.push({
          tag: "opaque",
          layer: a.depth,
          target: "WSLENV",
          detail: reason,
        });
      }
      continue;
    }

    if (isTempDirEnvVar(a.name)) {
      const trimmedTemp = a.value.trim();
      if (trimmedTemp.length > 0) {
        let safeTemp = false;
        if (!/[$`%!]/.test(trimmedTemp)) {
          const tempPath = classifyPath(trimmedTemp, pathCtx);
          safeTemp =
            !tempPath.isProtected &&
            !tempPath.isSensitive &&
            !tempPath.isRemoteUnc &&
            !tempPath.isDriveRelative &&
            (tempPath.inWorktree || tempPath.isTemp);
        }
        if (!safeTemp) {
          const reason = `env_redirect_or_tls:${a.name}`;
          opaqueReasons.push(reason);
          effects.push({
            tag: "opaque",
            layer: a.depth,
            target: a.name,
            detail: reason,
          });
        }
      }
      continue;
    }

    const execPolicy = classifyExecutionPolicyEnvVar(a.name, a.value);
    if (execPolicy === "bypass") {
      effects.push({
        tag: "exec_inline",
        layer: a.depth,
        target: a.name,
        detail: "execution_policy_bypass",
      });
    } else if (isExecHijackEnvVar(a.name, a.value)) {
      effects.push({
        tag: "exec_inline",
        layer: a.depth,
        target: a.name,
        detail: `env_exec_hijack:${a.name}`,
      });
    }

    if (isRedirectOrTlsEnvVar(a.name, a.value)) {
      const reason = `env_redirect_or_tls:${a.name}`;
      opaqueReasons.push(reason);
      effects.push({
        tag: "opaque",
        layer: a.depth,
        target: a.name,
        detail: reason,
      });
    }

    if (a.value.trim().length > 0 && isSensitiveEnvVarName(a.name)) {
      const reason = `sensitive_env_assignment:${a.name}`;
      opaqueReasons.push(reason);
      effects.push({
        tag: "opaque",
        layer: a.depth,
        target: a.name,
        detail: reason,
      });
    }
  }
}

function evaluateCliSecretFlags(
  cmd: CommandFact,
  bin: string,
  effects: EffectTag[],
  opaqueReasons: string[],
): void {
  const emitFlag = (flagLabel: string) => {
    const reason = `cli_secret_flag:${flagLabel}`;
    opaqueReasons.push(reason);
    effects.push({
      tag: "opaque",
      layer: cmd.depth,
      target: flagLabel,
      detail: reason,
    });
  };

  for (let i = 0; i < cmd.argv.length; i++) {
    const tok = cmd.argv[i];
    if (tok === "--") break;

    if ((bin === "mysql" || bin === "mariadb") && tok.startsWith("-p") && tok.length > 2) {
      emitFlag("-p");
      continue;
    }

    if (bin === "sshpass") {
      if (tok === "-p") {
        const next = cmd.argv[i + 1];
        if (next && !next.startsWith("-") && next.trim().length > 0) {
          emitFlag("-p");
          i += 1;
        }
        continue;
      }
      if (tok.startsWith("-p") && tok.length > 2) {
        emitFlag("-p");
        continue;
      }
    }

    if (bin === "curl" || bin === "wget") {
      if (tok === "-u" || tok === "--user") {
        const next = cmd.argv[i + 1];
        if (next && /^[^:]+:.+$/.test(next)) {
          emitFlag(tok);
          i += 1;
          continue;
        }
      } else if (tok.startsWith("--user=") || tok.startsWith("-u=")) {
        const eqIdx = tok.indexOf("=");
        const flagName = tok.slice(0, eqIdx);
        const val = tok.slice(eqIdx + 1);
        if (/^[^:]+:.+$/.test(val)) {
          emitFlag(flagName);
          continue;
        }
      }
    }

    if (tok.startsWith("-") && tok.length > 1) {
      const eqIdx = tok.indexOf("=");
      if (eqIdx > 0) {
        const flagName = tok.slice(0, eqIdx);
        const val = tok.slice(eqIdx + 1);
        if (val.trim().length > 0 && isSensitiveCliFlag(flagName)) {
          emitFlag(flagName);
        }
      } else if (isSensitiveCliFlag(tok)) {
        const next = cmd.argv[i + 1];
        if (next && !next.startsWith("-") && next.trim().length > 0) {
          emitFlag(tok);
          i += 1;
        }
      }
    }
  }
}

function isExplicitCredentialDumpSignature(cmd: CommandFact, bin: string): boolean {
  const raw = cmd.rawText.toLowerCase();
  if (bin === "procdump" && /\blsass(?:\.exe)?\b/.test(raw) && /\s-ma\b/.test(raw)) {
    return true;
  }
  if (bin === "rundll32" && /comsvcs(?:\.dll)?[, ]+minidump\b/.test(raw)) {
    return true;
  }
  if (
    bin === "reg" &&
    /\b(?:save|export)\b/.test(raw) &&
    /\bhklm\\(?:sam|security|system)\b/.test(raw)
  ) {
    return true;
  }
  if (bin === "ntdsutil" && /\bifm\b/.test(raw)) {
    return true;
  }
  if (
    (bin === "vssadmin" && /\bcreate\s+shadow\b/.test(raw)) ||
    (bin === "esentutl" && /\/vss\b/.test(raw) && /\b(?:sam|security|system|ntds\.dit)\b/.test(raw))
  ) {
    return true;
  }
  return false;
}

const SAFE_PATH_ENV_MACROS = new Set([
  "USERPROFILE",
  "HOME",
  "APPDATA",
  "LOCALAPPDATA",
  "PROGRAMDATA",
  "SYSTEMROOT",
  "WINDIR",
  "TEMP",
  "TMP",
  "PROGRAMFILES",
  "PROGRAMFILES(X86)",
]);

const WINDOWS_DESTRUCTIVE_ROOT_REGEX =
  /^[A-Za-z]:\\(?:windows(?:\\system32|\\syswow64)?|program files(?: \(x86\))?|users|programdata)?$/i;

function isDynamicOrUnexpandedPath(
  target: string,
  shell?: Shell,
  explicitDynamic?: boolean,
): boolean {
  if (explicitDynamic || target === "<dynamic>" || target === "[hashtable]") {
    return true;
  }
  if (shell !== "pwsh5" && shell !== "pwsh7") {
    if (/%[^%\r\n=]+:[^%\r\n]*%/.test(target) || /![^!\r\n=]+!/.test(target)) {
      return true;
    }
    const percentVars = target.matchAll(/%([^%\r\n=]+)%/g);
    for (const m of percentVars) {
      const varName = m[1].trim().toUpperCase();
      if (!SAFE_PATH_ENV_MACROS.has(varName)) {
        return true;
      }
    }
  }
  if (shell !== "cmd") {
    const envRefs = target.matchAll(/\$env:([A-Za-z0-9_]+)|\$\{env:([^}]+)\}/gi);
    for (const m of envRefs) {
      const name = (m[1] ?? m[2] ?? "").trim().toUpperCase();
      if (!SAFE_PATH_ENV_MACROS.has(name)) {
        return true;
      }
    }
  }
  return false;
}

function classifyDeleteTargets(
  rawTargets: Array<string | { value: string; dynamic?: boolean }>,
  recursive: boolean,
  cmd: CommandFact,
  pathCtx: WindowsPathContext,
  effects: EffectTag[],
  opaqueReasons: string[],
): void {
  if (rawTargets.length === 0) {
    effects.push({ tag: "opaque", layer: cmd.depth, detail: "rm_without_targets" });
    return;
  }

  for (const entry of rawTargets) {
    const target = typeof entry === "string" ? entry : entry.value;
    const isDyn = typeof entry === "string" ? false : Boolean(entry.dynamic);

    if (isDynamicOrUnexpandedPath(target, cmd.layer, isDyn)) {
      effects.push({
        tag: "opaque",
        layer: cmd.depth,
        target: "<dynamic>",
        detail: "dynamic_or_unexpanded_path",
      });
      opaqueReasons.push("dynamic_or_unexpanded_path");
      continue;
    }

    const uncertainRelative = cmd.cwdChanged && isRelativePath(target);
    if (uncertainRelative) {
      effects.push({
        tag: "opaque",
        layer: cmd.depth,
        target,
        detail: "relative_path_after_cwd_change",
      });
      opaqueReasons.push("relative_path_after_cwd_change");
      // Also classify against last known effectiveCwd so system roots / protected / outside paths never downgrade (C-4)
      if (!cmd.effectiveCwd) {
        continue;
      }
    }

    const p = classifyPath(target, pathCtx);
    emitWindowsPathAlerts(p, cmd.depth, effects, opaqueReasons);
    const normWinRoot = WINDOWS_DESTRUCTIVE_ROOT_REGEX.test(p.realPath);

    if (
      SYSTEM_DESTRUCTIVE_ROOTS.has(p.realPath) ||
      SYSTEM_DESTRUCTIVE_ROOTS.has(p.normalized) ||
      normWinRoot
    ) {
      effects.push({
        tag: "system_destructive",
        layer: cmd.depth,
        target: p.realPath,
        reversibility: "irreversible",
        recursive,
        detail: `delete targeting system root ${p.realPath}`,
      });
      continue;
    }
    if (p.isProtected || p.isSensitive) {
      effects.push({
        tag: "write_protected",
        layer: cmd.depth,
        target: p.realPath,
        pluginSelf: p.isPluginSelf,
        reversibility: "irreversible",
        detail: p.isProtected
          ? `delete targeting protected path ${p.realPath}`
          : `delete targeting sensitive path ${p.realPath}`,
      });
      continue;
    }
    if (p.inWorktree || p.isTemp) {
      if (!uncertainRelative || recursive) {
        effects.push({
          tag: "delete_worktree",
          layer: cmd.depth,
          target: p.realPath,
          recursive,
          reversibility: "irreversible",
        });
      }
    } else {
      effects.push({
        tag: "delete_outside",
        layer: cmd.depth,
        target: p.realPath,
        recursive,
        reversibility: "irreversible",
      });
    }
  }
}

function classifyRmCommand(
  cmd: CommandFact,
  pathCtx: WindowsPathContext,
  opaqueReasons: string[],
): EffectTag[] {
  const effects: EffectTag[] = [];
  let recursive = false;
  let afterDoubleDash = false;
  const targets: Array<{ value: string; dynamic?: boolean }> = [];

  for (let i = 0; i < cmd.argv.length; i++) {
    const tok = cmd.argv[i];
    const isDyn = Boolean(cmd.argvDynamic?.[i]);
    if (!afterDoubleDash && tok === "--" && !isDyn) {
      afterDoubleDash = true;
      continue;
    }
    if (!afterDoubleDash && tok.startsWith("-") && !isDyn) {
      if (tok === "--recursive" || /^-[a-zA-Z]*[rR]/.test(tok)) {
        recursive = true;
      }
      continue;
    }
    targets.push({ value: tok, dynamic: isDyn });
  }

  classifyDeleteTargets(targets, recursive, cmd, pathCtx, effects, opaqueReasons);
  return effects;
}

function checkCmdCwdShadowBinary(
  cmd: CommandFact,
  cmdPathCtx: WindowsPathContext,
  session: SessionState | undefined,
  effects: EffectTag[],
  opaqueReasons: string[],
): void {
  if (cmd.layer !== "cmd") return;
  if (cmd.name.includes("/") || cmd.name.includes("\\") || cmd.name.includes(":")) return;
  const baseLower = cmd.name.toLowerCase();
  const baseNoExt = normalizeBin(cmd.name);
  if (CMD_INTERNAL_BUILTINS.has(baseNoExt)) return;

  const exts = /\.(?:exe|cmd|bat|com)$/i.test(baseLower)
    ? [""]
    : [".com", ".exe", ".bat", ".cmd"];

  const cwdFwd = cmdPathCtx.cwd.replaceAll("\\", "/").replace(/\/+$/, "").toLowerCase();
  const cwdVariantList = [cwdFwd];
  try {
    cwdVariantList.push(
      realpathSync.native(cmdPathCtx.cwd).replaceAll("\\", "/").replace(/\/+$/, "").toLowerCase(),
    );
  } catch {
    // non-existent or virtual Windows CWD on POSIX host
  }
  try {
    cwdVariantList.push(
      realpathSync(cmdPathCtx.cwd).replaceAll("\\", "/").replace(/\/+$/, "").toLowerCase(),
    );
  } catch {
    // non-existent or virtual Windows CWD on POSIX host
  }
  const cwdVariants = Array.from(new Set(cwdVariantList));

  for (const ext of exts) {
    const modSet = session?.modifiedFiles ?? [];
    for (const cw of cwdVariants) {
      const candidateFwd = `${cw}/${baseLower}${ext}`;
      for (const modFile of modSet) {
        if (modFile.replaceAll("\\", "/").toLowerCase() === candidateFwd) {
          effects.push({
            tag: "exec_inline",
            layer: cmd.depth,
            target: cmd.name,
            detail: "provenance_cwd_shadow",
          });
          return;
        }
      }
    }
    const diskCandidate = join(cmdPathCtx.cwd, `${cmd.name}${ext}`);
    if (existsSync(diskCandidate)) {
      opaqueReasons.push(`cwd_shadow_binary:${cmd.name}`);
      effects.push({
        tag: "opaque",
        layer: cmd.depth,
        target: cmd.name,
        detail: `cwd_shadow_binary:${cmd.name}`,
      });
      return;
    }
  }
}

function collectPwshTargetsWithDynamic(
  cmd: CommandFact,
  keys: string[],
): Array<{ value: string; dynamic: boolean }> {
  const params = cmd.pwshParams ?? {};
  const arrayParams = cmd.pwshArrayParams ?? {};
  const out: Array<{ value: string; dynamic: boolean }> = [];
  for (const k of keys) {
    if (Array.isArray(arrayParams[k]) && arrayParams[k].length > 0) {
      for (const item of arrayParams[k]) {
        out.push({ value: item, dynamic: item === "<dynamic>" });
      }
    } else if (typeof params[k] === "string") {
      out.push({ value: params[k], dynamic: params[k] === "<dynamic>" });
    }
  }
  return out;
}

function collectPwshPositionalsWithDynamic(
  cmd: CommandFact,
  startIndex = 0,
): Array<{ value: string; dynamic: boolean }> {
  const positionals = cmd.pwshPositionalArgs ?? [];
  const dynFlags = cmd.pwshPositionalDynamic ?? [];
  const out: Array<{ value: string; dynamic: boolean }> = [];
  for (let i = startIndex; i < positionals.length; i++) {
    out.push({
      value: positionals[i],
      dynamic: Boolean(dynFlags[i]) || positionals[i] === "<dynamic>",
    });
  }
  return out;
}

function classifyPowerShellCmdlet(
  cmd: CommandFact,
  canon: string,
  cmdPathCtx: WindowsPathContext,
  trustedDomains: string[],
  effects: EffectTag[],
  opaqueReasons: string[],
  setUntrustedTaint: () => void,
  onDownloadFile?: (p: WindowsPathClassification) => void,
): boolean {
  const params = cmd.pwshParams ?? {};
  const positionals = cmd.pwshPositionalArgs ?? [];

  if (canon === "Invoke-Expression") {
    const iexArgs = [
      ...collectPwshTargetsWithDynamic(cmd, ["Command"]),
      ...collectPwshPositionalsWithDynamic(cmd, 0),
    ];
    const isDynamicOrPiped =
      iexArgs.length === 0 ||
      iexArgs.some((a) => a.dynamic || /\$|\(|\|/.test(a.value)) ||
      (cmd.pipelineId !== undefined && (cmd.pipelineIndex ?? 0) > 0);
    effects.push({
      tag: "exec_inline",
      layer: cmd.depth,
      target: canon,
      detail: isDynamicOrPiped ? "iex_dynamic" : "iex_static",
    });
    opaqueReasons.push("pwsh_iex");
    return true;
  }

  if (canon === "Invoke-Command") {
    if (params.ComputerName || params.Session) {
      effects.push({ tag: "infra_mutate", layer: cmd.depth, target: canon });
    }
    effects.push({ tag: "exec_inline", layer: cmd.depth, target: canon });
    opaqueReasons.push("pwsh_invoke_command");
    return true;
  }

  if (
    canon === "Set-Alias" ||
    canon === "New-Alias" ||
    canon === "Import-Module" ||
    canon === "Add-Type" ||
    canon === "Start-Job"
  ) {
    effects.push({ tag: "exec_inline", layer: cmd.depth, target: canon, detail: `pwsh_hijack:${canon}` });
    opaqueReasons.push(`pwsh_hijack:${canon}`);
    return true;
  }

  if (canon === "Set-ExecutionPolicy") {
    effects.push({
      tag: "write_protected",
      layer: cmd.depth,
      target: canon,
      detail: "env_persist:execution_policy",
    });
    const pol = typeof params.ExecutionPolicy === "string" ? params.ExecutionPolicy.toLowerCase() : "";
    if (pol === "bypass" || pol === "unrestricted") {
      effects.push({
        tag: "exec_inline",
        layer: cmd.depth,
        target: canon,
        detail: "execution_policy_bypass",
      });
    }
    return true;
  }

  if (canon === "Get-Process" || canon === "Get-Location" || canon === "Get-Command" || canon === "Write-Output") {
    effects.push({ tag: "read", layer: cmd.depth, target: canon });
    return true;
  }

  if (canon === "Get-CimInstance" || canon === "Get-WmiObject") {
    const className =
      (typeof params.ClassName === "string" ? params.ClassName : undefined) ??
      (typeof params.Class === "string" ? params.Class : undefined) ??
      positionals[0] ??
      "";
    if (className.toLowerCase() === "win32_process") {
      const propArg = typeof params.Property === "string" ? params.Property : undefined;
      if (propArg && !/\bcommandline\b|\*/i.test(propArg)) {
        effects.push({ tag: "read", layer: cmd.depth, target: `${canon} Win32_Process` });
      } else {
        effects.push({
          tag: "read_secret",
          layer: cmd.depth,
          target: `${canon} Win32_Process`,
          detail: "win32_process_commandline",
        });
      }
      return true;
    }
    effects.push({ tag: "read", layer: cmd.depth, target: canon });
    return true;
  }

  if (canon === "Get-Variable") {
    const nameArg = typeof params.Name === "string" ? params.Name : positionals[0];
    if (!nameArg || /[*?[\]]/.test(nameArg)) {
      effects.push({
        tag: "read_secret",
        layer: cmd.depth,
        target: "Get-Variable",
        detail: "pwsh_variable_dump",
      });
    } else if (isSensitiveEnvVarName(nameArg)) {
      effects.push({
        tag: "read_secret",
        layer: cmd.depth,
        target: nameArg,
        detail: "pwsh_sensitive_variable",
      });
    } else {
      effects.push({ tag: "read", layer: cmd.depth, target: canon });
    }
    return true;
  }

  if (canon === "Get-Credential") {
    opaqueReasons.push("pwsh_interactive_credential");
    effects.push({ tag: "opaque", layer: cmd.depth, target: canon, detail: "pwsh_interactive_credential" });
    return true;
  }

  if (canon === "ConvertFrom-SecureString" || canon === "Export-PfxCertificate") {
    effects.push({
      tag: "read_secret",
      layer: cmd.depth,
      target: canon,
      detail: "windows_credential_export",
    });
    return true;
  }

  if (canon === "ConvertTo-SecureString") {
    if (params.AsPlainText) {
      effects.push({
        tag: "read_secret",
        layer: cmd.depth,
        target: canon,
        detail: "plaintext_secure_string",
      });
    } else {
      effects.push({ tag: "read", layer: cmd.depth, target: canon });
    }
    return true;
  }

  if (canon === "Import-Certificate") {
    const store = typeof params.CertStoreLocation === "string" ? params.CertStoreLocation : positionals[1] ?? "";
    if (/root/i.test(store)) {
      effects.push({ tag: "write_protected", layer: cmd.depth, target: store, detail: "root_cert_store" });
      effects.push({ tag: "privilege", layer: cmd.depth, target: canon });
    } else {
      effects.push({ tag: "write_outside", layer: cmd.depth, target: store || canon });
    }
    return true;
  }

  if (canon === "Unblock-File") {
    opaqueReasons.push("unblock_file_motw");
    effects.push({ tag: "opaque", layer: cmd.depth, target: canon, detail: "unblock_file_motw" });
    return true;
  }

  if (
    canon === "Get-ChildItem" ||
    canon === "Get-Content" ||
    canon === "Get-Item" ||
    canon === "Get-ItemProperty" ||
    canon === "Select-String" ||
    canon === "Test-Path" ||
    canon === "Resolve-Path"
  ) {
    const targets = [
      ...collectPwshTargetsWithDynamic(cmd, ["Path", "LiteralPath"]),
      ...collectPwshPositionalsWithDynamic(cmd, canon === "Select-String" ? 1 : 0),
    ];

    if (targets.length === 0) {
      effects.push({ tag: "read", layer: cmd.depth, target: canon });
      return true;
    }

    for (const item of targets) {
      const target = item.value;
      if (isDynamicOrUnexpandedPath(target, cmd.layer, item.dynamic)) {
        opaqueReasons.push("dynamic_or_unexpanded_path");
        effects.push({ tag: "opaque", layer: cmd.depth, target: "<dynamic>", detail: "dynamic_or_unexpanded_path" });
        continue;
      }
      const uncertainRelative = cmd.cwdChanged && isRelativePath(target);
      if (uncertainRelative) {
        opaqueReasons.push("relative_path_after_cwd_change");
        effects.push({ tag: "opaque", layer: cmd.depth, target, detail: "relative_path_after_cwd_change" });
        if (!cmd.effectiveCwd) continue;
      }
      const p = classifyPath(target, cmdPathCtx);
      emitWindowsPathAlerts(p, cmd.depth, effects, opaqueReasons);
      if (p.isSensitive) {
        effects.push({
          tag: "read_secret",
          layer: cmd.depth,
          target: p.realPath,
          detail: p.matchedRules.join(","),
        });
      } else if (!uncertainRelative) {
        effects.push({ tag: "read", layer: cmd.depth, target: p.realPath });
      }
    }
    return true;
  }

  if (canon === "Remove-Item") {
    if (cmd.pwshExplicitWhatIf && params.WhatIf === true) {
      effects.push({ tag: "read", layer: cmd.depth, target: `${canon} -WhatIf` });
      return true;
    }
    const targets = [
      ...collectPwshTargetsWithDynamic(cmd, ["Path", "LiteralPath"]),
      ...collectPwshPositionalsWithDynamic(cmd, 0),
    ];
    classifyDeleteTargets(targets, Boolean(params.Recurse), cmd, cmdPathCtx, effects, opaqueReasons);
    return true;
  }

  if (canon === "Copy-Item" || canon === "Move-Item" || canon === "Rename-Item") {
    const posItems = collectPwshPositionalsWithDynamic(cmd, 0);
    const paramSrc = collectPwshTargetsWithDynamic(cmd, ["Path", "LiteralPath"]);
    const paramDest = collectPwshTargetsWithDynamic(cmd, ["Destination", "NewName"]);
    const srcItems = paramSrc.length > 0 ? paramSrc : posItems.slice(0, 1);
    const destItems =
      paramDest.length > 0
        ? paramDest
        : paramSrc.length === 0 && posItems.length > 1
          ? posItems.slice(1)
          : paramSrc.length > 0 && posItems.length > 0
            ? posItems
            : [];

    for (const src of srcItems) {
      if (isDynamicOrUnexpandedPath(src.value, cmd.layer, src.dynamic)) {
        opaqueReasons.push("dynamic_or_unexpanded_path");
        effects.push({ tag: "opaque", layer: cmd.depth, target: "<dynamic>", detail: "dynamic_or_unexpanded_path" });
        continue;
      }
      const prov = stripProviderDrive(src.value);
      if (prov && prov.provider === "env") continue;
      const uncertainRelative = cmd.cwdChanged && isRelativePath(src.value);
      if (uncertainRelative) {
        opaqueReasons.push("relative_path_after_cwd_change");
        effects.push({ tag: "opaque", layer: cmd.depth, target: src.value, detail: "relative_path_after_cwd_change" });
        if (!cmd.effectiveCwd) continue;
      }
      const p = classifyPath(src.value, cmdPathCtx);
      emitWindowsPathAlerts(p, cmd.depth, effects, opaqueReasons);
      if (p.isSensitive) {
        effects.push({ tag: "read_secret", layer: cmd.depth, target: p.realPath, detail: p.matchedRules.join(",") });
      }
      if (canon === "Move-Item" || canon === "Rename-Item") {
        if (p.isProtected || p.isSensitive) {
          effects.push({ tag: "write_protected", layer: cmd.depth, target: p.realPath, pluginSelf: p.isPluginSelf });
        } else if (!p.inWorktree && !p.isTemp) {
          effects.push({ tag: "delete_outside", layer: cmd.depth, target: p.realPath });
        } else if (!uncertainRelative) {
          effects.push({ tag: "write_worktree", layer: cmd.depth, target: p.realPath });
        }
      } else if (!uncertainRelative && !p.isSensitive) {
        effects.push({ tag: "read", layer: cmd.depth, target: p.realPath });
      }
    }

    for (const dest of destItems) {
      if (isDynamicOrUnexpandedPath(dest.value, cmd.layer, dest.dynamic)) {
        opaqueReasons.push("dynamic_or_unexpanded_path");
        effects.push({ tag: "opaque", layer: cmd.depth, target: "<dynamic>", detail: "dynamic_or_unexpanded_path" });
        continue;
      }
      const prov = stripProviderDrive(dest.value);
      if (prov && prov.provider === "env") continue;
      const uncertainRelative = cmd.cwdChanged && isRelativePath(dest.value);
      if (uncertainRelative) {
        opaqueReasons.push("relative_path_after_cwd_change");
        effects.push({ tag: "opaque", layer: cmd.depth, target: dest.value, detail: "relative_path_after_cwd_change" });
        if (!cmd.effectiveCwd) continue;
      }
      const p = classifyPath(dest.value, cmdPathCtx);
      emitWindowsPathAlerts(p, cmd.depth, effects, opaqueReasons);
      if (p.isProtected || p.isSensitive) {
        effects.push({ tag: "write_protected", layer: cmd.depth, target: p.realPath, pluginSelf: p.isPluginSelf });
      } else if (p.inWorktree) {
        if (!uncertainRelative) {
          effects.push({ tag: "write_worktree", layer: cmd.depth, target: p.realPath });
        }
      } else {
        effects.push({ tag: "write_outside", layer: cmd.depth, target: p.realPath, detail: p.isTemp ? "temp_dir" : "outside_worktree" });
      }
    }
    return true;
  }

  if (
    canon === "Set-Content" ||
    canon === "Add-Content" ||
    canon === "Out-File" ||
    canon === "Set-Item" ||
    canon === "New-Item" ||
    canon === "Set-ItemProperty" ||
    canon === "New-ItemProperty"
  ) {
    const paramTargets = collectPwshTargetsWithDynamic(cmd, [
      "Path",
      "LiteralPath",
      "FilePath",
      "Destination",
    ]);
    const writeTargets =
      paramTargets.length > 0
        ? paramTargets
        : collectPwshPositionalsWithDynamic(cmd, 0).slice(0, 1);

    for (const wtItem of writeTargets) {
      const wt = wtItem.value;
      if (isDynamicOrUnexpandedPath(wt, cmd.layer, wtItem.dynamic)) {
        opaqueReasons.push("dynamic_or_unexpanded_path");
        effects.push({ tag: "opaque", layer: cmd.depth, target: "<dynamic>", detail: "dynamic_or_unexpanded_path" });
        continue;
      }
      const prov = stripProviderDrive(wt);
      if (prov && prov.provider === "env") {
        // Already extracted as AssignmentFact by pwsh.ts
        continue;
      }
      const uncertainRelative = cmd.cwdChanged && isRelativePath(wt);
      if (uncertainRelative) {
        opaqueReasons.push("relative_path_after_cwd_change");
        effects.push({ tag: "opaque", layer: cmd.depth, target: wt, detail: "relative_path_after_cwd_change" });
        if (!cmd.effectiveCwd) continue;
      }
      const p = classifyPath(wt, cmdPathCtx);
      emitWindowsPathAlerts(p, cmd.depth, effects, opaqueReasons);
      if (p.isProtected || p.isSensitive) {
        effects.push({ tag: "write_protected", layer: cmd.depth, target: p.realPath, pluginSelf: p.isPluginSelf });
      } else if (p.inWorktree) {
        if (!uncertainRelative) {
          effects.push({ tag: "write_worktree", layer: cmd.depth, target: p.realPath });
        }
      } else {
        effects.push({ tag: "write_outside", layer: cmd.depth, target: p.realPath, detail: p.isTemp ? "temp_dir" : "outside_worktree" });
      }
    }
    return true;
  }

  if (canon === "Invoke-WebRequest" || canon === "Invoke-RestMethod") {
    const uri = (typeof params.Uri === "string" ? params.Uri : undefined) ?? positionals[0] ?? extractUrlFromArgv(cmd.argv);
    const method = typeof params.Method === "string" ? params.Method.toUpperCase() : "GET";
    const trusted = uri ? isUrlTrusted(uri, trustedDomains) : false;

    if (params.SkipCertificateCheck) {
      opaqueReasons.push("pwsh_skip_cert_check");
      effects.push({ tag: "opaque", layer: cmd.depth, target: canon, detail: "pwsh_skip_cert_check" });
    }
    if (params.UseDefaultCredentials || params.Credential) {
      effects.push({ tag: "read_secret", layer: cmd.depth, target: canon, detail: "pwsh_net_credentials" });
    }

    const isEgress =
      Boolean(params.Body) ||
      Boolean(params.InFile) ||
      Boolean(params.UseDefaultCredentials) ||
      Boolean(params.Credential) ||
      ["POST", "PUT", "PATCH", "DELETE"].includes(method);

    if (isEgress) {
      effects.push({
        tag: "net_egress",
        layer: cmd.depth,
        target: uri ?? canon,
        detail: trusted ? "trusted_domain" : "untrusted_domain",
      });
    } else {
      if (!trusted) setUntrustedTaint();
      effects.push({
        tag: "net_read",
        layer: cmd.depth,
        target: uri ?? canon,
        detail: trusted ? "trusted_domain" : "untrusted_domain",
      });
    }

    if (typeof params.InFile === "string") {
      const p = classifyPath(params.InFile, cmdPathCtx);
      if (p.isSensitive) {
        effects.push({ tag: "read_secret", layer: cmd.depth, target: p.realPath });
      }
    }
    for (const outItem of collectPwshTargetsWithDynamic(cmd, ["OutFile"])) {
      if (isDynamicOrUnexpandedPath(outItem.value, cmd.layer, outItem.dynamic)) {
        opaqueReasons.push("dynamic_or_unexpanded_path");
        effects.push({
          tag: "opaque",
          layer: cmd.depth,
          target: "<dynamic>",
          detail: "dynamic_or_unexpanded_path",
        });
        continue;
      }
      const p = classifyPath(outItem.value, cmdPathCtx);
      emitWindowsPathAlerts(p, cmd.depth, effects, opaqueReasons);
      if (p.isProtected || p.isSensitive) {
        effects.push({ tag: "write_protected", layer: cmd.depth, target: p.realPath, pluginSelf: p.isPluginSelf });
      } else if (p.inWorktree) {
        effects.push({ tag: "write_worktree", layer: cmd.depth, target: p.realPath });
      } else {
        effects.push({
          tag: "write_outside",
          layer: cmd.depth,
          target: p.realPath,
          detail: p.isTemp ? "temp_dir" : "outside_worktree",
        });
      }
      if (!isEgress) {
        onDownloadFile?.(p);
      }
    }
    return true;
  }

  if (canon === "Start-Process") {
    if (typeof params.Verb === "string" && params.Verb.toLowerCase() === "runas") {
      effects.push({ tag: "privilege", layer: cmd.depth, target: canon, detail: "runas" });
    } else {
      effects.push({ tag: "exec_inline", layer: cmd.depth, target: canon, detail: "start_process" });
    }
    return true;
  }

  if (canon === "Set-Location" || canon === "Push-Location" || canon === "Pop-Location") {
    effects.push({ tag: "read", layer: cmd.depth, target: canon });
    return true;
  }

  return false;
}

function classifyWindowsBuiltins(
  cmd: CommandFact,
  bin: string,
  cmdPathCtx: WindowsPathContext,
  effects: EffectTag[],
  opaqueReasons: string[],
): boolean {
  // LOLBins
  if (LOLBIN_COMMANDS.has(bin)) {
    effects.push({ tag: "exec_inline", layer: cmd.depth, target: bin, detail: `lolbin:${bin}` });
    opaqueReasons.push(`lolbin:${bin}`);
    return true;
  }

  if (bin === "certutil") {
    const raw = cmd.rawText.toLowerCase();
    if (raw.includes("-exportpfx")) {
      effects.push({ tag: "read_secret", layer: cmd.depth, target: "certutil -exportPFX", detail: "windows_credential_export" });
      return true;
    }
    if (raw.includes("-addstore") && raw.includes("root")) {
      effects.push({ tag: "write_protected", layer: cmd.depth, target: "RootCertStore", detail: "root_cert_store" });
      effects.push({ tag: "privilege", layer: cmd.depth, target: "certutil -addstore" });
      return true;
    }
    if (raw.includes("-urlcache")) {
      effects.push({ tag: "net_read", layer: cmd.depth, target: "certutil -urlcache" });
    }
    effects.push({ tag: "exec_inline", layer: cmd.depth, target: "certutil", detail: "lolbin:certutil" });
    return true;
  }

  if (bin === "bitsadmin") {
    if (/\/transfer/i.test(cmd.rawText)) {
      effects.push({ tag: "net_read", layer: cmd.depth, target: "bitsadmin" });
    }
    effects.push({ tag: "exec_inline", layer: cmd.depth, target: "bitsadmin", detail: "lolbin:bitsadmin" });
    return true;
  }

  if (bin === "regsvr32" || bin === "rundll32") {
    if (/https?:\/\//i.test(cmd.rawText)) {
      effects.push({ tag: "net_read", layer: cmd.depth, target: bin });
    }
    effects.push({ tag: "exec_inline", layer: cmd.depth, target: bin, detail: `lolbin:${bin}` });
    return true;
  }

  if (bin === "wmic") {
    const raw = cmd.rawText.toLowerCase();
    if (/\bprocess\b/.test(raw) && /\bcommandline\b/.test(raw)) {
      effects.push({ tag: "read_secret", layer: cmd.depth, target: "wmic process", detail: "win32_process_commandline" });
      return true;
    }
    if (/\bprocess\s+call\s+create\b/.test(raw)) {
      effects.push({ tag: "exec_inline", layer: cmd.depth, target: "wmic", detail: "lolbin:wmic" });
      return true;
    }
    opaqueReasons.push("wmic_opaque");
    effects.push({ tag: "opaque", layer: cmd.depth, target: "wmic", detail: "wmic_opaque" });
    return true;
  }

  // Windows credential commands
  if (bin === "cmdkey" || bin === "vaultcmd") {
    effects.push({ tag: "read_secret", layer: cmd.depth, target: bin, detail: "windows_credential_store" });
    return true;
  }

  if (bin === "netsh") {
    const raw = cmd.rawText.toLowerCase();
    if (/\bwlan\b/.test(raw) && /\bkey=clear\b/.test(raw)) {
      effects.push({ tag: "read_secret", layer: cmd.depth, target: "netsh wlan key=clear", detail: "windows_credential_store" });
      return true;
    }
    if (/\bwinhttp\s+set\s+proxy\b/.test(raw)) {
      effects.push({ tag: "privilege", layer: cmd.depth, target: "netsh winhttp set proxy" });
      return true;
    }
  }

  if (bin === "reg") {
    const sub = cmd.argv[0]?.toLowerCase() ?? "";
    const hiveTarget = cmd.argv[1] ?? "";
    const lowHive = hiveTarget.toLowerCase();
    if (sub === "query") {
      if (
        /hklm\\(?:sam|security|system)\b/.test(lowHive) ||
        /\\(?:winlogon|environment|putty|winscp)\b/.test(lowHive)
      ) {
        effects.push({ tag: "read_secret", layer: cmd.depth, target: hiveTarget, detail: "registry_secret_query" });
      } else {
        effects.push({ tag: "read", layer: cmd.depth, target: hiveTarget || `${bin} query` });
      }
      return true;
    }
    if (sub === "add" || sub === "delete" || sub === "import") {
      effects.push({ tag: "write_protected", layer: cmd.depth, target: hiveTarget || `${bin} ${sub}`, detail: `reg_${sub}` });
      if (/^hklm/i.test(lowHive)) {
        effects.push({ tag: "privilege", layer: cmd.depth, target: hiveTarget || bin });
      }
      return true;
    }
    effects.push({ tag: "privilege", layer: cmd.depth, target: sub && !sub.startsWith("/") ? `${bin} ${sub}` : bin });
    return true;
  }

  if (bin === "vssadmin") {
    if (/\bdelete\s+shadows\b/i.test(cmd.rawText)) {
      effects.push({ tag: "system_destructive", layer: cmd.depth, target: "vssadmin delete shadows", reversibility: "irreversible" });
    } else {
      effects.push({ tag: "privilege", layer: cmd.depth, target: "vssadmin" });
    }
    return true;
  }

  if (bin === "setx") {
    const positionals: string[] = [];
    let isMachine = false;
    let isRemote = false;

    for (let i = 0; i < cmd.argv.length; i++) {
      const a = cmd.argv[i];
      const low = a.toLowerCase();
      if (low === "/m") {
        isMachine = true;
      } else if (low === "/s") {
        isRemote = true;
        i += 1;
      } else if (low === "/u" || low === "/p" || low === "/k" || low === "/f" || low === "/d") {
        if ((low === "/k" || low === "/f") && cmd.argv[i + 1]) {
          effects.push({ tag: "read_secret", layer: cmd.depth, target: cmd.argv[i + 1], detail: "setx_source_read" });
        }
        i += 1;
      } else if (!low.startsWith("/")) {
        positionals.push(a);
      }
    }

    const varName = positionals[0] ?? "setx";
    const varVal = positionals[1] ?? "";
    effects.push({
      tag: "write_protected",
      layer: cmd.depth,
      target: varName,
      detail: isMachine ? "env_persist:machine" : "env_persist:user",
    });
    if (isMachine) {
      effects.push({ tag: "privilege", layer: cmd.depth, target: varName, detail: "env_persist:machine" });
    }
    if (isRemote) {
      effects.push({ tag: "infra_mutate", layer: cmd.depth, target: "setx /s" });
    }
    if (varName) {
      evaluateAssignments(
        [{ name: varName, value: varVal, standalone: true, depth: cmd.depth, source: "standalone" }],
        effects,
        opaqueReasons,
        cmdPathCtx,
      );
    }
    return true;
  }

  if (WINDOWS_PRIVILEGE_TOOLS.has(bin)) {
    const sub = cmd.argv[0]?.toLowerCase() ?? "";
    const safeSub = sub && /^[a-z0-9_-]+$/.test(sub) ? `${bin} ${sub}` : bin;
    effects.push({ tag: "privilege", layer: cmd.depth, target: safeSub });
    return true;
  }

  if (WINDOWS_PKG_INSTALL_TOOLS.has(bin)) {
    const sub = cmd.argv[0]?.toLowerCase() ?? "";
    const safeTarget = sub && /^[a-z0-9_-]+$/.test(sub) ? `${bin} ${sub}` : bin;
    if (bin === "winget" && ["list", "search", "show"].includes(sub)) {
      effects.push({ tag: "read", layer: cmd.depth, target: safeTarget });
    } else {
      effects.push({ tag: "pkg_install", layer: cmd.depth, target: safeTarget });
    }
    return true;
  }

  if (bin === "del" || bin === "erase" || bin === "rd" || bin === "rmdir") {
    let recursive = bin === "rd" || bin === "rmdir";
    const targets: string[] = [];
    let hasInvalidSwitch = false;
    for (const tok of cmd.argv) {
      const low = tok.toLowerCase();
      if (low.startsWith("/")) {
        if (/^\/(?:[pqfsnw]|a(?::[+-a-z]*)?)$/i.test(low)) {
          if (low === "/s") recursive = true;
          continue;
        }
        hasInvalidSwitch = true;
        for (const part of tok.split(/[;,]/).filter(Boolean)) {
          if (/^\/s$/i.test(part)) recursive = true;
          else if (!/^\/[pqfnw]$/i.test(part)) targets.push(part);
        }
        continue;
      }
      targets.push(tok);
    }
    if (hasInvalidSwitch) {
      opaqueReasons.push(`cmd_unknown_switch:${bin}`);
      effects.push({ tag: "opaque", layer: cmd.depth, target: bin, detail: `cmd_unknown_switch:${bin}` });
    }
    classifyDeleteTargets(targets, recursive, cmd, cmdPathCtx, effects, opaqueReasons);
    return true;
  }

  if (bin === "robocopy") {
    const isMir = cmd.argv.some((a) => /^\/(?:mir|purge)$/i.test(a));
    if (isMir) {
      effects.push({ tag: "delete_outside", layer: cmd.depth, target: "robocopy /MIR", recursive: true });
      return true;
    }
    const pos = cmd.argv.filter((a) => !a.startsWith("/"));
    const dest = pos[1];
    if (dest) {
      if (isDynamicOrUnexpandedPath(dest, cmd.layer)) {
        opaqueReasons.push("dynamic_or_unexpanded_path");
        effects.push({ tag: "opaque", layer: cmd.depth, target: "<dynamic>", detail: "dynamic_or_unexpanded_path" });
        return true;
      }
      const p = classifyPath(dest, cmdPathCtx);
      emitWindowsPathAlerts(p, cmd.depth, effects, opaqueReasons);
      if (p.isProtected || p.isSensitive) effects.push({ tag: "write_protected", layer: cmd.depth, target: p.realPath, pluginSelf: p.isPluginSelf });
      else if (p.inWorktree) effects.push({ tag: "write_worktree", layer: cmd.depth, target: p.realPath });
      else effects.push({ tag: "write_outside", layer: cmd.depth, target: p.realPath });
    }
    return true;
  }

  if (bin === "tasklist" || bin === "ver" || bin === "where") {
    effects.push({ tag: "read", layer: cmd.depth, target: bin });
    return true;
  }

  if (cmd.layer === "cmd") {
    if (bin === "dir" || bin === "type") {
      const targets = cmd.argv.filter((a) => !a.startsWith("/"));
      for (const target of targets) {
        if (isDynamicOrUnexpandedPath(target, cmd.layer)) {
          opaqueReasons.push("dynamic_or_unexpanded_path");
          effects.push({ tag: "opaque", layer: cmd.depth, target: "<dynamic>", detail: "dynamic_or_unexpanded_path" });
          continue;
        }
        const uncertainRelative = cmd.cwdChanged && isRelativePath(target);
        if (uncertainRelative) {
          opaqueReasons.push("relative_path_after_cwd_change");
          effects.push({ tag: "opaque", layer: cmd.depth, target, detail: "relative_path_after_cwd_change" });
          if (!cmd.effectiveCwd) continue;
        }
        const p = classifyPath(target, cmdPathCtx);
        emitWindowsPathAlerts(p, cmd.depth, effects, opaqueReasons);
        if (p.isSensitive) {
          effects.push({ tag: "read_secret", layer: cmd.depth, target: p.realPath, detail: p.matchedRules.join(",") });
        } else if (!uncertainRelative) {
          effects.push({ tag: "read", layer: cmd.depth, target: p.realPath });
        }
      }
      if (targets.length === 0) effects.push({ tag: "read", layer: cmd.depth, target: bin });
      return true;
    }

    if (bin === "copy" || bin === "move" || bin === "ren" || bin === "rename") {
      const pos = cmd.argv.filter((a) => !a.startsWith("/"));
      for (const target of pos) {
        if (isDynamicOrUnexpandedPath(target, cmd.layer)) {
          opaqueReasons.push("dynamic_or_unexpanded_path");
          effects.push({ tag: "opaque", layer: cmd.depth, target: "<dynamic>", detail: "dynamic_or_unexpanded_path" });
          continue;
        }
        const uncertainRelative = cmd.cwdChanged && isRelativePath(target);
        if (uncertainRelative) {
          opaqueReasons.push("relative_path_after_cwd_change");
          effects.push({ tag: "opaque", layer: cmd.depth, target, detail: "relative_path_after_cwd_change" });
          if (!cmd.effectiveCwd) continue;
        }
        const p = classifyPath(target, cmdPathCtx);
        emitWindowsPathAlerts(p, cmd.depth, effects, opaqueReasons);
        if (p.isSensitive) effects.push({ tag: "read_secret", layer: cmd.depth, target: p.realPath });
        else if (p.isProtected) effects.push({ tag: "write_protected", layer: cmd.depth, target: p.realPath });
        else if (p.inWorktree) {
          if (!uncertainRelative) effects.push({ tag: "write_worktree", layer: cmd.depth, target: p.realPath });
        } else effects.push({ tag: "write_outside", layer: cmd.depth, target: p.realPath });
      }
      return true;
    }
  }

  return false;
}

function finalizeResult(
  effects: EffectTag[],
  opaqueReasons: string[],
  pipelines: PipelineFact[],
  commands: CommandFact[],
  touchedUntrusted: boolean,
): EffectAnalysisResult {
  return {
    effects,
    opaqueReasons: Array.from(new Set(opaqueReasons)),
    pipelines,
    commands,
    touchedSecret: effects.some((e) => e.tag === "read_secret"),
    touchedUntrusted,
  };
}

export async function analyzeActionEffects(
  action: Action,
  options: EffectAnalysisOptions,
): Promise<EffectAnalysisResult> {
  const effects: EffectTag[] = [];
  const opaqueReasons: string[] = [];
  const trustedDomains = options.trustedDomains ?? DEFAULT_TRUSTED_DOMAINS;
  let pipelines: PipelineFact[] = [];
  let commands: CommandFact[] = [];
  let touchedUntrusted = false;
  if (action.sandboxBypass) {
    effects.push({ tag: "privilege", layer: 0, detail: "sandbox_bypass" });
  }

  const basePathCtx: WindowsPathContext = {
    ...options.pathCtx,
    os: options.pathCtx.os ?? action.host.os,
    wsl: options.pathCtx.wsl ?? action.host.wsl,
    envSnapshot: options.pathCtx.envSnapshot ?? options.envSnapshot,
  };

  if (action.kind === "read") {
    for (const rawPath of action.paths ?? []) {
      const p = classifyPath(rawPath, basePathCtx);
      emitWindowsPathAlerts(p, 0, effects, opaqueReasons);
      if (p.isSensitive) {
        effects.push({
          tag: "read_secret",
          layer: 0,
          target: p.realPath,
          detail: p.matchedRules.join(","),
        });
      } else {
        effects.push({ tag: "read", layer: 0, target: p.realPath });
      }
    }
    if ((action.paths ?? []).length === 0) {
      effects.push({ tag: "opaque", layer: 0, detail: "read_without_path" });
      opaqueReasons.push("read_without_path");
    }
    return finalizeResult(effects, opaqueReasons, pipelines, commands, touchedUntrusted);
  }

  if (action.kind === "edit") {
    for (const rawPath of action.paths ?? []) {
      const p = classifyPath(rawPath, basePathCtx);
      emitWindowsPathAlerts(p, 0, effects, opaqueReasons);
      if (p.isProtected || p.isSensitive) {
        effects.push({
          tag: "write_protected",
          layer: 0,
          target: p.realPath,
          pluginSelf: p.isPluginSelf,
          detail: p.matchedRules.join(","),
        });
      } else if (p.inWorktree) {
        effects.push({ tag: "write_worktree", layer: 0, target: p.realPath });
      } else {
        effects.push({
          tag: "write_outside",
          layer: 0,
          target: p.realPath,
          detail: p.isTemp ? "temp_dir" : "outside_worktree",
        });
      }
    }
    if ((action.paths ?? []).length === 0) {
      effects.push({ tag: "opaque", layer: 0, detail: "edit_without_path" });
      opaqueReasons.push("edit_without_path");
    }
    return finalizeResult(effects, opaqueReasons, pipelines, commands, touchedUntrusted);
  }

  if (action.kind === "delete") {
    for (const rawPath of action.paths ?? []) {
      const p = classifyPath(rawPath, basePathCtx);
      emitWindowsPathAlerts(p, 0, effects, opaqueReasons);
      if (p.isProtected || p.isSensitive) {
        effects.push({
          tag: "write_protected",
          layer: 0,
          target: p.realPath,
          pluginSelf: p.isPluginSelf,
        });
      } else if (p.inWorktree || p.isTemp) {
        effects.push({ tag: "delete_worktree", layer: 0, target: p.realPath });
      } else {
        effects.push({ tag: "delete_outside", layer: 0, target: p.realPath });
      }
    }
    if ((action.paths ?? []).length === 0) {
      effects.push({ tag: "opaque", layer: 0, detail: "delete_without_path" });
      opaqueReasons.push("delete_without_path");
    }
    return finalizeResult(effects, opaqueReasons, pipelines, commands, touchedUntrusted);
  }

  if (action.kind === "fetch") {
    const href = action.url?.href;
    const method = action.url?.method?.toUpperCase() ?? "GET";
    const isEgress =
      action.url?.hasBody === true || ["POST", "PUT", "PATCH", "DELETE"].includes(method);
    const trusted = href ? isUrlTrusted(href, trustedDomains) : false;

    if (isEgress) {
      effects.push({
        tag: "net_egress",
        layer: 0,
        target: href,
        detail: trusted ? "trusted_domain" : "untrusted_domain",
      });
    } else {
      if (!trusted) touchedUntrusted = true;
      effects.push({
        tag: "net_read",
        layer: 0,
        target: href,
        detail: trusted ? "trusted_domain" : "untrusted_domain",
      });
    }
    return finalizeResult(effects, opaqueReasons, pipelines, commands, touchedUntrusted);
  }

  if (action.kind === "mcp") {
    if (
      action.mcp?.server.toLowerCase() === "paseo" &&
      !PASEO_READONLY_MCP_TOOLS.has(action.mcp.tool)
    ) {
      effects.push({
        tag: "infra_mutate",
        layer: 0,
        target: `paseo:${action.mcp.tool}`,
        detail: "paseo_control",
      });
    }
    effects.push({
      tag: "opaque",
      layer: 0,
      target: action.mcp ? `${action.mcp.server}:${action.mcp.tool}` : action.toolName,
      detail: "unlisted_mcp_tool",
    });
    opaqueReasons.push("unlisted_mcp_tool");
    return finalizeResult(effects, opaqueReasons, pipelines, commands, touchedUntrusted);
  }

  if (action.kind !== "exec" || !action.exec) {
    effects.push({ tag: "opaque", layer: 0, detail: `unclassified_kind:${action.kind}` });
    opaqueReasons.push(`unclassified_kind:${action.kind}`);
    return finalizeResult(effects, opaqueReasons, pipelines, commands, touchedUntrusted);
  }

  // P0: Scan raw exec source for high-confidence credential literals BEFORE/regardless of parse errors
  for (const kind of detectCredentialLiterals(action.exec.source)) {
    effects.push({
      tag: "read_secret",
      layer: 0,
      target: kind,
      detail: "inline_secret_literal",
    });
  }

  const layerResult = await analyzeShellLayers(action.exec.shell, action.exec.source, {
    os: action.host.os,
    cwd: action.cwd,
    worktreeRoot: action.worktreeRoot,
    home: options.pathCtx.home,
    depth: 0,
    pwshHost: options.pwshHost,
    allowPosixPwshHost: options.allowPosixPwshHost,
    pwshBinaryPath: options.pwshBinaryPath,
    envSnapshot: options.envSnapshot ?? options.pathCtx.envSnapshot,
    wsl: action.host.wsl ?? options.pathCtx.wsl,
    session: options.session,
  });

  // Also scan unescaped command text (cmd ^-unescaped, pwsh `-unescaped) for P0 literals
  for (const unescaped of layerResult.unescapedSources ?? []) {
    if (unescaped && unescaped !== action.exec.source) {
      for (const kind of detectCredentialLiterals(unescaped)) {
        effects.push({
          tag: "read_secret",
          layer: 0,
          target: kind,
          detail: "inline_secret_literal_unescaped",
        });
      }
    }
  }

  pipelines = layerResult.pipelines;
  commands = layerResult.commands;
  effects.push(...layerResult.effects);
  opaqueReasons.push(...layerResult.opaque);

  for (const envVar of layerResult.envReads) {
    if (isSensitiveEnvVarName(envVar)) {
      effects.push({
        tag: "read_secret",
        layer: 0,
        target: `$${envVar}`,
        detail: "sensitive_env_expansion",
      });
    }
  }

  evaluateAssignments(layerResult.assignments, effects, opaqueReasons, basePathCtx);

  const registry = options.registry ?? getDefaultSafeChainsRegistry();
  const downloadedFiles = new Set<string>();
  const normalizeTrackedPath = (p: WindowsPathClassification, osHint?: string): string =>
    osHint === "windows" ? p.realPath.replaceAll("/", "\\").toLowerCase() : p.realPath;

  for (const cmd of commands) {
    if (cmd.pwshAllowVenvActivate) {
      effects.push({ tag: "read", layer: cmd.depth, target: cmd.name });
      continue;
    }

    const bin = normalizeBin(cmd.name);
    const layerOs =
      cmd.layer === "cmd" || cmd.layer === "pwsh5" || cmd.layer === "pwsh7"
        ? "windows"
        : cmd.depth > 0 && action.host.os === "windows"
          ? "linux"
          : basePathCtx.os;

    const cmdPathCtx: WindowsPathContext = {
      ...basePathCtx,
      os: layerOs,
      shell: cmd.layer,
      ...(cmd.depth > 0 && action.host.os === "windows" && !basePathCtx.wsl
        ? { wsl: { distro: "default" } }
        : {}),
      ...(cmd.effectiveCwd ? { cwd: cmd.effectiveCwd } : {}),
      ...(cmd.effectiveWorktree ? { worktreeRoot: cmd.effectiveWorktree } : {}),
      ...(cmd.effectiveHome ? { home: cmd.effectiveHome } : {}),
    };

    for (const envVar of cmd.envReads) {
      if (isSensitiveEnvVarName(envVar)) {
        effects.push({
          tag: "read_secret",
          layer: cmd.depth,
          target: `$${envVar}`,
          detail: "sensitive_env_expansion",
        });
      }
    }

    for (const redir of cmd.redirections) {
      if (redir.target === "/dev/null" || redir.target.toUpperCase() === "NUL") continue;
      if (isDynamicOrUnexpandedPath(redir.target, cmd.layer, redir.dynamic)) {
        opaqueReasons.push("dynamic_or_unexpanded_path");
        effects.push({
          tag: "opaque",
          layer: cmd.depth,
          target: "<dynamic>",
          detail: "dynamic_or_unexpanded_path",
        });
        continue;
      }
      const uncertainRelative = cmd.cwdChanged && isRelativePath(redir.target);
      if (uncertainRelative) {
        effects.push({
          tag: "opaque",
          layer: cmd.depth,
          target: redir.target,
          detail: "relative_path_after_cwd_change",
        });
        opaqueReasons.push("relative_path_after_cwd_change");
        if (!cmd.effectiveCwd) {
          continue;
        }
      }
      const p = classifyPath(redir.target, cmdPathCtx);
      emitWindowsPathAlerts(p, cmd.depth, effects, opaqueReasons);
      if (redir.isWrite) {
        if (p.isProtected || p.isSensitive) {
          effects.push({
            tag: "write_protected",
            layer: cmd.depth,
            target: p.realPath,
            pluginSelf: p.isPluginSelf,
            detail: `redirection:${redir.operator}`,
          });
        } else if (p.inWorktree) {
          if (!uncertainRelative) {
            effects.push({
              tag: "write_worktree",
              layer: cmd.depth,
              target: p.realPath,
              detail: `redirection:${redir.operator}`,
            });
          }
        } else {
          effects.push({
            tag: "write_outside",
            layer: cmd.depth,
            target: p.realPath,
            detail: p.isTemp ? "temp_dir" : "outside_worktree",
          });
        }
      }
      if (redir.isRead && p.isSensitive) {
        effects.push({
          tag: "read_secret",
          layer: cmd.depth,
          target: p.realPath,
          detail: `redirection:${redir.operator}`,
        });
      }
    }

    evaluateCliSecretFlags(cmd, bin, effects, opaqueReasons);

    if (isPaseoControlCommand(bin, cmd.argv)) {
      effects.push({
        tag: "infra_mutate",
        layer: cmd.depth,
        target: "paseo",
        detail: "paseo_control",
      });
    }

    // Explicit Windows credential dump signatures -> L3 system_destructive
    if (isExplicitCredentialDumpSignature(cmd, bin)) {
      effects.push({
        tag: "system_destructive",
        layer: cmd.depth,
        target: bin,
        reversibility: "irreversible",
        detail: "credential_dump",
      });
      continue;
    }

    if (SYSTEM_DESTRUCTIVE_COMMANDS.has(bin)) {
      effects.push({
        tag: "system_destructive",
        layer: cmd.depth,
        target: bin,
        reversibility: "irreversible",
      });
      continue;
    }

    // cmd.exe CWD shadow binary check
    checkCmdCwdShadowBinary(cmd, cmdPathCtx, options.session, effects, opaqueReasons);
    if (cmd.preclassified) {
      continue;
    }

    // PowerShell cmdlet dispatch
    if ((cmd.layer === "pwsh5" || cmd.layer === "pwsh7") && cmd.pwshCanonicalName) {
      if (
        classifyPowerShellCmdlet(
          cmd,
          cmd.pwshCanonicalName,
          cmdPathCtx,
          trustedDomains,
          effects,
          opaqueReasons,
          () => {
            touchedUntrusted = true;
          },
          (p) => {
            downloadedFiles.add(normalizeTrackedPath(p, "windows"));
          },
        )
      ) {
        continue;
      }
    }

    if (bin === "cd" || bin === "chdir" || bin === "pushd" || bin === "popd") {
      effects.push({ tag: "read", layer: cmd.depth, target: bin });
      continue;
    }

    if (bin === "env") {
      effects.push({
        tag: "read_secret",
        layer: cmd.depth,
        target: "env",
        detail: "env_dump",
      });
      continue;
    }

    if (bin === "printenv") {
      const positionals = cmd.argv.filter((a) => !a.startsWith("-"));
      if (positionals.length === 0 || positionals.some((a) => isSensitiveEnvVarName(a))) {
        effects.push({
          tag: "read_secret",
          layer: cmd.depth,
          target: "printenv",
          detail: "env_dump_or_secret_read",
        });
      } else {
        effects.push({ tag: "read", layer: cmd.depth, target: "printenv" });
      }
      continue;
    }

    if (bin === "set") {
      if (cmd.layer === "cmd") {
        if (cmd.argv.length === 0) {
          effects.push({ tag: "read_secret", layer: cmd.depth, target: "set", detail: "env_dump" });
        } else {
          const arg0 = cmd.argv[0].toLowerCase();
          if (arg0 === "/a" || arg0 === "/p") {
            effects.push({ tag: "read", layer: cmd.depth, target: "set" });
          } else if (!cmd.argv[0].includes("=")) {
            effects.push({ tag: "read_secret", layer: cmd.depth, target: "set", detail: "env_dump" });
          } else {
            effects.push({ tag: "read", layer: cmd.depth, target: "set" });
          }
        }
        continue;
      }

      if (cmd.argv.length === 0) {
        effects.push({
          tag: "read_secret",
          layer: cmd.depth,
          target: "set",
          detail: "env_dump",
        });
      } else if (cmd.argv[0].startsWith("-") || cmd.argv[0].startsWith("+")) {
        effects.push({ tag: "read", layer: cmd.depth, target: "set" });
      } else {
        opaqueReasons.push("set_positional_args");
        effects.push({ tag: "opaque", layer: cmd.depth, target: "set", detail: "set_positional_args" });
      }
      continue;
    }

    if (DECLARATION_BUILTINS.has(bin)) {
      if ((bin === "declare" || bin === "typeset") && hasShortFlag(cmd.argv, "n")) {
        opaqueReasons.push("indirect_var_nameref");
        effects.push({
          tag: "opaque",
          layer: cmd.depth,
          target: bin,
          detail: "indirect_var_nameref",
        });
        continue;
      }

      const hasAssignments = Object.keys(cmd.assignments).length > 0;
      const nonFlagArgs = cmd.argv.filter((a) => !a.startsWith("-"));
      if (!hasAssignments && nonFlagArgs.length === 0) {
        effects.push({
          tag: "read_secret",
          layer: cmd.depth,
          target: bin,
          detail: "env_dump",
        });
      } else {
        effects.push({ tag: "read", layer: cmd.depth, target: bin });
      }
      continue;
    }

    if (bin === "compgen" && isCompgenEnvDump(cmd.argv)) {
      effects.push({
        tag: "read_secret",
        layer: cmd.depth,
        target: "compgen",
        detail: "env_dump",
      });
      continue;
    }

    if (bin === "ps" && isPsEnvDump(cmd.argv)) {
      effects.push({
        tag: "read_secret",
        layer: cmd.depth,
        target: "ps",
        detail: "ps_env_dump",
      });
      continue;
    }

    if (classifyWindowsBuiltins(cmd, bin, cmdPathCtx, effects, opaqueReasons)) {
      continue;
    }

    if (bin === "rm") {
      effects.push(...classifyRmCommand(cmd, cmdPathCtx, opaqueReasons));
      continue;
    }

    if (bin === "curl" || bin === "wget") {
      const url = extractUrlFromArgv(cmd.argv);
      const trusted = url ? isUrlTrusted(url, trustedDomains) : false;
      const egress =
        bin === "curl" ? isCurlEgress(cmd.argv) : cmd.argv.some((a) => a.startsWith("--post"));
      if (egress) {
        effects.push({
          tag: "net_egress",
          layer: cmd.depth,
          target: url ?? bin,
          detail: trusted ? "trusted_domain" : "untrusted_domain",
        });
      } else {
        if (!trusted) touchedUntrusted = true;
        effects.push({
          tag: "net_read",
          layer: cmd.depth,
          target: url ?? bin,
          detail: trusted ? "trusted_domain" : "untrusted_domain",
        });
      }
      for (let idx = 0; idx < cmd.argv.length; idx++) {
        const arg = cmd.argv[idx];
        const isDynArg = Boolean(cmd.argvDynamic?.[idx]);

        let outCandidate: string | undefined;
        let outIsDyn = isDynArg;
        if (bin === "curl" && (arg === "-o" || arg === "--output") && idx + 1 < cmd.argv.length) {
          outCandidate = cmd.argv[idx + 1];
          outIsDyn = Boolean(cmd.argvDynamic?.[idx + 1]);
          idx += 1;
        } else if (bin === "curl" && arg.startsWith("--output=")) {
          outCandidate = arg.slice("--output=".length);
        } else if (bin === "curl" && arg.startsWith("-o") && arg.length > 2) {
          outCandidate = arg.slice(2);
        } else if (
          bin === "wget" &&
          (arg === "-O" || arg === "--output-document") &&
          idx + 1 < cmd.argv.length
        ) {
          outCandidate = cmd.argv[idx + 1];
          outIsDyn = Boolean(cmd.argvDynamic?.[idx + 1]);
          idx += 1;
        } else if (bin === "wget" && arg.startsWith("--output-document=")) {
          outCandidate = arg.slice("--output-document=".length);
        } else if (bin === "wget" && arg.startsWith("-O") && arg.length > 2) {
          outCandidate = arg.slice(2);
        }

        if (outCandidate !== undefined) {
          if (outCandidate === "-" || outCandidate === "/dev/null" || outCandidate.toUpperCase() === "NUL") {
            continue;
          }
          if (isDynamicOrUnexpandedPath(outCandidate, cmd.layer, outIsDyn)) {
            opaqueReasons.push("dynamic_or_unexpanded_path");
            effects.push({
              tag: "opaque",
              layer: cmd.depth,
              target: "<dynamic>",
              detail: "dynamic_or_unexpanded_path",
            });
            continue;
          }
          const p = classifyPath(outCandidate, cmdPathCtx);
          emitWindowsPathAlerts(p, cmd.depth, effects, opaqueReasons);
          if (p.isProtected || p.isSensitive) {
            effects.push({
              tag: "write_protected",
              layer: cmd.depth,
              target: p.realPath,
              pluginSelf: p.isPluginSelf,
            });
          } else if (p.inWorktree) {
            effects.push({ tag: "write_worktree", layer: cmd.depth, target: p.realPath });
          } else {
            effects.push({
              tag: "write_outside",
              layer: cmd.depth,
              target: p.realPath,
              detail: p.isTemp ? "temp_dir" : "outside_worktree",
            });
          }
          if (!egress) {
            downloadedFiles.add(normalizeTrackedPath(p, layerOs));
          }
          continue;
        }

        const candidate = arg.startsWith("@") ? arg.slice(1) : arg;
        if (
          candidate &&
          candidate !== "-" &&
          !candidate.startsWith("-") &&
          !/^https?:\/\//i.test(candidate)
        ) {
          if (
            isDynamicOrUnexpandedPath(candidate, cmd.layer, isDynArg) &&
            (arg.startsWith("@") || egress)
          ) {
            opaqueReasons.push("dynamic_or_unexpanded_path");
            effects.push({
              tag: "opaque",
              layer: cmd.depth,
              target: "<dynamic>",
              detail: "dynamic_or_unexpanded_path",
            });
            continue;
          }
          if (cmd.cwdChanged && isRelativePath(candidate)) {
            effects.push({
              tag: "opaque",
              layer: cmd.depth,
              target: candidate,
              detail: "relative_path_after_cwd_change",
            });
            opaqueReasons.push("relative_path_after_cwd_change");
            continue;
          }
          const p = classifyPath(candidate, cmdPathCtx);
          if (p.isSensitive) {
            effects.push({ tag: "read_secret", layer: cmd.depth, target: p.realPath });
          }
        }
      }
      continue;
    }

    if (bin === "git") {
      const sub = cmd.argv.find((a) => !a.startsWith("-"));
      if (sub === "push") {
        const isForce = cmd.argv.some(
          (a) => a === "-f" || a === "--force" || a === "--force-with-lease",
        );
        effects.push({
          tag: "vcs_remote",
          layer: cmd.depth,
          target: "git push",
          reversibility: isForce ? "irreversible" : "reversible",
          detail: isForce ? "git_push_force" : "git_push",
        });
        continue;
      }
    }

    if (
      (bin === "npm" || bin === "pnpm" || bin === "yarn") &&
      cmd.argv.some((a) => a === "install" || a === "i" || a === "add")
    ) {
      effects.push({ tag: "pkg_install", layer: cmd.depth, target: `${bin} install` });
      continue;
    }

    if ((bin === "pip" || bin === "pip3") && cmd.argv[0] === "install") {
      effects.push({ tag: "pkg_install", layer: cmd.depth, target: `${bin} install` });
      continue;
    }

    if (INFRA_MUTATE_COMMANDS.has(bin)) {
      const sub = cmd.argv[0]?.toLowerCase() ?? "";
      const safeTarget = sub && /^[a-z0-9_-]+$/.test(sub) ? `${bin} ${sub}` : bin;
      if (["get", "describe", "logs", "plan", "show", "list", "version"].includes(sub)) {
        effects.push({ tag: "infra_read", layer: cmd.depth, target: safeTarget });
      } else {
        effects.push({ tag: "infra_mutate", layer: cmd.depth, target: safeTarget });
      }
      continue;
    }

    if (bin === "chmod" || bin === "chown") {
      effects.push({ tag: "privilege", layer: cmd.depth, target: bin });
      continue;
    }

    // 4. safe-chains declarative registry lookup + mandatory path sweep (ADR-0004)
    const match = registry.match(cmd.name, cmd.argv, cmdPathCtx, cmd.argvDynamic);
    if (match.matched && match.level) {
      let blockedByPathSweep = false;

      if (match.dynamicPaths.length > 0) {
        blockedByPathSweep = true;
        opaqueReasons.push("dynamic_or_unexpanded_path");
        effects.push({
          tag: "opaque",
          layer: cmd.depth,
          target: "<dynamic>",
          detail: "dynamic_or_unexpanded_path",
        });
      }

      if (cmd.cwdChanged) {
        for (const swept of match.sweptPaths) {
          if (isRelativePath(swept.raw)) {
            blockedByPathSweep = true;
            opaqueReasons.push("relative_path_after_cwd_change");
            effects.push({
              tag: "opaque",
              layer: cmd.depth,
              target: swept.raw,
              detail: "relative_path_after_cwd_change",
            });
          }
        }
      }

      for (const swept of match.sweptPaths) {
        emitWindowsPathAlerts(swept as WindowsPathClassification, cmd.depth, effects, opaqueReasons);
        if (swept.isSensitive) {
          blockedByPathSweep = true;
          effects.push({
            tag: "read_secret",
            layer: cmd.depth,
            target: swept.realPath,
            detail: `path_sweep:${swept.matchedRules.join(",")}`,
          });
        }
        if (match.level === "SafeWrite") {
          if (swept.isProtected) {
            blockedByPathSweep = true;
            effects.push({
              tag: "write_protected",
              layer: cmd.depth,
              target: swept.realPath,
              pluginSelf: swept.isPluginSelf,
              detail: `path_sweep:${swept.matchedRules.join(",")}`,
            });
          } else if (!swept.inWorktree && !swept.isTemp) {
            blockedByPathSweep = true;
            effects.push({
              tag: "write_outside",
              layer: cmd.depth,
              target: swept.realPath,
              detail: "outside_worktree",
            });
          }
        }
      }

      if (!blockedByPathSweep) {
        if (match.level === "Inert" || match.level === "SafeRead") {
          effects.push({ tag: "read", layer: cmd.depth, target: match.matchedRulePath.join(" ") });
        } else if (match.level === "SafeWrite") {
          effects.push({
            tag: "write_worktree",
            layer: cmd.depth,
            target: match.matchedRulePath.join(" "),
          });
        } else if (match.level === "ExecProject") {
          const hasModifiedEntrypoint = (options.session?.modifiedEntrypoints.size ?? 0) > 0;
          if (hasModifiedEntrypoint) {
            effects.push({
              tag: "exec_inline",
              layer: cmd.depth,
              target: match.matchedRulePath.join(" "),
              detail: "provenance_entrypoint_modified",
            });
          } else {
            effects.push({
              tag: "exec_project",
              layer: cmd.depth,
              target: match.matchedRulePath.join(" "),
            });
          }
        }
      }
      continue;
    }

    // Check if directly executing a downloaded file or modified local script
    if (cmd.name.startsWith("./") || cmd.name.startsWith(".\\") || cmd.name.startsWith("/") || cmd.name.includes("/") || cmd.name.includes("\\")) {
      if (cmd.cwdChanged && isRelativePath(cmd.name)) {
        opaqueReasons.push("relative_path_after_cwd_change");
        effects.push({
          tag: "opaque",
          layer: cmd.depth,
          target: cmd.name,
          detail: "relative_path_after_cwd_change",
        });
        continue;
      }
      const scriptPath = classifyPath(cmd.name, cmdPathCtx);
      if (downloadedFiles.has(normalizeTrackedPath(scriptPath, layerOs))) {
        effects.push({
          tag: "exec_network_sourced",
          layer: cmd.depth,
          target: scriptPath.realPath,
          detail: "downloaded_and_executed",
        });
        continue;
      }
      if (options.session?.modifiedFiles.has(scriptPath.realPath)) {
        effects.push({
          tag: "exec_inline",
          layer: cmd.depth,
          target: scriptPath.realPath,
          detail: "provenance_modified_script",
        });
        continue;
      }
    } else if (downloadedFiles.size > 0 && INTERPRETER_BINARIES.has(bin)) {
      for (const arg of cmd.argv) {
        if (!arg || arg.startsWith("-")) continue;
        const p = classifyPath(arg, cmdPathCtx);
        if (downloadedFiles.has(normalizeTrackedPath(p, layerOs))) {
          effects.push({
            tag: "exec_network_sourced",
            layer: cmd.depth,
            target: p.realPath,
            detail: "downloaded_and_executed",
          });
        }
      }
    }

    // 5. Unknown command -> opaque (never auto-allow)
    const reason = match.reason ?? `unknown_command:${bin}`;
    opaqueReasons.push(reason);
    effects.push({ tag: "opaque", layer: cmd.depth, target: bin, detail: reason });
  }

  return finalizeResult(effects, opaqueReasons, pipelines, commands, touchedUntrusted);
}

export function hasNetReadPipedToInterpreter(pipelines: PipelineFact[]): boolean {
  const netReaders = new Set(["curl", "wget", "fetch", "invoke-webrequest", "invoke-restmethod", "iwr", "irm"]);
  for (const pipe of pipelines) {
    if (pipe.commands.length < 2) continue;
    let sawNetRead = false;
    for (const cmdName of pipe.commands) {
      const bin = normalizeBin(cmdName);
      if (netReaders.has(bin)) {
        sawNetRead = true;
      } else if (sawNetRead && INTERPRETER_BINARIES.has(bin)) {
        return true;
      }
    }
  }
  return false;
}
