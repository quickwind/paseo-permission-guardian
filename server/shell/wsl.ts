import { basename } from "node:path";
import type { EffectTag } from "../../shared/types.js";
import { mapWindowsToWslPath } from "../paths/windows.js";

export interface WslInvocationPlan {
  kind: "exec_shell" | "exec_argv" | "management" | "opaque";
  distro?: string;
  user?: string;
  automountRoot?: string;
  childCwd: string;
  childHome: string;
  childSource?: string;
  extraChildSources?: string[];
  childArgv?: string[];
  effects: EffectTag[];
  opaqueReasons: string[];
  loginShell?: boolean;
}

function shellQuoteArg(arg: string): string {
  if (arg.length > 0 && /^[A-Za-z0-9_./:@%+=,-]+$/.test(arg)) {
    return arg;
  }
  return `'${arg.replaceAll("'", "'\\''")}'`;
}

function buildWslShellSources(remaining: string[]): { primary: string; extras: string[] } {
  const firstBin = remaining[0] ? basename(remaining[0]).toLowerCase() : "";
  if (
    (firstBin === "bash" || firstBin === "sh" || firstBin === "zsh") &&
    /^-[a-zA-Z]*c$/.test(remaining[1] ?? "") &&
    typeof remaining[2] === "string"
  ) {
    return { primary: remaining.slice(2).join(" "), extras: [] };
  }
  const rawJoined = remaining.join(" ");
  if (remaining.some((tok) => /[\s;&|<>()$`'"\\]/.test(tok))) {
    const quotedJoined = remaining.map(shellQuoteArg).join(" ");
    if (quotedJoined !== rawJoined) {
      return { primary: quotedJoined, extras: [rawJoined] };
    }
  }
  return { primary: rawJoined, extras: [] };
}

const WSL_DESTRUCTIVE_FLAGS = new Set(["--unregister"]);
const WSL_PRIVILEGE_FLAGS = new Set([
  "--mount",
  "--unmount",
  "--manage",
  "--uninstall",
  "--set-sparse",
  "--move",
  "--resize",
  "--import",
  "--export",
  "--set-default",
  "-s",
  "--install",
  "--shutdown",
  "--terminate",
  "-t",
  "--set-version",
  "--set-default-version",
  "--update",
]);
const WSL_SAFE_STATUS_FLAGS = new Set([
  "-l",
  "--list",
  "--status",
  "--version",
  "-v",
  "--verbose",
  "-q",
  "--quiet",
  "--all",
  "--running",
  "--online",
]);

function stripExeExt(name: string): string {
  return basename(name).toLowerCase().replace(/\.exe$/, "");
}

export function isWslWrapper(
  baseName: string,
  argv: string[],
  hostOs: string,
  rawName?: string,
): boolean {
  if (baseName === "wsl") return true;
  if (hostOs === "windows" && baseName === "bash" && !argv.includes("--login-posix-only")) {
    // Distinguish Git Bash / MSYS2 / Cygwin `bash.exe` from Windows System32 WSL `bash.exe`
    if (rawName && /[\\/](?:git|msys|mingw|cygwin)[^\\/]*[\\/]/i.test(rawName)) {
      return false;
    }
    return true;
  }
  // Distro launcher like `ubuntu.exe run ...`, `debian.exe run ...`, `kali-linux.exe run ...`
  const knownDistros = new Set(["ubuntu", "ubuntu2004", "ubuntu2204", "ubuntu2404", "debian", "kali-linux", "opensuse-leap", "alpine"]);
  if (knownDistros.has(stripExeExt(baseName)) && argv[0]?.toLowerCase() === "run") {
    return true;
  }
  return false;
}

export function parseWslInvocation(
  baseName: string,
  argv: string[],
  ctx: {
    depth: number;
    winCwd: string;
    automountRoot?: string;
    defaultUserHome?: string;
    sessionModifiedFiles?: ReadonlySet<string>;
  },
): WslInvocationPlan {
  const effects: EffectTag[] = [];
  const opaqueReasons: string[] = [];
  const automount = ctx.automountRoot ?? "/mnt";
  let distro: string | undefined;
  let user: string | undefined;
  let loginShell = false;
  let rawCd: string | undefined;
  let execDirect = false;
  let i = 0;

  // Distro launcher `<distro>.exe run <cmd>`
  if (stripExeExt(baseName) !== "wsl" && stripExeExt(baseName) !== "bash") {
    distro = stripExeExt(baseName);
    if (argv[0]?.toLowerCase() === "run") {
      i = 1;
      const childCmd = argv.slice(i);
      const childCwd = mapWindowsToWslPath(ctx.winCwd, automount) ?? "/";
      const childHome = ctx.defaultUserHome ?? "/home/user";
      if (childCmd.length === 0) {
        opaqueReasons.push("wsl_interactive");
        return { kind: "opaque", distro, childCwd, childHome, effects, opaqueReasons };
      }
      const sources = buildWslShellSources(childCmd);
      return {
        kind: "exec_shell",
        distro,
        childCwd,
        childHome,
        childSource: sources.primary,
        ...(sources.extras.length > 0 ? { extraChildSources: sources.extras } : {}),
        effects,
        opaqueReasons,
      };
    }
  }

  // `bash.exe -c "..."` on Windows runs inside default WSL distro
  if (stripExeExt(baseName) === "bash") {
    const childCwd = mapWindowsToWslPath(ctx.winCwd, automount) ?? "/";
    const childHome = ctx.defaultUserHome ?? "/home/user";
    const dashCIdx = argv.findIndex((a) => a === "-c" || /^-[a-zA-Z]*c$/.test(a));
    if (dashCIdx >= 0 && typeof argv[dashCIdx + 1] === "string") {
      return {
        kind: "exec_shell",
        childCwd,
        childHome,
        childSource: argv[dashCIdx + 1],
        effects,
        opaqueReasons,
      };
    }
    opaqueReasons.push("wsl_interactive");
    return { kind: "opaque", childCwd, childHome, effects, opaqueReasons };
  }

  while (i < argv.length) {
    const tok = argv[i];
    const lower = tok.toLowerCase();

    if (tok === "--") {
      i += 1;
      break;
    }

    if (WSL_DESTRUCTIVE_FLAGS.has(lower)) {
      effects.push({
        tag: "system_destructive",
        layer: ctx.depth,
        target: `wsl ${argv.join(" ")}`,
        reversibility: "irreversible",
        detail: "wsl_unregister",
      });
      return {
        kind: "management",
        childCwd: "/",
        childHome: "/root",
        effects,
        opaqueReasons,
      };
    }

    if (WSL_PRIVILEGE_FLAGS.has(lower)) {
      effects.push({
        tag: "privilege",
        layer: ctx.depth,
        target: `wsl ${tok}`,
        detail: "wsl_management",
      });
      if (lower === "--mount") {
        effects.push({
          tag: "system_destructive",
          layer: ctx.depth,
          target: `wsl ${tok}`,
          detail: "wsl_mount",
        });
      }
      return {
        kind: "management",
        childCwd: "/",
        childHome: "/root",
        effects,
        opaqueReasons,
      };
    }

    if (lower === "-d" || lower === "--distribution") {
      distro = argv[i + 1];
      i += 2;
      continue;
    }
    if (lower.startsWith("--distribution=")) {
      distro = tok.slice("--distribution=".length);
      i += 1;
      continue;
    }

    if (lower === "-u" || lower === "--user") {
      user = argv[i + 1];
      i += 2;
      continue;
    }
    if (lower.startsWith("--user=")) {
      user = tok.slice("--user=".length);
      i += 1;
      continue;
    }

    if (lower === "--system") {
      user = "root";
      i += 1;
      continue;
    }

    if (lower === "--cd") {
      rawCd = argv[i + 1];
      i += 2;
      continue;
    }
    if (lower.startsWith("--cd=")) {
      rawCd = tok.slice("--cd=".length);
      i += 1;
      continue;
    }

    if (lower === "--shell-type") {
      if (argv[i + 1]?.toLowerCase() === "login") {
        loginShell = true;
      }
      i += 2;
      continue;
    }
    if (lower.startsWith("--shell-type=")) {
      if (tok.slice("--shell-type=".length).toLowerCase() === "login") {
        loginShell = true;
      }
      i += 1;
      continue;
    }

    if (lower === "-e" || lower === "--exec") {
      execDirect = true;
      i += 1;
      break;
    }

    if (tok.startsWith("-")) {
      if (lower === "-l" || lower === "--list" || lower === "--status" || lower === "--version") {
        effects.push({ tag: "read", layer: ctx.depth, target: `wsl ${tok}` });
        return {
          kind: "management",
          childCwd: "/",
          childHome: "/home/user",
          effects,
          opaqueReasons,
        };
      }
      if (!WSL_SAFE_STATUS_FLAGS.has(lower)) {
        opaqueReasons.push(`wsl_unknown_flag:${tok}`);
      }
      i += 1;
      continue;
    }

    break;
  }

  const isRootUser = user?.toLowerCase() === "root" || user === "0";
  if (isRootUser) {
    effects.push({
      tag: "privilege",
      layer: ctx.depth,
      target: "wsl -u root",
      detail: "wsl_root_user",
    });
  }

  const childHome = isRootUser ? "/root" : (ctx.defaultUserHome ?? "/home/user");
  let childCwd = mapWindowsToWslPath(ctx.winCwd, automount) ?? "/";
  if (rawCd) {
    if (rawCd === "~") {
      childCwd = childHome;
    } else if (/^[A-Za-z]:/.test(rawCd) || rawCd.startsWith("\\\\")) {
      childCwd = mapWindowsToWslPath(rawCd, automount) ?? "/";
    } else if (rawCd.startsWith("/")) {
      childCwd = rawCd;
    } else {
      opaqueReasons.push("wsl_relative_cd");
    }
  }

  if (loginShell) {
    const profileModified = Array.from(ctx.sessionModifiedFiles ?? []).some((f) =>
      /(?:^|\/)(?:\.profile|\.bash_profile|\.bashrc|\.zshrc|\.zprofile)$/.test(f),
    );
    if (profileModified) {
      effects.push({
        tag: "exec_inline",
        layer: ctx.depth,
        target: "wsl --shell-type login",
        detail: "provenance_login_profile_modified",
      });
    }
  }

  const remaining = argv.slice(i);
  if (remaining.length === 0) {
    opaqueReasons.push("wsl_interactive");
    return {
      kind: "opaque",
      distro,
      user,
      automountRoot: automount,
      childCwd,
      childHome,
      loginShell,
      effects,
      opaqueReasons,
    };
  }

  if (execDirect) {
    const bin = basename(remaining[0]).toLowerCase();
    if (
      (bin === "bash" || bin === "sh" || bin === "zsh") &&
      /^-[a-zA-Z]*c$/.test(remaining[1] ?? "") &&
      typeof remaining[2] === "string"
    ) {
      return {
        kind: "exec_shell",
        distro,
        user,
        automountRoot: automount,
        childCwd,
        childHome,
        childSource: remaining.slice(2).join(" "),
        loginShell,
        effects,
        opaqueReasons,
      };
    }

    return {
      kind: "exec_argv",
      distro,
      user,
      automountRoot: automount,
      childCwd,
      childHome,
      childArgv: remaining,
      loginShell,
      effects,
      opaqueReasons,
    };
  }

  // `wsl <command...>` evaluates shell-quoted reconstruction and raw reconstruction (C2 / H-7)
  const sources = buildWslShellSources(remaining);
  return {
    kind: "exec_shell",
    distro,
    user,
    automountRoot: automount,
    childCwd,
    childHome,
    childSource: sources.primary,
    ...(sources.extras.length > 0 ? { extraChildSources: sources.extras } : {}),
    loginShell,
    effects,
    opaqueReasons,
  };
}
