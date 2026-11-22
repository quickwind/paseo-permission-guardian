import type { EffectTag, Shell } from "../../shared/types.js";
import { mapWindowsToWslPath } from "../paths/windows.js";
import { parseBash } from "./bash.js";
import { parseCmd, SAFE_CMD_SYSTEM_MACROS } from "./cmd.js";
import { resolveStaticPosixCwd } from "./cwd.js";
import { parsePowerShell } from "./pwsh.js";
import type {
  AssignmentFact,
  CommandFact,
  LayerContext,
  LayerResult,
  PipelineFact,
} from "./types.js";
import { isWslWrapper, parseWslInvocation } from "./wsl.js";

const MAX_LAYER_DEPTH = 3;

const SHELL_WRAPPERS = new Set(["bash", "sh", "zsh", "dash", "ksh"]);
const INLINE_INTERPRETERS = new Map<string, Set<string>>([
  ["python", new Set(["-c"])],
  ["python3", new Set(["-c"])],
  ["node", new Set(["-e", "--eval", "-p", "--print"])],
  ["perl", new Set(["-e", "-E"])],
  ["ruby", new Set(["-e"])],
  ["php", new Set(["-r"])],
]);
const OPAQUE_BUILTINS = new Set(["eval", "source", ".", "alias"]);
const NETWORK_RUNNERS = new Set(["npx", "uvx"]);

interface UnwrapResult {
  innerName?: string;
  innerArgv: string[];
  innerArgvDynamic?: boolean[];
  addedPrivilege?: boolean;
  extractedAssignments: AssignmentFact[];
  splitString?: string;
  chdirTarget?: string;
  chdirDynamic?: boolean;
}

function normalizeCommandBase(name: string): string {
  const base = (name.split(/[\\/]/).pop() ?? name).toLowerCase();
  return base.replace(/\.(?:exe|cmd|bat|ps1|com)$/, "");
}

function splitEnvAssignmentToken(
  token: string,
  depth: number,
): AssignmentFact | null {
  if (token.startsWith("-")) {
    return null;
  }
  const eqIdx = token.indexOf("=");
  if (eqIdx <= 0) {
    return null;
  }
  const name = token.slice(0, eqIdx);
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
    return null;
  }
  return {
    name,
    value: token.slice(eqIdx + 1),
    standalone: false,
    depth,
    source: "wrapper",
  };
}

function unwrapShellDashC(argv: string[]): string | null {
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--") break;
    if (arg === "-c" || /^-[a-zA-Z]*c$/.test(arg)) {
      const next = argv[i + 1];
      return typeof next === "string" ? next : null;
    }
  }
  return null;
}

function isShoptExpandAliases(argv: string[]): boolean {
  let enableFlag = false;
  let hasExpandAliases = false;

  for (const arg of argv) {
    if (arg === "--") break;
    if (arg.startsWith("-") && !arg.startsWith("--") && arg.slice(1).includes("s")) {
      enableFlag = true;
    } else if (arg === "expand_aliases") {
      hasExpandAliases = true;
    }
  }
  return enableFlag && hasExpandAliases;
}

function isPwshEncodedCommandFlag(arg: string): boolean {
  const lower = arg.toLowerCase();
  if (lower === "-e" || lower === "-ec") return true;
  return lower.startsWith("-en") && "-encodedcommand".startsWith(lower);
}

function isPwshExecutionPolicyFlag(arg: string): boolean {
  const lower = arg.toLowerCase();
  return (lower.startsWith("-ep") || lower.startsWith("-ex")) && "-executionpolicy".startsWith(lower);
}

function isPwshCommandFlag(arg: string): boolean {
  const lower = arg.toLowerCase();
  return lower.startsWith("-c") && "-command".startsWith(lower);
}

function isPwshFileFlag(arg: string): boolean {
  const lower = arg.toLowerCase();
  return lower.startsWith("-f") && "-file".startsWith(lower);
}

function unwrapPrefixWrapper(
  baseName: string,
  argv: string[],
  argvDynamic: boolean[] | undefined,
  depth: number,
): UnwrapResult | null {
  if (baseName === "sudo") {
    let i = 0;
    while (i < argv.length) {
      const token = argv[i];
      if (token === "--") {
        i += 1;
        break;
      }
      if (["-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U"].includes(token)) {
        i += 2;
        continue;
      }
      if (token.startsWith("-")) {
        i += 1;
        continue;
      }
      break;
    }

    const extractedAssignments: AssignmentFact[] = [];
    while (i < argv.length) {
      const assign = splitEnvAssignmentToken(argv[i], depth);
      if (!assign) break;
      extractedAssignments.push(assign);
      i += 1;
    }

    if (i < argv.length) {
      return {
        innerName: argv[i],
        innerArgv: argv.slice(i + 1),
        innerArgvDynamic: argvDynamic?.slice(i + 1),
        addedPrivilege: true,
        extractedAssignments,
      };
    }
    return null;
  }

  if (baseName === "env") {
    let i = 0;
    const extractedAssignments: AssignmentFact[] = [];
    let splitString: string | undefined;
    let chdirTarget: string | undefined;
    let chdirDynamic = false;

    while (i < argv.length) {
      const token = argv[i];
      const tokDynamic = argvDynamic?.[i] ?? false;

      if (token === "--") {
        i += 1;
        break;
      }
      if (token === "-u") {
        i += 2;
        continue;
      }
      if (token === "-C") {
        if (typeof argv[i + 1] === "string") {
          chdirTarget = argv[i + 1];
          chdirDynamic = argvDynamic?.[i + 1] ?? false;
        } else {
          chdirTarget = "";
          chdirDynamic = true;
        }
        i += 2;
        continue;
      }
      if (token.startsWith("-C") && token.length > 2) {
        chdirTarget = token.slice(2);
        chdirDynamic = tokDynamic;
        i += 1;
        continue;
      }
      if (token.startsWith("--chdir=")) {
        chdirTarget = token.slice("--chdir=".length);
        chdirDynamic = tokDynamic;
        i += 1;
        continue;
      }
      if (token === "--chdir") {
        if (typeof argv[i + 1] === "string") {
          chdirTarget = argv[i + 1];
          chdirDynamic = argvDynamic?.[i + 1] ?? false;
        } else {
          chdirTarget = "";
          chdirDynamic = true;
        }
        i += 2;
        continue;
      }
      if (token === "-S" || token === "--split-string") {
        if (typeof argv[i + 1] === "string") {
          splitString = argv[i + 1];
        }
        i += 2;
        continue;
      }
      if (token.startsWith("--split-string=")) {
        splitString = token.slice("--split-string=".length);
        i += 1;
        continue;
      }
      if (token.startsWith("-S") && token.length > 2) {
        splitString = token.slice(2);
        i += 1;
        continue;
      }
      if (token.startsWith("-")) {
        i += 1;
        continue;
      }

      const assign = splitEnvAssignmentToken(token, depth);
      if (assign) {
        extractedAssignments.push(assign);
        i += 1;
        continue;
      }
      break;
    }

    return {
      innerName: i < argv.length ? argv[i] : undefined,
      innerArgv: i < argv.length ? argv.slice(i + 1) : [],
      innerArgvDynamic: i < argv.length ? argvDynamic?.slice(i + 1) : undefined,
      extractedAssignments,
      splitString,
      chdirTarget,
      chdirDynamic,
    };
  }

  if (baseName === "nohup" || baseName === "command") {
    let i = 0;
    while (i < argv.length && argv[i].startsWith("-")) {
      i += 1;
    }
    if (i < argv.length) {
      return {
        innerName: argv[i],
        innerArgv: argv.slice(i + 1),
        innerArgvDynamic: argvDynamic?.slice(i + 1),
        extractedAssignments: [],
      };
    }
    return null;
  }

  if (baseName === "nice") {
    let i = 0;
    while (i < argv.length) {
      if (argv[i] === "-n") {
        i += 2;
        continue;
      }
      if (argv[i].startsWith("-")) {
        i += 1;
        continue;
      }
      break;
    }
    if (i < argv.length) {
      return {
        innerName: argv[i],
        innerArgv: argv.slice(i + 1),
        innerArgvDynamic: argvDynamic?.slice(i + 1),
        extractedAssignments: [],
      };
    }
    return null;
  }

  if (baseName === "timeout") {
    let i = 0;
    while (i < argv.length && argv[i].startsWith("-")) {
      if (["-k", "-s", "--kill-after", "--signal"].includes(argv[i])) {
        i += 2;
      } else {
        i += 1;
      }
    }
    i += 1;
    if (i < argv.length) {
      return {
        innerName: argv[i],
        innerArgv: argv.slice(i + 1),
        innerArgvDynamic: argvDynamic?.slice(i + 1),
        extractedAssignments: [],
      };
    }
    return null;
  }

  return null;
}

function mergeChildLayer(
  child: LayerResult,
  allCommands: CommandFact[],
  allPipelines: PipelineFact[],
  allEffects: EffectTag[],
  allOpaque: string[],
  allAssignments: AssignmentFact[],
  allEnvReads: Set<string>,
  allUnescapedSources: string[],
): void {
  allCommands.push(...child.commands);
  allPipelines.push(...child.pipelines);
  allEffects.push(...child.effects);
  allOpaque.push(...child.opaque);
  allAssignments.push(...child.assignments);
  for (const v of child.envReads) {
    allEnvReads.add(v);
  }
  if (child.unescapedSources) {
    allUnescapedSources.push(...child.unescapedSources);
  }
}

const SUBSHELL_WRAPPER_BASES = new Set(["cmd", "powershell", "pwsh", "wsl", "start"]);

function preserveWrapperRedirections(
  cmd: CommandFact,
  ctx: LayerContext,
  cmdCwd: string,
  cmdUncertain: boolean,
  allCommands: CommandFact[],
): void {
  if (cmd.redirections.length === 0 && cmd.envReads.length === 0) {
    return;
  }
  allCommands.push({
    name: cmd.name,
    argv: [],
    rawText: cmd.rawText,
    redirections: cmd.redirections,
    assignments: {},
    envReads: cmd.envReads,
    depth: cmd.depth,
    layer: cmd.layer,
    effectiveCwd: cmdCwd,
    ...(ctx.worktreeRoot ? { effectiveWorktree: ctx.worktreeRoot } : {}),
    ...(ctx.home ? { effectiveHome: ctx.home } : {}),
    ...(cmdUncertain ? { cwdChanged: true } : {}),
    preclassified: true,
  });
}

export async function analyzeShellLayers(
  shell: Shell,
  source: string,
  ctx: LayerContext & { cwdChanged?: boolean },
): Promise<LayerResult> {
  const allCommands: CommandFact[] = [];
  const allPipelines: PipelineFact[] = [];
  const allEffects: EffectTag[] = [];
  const allOpaque: string[] = [];
  const allAssignments: AssignmentFact[] = [];
  const allEnvReads = new Set<string>();
  const allUnescapedSources: string[] = [];
  const cwdChanged = Boolean(ctx.cwdChanged);
  let pwdUncertain = Boolean(ctx.pwdUncertain);
  let cdpathActive = Boolean(
    ctx.cdpathActive || (ctx.envSnapshot?.CDPATH && ctx.envSnapshot.CDPATH.length > 0),
  );

  if (ctx.depth > MAX_LAYER_DEPTH) {
    allOpaque.push("max_depth_exceeded");
    return {
      commands: allCommands,
      pipelines: allPipelines,
      effects: [{ tag: "opaque", layer: ctx.depth, detail: "max_depth_exceeded" }],
      opaque: allOpaque,
      assignments: allAssignments,
      envReads: [],
      unescapedSources: allUnescapedSources,
      cwdChanged,
    };
  }

  let parsedCommands: CommandFact[] = [];

  if (shell === "bash") {
    const parsed = await parseBash(source, ctx.depth, {
      cwd: ctx.cwd,
      home: ctx.home,
      cwdUncertain: cwdChanged,
      pwdUncertain,
      cdpathActive,
      envSnapshot: ctx.envSnapshot,
    });
    if (parsed.pwdMutated) {
      pwdUncertain = true;
    }
    if (parsed.cdpathTouched) {
      cdpathActive = true;
    }
    allPipelines.push(...parsed.pipelines);
    allOpaque.push(...parsed.opaque);
    allAssignments.push(...parsed.assignments);
    for (const v of parsed.envReads) allEnvReads.add(v);
    parsedCommands = parsed.commands;
  } else if (shell === "cmd") {
    const parsed = parseCmd(source, ctx.depth, {
      cwd: ctx.cwd,
      home: ctx.home,
      cwdUncertain: cwdChanged,
      envSnapshot: ctx.envSnapshot,
    });
    allPipelines.push(...parsed.pipelines);
    allOpaque.push(...parsed.opaque);
    allAssignments.push(...parsed.assignments);
    for (const v of parsed.envReads) allEnvReads.add(v);
    allUnescapedSources.push(parsed.unescapedSource);
    parsedCommands = parsed.commands;
  } else if (shell === "pwsh5" || shell === "pwsh7") {
    const parsed = await parsePowerShell(shell, source, ctx.depth, {
      cwd: ctx.cwd,
      worktreeRoot: ctx.worktreeRoot,
      home: ctx.home,
      pluginDataDir: ctx.pluginDataDir,
      paseoRoots: ctx.paseoRoots,
      paseoHomeRoots: ctx.paseoHomeRoots,
      skipHostRealpath: ctx.skipHostRealpath,
      pwshHostMode: ctx.pwshHost,
      hostProvider: ctx.pwshHostProvider,
      allowPosixHost: ctx.allowPosixPwshHost,
      binaryPath: ctx.pwshBinaryPath,
      envSnapshot: ctx.envSnapshot,
      session: ctx.session,
    });
    allPipelines.push(...parsed.pipelines);
    allEffects.push(...parsed.effects);
    allOpaque.push(...parsed.opaque);
    allAssignments.push(...parsed.assignments);
    for (const v of parsed.envReads) allEnvReads.add(v);
    allUnescapedSources.push(...parsed.unescapedSources);
    parsedCommands = parsed.commands;
  } else if (shell === "argv") {
    const parts = source.split("\u0000").filter((p) => p.length > 0);
    if (parts.length > 0) {
      parsedCommands = [
        {
          name: parts[0],
          argv: parts.slice(1),
          ...(ctx.argvDynamic ? { argvDynamic: ctx.argvDynamic } : {}),
          rawText: parts.join(" "),
          redirections: [],
          assignments: {},
          envReads: [],
          depth: ctx.depth,
          layer: "argv",
          effectiveCwd: ctx.cwd,
          ...(cwdChanged ? { cwdChanged: true } : {}),
        },
      ];
    }
  } else {
    const reason = `unsupported_shell:${shell}`;
    allOpaque.push(reason);
    return {
      commands: allCommands,
      pipelines: allPipelines,
      effects: [{ tag: "opaque", layer: ctx.depth, detail: reason }],
      opaque: allOpaque,
      assignments: allAssignments,
      envReads: [],
      unescapedSources: allUnescapedSources,
      cwdChanged,
    };
  }

  for (const cmd of parsedCommands) {
    const cmdCwd = cmd.effectiveCwd ?? ctx.cwd;
    const cmdUncertain = Boolean(cmd.cwdChanged);
    const hasNonSafeAssignment = allAssignments.some(
      (a) => !SAFE_CMD_SYSTEM_MACROS.has(a.name.trim().toUpperCase()),
    );
    if (
      hasNonSafeAssignment &&
      SUBSHELL_WRAPPER_BASES.has(normalizeCommandBase(cmd.name)) &&
      cmd.argv.some((a) => /%[^%\r\n]+%|!/.test(a))
    ) {
      allOpaque.push("env_set_before_subshell");
    }
    await inspectCommand(
      cmd,
      {
        ...ctx,
        cwd: cmdCwd,
        cwdChanged: cmdUncertain,
        pwdUncertain,
        cdpathActive,
        argvDynamic: undefined,
      },
      allCommands,
      allPipelines,
      allEffects,
      allOpaque,
      allAssignments,
      allEnvReads,
      allUnescapedSources,
    );
  }

  for (const reason of allOpaque) {
    allEffects.push({ tag: "opaque", layer: ctx.depth, detail: reason });
  }

  return {
    commands: allCommands,
    pipelines: allPipelines,
    effects: allEffects,
    opaque: Array.from(new Set(allOpaque)),
    assignments: allAssignments,
    envReads: Array.from(allEnvReads),
    unescapedSources: Array.from(new Set(allUnescapedSources)),
    cwdChanged,
  };
}

async function inspectCommand(
  cmd: CommandFact,
  ctx: LayerContext & { cwdChanged?: boolean },
  allCommands: CommandFact[],
  allPipelines: PipelineFact[],
  allEffects: EffectTag[],
  allOpaque: string[],
  allAssignments: AssignmentFact[],
  allEnvReads: Set<string>,
  allUnescapedSources: string[],
): Promise<void> {
  const baseName = normalizeCommandBase(cmd.name);
  const cmdCwd = cmd.effectiveCwd ?? ctx.cwd;
  const cmdUncertain = Boolean(cmd.cwdChanged || ctx.cwdChanged);
  const cmdPwdUncertain =
    Boolean(ctx.pwdUncertain) || Object.prototype.hasOwnProperty.call(cmd.assignments, "PWD");
  const cmdCdpathActive =
    Boolean(ctx.cdpathActive) || Object.prototype.hasOwnProperty.call(cmd.assignments, "CDPATH");

  if (cmd.pwshAllowVenvActivate) {
    allCommands.push(cmd);
    return;
  }

  if (baseName === "cd" || baseName === "pushd" || baseName === "popd" || baseName === "chdir") {
    allCommands.push(cmd);
    return;
  }

  if (OPAQUE_BUILTINS.has(baseName)) {
    allCommands.push(cmd);
    allOpaque.push(`opaque_builtin:${baseName}`);
    return;
  }

  if (baseName === "shopt" && isShoptExpandAliases(cmd.argv)) {
    allCommands.push(cmd);
    allOpaque.push("opaque_builtin:shopt_expand_aliases");
    return;
  }

  // Inline code execution (python -c, node -e, perl -e, etc.)
  const inlineFlags = INLINE_INTERPRETERS.get(baseName);
  if (inlineFlags && cmd.argv.some((arg) => inlineFlags.has(arg))) {
    allCommands.push(cmd);
    allEffects.push({
      tag: "exec_inline",
      layer: ctx.depth,
      target: baseName,
      detail: `${baseName} inline code`,
    });
    allOpaque.push(`inline_code:${baseName}`);
    return;
  }

  // Network-sourced runners (npx, pnpm dlx, uvx, pipx run)
  if (
    NETWORK_RUNNERS.has(baseName) ||
    (baseName === "pnpm" && cmd.argv[0] === "dlx") ||
    (baseName === "pipx" && cmd.argv[0] === "run")
  ) {
    allCommands.push(cmd);
    allEffects.push({
      tag: "exec_network_sourced",
      layer: ctx.depth,
      target: baseName,
      detail: `${baseName} network-sourced execution`,
    });
    return;
  }

  // Windows explorer / wslview arbitrary launcher
  if (baseName === "explorer" || baseName === "wslview") {
    allCommands.push(cmd);
    allOpaque.push(`windows_launcher_opaque:${baseName}`);
    return;
  }

  // WSL wrapper (`wsl`, Windows `bash.exe`, `<distro>.exe run`)
  if (isWslWrapper(baseName, cmd.argv, ctx.os, cmd.name)) {
    if (ctx.depth + 1 > MAX_LAYER_DEPTH) {
      allCommands.push(cmd);
      allOpaque.push("max_depth_exceeded");
      return;
    }
    const plan = parseWslInvocation(baseName, cmd.argv, {
      depth: ctx.depth,
      winCwd: cmdCwd,
      automountRoot: ctx.wsl?.automountRoot,
      sessionModifiedFiles: ctx.session?.modifiedFiles,
    });
    allEffects.push(...plan.effects);
    allOpaque.push(...plan.opaqueReasons);

    const wslChildWorktree = ctx.worktreeRoot
      ? (mapWindowsToWslPath(ctx.worktreeRoot, plan.automountRoot) ?? ctx.worktreeRoot)
      : undefined;

    if (plan.kind === "exec_shell" && plan.childSource) {
      preserveWrapperRedirections(cmd, ctx, cmdCwd, cmdUncertain, allCommands);
      const sources = [plan.childSource, ...(plan.extraChildSources ?? [])];
      for (const childSrc of sources) {
        const child = await analyzeShellLayers("bash", childSrc, {
          ...ctx,
          os: "linux",
          cwd: plan.childCwd,
          worktreeRoot: wslChildWorktree,
          home: plan.childHome,
          depth: ctx.depth + 1,
          pwdUncertain: cmdPwdUncertain,
          cdpathActive: cmdCdpathActive,
          argvDynamic: undefined,
          wsl: {
            distro: plan.distro,
            user: plan.user,
            automountRoot: plan.automountRoot,
          },
        });
        mergeChildLayer(
          child,
          allCommands,
          allPipelines,
          allEffects,
          allOpaque,
          allAssignments,
          allEnvReads,
          allUnescapedSources,
        );
      }
      return;
    }

    if (plan.kind === "exec_argv" && plan.childArgv && plan.childArgv.length > 0) {
      preserveWrapperRedirections(cmd, ctx, cmdCwd, cmdUncertain, allCommands);
      let childArgvDynamic: boolean[] | undefined;
      if (cmd.argvDynamic) {
        const startIdx = cmd.argv.length - plan.childArgv.length;
        if (startIdx >= 0) {
          if (cmd.argvDynamic[startIdx]) {
            allOpaque.push("dynamic_wsl_command");
          }
          childArgvDynamic = cmd.argvDynamic.slice(startIdx + 1);
        }
      }
      const child = await analyzeShellLayers("argv", plan.childArgv.join("\u0000"), {
        ...ctx,
        os: "linux",
        cwd: plan.childCwd,
        worktreeRoot: wslChildWorktree,
        home: plan.childHome,
        depth: ctx.depth + 1,
        pwdUncertain: cmdPwdUncertain,
        cdpathActive: cmdCdpathActive,
        ...(childArgvDynamic ? { argvDynamic: childArgvDynamic } : { argvDynamic: undefined }),
        wsl: {
          distro: plan.distro,
          user: plan.user,
          automountRoot: plan.automountRoot,
        },
      });
      mergeChildLayer(
        child,
        allCommands,
        allPipelines,
        allEffects,
        allOpaque,
        allAssignments,
        allEnvReads,
        allUnescapedSources,
      );
      return;
    }

    allCommands.push({ ...cmd, preclassified: true });
    return;
  }

  // `cmd.exe /c ...` / `cmd.exe /k ...` wrapper unwrapping (supports glued `/c<cmd>`)
  if (baseName === "cmd") {
    if (/^[\\/]{2}(?:wsl\$|wsl\.localhost)[\\/]/i.test(cmdCwd)) {
      allOpaque.push("cmd_unc_cwd");
    }
    let idx = 0;
    let modeFlag: string | null = null;
    let modeArgIdx = -1;
    let gluedFirst: string | null = null;
    while (idx < cmd.argv.length) {
      const tokLower = cmd.argv[idx].toLowerCase();
      if (tokLower === "--%") {
        idx += 1;
        continue;
      }
      if (tokLower === "/v:on") {
        allOpaque.push("cmd_delayed_expansion");
        idx += 1;
        continue;
      }
      if (tokLower === "/c" || tokLower === "/k" || tokLower === "/r") {
        modeFlag = tokLower;
        modeArgIdx = idx;
        idx += 1;
        break;
      }
      const chainedMode = cmd.argv[idx].match(/^((?:\/[a-z](?::[^\s/]+)?)*)(\/[ckr])(.*)$/i);
      if (chainedMode) {
        const prefixSwitches = chainedMode[1] ?? "";
        if (/\/v:on/i.test(prefixSwitches)) {
          allOpaque.push("cmd_delayed_expansion");
        }
        modeFlag = chainedMode[2].toLowerCase();
        modeArgIdx = idx;
        gluedFirst = chainedMode[3].length > 0 ? chainedMode[3] : null;
        idx += 1;
        break;
      }
      if (tokLower.startsWith("/")) {
        idx += 1;
        continue;
      }
      break;
    }

    if (modeFlag) {
      if (ctx.depth + 1 > MAX_LAYER_DEPTH) {
        allCommands.push(cmd);
        allOpaque.push("max_depth_exceeded");
        return;
      }
      preserveWrapperRedirections(cmd, ctx, cmdCwd, cmdUncertain, allCommands);
      if (
        cmd.layer === "bash" &&
        ((gluedFirst !== null && Boolean(cmd.argvDynamic?.[modeArgIdx])) ||
          cmd.argvDynamic?.slice(idx).some(Boolean))
      ) {
        allOpaque.push("dynamic_subshell_arg");
      }
      const rawRest =
        gluedFirst !== null ? [gluedFirst, ...cmd.argv.slice(idx)] : cmd.argv.slice(idx);
      const restTokens = rawRest[0] === "--%" ? rawRest.slice(1) : rawRest;
      const innerCmdStr = restTokens.join(" ");
      const child = await analyzeShellLayers("cmd", innerCmdStr, {
        ...ctx,
        os: "windows",
        cwd: cmdCwd,
        depth: ctx.depth + 1,
        cwdChanged: cmdUncertain,
        pwdUncertain: cmdPwdUncertain,
        cdpathActive: cmdCdpathActive,
        argvDynamic: undefined,
      });
      mergeChildLayer(
        child,
        allCommands,
        allPipelines,
        allEffects,
        allOpaque,
        allAssignments,
        allEnvReads,
        allUnescapedSources,
      );
      return;
    }

    allOpaque.push("cmd_interactive");
    allCommands.push(cmd);
    return;
  }

  // `powershell` / `pwsh` CLI wrapper unwrapping
  if (baseName === "powershell" || baseName === "pwsh") {
    const targetVariant = baseName === "powershell" ? "pwsh5" : "pwsh7";
    let encodedFlag = false;
    let commandIdx = -1;
    let fileArg: string | undefined;

    for (let i = 0; i < cmd.argv.length; i++) {
      const arg = cmd.argv[i];
      if (isPwshEncodedCommandFlag(arg)) {
        encodedFlag = true;
      } else if (isPwshExecutionPolicyFlag(arg) && cmd.argv[i + 1]) {
        const pol = cmd.argv[i + 1].toLowerCase();
        if (pol === "bypass" || pol === "unrestricted") {
          allEffects.push({
            tag: "exec_inline",
            layer: ctx.depth,
            target: baseName,
            detail: "execution_policy_bypass",
          });
        }
        i += 1;
      } else if (isPwshFileFlag(arg) && cmd.argv[i + 1]) {
        fileArg = cmd.argv[i + 1];
        i += 1;
      } else if (isPwshCommandFlag(arg)) {
        commandIdx = i + 1;
        break;
      } else if (!arg.startsWith("-")) {
        commandIdx = i;
        break;
      }
    }

    if (encodedFlag) {
      allCommands.push(cmd);
      allEffects.push({
        tag: "exec_inline",
        layer: ctx.depth,
        target: baseName,
        detail: "pwsh_encoded_command",
      });
      allOpaque.push("pwsh_encoded_command");
      return;
    }

    if (fileArg !== undefined) {
      allCommands.push(cmd);
      allOpaque.push(`pwsh_script_file:${fileArg}`);
      return;
    }

    if (commandIdx >= 0 && commandIdx < cmd.argv.length) {
      if (ctx.depth + 1 > MAX_LAYER_DEPTH) {
        allCommands.push(cmd);
        allOpaque.push("max_depth_exceeded");
        return;
      }
      preserveWrapperRedirections(cmd, ctx, cmdCwd, cmdUncertain, allCommands);
      if (cmd.layer === "bash" && cmd.argvDynamic?.slice(commandIdx).some(Boolean)) {
        allOpaque.push("dynamic_subshell_arg");
      }
      const innerScript = cmd.argv.slice(commandIdx).join(" ");
      const child = await analyzeShellLayers(targetVariant, innerScript, {
        ...ctx,
        cwd: cmdCwd,
        depth: ctx.depth + 1,
        cwdChanged: cmdUncertain,
        pwdUncertain: cmdPwdUncertain,
        cdpathActive: cmdCdpathActive,
        argvDynamic: undefined,
      });
      mergeChildLayer(
        child,
        allCommands,
        allPipelines,
        allEffects,
        allOpaque,
        allAssignments,
        allEnvReads,
        allUnescapedSources,
      );
      return;
    }
  }

  // `cmd.exe` `start "" /d <dir> <exe> ...` unwrapping
  if (cmd.layer === "cmd" && baseName === "start") {
    let i = 0;
    let startDir: string | undefined;
    let skippedTitle = false;
    while (i < cmd.argv.length) {
      const tok = cmd.argv[i];
      const low = tok.toLowerCase();
      if (low === "/d" && cmd.argv[i + 1]) {
        startDir = cmd.argv[i + 1];
        i += 2;
        continue;
      }
      if (low.startsWith("/")) {
        i += 1;
        continue;
      }
      // `start` treats an empty or quoted first non-flag token as window title if followed by another token
      if (!skippedTitle && i + 1 < cmd.argv.length && (tok === "" || tok.includes(" ") || cmd.rawText.includes(`"${tok}"`))) {
        skippedTitle = true;
        i += 1;
        continue;
      }
      break;
    }
    if (i < cmd.argv.length) {
      if (ctx.depth + 1 > MAX_LAYER_DEPTH) {
        allCommands.push(cmd);
        allOpaque.push("max_depth_exceeded");
        return;
      }
      preserveWrapperRedirections(cmd, ctx, cmdCwd, cmdUncertain, allCommands);
      const syntheticInner: CommandFact = {
        ...cmd,
        name: cmd.argv[i],
        argv: cmd.argv.slice(i + 1),
        redirections: [],
        envReads: [],
        depth: ctx.depth + 1,
        effectiveCwd: startDir ?? cmdCwd,
        ...(startDir ? {} : cmdUncertain ? { cwdChanged: true } : {}),
      };
      await inspectCommand(
        syntheticInner,
        {
          ...ctx,
          cwd: startDir ?? cmdCwd,
          depth: ctx.depth + 1,
          cwdChanged: startDir ? false : cmdUncertain,
          pwdUncertain: cmdPwdUncertain,
          cdpathActive: cmdCdpathActive,
          argvDynamic: undefined,
        },
        allCommands,
        allPipelines,
        allEffects,
        allOpaque,
        allAssignments,
        allEnvReads,
        allUnescapedSources,
      );
      return;
    }
  }

  // Nested shell wrapper: bash -c "...", sh -c "...", zsh -c "..."
  if (SHELL_WRAPPERS.has(baseName)) {
    const innerScript = unwrapShellDashC(cmd.argv);
    if (innerScript !== null) {
      if (ctx.depth + 1 > MAX_LAYER_DEPTH) {
        allCommands.push(cmd);
        allOpaque.push("max_depth_exceeded");
        return;
      }
      preserveWrapperRedirections(cmd, ctx, cmdCwd, cmdUncertain, allCommands);
      const child = await analyzeShellLayers("bash", innerScript, {
        ...ctx,
        cwd: cmdCwd,
        depth: ctx.depth + 1,
        cwdChanged: cmdUncertain,
        pwdUncertain: cmdPwdUncertain,
        cdpathActive: cmdCdpathActive,
        argvDynamic: undefined,
      });
      mergeChildLayer(
        child,
        allCommands,
        allPipelines,
        allEffects,
        allOpaque,
        allAssignments,
        allEnvReads,
        allUnescapedSources,
      );
      return;
    }
  }

  // Prefix wrapper: sudo, env, timeout, nice, nohup, command
  const unwrapped = unwrapPrefixWrapper(baseName, cmd.argv, cmd.argvDynamic, ctx.depth);
  if (unwrapped) {
    if (unwrapped.extractedAssignments.length > 0) {
      allAssignments.push(...unwrapped.extractedAssignments);
    }
    const innerPwdUncertain =
      cmdPwdUncertain || unwrapped.extractedAssignments.some((a) => a.name === "PWD");
    const innerCdpathActive =
      cmdCdpathActive || unwrapped.extractedAssignments.some((a) => a.name === "CDPATH");

    let innerCwd = cmdCwd;
    let innerUncertain = cmdUncertain;
    if (unwrapped.chdirTarget !== undefined) {
      if (unwrapped.chdirDynamic || innerUncertain) {
        innerUncertain = true;
      } else {
        const resolved = resolveStaticPosixCwd(cmdCwd, unwrapped.chdirTarget, ctx.home);
        if (resolved) {
          innerCwd = resolved;
          innerUncertain = false;
        } else {
          innerUncertain = true;
        }
      }
    }

    if (unwrapped.splitString !== undefined) {
      if (ctx.depth + 1 > MAX_LAYER_DEPTH) {
        allCommands.push(cmd);
        allOpaque.push("max_depth_exceeded");
        return;
      }
      preserveWrapperRedirections(cmd, ctx, cmdCwd, cmdUncertain, allCommands);
      const child = await analyzeShellLayers("bash", unwrapped.splitString, {
        ...ctx,
        cwd: innerCwd,
        depth: ctx.depth + 1,
        cwdChanged: innerUncertain,
        pwdUncertain: innerPwdUncertain,
        cdpathActive: innerCdpathActive,
        argvDynamic: undefined,
      });
      mergeChildLayer(
        child,
        allCommands,
        allPipelines,
        allEffects,
        allOpaque,
        allAssignments,
        allEnvReads,
        allUnescapedSources,
      );
      return;
    }

    if (!unwrapped.innerName) {
      allCommands.push({
        ...cmd,
        effectiveCwd: innerCwd,
        ...(ctx.worktreeRoot ? { effectiveWorktree: ctx.worktreeRoot } : {}),
        ...(ctx.home ? { effectiveHome: ctx.home } : {}),
        ...(innerUncertain ? { cwdChanged: true } : {}),
      });
      return;
    }

    if (unwrapped.addedPrivilege) {
      allEffects.push({
        tag: "privilege",
        layer: ctx.depth,
        target: unwrapped.innerName,
        detail: "sudo",
      });
    }
    if (ctx.depth + 1 > MAX_LAYER_DEPTH) {
      allCommands.push(cmd);
      allOpaque.push("max_depth_exceeded");
      return;
    }

    preserveWrapperRedirections(cmd, ctx, cmdCwd, cmdUncertain, allCommands);
    const mergedAssignments: Record<string, string> = { ...cmd.assignments };
    for (const a of unwrapped.extractedAssignments) {
      mergedAssignments[a.name] = a.value;
    }
    const syntheticInner: CommandFact = {
      ...cmd,
      name: unwrapped.innerName,
      argv: unwrapped.innerArgv,
      argvDynamic: unwrapped.innerArgvDynamic,
      redirections: [],
      envReads: [],
      assignments: mergedAssignments,
      depth: ctx.depth + 1,
      effectiveCwd: innerCwd,
      ...(ctx.worktreeRoot ? { effectiveWorktree: ctx.worktreeRoot } : {}),
      ...(ctx.home ? { effectiveHome: ctx.home } : {}),
      ...(innerUncertain ? { cwdChanged: true } : { cwdChanged: undefined }),
    };
    await inspectCommand(
      syntheticInner,
      {
        ...ctx,
        cwd: innerCwd,
        depth: ctx.depth + 1,
        cwdChanged: innerUncertain,
        pwdUncertain: innerPwdUncertain,
        cdpathActive: innerCdpathActive,
        argvDynamic: undefined,
      },
      allCommands,
      allPipelines,
      allEffects,
      allOpaque,
      allAssignments,
      allEnvReads,
      allUnescapedSources,
    );
    return;
  }

  allCommands.push({
    ...cmd,
    effectiveCwd: cmdCwd,
    ...(ctx.worktreeRoot ? { effectiveWorktree: ctx.worktreeRoot } : {}),
    ...(ctx.home ? { effectiveHome: ctx.home } : {}),
    ...(cmdUncertain ? { cwdChanged: true } : {}),
  });
}
