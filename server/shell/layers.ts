import { basename } from "node:path";
import type { EffectTag, Shell } from "../../shared/types.js";
import { parseBash } from "./bash.js";
import type {
  AssignmentFact,
  CommandFact,
  LayerContext,
  LayerResult,
  PipelineFact,
} from "./types.js";

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
const OPAQUE_BUILTINS = new Set(["eval", "source", "."]);
const NETWORK_RUNNERS = new Set(["npx", "uvx"]);

interface UnwrapResult {
  innerName?: string;
  innerArgv: string[];
  addedPrivilege?: boolean;
  extractedAssignments: AssignmentFact[];
  splitString?: string;
  changedCwd?: boolean;
}

function normalizeCommandBase(name: string): string {
  const base = basename(name).toLowerCase();
  return base.replace(/\.(?:exe|cmd|bat)$/, "");
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

function unwrapPrefixWrapper(
  baseName: string,
  argv: string[],
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
    let changedCwd = false;

    while (i < argv.length) {
      const token = argv[i];
      if (token === "--") {
        i += 1;
        break;
      }
      if (token === "-u") {
        i += 2;
        continue;
      }
      if (token === "-C") {
        changedCwd = true;
        i += 2;
        continue;
      }
      if (token.startsWith("--chdir=")) {
        changedCwd = true;
        i += 1;
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
      extractedAssignments,
      splitString,
      changedCwd,
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
    // Skip duration operand
    i += 1;
    if (i < argv.length) {
      return {
        innerName: argv[i],
        innerArgv: argv.slice(i + 1),
        extractedAssignments: [],
      };
    }
    return null;
  }

  return null;
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
  let cwdChanged = Boolean(ctx.cwdChanged);

  if (ctx.depth > MAX_LAYER_DEPTH) {
    allOpaque.push("max_depth_exceeded");
    return {
      commands: allCommands,
      pipelines: allPipelines,
      effects: [{ tag: "opaque", layer: ctx.depth, detail: "max_depth_exceeded" }],
      opaque: allOpaque,
      assignments: allAssignments,
      envReads: [],
      cwdChanged,
    };
  }

  if (shell !== "bash") {
    // PowerShell / cmd parsers arrive in P1b; fail safely to opaque.
    const reason = `unsupported_shell_in_p1a:${shell}`;
    allOpaque.push(reason);
    return {
      commands: allCommands,
      pipelines: allPipelines,
      effects: [{ tag: "opaque", layer: ctx.depth, detail: reason }],
      opaque: allOpaque,
      assignments: allAssignments,
      envReads: [],
      cwdChanged,
    };
  }

  const parsed = await parseBash(source, ctx.depth);
  allPipelines.push(...parsed.pipelines);
  allOpaque.push(...parsed.opaque);
  allAssignments.push(...parsed.assignments);
  for (const v of parsed.envReads) {
    allEnvReads.add(v);
  }

  for (const cmd of parsed.commands) {
    const cmdCwdChanged = cwdChanged || Boolean(cmd.cwdChanged);
    const updated = await inspectCommand(
      cmdCwdChanged ? { ...cmd, cwdChanged: true } : cmd,
      { ...ctx, cwdChanged: cmdCwdChanged },
      allCommands,
      allPipelines,
      allEffects,
      allOpaque,
      allAssignments,
      allEnvReads,
    );
    if (updated.cwdChanged) {
      cwdChanged = true;
    }
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
): Promise<{ cwdChanged: boolean }> {
  const baseName = normalizeCommandBase(cmd.name);
  let cwdChanged = Boolean(ctx.cwdChanged || cmd.cwdChanged);

  if (baseName === "cd") {
    allCommands.push(cmd);
    return { cwdChanged: true };
  }

  if (OPAQUE_BUILTINS.has(baseName)) {
    allCommands.push(cmd);
    allOpaque.push(`opaque_builtin:${baseName}`);
    return { cwdChanged };
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
    return { cwdChanged };
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
      target: cmd.rawText,
      detail: `${baseName} network-sourced execution`,
    });
    return { cwdChanged };
  }

  // Nested shell wrapper: bash -c "...", sh -c "...", zsh -c "..."
  if (SHELL_WRAPPERS.has(baseName)) {
    const innerScript = unwrapShellDashC(cmd.argv);
    if (innerScript !== null) {
      if (ctx.depth + 1 > MAX_LAYER_DEPTH) {
        allCommands.push(cmd);
        allOpaque.push("max_depth_exceeded");
        return { cwdChanged };
      }
      const child = await analyzeShellLayers("bash", innerScript, {
        ...ctx,
        depth: ctx.depth + 1,
        cwdChanged,
      });
      allCommands.push(...child.commands);
      allPipelines.push(...child.pipelines);
      allEffects.push(...child.effects);
      allOpaque.push(...child.opaque);
      allAssignments.push(...child.assignments);
      for (const v of child.envReads) {
        allEnvReads.add(v);
      }
      return { cwdChanged: cwdChanged || child.cwdChanged };
    }
  }

  // Prefix wrapper: sudo, env, timeout, nice, nohup, command
  const unwrapped = unwrapPrefixWrapper(baseName, cmd.argv, ctx.depth);
  if (unwrapped) {
    if (unwrapped.extractedAssignments.length > 0) {
      allAssignments.push(...unwrapped.extractedAssignments);
    }
    const nextCwdChanged = cwdChanged || Boolean(unwrapped.changedCwd);

    if (unwrapped.splitString !== undefined) {
      if (ctx.depth + 1 > MAX_LAYER_DEPTH) {
        allCommands.push(cmd);
        allOpaque.push("max_depth_exceeded");
        return { cwdChanged: nextCwdChanged };
      }
      const child = await analyzeShellLayers("bash", unwrapped.splitString, {
        ...ctx,
        depth: ctx.depth + 1,
        cwdChanged: nextCwdChanged,
      });
      allCommands.push(...child.commands);
      allPipelines.push(...child.pipelines);
      allEffects.push(...child.effects);
      allOpaque.push(...child.opaque);
      allAssignments.push(...child.assignments);
      for (const v of child.envReads) {
        allEnvReads.add(v);
      }
      return { cwdChanged: nextCwdChanged || child.cwdChanged };
    }

    if (!unwrapped.innerName) {
      // e.g. `env`, `env -0`, `env -u FOO` with no inner command -> keep for dump check
      allCommands.push(nextCwdChanged ? { ...cmd, cwdChanged: true } : cmd);
      return { cwdChanged: nextCwdChanged };
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
      return { cwdChanged: nextCwdChanged };
    }

    const mergedAssignments: Record<string, string> = { ...cmd.assignments };
    for (const a of unwrapped.extractedAssignments) {
      mergedAssignments[a.name] = a.value;
    }
    const syntheticInner: CommandFact = {
      ...cmd,
      name: unwrapped.innerName,
      argv: unwrapped.innerArgv,
      assignments: mergedAssignments,
      depth: ctx.depth + 1,
      ...(nextCwdChanged ? { cwdChanged: true } : {}),
    };
    const childResult = await inspectCommand(
      syntheticInner,
      { ...ctx, depth: ctx.depth + 1, cwdChanged: nextCwdChanged },
      allCommands,
      allPipelines,
      allEffects,
      allOpaque,
      allAssignments,
      allEnvReads,
    );
    return { cwdChanged: nextCwdChanged || childResult.cwdChanged };
  }

  allCommands.push(cwdChanged ? { ...cmd, cwdChanged: true } : cmd);
  return { cwdChanged };
}
