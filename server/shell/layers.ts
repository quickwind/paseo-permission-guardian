import { basename } from "node:path";
import type { EffectTag, Shell } from "../../shared/types.js";
import { parseBash } from "./bash.js";
import type { CommandFact, LayerContext, LayerResult, PipelineFact } from "./types.js";

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

function normalizeCommandBase(name: string): string {
  const base = basename(name).toLowerCase();
  return base.replace(/\.(?:exe|cmd|bat)$/, "");
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
): { innerName: string; innerArgv: string[]; addedPrivilege?: boolean } | null {
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
    if (i < argv.length) {
      return { innerName: argv[i], innerArgv: argv.slice(i + 1), addedPrivilege: true };
    }
    return null;
  }

  if (baseName === "env") {
    let i = 0;
    while (i < argv.length) {
      const token = argv[i];
      if (token === "--") {
        i += 1;
        break;
      }
      if (token === "-u" || token === "-C") {
        i += 2;
        continue;
      }
      if (token.startsWith("-") || token.includes("=")) {
        i += 1;
        continue;
      }
      break;
    }
    if (i < argv.length) {
      return { innerName: argv[i], innerArgv: argv.slice(i + 1) };
    }
    return null;
  }

  if (baseName === "nohup" || baseName === "command") {
    let i = 0;
    while (i < argv.length && argv[i].startsWith("-")) {
      i += 1;
    }
    if (i < argv.length) {
      return { innerName: argv[i], innerArgv: argv.slice(i + 1) };
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
      return { innerName: argv[i], innerArgv: argv.slice(i + 1) };
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
      return { innerName: argv[i], innerArgv: argv.slice(i + 1) };
    }
    return null;
  }

  return null;
}

export async function analyzeShellLayers(
  shell: Shell,
  source: string,
  ctx: LayerContext,
): Promise<LayerResult> {
  const allCommands: CommandFact[] = [];
  const allPipelines: PipelineFact[] = [];
  const allEffects: EffectTag[] = [];
  const allOpaque: string[] = [];

  if (ctx.depth > MAX_LAYER_DEPTH) {
    allOpaque.push("max_depth_exceeded");
    return {
      commands: allCommands,
      pipelines: allPipelines,
      effects: [{ tag: "opaque", layer: ctx.depth, detail: "max_depth_exceeded" }],
      opaque: allOpaque,
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
    };
  }

  const parsed = await parseBash(source, ctx.depth);
  allPipelines.push(...parsed.pipelines);
  allOpaque.push(...parsed.opaque);

  for (const cmd of parsed.commands) {
    await inspectCommand(cmd, ctx, allCommands, allPipelines, allEffects, allOpaque);
  }

  for (const reason of allOpaque) {
    allEffects.push({ tag: "opaque", layer: ctx.depth, detail: reason });
  }

  return {
    commands: allCommands,
    pipelines: allPipelines,
    effects: allEffects,
    opaque: Array.from(new Set(allOpaque)),
  };
}

async function inspectCommand(
  cmd: CommandFact,
  ctx: LayerContext,
  allCommands: CommandFact[],
  allPipelines: PipelineFact[],
  allEffects: EffectTag[],
  allOpaque: string[],
): Promise<void> {
  const baseName = normalizeCommandBase(cmd.name);

  if (OPAQUE_BUILTINS.has(baseName)) {
    allCommands.push(cmd);
    allOpaque.push(`opaque_builtin:${baseName}`);
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
      target: cmd.rawText,
      detail: `${baseName} network-sourced execution`,
    });
    return;
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
      const child = await analyzeShellLayers("bash", innerScript, {
        ...ctx,
        depth: ctx.depth + 1,
      });
      allCommands.push(...child.commands);
      allPipelines.push(...child.pipelines);
      allEffects.push(...child.effects);
      allOpaque.push(...child.opaque);
      return;
    }
  }

  // Prefix wrapper: sudo, env, timeout, nice, nohup, command
  const unwrapped = unwrapPrefixWrapper(baseName, cmd.argv);
  if (unwrapped) {
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
    const syntheticInner: CommandFact = {
      ...cmd,
      name: unwrapped.innerName,
      argv: unwrapped.innerArgv,
      depth: ctx.depth + 1,
    };
    await inspectCommand(
      syntheticInner,
      { ...ctx, depth: ctx.depth + 1 },
      allCommands,
      allPipelines,
      allEffects,
      allOpaque,
    );
    return;
  }

  allCommands.push(cmd);
}
