import { basename } from "node:path";
import type { Action, EffectTag } from "../shared/types.js";
import type { SessionState } from "./context/session.js";
import {
  getDefaultSafeChainsRegistry,
  type SafeChainsRegistry,
} from "./knowledge/sc-registry/interpreter.js";
import { classifyPosixPath, type PathContext } from "./paths/index.js";
import { analyzeShellLayers } from "./shell/layers.js";
import type { CommandFact, PipelineFact } from "./shell/types.js";

export interface EffectAnalysisResult {
  effects: EffectTag[];
  opaqueReasons: string[];
  pipelines: PipelineFact[];
  commands: CommandFact[];
  touchedSecret: boolean;
  touchedUntrusted: boolean;
}

export interface EffectAnalysisOptions {
  pathCtx: PathContext;
  registry?: SafeChainsRegistry;
  trustedDomains?: string[];
  session?: SessionState;
}

const DEFAULT_TRUSTED_DOMAINS = [
  "registry.npmjs.org",
  "pypi.org",
  "github.com",
  "crates.io",
  "pkg.go.dev",
  "developer.mozilla.org",
];

const SENSITIVE_ENV_VAR_PATTERN = /(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)/i;

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
]);

const INFRA_MUTATE_COMMANDS = new Set(["kubectl", "terraform", "tofu", "helm", "aws", "gcloud", "az", "flyctl", "wrangler"]);

function normalizeBin(name: string): string {
  return basename(name).toLowerCase().replace(/\.(?:exe|cmd|bat)$/, "");
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

function classifyRmCommand(cmd: CommandFact, pathCtx: PathContext): EffectTag[] {
  const effects: EffectTag[] = [];
  let recursive = false;
  const targets: string[] = [];

  for (const tok of cmd.argv) {
    if (tok === "--") continue;
    if (tok.startsWith("-")) {
      if (tok === "--recursive" || /^-[a-zA-Z]*[rR]/.test(tok)) {
        recursive = true;
      }
      continue;
    }
    targets.push(tok);
  }

  if (targets.length === 0) {
    effects.push({ tag: "opaque", layer: cmd.depth, detail: "rm_without_targets" });
    return effects;
  }

  for (const target of targets) {
    const p = classifyPosixPath(target, pathCtx);
    if (p.realPath === "/" || p.realPath === "/etc" || p.realPath === "/usr" || p.realPath === "/System") {
      effects.push({
        tag: "system_destructive",
        layer: cmd.depth,
        target: p.realPath,
        reversibility: "irreversible",
        recursive,
        detail: `rm targeting system root ${p.realPath}`,
      });
      continue;
    }
    if (p.isProtected) {
      effects.push({
        tag: "write_protected",
        layer: cmd.depth,
        target: p.realPath,
        pluginSelf: p.isPluginSelf,
        reversibility: "irreversible",
        detail: `rm targeting protected path ${p.realPath}`,
      });
      continue;
    }
    if (p.inWorktree || p.isTemp) {
      effects.push({
        tag: "delete_worktree",
        layer: cmd.depth,
        target: p.realPath,
        recursive,
        reversibility: "irreversible",
      });
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

  return effects;
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
  let touchedSecret = false;
  let touchedUntrusted = false;

  if (action.kind === "read") {
    for (const rawPath of action.paths ?? []) {
      const p = classifyPosixPath(rawPath, options.pathCtx);
      if (p.isSensitive) {
        touchedSecret = true;
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
      effects.push({ tag: "read", layer: 0 });
    }
    return { effects, opaqueReasons, pipelines, commands, touchedSecret, touchedUntrusted };
  }

  if (action.kind === "edit") {
    for (const rawPath of action.paths ?? []) {
      const p = classifyPosixPath(rawPath, options.pathCtx);
      if (p.isProtected) {
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
    return { effects, opaqueReasons, pipelines, commands, touchedSecret, touchedUntrusted };
  }

  if (action.kind === "delete") {
    for (const rawPath of action.paths ?? []) {
      const p = classifyPosixPath(rawPath, options.pathCtx);
      if (p.isProtected) {
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
    return { effects, opaqueReasons, pipelines, commands, touchedSecret, touchedUntrusted };
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
    return { effects, opaqueReasons, pipelines, commands, touchedSecret, touchedUntrusted };
  }

  if (action.kind === "mcp") {
    // Unlisted MCP tools go to L1 grey zone (ask) until configured in policy
    effects.push({
      tag: "opaque",
      layer: 0,
      target: action.mcp ? `${action.mcp.server}:${action.mcp.tool}` : action.toolName,
      detail: "unlisted_mcp_tool",
    });
    opaqueReasons.push("unlisted_mcp_tool");
    return { effects, opaqueReasons, pipelines, commands, touchedSecret, touchedUntrusted };
  }

  if (action.kind !== "exec" || !action.exec) {
    effects.push({ tag: "opaque", layer: 0, detail: `unclassified_kind:${action.kind}` });
    opaqueReasons.push(`unclassified_kind:${action.kind}`);
    return { effects, opaqueReasons, pipelines, commands, touchedSecret, touchedUntrusted };
  }

  // Shell exec analysis
  const layerResult = await analyzeShellLayers(action.exec.shell, action.exec.source, {
    os: action.host.os,
    cwd: action.cwd,
    worktreeRoot: action.worktreeRoot,
    home: options.pathCtx.home,
    depth: 0,
  });

  pipelines = layerResult.pipelines;
  commands = layerResult.commands;
  effects.push(...layerResult.effects);
  opaqueReasons.push(...layerResult.opaque);

  const registry = options.registry ?? getDefaultSafeChainsRegistry();

  for (const cmd of commands) {
    const bin = normalizeBin(cmd.name);

    // 1. Sensitive env var reads inside command
    for (const envVar of cmd.envReads) {
      if (SENSITIVE_ENV_VAR_PATTERN.test(envVar)) {
        touchedSecret = true;
        effects.push({
          tag: "read_secret",
          layer: cmd.depth,
          target: `$${envVar}`,
          detail: "sensitive_env_expansion",
        });
      }
    }

    // 2. File redirections (write / read)
    for (const redir of cmd.redirections) {
      if (redir.target === "/dev/null") continue;
      const p = classifyPosixPath(redir.target, options.pathCtx);
      if (redir.isWrite) {
        if (p.isProtected) {
          effects.push({
            tag: "write_protected",
            layer: cmd.depth,
            target: p.realPath,
            pluginSelf: p.isPluginSelf,
            detail: `redirection:${redir.operator}`,
          });
        } else if (p.inWorktree) {
          effects.push({
            tag: "write_worktree",
            layer: cmd.depth,
            target: p.realPath,
            detail: `redirection:${redir.operator}`,
          });
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
        touchedSecret = true;
        effects.push({
          tag: "read_secret",
          layer: cmd.depth,
          target: p.realPath,
          detail: `redirection:${redir.operator}`,
        });
      }
    }

    // 3. Dedicated high-risk command classifications
    if (SYSTEM_DESTRUCTIVE_COMMANDS.has(bin)) {
      effects.push({
        tag: "system_destructive",
        layer: cmd.depth,
        target: cmd.rawText,
        reversibility: "irreversible",
      });
      continue;
    }

    if (bin === "env" || bin === "printenv") {
      if (cmd.argv.length === 0 || cmd.argv.some((a) => SENSITIVE_ENV_VAR_PATTERN.test(a))) {
        touchedSecret = true;
        effects.push({
          tag: "read_secret",
          layer: cmd.depth,
          target: bin,
          detail: "env_dump_or_secret_read",
        });
      } else {
        effects.push({ tag: "read", layer: cmd.depth, target: bin });
      }
      continue;
    }

    if (bin === "rm") {
      effects.push(...classifyRmCommand(cmd, options.pathCtx));
      continue;
    }

    if (bin === "curl" || bin === "wget") {
      const url = extractUrlFromArgv(cmd.argv);
      const trusted = url ? isUrlTrusted(url, trustedDomains) : false;
      const egress = bin === "curl" ? isCurlEgress(cmd.argv) : cmd.argv.some((a) => a.startsWith("--post"));
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
      // Also sweep curl/wget file arguments (@file, -o, -O, -d @file)
      for (const arg of cmd.argv) {
        const candidate = arg.startsWith("@") ? arg.slice(1) : arg;
        if (candidate && candidate !== "-" && !candidate.startsWith("-") && !/^https?:\/\//i.test(candidate)) {
          const p = classifyPosixPath(candidate, options.pathCtx);
          if (p.isSensitive) {
            touchedSecret = true;
            effects.push({ tag: "read_secret", layer: cmd.depth, target: p.realPath });
          }
        }
      }
      continue;
    }

    if (bin === "git") {
      const sub = cmd.argv.find((a) => !a.startsWith("-"));
      if (sub === "push" || sub === "fetch" || sub === "pull" || sub === "remote") {
        if (sub === "push") {
          const isForce = cmd.argv.some((a) => a === "-f" || a === "--force" || a === "--force-with-lease");
          effects.push({
            tag: "vcs_remote",
            layer: cmd.depth,
            target: cmd.rawText,
            reversibility: isForce ? "irreversible" : "reversible",
            detail: isForce ? "git_push_force" : "git_push",
          });
          continue;
        }
      }
    }

    if (
      (bin === "npm" || bin === "pnpm" || bin === "yarn") &&
      cmd.argv.some((a) => a === "install" || a === "i" || a === "add")
    ) {
      effects.push({ tag: "pkg_install", layer: cmd.depth, target: cmd.rawText });
      continue;
    }

    if ((bin === "pip" || bin === "pip3") && cmd.argv[0] === "install") {
      effects.push({ tag: "pkg_install", layer: cmd.depth, target: cmd.rawText });
      continue;
    }

    if (INFRA_MUTATE_COMMANDS.has(bin)) {
      const sub = cmd.argv[0]?.toLowerCase() ?? "";
      if (["get", "describe", "logs", "plan", "show", "list", "version"].includes(sub)) {
        effects.push({ tag: "infra_read", layer: cmd.depth, target: cmd.rawText });
      } else {
        effects.push({ tag: "infra_mutate", layer: cmd.depth, target: cmd.rawText });
      }
      continue;
    }

    if (bin === "chmod" || bin === "chown") {
      effects.push({ tag: "privilege", layer: cmd.depth, target: cmd.rawText });
      continue;
    }

    // 4. safe-chains declarative registry lookup + mandatory path sweep (ADR-0004)
    const match = registry.match(cmd.name, cmd.argv, options.pathCtx);
    if (match.matched && match.level) {
      let blockedByPathSweep = false;

      for (const swept of match.sweptPaths) {
        if (swept.isSensitive) {
          touchedSecret = true;
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
          // Targeted provenance check (ADR-0002):
          // Only upgrade exec_project -> exec_inline when build/task entrypoints were modified
          // (or when directly executing a modified script). Ordinary source edits do not trigger this.
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

    // Check if directly executing a modified local script (e.g. ./scripts/deploy.sh)
    if (cmd.name.startsWith("./") || cmd.name.startsWith("/") || cmd.name.includes("/")) {
      const scriptPath = classifyPosixPath(cmd.name, options.pathCtx);
      if (options.session?.modifiedFiles.has(scriptPath.realPath)) {
        effects.push({
          tag: "exec_inline",
          layer: cmd.depth,
          target: scriptPath.realPath,
          detail: "provenance_modified_script",
        });
        continue;
      }
    }

    // 5. Unknown command -> opaque (never auto-allow)
    const reason = match.reason ?? `unknown_command:${bin}`;
    opaqueReasons.push(reason);
    effects.push({ tag: "opaque", layer: cmd.depth, target: bin, detail: reason });
  }

  return {
    effects,
    opaqueReasons: Array.from(new Set(opaqueReasons)),
    pipelines,
    commands,
    touchedSecret,
    touchedUntrusted,
  };
}

export function hasNetReadPipedToInterpreter(pipelines: PipelineFact[]): boolean {
  const netReaders = new Set(["curl", "wget", "fetch"]);
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
