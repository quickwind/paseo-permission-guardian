import { basename } from "node:path";
import { parse as parseToml } from "smol-toml";
import { classifyPath, type PathClassification, type PathContext } from "../../paths/index.js";
import { BUILTINS_TOML } from "./builtins.js";

export type SafeChainsLevel = "Inert" | "SafeRead" | "SafeWrite" | "ExecProject";

export interface CommandRule {
  name: string;
  aliases?: string[];
  level?: SafeChainsLevel;
  bare?: boolean;
  bare_flags?: string[];
  standalone?: string[];
  valued?: string[];
  max_positional?: number;
  first_arg?: string[];
  require_any?: string[];
  write_flags?: string[];
  allow_all?: boolean;
  deny?: string[];
  tolerate_unknown_flags?: boolean;
  tolerate_unknown_subcommands?: boolean;
  sub?: CommandRule[];
}

export interface RegistryMatchResult {
  matched: boolean;
  commandName: string;
  matchedRulePath: string[];
  level?: SafeChainsLevel;
  reason?: string;
  sweptPaths: PathClassification[];
  dynamicPaths: string[];
}

const PATH_LIKE_FLAGS = new Set([
  "-f",
  "--file",
  "-C",
  "--config",
  "-c",
  "-i",
  "--input",
  "-o",
  "--output",
  "-d",
  "--dir",
  "--directory",
  "-p",
  "--path",
  "--cwd",
  "--prefix",
]);

function normalizeCommandName(raw: string): string {
  const base = basename(raw).toLowerCase();
  return base.replace(/\.(?:exe|cmd|bat)$/, "");
}

function looksLikePathCandidate(token: string): boolean {
  if (!token || token === "-" || token === "--") return false;
  if (token.startsWith("http://") || token.startsWith("https://")) return false;
  if (
    token.startsWith("/") ||
    token.startsWith("./") ||
    token.startsWith("../") ||
    token.startsWith("~/") ||
    token === "~" ||
    token.startsWith("$HOME") ||
    token.startsWith("${HOME}") ||
    token.includes("/") ||
    token.startsWith(".") ||
    /\.(?:env|pem|key|pfx|p12|json|yaml|yml|toml|sh|py|ts|js|conf|cfg|ini|txt)$/i.test(token)
  ) {
    return true;
  }
  return false;
}

const FILE_POSITIONAL_COMMANDS = new Set([
  "ls",
  "cat",
  "head",
  "tail",
  "wc",
  "stat",
  "file",
  "diff",
  "find",
  "mkdir",
  "touch",
  "cp",
  "mv",
  "tee",
]);

const PATTERN_FIRST_FILE_REST_COMMANDS = new Set(["grep", "egrep", "fgrep", "rg", "jq"]);

const GIT_FILE_SUBCOMMANDS = new Set(["add", "restore", "blame", "ls-files", "diff"]);
const GIT_REV_PATH_SUBCOMMANDS = new Set([
  "show",
  "cat-file",
  "rev-parse",
  "log",
  "diff",
  "blame",
]);

export class SafeChainsRegistry {
  private readonly rulesByName = new Map<string, CommandRule>();

  constructor(rules: CommandRule[]) {
    for (const rule of rules) {
      this.registerRule(rule);
    }
  }

  static fromToml(tomlSources: string[]): SafeChainsRegistry {
    const allRules: CommandRule[] = [];
    for (const source of tomlSources) {
      const parsed = parseToml(source) as { commands?: CommandRule[] };
      if (Array.isArray(parsed.commands)) {
        allRules.push(...parsed.commands);
      }
    }
    return new SafeChainsRegistry(allRules);
  }

  private registerRule(rule: CommandRule): void {
    const primary = normalizeCommandName(rule.name);
    this.rulesByName.set(primary, rule);
    for (const alias of rule.aliases ?? []) {
      this.rulesByName.set(normalizeCommandName(alias), rule);
    }
  }

  match(
    rawCommandName: string,
    argv: string[],
    pathCtx: PathContext,
    argvDynamic?: boolean[],
  ): RegistryMatchResult {
    const commandName = normalizeCommandName(rawCommandName);
    const rootRule = this.rulesByName.get(commandName);
    if (!rootRule) {
      return {
        matched: false,
        commandName,
        matchedRulePath: [],
        reason: `unknown_command:${commandName}`,
        sweptPaths: [],
        dynamicPaths: [],
      };
    }

    const evalResult = this.evaluateRule(rootRule, argv, [commandName], rootRule.level, 0);
    if (!evalResult.matched) {
      return {
        matched: false,
        commandName,
        matchedRulePath: evalResult.rulePath,
        reason: evalResult.reason,
        sweptPaths: [],
        dynamicPaths: [],
      };
    }

    // Mandatory path sweep (ADR-0004): every matched command has positional & path-like flag values checked
    const sweep = this.sweepArgumentsForPaths(
      argv,
      pathCtx,
      evalResult.rulePath,
      evalResult.level,
      evalResult.leafPositionals,
      evalResult.hasExplicitPatternFlag,
      argvDynamic,
    );

    return {
      matched: true,
      commandName,
      matchedRulePath: evalResult.rulePath,
      level: evalResult.level,
      sweptPaths: sweep.sweptPaths,
      dynamicPaths: sweep.dynamicPaths,
    };
  }

  private evaluateRule(
    rule: CommandRule,
    argv: string[],
    rulePath: string[],
    inheritedLevel?: SafeChainsLevel,
    argvOffset = 0,
  ): {
    matched: boolean;
    level?: SafeChainsLevel;
    rulePath: string[];
    reason?: string;
    leafPositionals?: Array<{ value: string; index: number }>;
    hasExplicitPatternFlag?: boolean;
  } {
    const effectiveLevel = rule.level ?? inheritedLevel;
    const denySet = new Set(rule.deny ?? []);
    const bareFlags = new Set(rule.bare_flags ?? []);
    const valuedFlags = new Set(rule.valued ?? []);
    const writeFlags = new Set(rule.write_flags ?? []);
    const standaloneSet = new Set(rule.standalone ?? []);

    // Check top-level deny flags before subcommand dispatch
    for (const token of argv) {
      if (token === "--") break;
      const flagName = token.includes("=") ? token.slice(0, token.indexOf("=")) : token;
      if (denySet.has(flagName)) {
        return { matched: false, rulePath, reason: `denied_flag:${flagName}` };
      }
    }

    // If rule defines subcommands, consume leading known flags on the parent rule then dispatch
    if (rule.sub && rule.sub.length > 0) {
      let i = 0;
      while (i < argv.length) {
        const token = argv[i];
        if (!token.startsWith("-")) break;
        const flagName = token.includes("=") ? token.slice(0, token.indexOf("=")) : token;
        if (valuedFlags.has(flagName)) {
          i += token.includes("=") ? 1 : 2;
          continue;
        }
        if (bareFlags.has(flagName)) {
          i += 1;
          continue;
        }
        return { matched: false, rulePath, reason: `unknown_parent_flag:${flagName}` };
      }

      const subToken = argv[i];
      if (!subToken) {
        if (rule.bare) {
          return { matched: true, level: effectiveLevel, rulePath, leafPositionals: [] };
        }
        return { matched: false, rulePath, reason: "missing_subcommand" };
      }

      const subRule = rule.sub.find(
        (s) => s.name === subToken || (s.aliases ?? []).includes(subToken),
      );
      if (!subRule) {
        if (rule.tolerate_unknown_subcommands) {
          return {
            matched: true,
            level: effectiveLevel,
            rulePath,
            leafPositionals: argv.slice(i).map((value, idx) => ({ value, index: argvOffset + i + idx })),
          };
        }
        return { matched: false, rulePath, reason: `unknown_subcommand:${subToken}` };
      }

      return this.evaluateRule(
        subRule,
        argv.slice(i + 1),
        [...rulePath, subRule.name],
        effectiveLevel,
        argvOffset + i + 1,
      );
    }

    if (rule.allow_all) {
      const leafPositionals: Array<{ value: string; index: number }> = [];
      let afterDash = false;
      for (let idx = 0; idx < argv.length; idx++) {
        const tok = argv[idx];
        if (!afterDash && tok === "--") {
          afterDash = true;
          continue;
        }
        if (!afterDash && tok.startsWith("-") && tok.length > 1) continue;
        leafPositionals.push({ value: tok, index: argvOffset + idx });
      }
      return { matched: true, level: effectiveLevel, rulePath, leafPositionals };
    }

    if (argv.length === 0) {
      if (rule.bare || (rule.max_positional === undefined && !rule.first_arg && !rule.require_any)) {
        return { matched: true, level: effectiveLevel, rulePath, leafPositionals: [] };
      }
      return { matched: false, rulePath, reason: "bare_invocation_not_allowed" };
    }

    let positionalCount = 0;
    let firstPositional: string | undefined;
    let afterDoubleDash = false;
    let sawWriteFlag = false;
    let hasExplicitPatternFlag = false;
    const seenFlags = new Set<string>();
    const leafPositionals: Array<{ value: string; index: number }> = [];

    for (let i = 0; i < argv.length; i++) {
      const token = argv[i];

      if (!afterDoubleDash && token === "--") {
        afterDoubleDash = true;
        continue;
      }

      if (!afterDoubleDash && token.startsWith("-") && token.length > 1) {
        const eqIdx = token.indexOf("=");
        const flagName = eqIdx > 0 ? token.slice(0, eqIdx) : token;

        if (denySet.has(flagName)) {
          return { matched: false, rulePath, reason: `denied_flag:${flagName}` };
        }

        if (standaloneSet.has(flagName) && argv.length === 1) {
          return { matched: true, level: effectiveLevel, rulePath, leafPositionals: [] };
        }

        if (writeFlags.has(flagName)) {
          sawWriteFlag = true;
          seenFlags.add(flagName);
          continue;
        }

        if (valuedFlags.has(flagName)) {
          seenFlags.add(flagName);
          if (flagName === "-e" || flagName === "-f") {
            hasExplicitPatternFlag = true;
          }
          if (eqIdx < 0) {
            i += 1; // consume value
          }
          continue;
        }

        if (bareFlags.has(flagName)) {
          seenFlags.add(flagName);
          continue;
        }

        // Combined short flags like -la, -rn
        if (/^-[a-zA-Z]{2,}$/.test(token)) {
          const chars = token.slice(1).split("");
          const allKnownBare = chars.every((ch) => bareFlags.has(`-${ch}`));
          const anyDenied = chars.some((ch) => denySet.has(`-${ch}`));
          if (anyDenied) {
            return { matched: false, rulePath, reason: `denied_combined_flag:${token}` };
          }
          if (allKnownBare) {
            for (const ch of chars) seenFlags.add(`-${ch}`);
            continue;
          }
        }

        if (!rule.tolerate_unknown_flags) {
          return { matched: false, rulePath, reason: `unknown_flag:${flagName}` };
        }
        continue;
      }

      positionalCount += 1;
      leafPositionals.push({ value: token, index: argvOffset + i });
      if (firstPositional === undefined) {
        firstPositional = token;
      }
    }

    if (rule.first_arg && rule.first_arg.length > 0) {
      if (!firstPositional || !rule.first_arg.includes(firstPositional)) {
        return {
          matched: false,
          rulePath,
          reason: `disallowed_first_arg:${firstPositional ?? "<none>"}`,
        };
      }
    }

    if (rule.require_any && rule.require_any.length > 0) {
      const satisfied = rule.require_any.some((f) => seenFlags.has(f));
      if (!satisfied) {
        return { matched: false, rulePath, reason: "missing_required_flag" };
      }
    }

    if (rule.max_positional !== undefined && positionalCount > rule.max_positional) {
      return {
        matched: false,
        rulePath,
        reason: `too_many_positionals:${positionalCount}>${rule.max_positional}`,
      };
    }

    const finalLevel: SafeChainsLevel | undefined =
      sawWriteFlag && effectiveLevel === "SafeRead" ? "SafeWrite" : effectiveLevel;

    return {
      matched: true,
      level: finalLevel,
      rulePath,
      leafPositionals,
      hasExplicitPatternFlag,
    };
  }

  private sweepArgumentsForPaths(
    argv: string[],
    pathCtx: PathContext,
    rulePath: string[],
    level?: SafeChainsLevel,
    leafPositionals: Array<{ value: string; index: number }> = [],
    hasExplicitPatternFlag = false,
    argvDynamic?: boolean[],
  ): { sweptPaths: PathClassification[]; dynamicPaths: string[] } {
    const results: PathClassification[] = [];
    const dynamicPaths: string[] = [];
    const seen = new Set<string>();
    const seenDyn = new Set<string>();
    let afterDoubleDash = false;
    const rootCmd = rulePath[0] ?? "";
    const subCmd = rulePath[1];

    const unwrapGitRevPath = (candidate: string): { path: string; fromGitRev: boolean } => {
      if (rootCmd === "git" && subCmd && GIT_REV_PATH_SUBCOMMANDS.has(subCmd)) {
        const revMatch = candidate.match(/^([^\\/]*):([^:].*)$/);
        if (
          revMatch &&
          !/^[A-Za-z]$/.test(revMatch[1]) &&
          !/\$(?:INDEX_ALLOCATION|DATA)|Zone\.Identifier/i.test(revMatch[2])
        ) {
          let extractedPath = revMatch[2];
          if (revMatch[1] === "") {
            const stageMatch = extractedPath.match(/^[0-3]:(.+)$/);
            if (stageMatch) extractedPath = stageMatch[1];
          }
          return { path: extractedPath, fromGitRev: true };
        }
      }
      return { path: candidate, fromGitRev: false };
    };

    const inspect = (candidate: string, forcePathCheck = false, isDynamic = false) => {
      if (!candidate || candidate === "-" || candidate === "--") return;
      if (candidate.startsWith("http://") || candidate.startsWith("https://")) return;

      const unwrapped = unwrapGitRevPath(candidate);
      const resolvedCandidate = unwrapped.path;
      const effectiveForce = forcePathCheck || unwrapped.fromGitRev;
      if (
        isDynamic &&
        (effectiveForce ||
          level === "SafeWrite" ||
          (level !== "Inert" && looksLikePathCandidate(resolvedCandidate)))
      ) {
        if (!seenDyn.has(candidate)) {
          seenDyn.add(candidate);
          dynamicPaths.push(candidate);
        }
        return;
      }

      if (seen.has(resolvedCandidate)) return;
      if (effectiveForce || looksLikePathCandidate(resolvedCandidate)) {
        seen.add(resolvedCandidate);
        results.push(classifyPath(resolvedCandidate, pathCtx));
      }
    };

    // For filesystem SafeRead / SafeWrite commands, also sweep bare positional filenames
    // (such as `cat id_rsa` after `cd ~/.ssh` or `cat foo` after uncertain cwd).
    if (level === "SafeRead" || level === "SafeWrite") {
      if (FILE_POSITIONAL_COMMANDS.has(rootCmd)) {
        for (const pos of leafPositionals) {
          if (rootCmd === "find" && (pos.value === "!" || pos.value === "(" || pos.value === ")")) {
            continue;
          }
          inspect(pos.value, true, Boolean(argvDynamic?.[pos.index]));
        }
      } else if (PATTERN_FIRST_FILE_REST_COMMANDS.has(rootCmd)) {
        const startIdx = hasExplicitPatternFlag ? 0 : 1;
        for (const pos of leafPositionals.slice(startIdx)) {
          inspect(pos.value, true, Boolean(argvDynamic?.[pos.index]));
        }
      } else if (rootCmd === "git" && subCmd && GIT_FILE_SUBCOMMANDS.has(subCmd)) {
        for (const pos of leafPositionals) {
          inspect(pos.value, true, Boolean(argvDynamic?.[pos.index]));
        }
      }
    }

    for (let i = 0; i < argv.length; i++) {
      const token = argv[i];
      if (!afterDoubleDash && token === "--") {
        afterDoubleDash = true;
        continue;
      }

      if (!afterDoubleDash && token.startsWith("-") && !argvDynamic?.[i]) {
        const eqIdx = token.indexOf("=");
        if (eqIdx > 0) {
          const flag = token.slice(0, eqIdx);
          const val = token.slice(eqIdx + 1);
          if (PATH_LIKE_FLAGS.has(flag) || looksLikePathCandidate(val)) {
            inspect(val, PATH_LIKE_FLAGS.has(flag), Boolean(argvDynamic?.[i]));
          }
        } else if (PATH_LIKE_FLAGS.has(token) && i + 1 < argv.length) {
          inspect(argv[i + 1], true, Boolean(argvDynamic?.[i + 1]));
          i += 1;
        }
        continue;
      }

      inspect(token, false, Boolean(argvDynamic?.[i]));
    }

    return { sweptPaths: results, dynamicPaths };
  }
}

let defaultRegistryInstance: SafeChainsRegistry | null = null;

export function getDefaultSafeChainsRegistry(): SafeChainsRegistry {
  if (!defaultRegistryInstance) {
    defaultRegistryInstance = SafeChainsRegistry.fromToml([BUILTINS_TOML]);
  }
  return defaultRegistryInstance;
}
