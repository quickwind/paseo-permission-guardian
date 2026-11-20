import { basename } from "node:path";
import { parse as parseToml } from "smol-toml";
import { classifyPosixPath, type PathClassification, type PathContext } from "../../paths/index.js";
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

  match(rawCommandName: string, argv: string[], pathCtx: PathContext): RegistryMatchResult {
    const commandName = normalizeCommandName(rawCommandName);
    const rootRule = this.rulesByName.get(commandName);
    if (!rootRule) {
      return {
        matched: false,
        commandName,
        matchedRulePath: [],
        reason: `unknown_command:${commandName}`,
        sweptPaths: [],
      };
    }

    const evalResult = this.evaluateRule(rootRule, argv, [commandName], rootRule.level);
    if (!evalResult.matched) {
      return {
        matched: false,
        commandName,
        matchedRulePath: evalResult.rulePath,
        reason: evalResult.reason,
        sweptPaths: [],
      };
    }

    // Mandatory path sweep (ADR-0004): every matched command has positional & path-like flag values checked
    const sweptPaths = this.sweepArgumentsForPaths(argv, pathCtx);

    return {
      matched: true,
      commandName,
      matchedRulePath: evalResult.rulePath,
      level: evalResult.level,
      sweptPaths,
    };
  }

  private evaluateRule(
    rule: CommandRule,
    argv: string[],
    rulePath: string[],
    inheritedLevel?: SafeChainsLevel,
  ): { matched: boolean; level?: SafeChainsLevel; rulePath: string[]; reason?: string } {
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
          return { matched: true, level: effectiveLevel, rulePath };
        }
        return { matched: false, rulePath, reason: "missing_subcommand" };
      }

      const subRule = rule.sub.find(
        (s) => s.name === subToken || (s.aliases ?? []).includes(subToken),
      );
      if (!subRule) {
        if (rule.tolerate_unknown_subcommands) {
          return { matched: true, level: effectiveLevel, rulePath };
        }
        return { matched: false, rulePath, reason: `unknown_subcommand:${subToken}` };
      }

      return this.evaluateRule(
        subRule,
        argv.slice(i + 1),
        [...rulePath, subRule.name],
        effectiveLevel,
      );
    }

    if (rule.allow_all) {
      return { matched: true, level: effectiveLevel, rulePath };
    }

    if (argv.length === 0) {
      if (rule.bare || (rule.max_positional === undefined && !rule.first_arg && !rule.require_any)) {
        return { matched: true, level: effectiveLevel, rulePath };
      }
      return { matched: false, rulePath, reason: "bare_invocation_not_allowed" };
    }

    let positionalCount = 0;
    let firstPositional: string | undefined;
    let afterDoubleDash = false;
    let sawWriteFlag = false;
    const seenFlags = new Set<string>();

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
          return { matched: true, level: effectiveLevel, rulePath };
        }

        if (writeFlags.has(flagName)) {
          sawWriteFlag = true;
          seenFlags.add(flagName);
          continue;
        }

        if (valuedFlags.has(flagName)) {
          seenFlags.add(flagName);
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

    return { matched: true, level: finalLevel, rulePath };
  }

  private sweepArgumentsForPaths(argv: string[], pathCtx: PathContext): PathClassification[] {
    const results: PathClassification[] = [];
    const seen = new Set<string>();
    let afterDoubleDash = false;

    const inspect = (candidate: string) => {
      if (seen.has(candidate)) return;
      seen.add(candidate);
      if (looksLikePathCandidate(candidate)) {
        results.push(classifyPosixPath(candidate, pathCtx));
      }
    };

    for (let i = 0; i < argv.length; i++) {
      const token = argv[i];
      if (!afterDoubleDash && token === "--") {
        afterDoubleDash = true;
        continue;
      }

      if (!afterDoubleDash && token.startsWith("-")) {
        const eqIdx = token.indexOf("=");
        if (eqIdx > 0) {
          const flag = token.slice(0, eqIdx);
          const val = token.slice(eqIdx + 1);
          if (PATH_LIKE_FLAGS.has(flag) || looksLikePathCandidate(val)) {
            inspect(val);
          }
        } else if (PATH_LIKE_FLAGS.has(token) && i + 1 < argv.length) {
          inspect(argv[i + 1]);
          i += 1;
        }
        continue;
      }

      inspect(token);
    }

    return results;
  }
}

let defaultRegistryInstance: SafeChainsRegistry | null = null;

export function getDefaultSafeChainsRegistry(): SafeChainsRegistry {
  if (!defaultRegistryInstance) {
    defaultRegistryInstance = SafeChainsRegistry.fromToml([BUILTINS_TOML]);
  }
  return defaultRegistryInstance;
}
