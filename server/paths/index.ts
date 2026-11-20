import { realpathSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, posix, resolve } from "node:path";

export interface PathContext {
  cwd: string;
  worktreeRoot?: string;
  home?: string;
  pluginDataDir?: string;
  extraSensitivePatterns?: string[];
  extraProtectedPatterns?: string[];
}

export interface PathClassification {
  raw: string;
  normalized: string;
  realPath: string;
  inWorktree: boolean;
  isTemp: boolean;
  isSensitive: boolean;
  isProtected: boolean;
  isPluginSelf: boolean;
  matchedRules: string[];
}

const HOME_SENSITIVE_SUBPATHS = [
  ".ssh",
  ".aws",
  ".azure",
  ".kube",
  ".config/gcloud",
  ".docker/config.json",
  ".npmrc",
  ".pypirc",
  ".netrc",
  ".git-credentials",
  ".gnupg",
];

const SYSTEM_SENSITIVE_PATHS = ["/etc/shadow", "/etc/sudoers", "/etc/master.passwd"];

const HOME_PROTECTED_SUBPATHS = [
  ".bashrc",
  ".bash_profile",
  ".zshrc",
  ".zprofile",
  ".zshenv",
  ".profile",
  ".npmrc",
  ".pip/pip.conf",
  ".claude",
  ".devin",
  ".codex",
  ".cursor",
  ".paseo/permission-guardian",
];

const REPO_PROTECTED_PREFIXES = [
  ".git",
  ".claude",
  ".devin",
  ".codex",
  ".cursor",
  ".github/workflows",
];

const SENSITIVE_BASENAME_PATTERNS: readonly RegExp[] = [
  /^\.env(?:\..+)?$/i,
  /^id_(?:rsa|dsa|ecdsa|ed25519)(?:\..+)?$/i,
  /\.(?:pem|pfx|p12|key|jks|keystore)$/i,
  /^\.git-credentials$/i,
  /^\.netrc$/i,
  /^\.npmrc$/i,
  /^\.pypirc$/i,
];

const ENTRYPOINT_BASENAMES = new Set([
  "package.json",
  "makefile",
  "gnumakefile",
  "pyproject.toml",
  "cargo.toml",
  "go.mod",
  "vitest.config.ts",
  "vitest.config.js",
  "vitest.config.mjs",
  "jest.config.ts",
  "jest.config.js",
  "jest.config.mjs",
  "pytest.ini",
  "setup.py",
  "setup.cfg",
  "justfile",
  "taskfile.yml",
  "taskfile.yaml",
]);

/**
 * Resolve the real path of an existing file/directory, or walk up to the nearest
 * existing ancestor, resolve its realpath, and re-append the remaining segments.
 * Prevents symlinked parent directories from escaping worktree checks (ADR-0004).
 */
export function resolveAncestorRealPath(absolutePath: string): string {
  const normalized = resolve(absolutePath);
  const trailingSegments: string[] = [];
  let current = normalized;

  while (true) {
    try {
      const resolvedAncestor = realpathSync.native(current);
      if (trailingSegments.length === 0) {
        return resolvedAncestor;
      }
      return join(resolvedAncestor, ...trailingSegments.reverse());
    } catch {
      const parent = dirname(current);
      if (parent === current) {
        return normalized;
      }
      trailingSegments.push(basename(current));
      current = parent;
    }
  }
}

export function expandPosixPath(rawPath: string, cwd: string, home: string): string {
  let expanded = rawPath.trim();
  if (expanded === "~") {
    expanded = home;
  } else if (expanded.startsWith("~/")) {
    expanded = join(home, expanded.slice(2));
  } else if (expanded.startsWith("$HOME/")) {
    expanded = join(home, expanded.slice("$HOME/".length));
  } else if (expanded === "$HOME" || expanded === "${HOME}") {
    expanded = home;
  } else if (expanded.startsWith("${HOME}/")) {
    expanded = join(home, expanded.slice("${HOME}/".length));
  }

  return isAbsolute(expanded) ? resolve(expanded) : resolve(cwd, expanded);
}

function isPathUnder(candidate: string, root: string): boolean {
  const normCandidate = candidate.replace(/\/+$/, "") || "/";
  const normRoot = root.replace(/\/+$/, "") || "/";
  if (normRoot === "/") {
    return true;
  }
  return normCandidate === normRoot || normCandidate.startsWith(`${normRoot}/`);
}

function hasPathSegment(candidate: string, segment: string): boolean {
  const parts = candidate.split("/").filter(Boolean);
  return parts.includes(segment);
}

function toPosixSlash(value: string): string {
  return value.replaceAll("\\", "/");
}

function matchSimpleGlob(candidate: string, pattern: string): boolean {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "§GLOBSTAR§")
    .replace(/\*/g, "[^/]*")
    .replace(/§GLOBSTAR§/g, ".*");
  const regex = new RegExp(`^${escaped}$`);
  return regex.test(candidate);
}

export function isBuildOrScriptEntrypoint(filePath: string, worktreeRoot?: string): boolean {
  const norm = toPosixSlash(filePath);
  const base = posix.basename(norm).toLowerCase();
  if (ENTRYPOINT_BASENAMES.has(base)) {
    return true;
  }

  let rel = norm;
  if (worktreeRoot) {
    const normRoot = toPosixSlash(worktreeRoot).replace(/\/+$/, "");
    if (norm.startsWith(`${normRoot}/`)) {
      rel = norm.slice(normRoot.length + 1);
    }
  }
  const relLower = rel.toLowerCase();
  if (relLower.startsWith("scripts/") || relLower.includes("/scripts/")) {
    return true;
  }
  if (relLower.startsWith(".github/workflows/")) {
    return true;
  }
  return false;
}

export function classifyPosixPath(rawPath: string, ctx: PathContext): PathClassification {
  const home = ctx.home ?? homedir();
  const realHome = resolveAncestorRealPath(home);
  const normalized = expandPosixPath(rawPath, ctx.cwd, home);
  const realPath = resolveAncestorRealPath(normalized);

  const worktreeBase = ctx.worktreeRoot ?? ctx.cwd;
  const realWorktree = resolveAncestorRealPath(worktreeBase);
  const inWorktree = isPathUnder(realPath, realWorktree);

  const tempRoots = Array.from(
    new Set([
      "/tmp",
      "/private/tmp",
      "/var/tmp",
      "/private/var/tmp",
      resolveAncestorRealPath(tmpdir()),
    ]),
  );
  const isTemp = tempRoots.some((root) => isPathUnder(realPath, root));

  const matchedRules: string[] = [];
  let isSensitive = false;
  let isProtected = false;
  let isPluginSelf = false;

  // Sensitive paths check (evaluated on both normalized and realPath)
  const candidates = Array.from(new Set([normalized, realPath]));
  const base = basename(realPath);

  for (const candidate of candidates) {
    for (const sub of HOME_SENSITIVE_SUBPATHS) {
      if (isPathUnder(candidate, join(home, sub)) || isPathUnder(candidate, join(realHome, sub))) {
        isSensitive = true;
        matchedRules.push(`sensitive:home:${sub}`);
      }
    }
    for (const sysPath of SYSTEM_SENSITIVE_PATHS) {
      if (isPathUnder(candidate, sysPath)) {
        isSensitive = true;
        matchedRules.push(`sensitive:system:${sysPath}`);
      }
    }
  }

  for (const rx of SENSITIVE_BASENAME_PATTERNS) {
    if (rx.test(base)) {
      isSensitive = true;
      matchedRules.push(`sensitive:basename:${base}`);
      break;
    }
  }

  // Protected paths check
  const pluginDir = ctx.pluginDataDir ?? join(home, ".paseo", "permission-guardian");
  const realPluginDir = resolveAncestorRealPath(pluginDir);
  if (isPathUnder(realPath, realPluginDir) || isPathUnder(normalized, pluginDir)) {
    isProtected = true;
    isPluginSelf = true;
    matchedRules.push("protected:plugin_self");
  }

  for (const candidate of candidates) {
    for (const sub of HOME_PROTECTED_SUBPATHS) {
      if (isPathUnder(candidate, join(home, sub)) || isPathUnder(candidate, join(realHome, sub))) {
        isProtected = true;
        if (sub === ".paseo/permission-guardian") {
          isPluginSelf = true;
        }
        matchedRules.push(`protected:home:${sub}`);
      }
    }

    // Protect .git/ anywhere (ADR-0004: entire .git/ directory)
    if (hasPathSegment(candidate, ".git")) {
      isProtected = true;
      matchedRules.push("protected:.git");
    }

    // Protect agent configs and CI workflows inside worktree or anywhere
    for (const prefix of REPO_PROTECTED_PREFIXES) {
      if (
        isPathUnder(candidate, join(realWorktree, prefix)) ||
        isPathUnder(candidate, join(worktreeBase, prefix))
      ) {
        isProtected = true;
        matchedRules.push(`protected:repo:${prefix}`);
      }
    }
  }

  // Policy extra patterns
  for (const pat of ctx.extraSensitivePatterns ?? []) {
    const expandedPat = expandPosixPath(pat, worktreeBase, home);
    if (matchSimpleGlob(realPath, expandedPat) || matchSimpleGlob(normalized, expandedPat)) {
      isSensitive = true;
      matchedRules.push(`sensitive:policy:${pat}`);
    }
  }

  for (const pat of ctx.extraProtectedPatterns ?? []) {
    const expandedPat = expandPosixPath(pat, worktreeBase, home);
    if (matchSimpleGlob(realPath, expandedPat) || matchSimpleGlob(normalized, expandedPat)) {
      isProtected = true;
      matchedRules.push(`protected:policy:${pat}`);
    }
  }

  return {
    raw: rawPath,
    normalized,
    realPath,
    inWorktree,
    isTemp,
    isSensitive,
    isProtected,
    isPluginSelf,
    matchedRules: Array.from(new Set(matchedRules)),
  };
}
