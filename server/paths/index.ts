import { realpathSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, posix, resolve } from "node:path";
import {
  classifyWindowsPath,
  mapMsysToWindowsPath,
  mapWindowsToWslPath,
  mapWslToWindowsPath,
  stripProviderDrive,
  type WindowsPathClassification,
  type WindowsPathContext,
} from "./windows.js";

export {
  classifyWindowsPath,
  mapMsysToWindowsPath,
  mapWindowsToWslPath,
  mapWslToWindowsPath,
  stripProviderDrive,
  type WindowsPathClassification,
  type WindowsPathContext,
};

export interface PathContext {
  cwd: string;
  worktreeRoot?: string;
  home?: string;
  pluginDataDir?: string;
  extraSensitivePatterns?: string[];
  extraProtectedPatterns?: string[];
  skipHostRealpath?: boolean;
  /** Extra plugin-self roots (already resolved); see resolvePaseoSelfRoots. */
  paseoRoots?: string[];
  envSnapshot?: Record<string, string | undefined>;
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
  "build.rs",
  "conftest.py",
  "noxfile.py",
  "tox.ini",
  "build.gradle",
  "build.gradle.kts",
  "settings.gradle",
  "settings.gradle.kts",
  "pom.xml",
  "cmakelists.txt",
  "meson.build",
  "rakefile",
  "gemfile",
  "composer.json",
  "deno.json",
  "deno.jsonc",
  "bunfig.toml",
  "directory.build.props",
  "directory.build.targets",
]);

/**
 * Roots whose contents belong to Paseo or this plugin (plugin-self). Only defined,
 * absolute values are returned.
 */
export function resolvePaseoSelfRoots(
  env: Record<string, string | undefined>,
  home: string,
  pluginDataDir?: string,
): string[] {
  const candidates = [
    joinAware(home, ".paseo"),
    env.PASEO_HOME,
    env.PASEO_PLUGIN_DIR,
    env.PASEO_GUARDIAN_DATA_DIR,
    pluginDataDir,
  ];
  const roots: string[] = [];
  for (const c of candidates) {
    if (!c) continue;
    const t = c.trim();
    if (t && (posix.isAbsolute(t) || isAbsolute(t))) roots.push(t);
  }
  return Array.from(new Set(roots));
}

function toPosixSlash(value: string): string {
  return value.replaceAll("\\", "/");
}

function isPosixStyleRoot(p: string): boolean {
  return p.startsWith("/") && !p.startsWith("//") && !/^[A-Za-z]:/.test(p);
}

function joinAware(base: string, ...segments: string[]): string {
  return isPosixStyleRoot(base) ? posix.join(base, ...segments) : join(base, ...segments);
}

/**
 * Resolve the real path of an existing file/directory, or walk up to the nearest
 * existing ancestor, resolve its realpath, and re-append the remaining segments.
 * Prevents symlinked parent directories from escaping worktree checks (ADR-0004).
 */
export function resolveAncestorRealPath(absolutePath: string): string {
  // Preserve virtual POSIX paths (e.g. `/repo` in cross-platform tests) on Windows hosts
  if (process.platform === "win32" && isPosixStyleRoot(absolutePath)) {
    return posix.resolve(absolutePath);
  }

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
  const cwdIsPosix = isPosixStyleRoot(cwd);
  const homeJoin = isPosixStyleRoot(home) ? posix.join : join;
  const cwdJoin = cwdIsPosix ? posix.join : join;

  let expanded = rawPath.trim();
  if (expanded === "~") {
    expanded = home;
  } else if (expanded.startsWith("~/")) {
    expanded = homeJoin(home, expanded.slice(2));
  } else if (expanded.startsWith("$HOME/")) {
    expanded = homeJoin(home, expanded.slice("$HOME/".length));
  } else if (expanded === "$HOME" || expanded === "${HOME}") {
    expanded = home;
  } else if (expanded.startsWith("${HOME}/")) {
    expanded = homeJoin(home, expanded.slice("${HOME}/".length));
  } else if (expanded === "$PWD" || expanded === "${PWD}") {
    expanded = cwd;
  } else if (expanded.startsWith("$PWD/")) {
    expanded = cwdJoin(cwd, expanded.slice("$PWD/".length));
  } else if (expanded.startsWith("${PWD}/")) {
    expanded = cwdJoin(cwd, expanded.slice("${PWD}/".length));
  }

  if (cwdIsPosix && !/^[A-Za-z]:[\\/]/.test(expanded)) {
    return posix.isAbsolute(expanded)
      ? posix.resolve(expanded)
      : posix.resolve(cwd, expanded);
  }
  return isAbsolute(expanded) ? resolve(expanded) : resolve(cwd, expanded);
}

function isPathUnder(candidate: string, root: string): boolean {
  let normCandidate = toPosixSlash(candidate).replace(/\/+$/, "") || "/";
  let normRoot = toPosixSlash(root).replace(/\/+$/, "") || "/";
  if (/^[A-Za-z]:\//.test(normCandidate) || /^[A-Za-z]:\//.test(normRoot)) {
    normCandidate = normCandidate.toLowerCase();
    normRoot = normRoot.toLowerCase();
  }
  if (normRoot === "/") {
    return isPosixStyleRoot(normCandidate);
  }
  return normCandidate === normRoot || normCandidate.startsWith(`${normRoot}/`);
}

function hasPathSegment(candidate: string, segment: string): boolean {
  const parts = toPosixSlash(candidate).split("/").filter(Boolean);
  return parts.includes(segment);
}

function matchSimpleGlob(candidate: string, pattern: string): boolean {
  const escaped = toPosixSlash(pattern)
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "§GLOBSTAR§")
    .replace(/\*/g, "[^/]*")
    .replace(/§GLOBSTAR§/g, ".*");
  const regex = new RegExp(`^${escaped}$`);
  return regex.test(toPosixSlash(candidate));
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
    if (norm.toLowerCase().startsWith(`${normRoot.toLowerCase()}/`)) {
      rel = norm.slice(normRoot.length + 1);
    }
  }
  const relLower = rel.toLowerCase();
  if (base.endsWith(".csproj") || relLower === ".cargo/config.toml" || relLower.endsWith("/.cargo/config.toml")) {
    return true;
  }
  if (relLower.startsWith("scripts/") || relLower.includes("/scripts/")) {
    return true;
  }
  if (relLower.startsWith(".github/workflows/")) {
    return true;
  }
  return false;
}

export function classifyPosixPath(rawPath: string, ctx: PathContext): PathClassification {
  const resolveReal = (p: string): string => (ctx.skipHostRealpath ? p : resolveAncestorRealPath(p));
  const home = ctx.home ?? homedir();
  const realHome = resolveReal(home);
  const paseoRoots = ctx.paseoRoots ?? resolvePaseoSelfRoots(ctx.envSnapshot ?? {}, home, ctx.pluginDataDir);
  let pathInput = rawPath;
  const varMatch = /^\$(?:\{(PASEO_HOME|PASEO_PLUGIN_DIR|PASEO_GUARDIAN_DATA_DIR)\}|(PASEO_HOME|PASEO_PLUGIN_DIR|PASEO_GUARDIAN_DATA_DIR))(?=\/|$)/.exec(
    rawPath.trim(),
  );
  if (varMatch) {
    const varName = varMatch[1] ?? varMatch[2];
    const varValue = ctx.envSnapshot?.[varName]?.trim();
    if (varValue) pathInput = varValue + rawPath.trim().slice(varMatch[0].length);
  }
  const normalized = expandPosixPath(pathInput, ctx.cwd, home);
  const realPath = resolveReal(normalized);

  const worktreeBase = ctx.worktreeRoot ?? ctx.cwd;
  const realWorktree = resolveReal(worktreeBase);
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
  const base = posix.basename(toPosixSlash(realPath));

  for (const candidate of candidates) {
    for (const sub of HOME_SENSITIVE_SUBPATHS) {
      if (
        isPathUnder(candidate, joinAware(home, sub)) ||
        isPathUnder(candidate, joinAware(realHome, sub))
      ) {
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
    if (/^\/proc\/(?:self|thread-self|\d+)\/environ$/.test(toPosixSlash(candidate))) {
      isSensitive = true;
      matchedRules.push("sensitive:system:proc_environ");
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
  const pluginDir = ctx.pluginDataDir ?? joinAware(home, ".paseo", "permission-guardian");
  const realPluginDir = resolveReal(pluginDir);
  if (isPathUnder(realPath, realPluginDir) || isPathUnder(normalized, pluginDir)) {
    isProtected = true;
    isPluginSelf = true;
    matchedRules.push("protected:plugin_self");
  }

  for (const root of paseoRoots) {
    const realRoot = resolveReal(root);
    if (
      candidates.some((c) => isPathUnder(c, root) || isPathUnder(c, realRoot))
    ) {
      isProtected = true;
      isPluginSelf = true;
      if (!matchedRules.includes("protected:plugin_self")) matchedRules.push("protected:plugin_self");
      if (base === "config.json" || base === "settings.json") {
        isSensitive = true;
        matchedRules.push(`sensitive:paseo_self:${base}`);
      }
    }
  }

  for (const candidate of candidates) {
    for (const sub of HOME_PROTECTED_SUBPATHS) {
      if (
        isPathUnder(candidate, joinAware(home, sub)) ||
        isPathUnder(candidate, joinAware(realHome, sub))
      ) {
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
        isPathUnder(candidate, joinAware(realWorktree, prefix)) ||
        isPathUnder(candidate, joinAware(worktreeBase, prefix))
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

/**
 * Unified OS-aware path classifier.
 * Routes Windows paths, UNC shares, and PowerShell provider drives to `classifyWindowsPath`,
 * and checks DrvFs (`/mnt/<drive>/...`) paths case-insensitively across both worlds.
 */
export function classifyPath(
  rawPath: string,
  ctx: WindowsPathContext,
): WindowsPathClassification {
  const trimmed = rawPath.trim();
  const isWinShellOrOs =
    ctx.os === "windows" || ctx.shell === "cmd" || ctx.shell === "pwsh5" || ctx.shell === "pwsh7";
  const isStrictWinLiteral =
    (isWinShellOrOs ? /^[A-Za-z]:/.test(trimmed) : /^[A-Za-z]:[\\/]/.test(trimmed)) ||
    trimmed.startsWith("\\\\") ||
    /^\/\/(?:wsl\$|wsl\.localhost|localhost|127\.0\.0\.1)/i.test(trimmed) ||
    (isWinShellOrOs && trimmed.startsWith("//")) ||
    (isWinShellOrOs && stripProviderDrive(trimmed) !== null);
  const isWinMacroLiteral =
    (ctx.shell !== "pwsh5" && ctx.shell !== "pwsh7" && /%[^%\r\n=]+%/.test(trimmed)) ||
    (ctx.shell !== "cmd" && /\$env:/i.test(trimmed));

  if (ctx.shell !== "bash" && (ctx.os === "windows" || isStrictWinLiteral || isWinMacroLiteral)) {
    return classifyWindowsPath(rawPath, ctx);
  }
  if (ctx.shell === "bash" && isStrictWinLiteral) {
    return classifyWindowsPath(rawPath, { ...ctx, os: "windows" });
  }

  const automount = ctx.wsl?.automountRoot ?? "/mnt";
  const toPosixCtxPath = (p: string | undefined, fallback: string): string => {
    if (!p) return fallback;
    if (/^[A-Za-z]:/.test(p) || p.startsWith("\\\\")) {
      return mapWindowsToWslPath(p, automount) ?? toPosixSlash(p);
    }
    return p;
  };

  const skipHostRealpath = Boolean(ctx.wsl) && process.platform !== "linux";
  const posixCtx: PathContext =
    ctx.shell === "bash" && ctx.os === "windows"
      ? {
          ...ctx,
          cwd: toPosixCtxPath(ctx.cwd, "/"),
          worktreeRoot: ctx.worktreeRoot ? toPosixCtxPath(ctx.worktreeRoot, "/") : undefined,
          home: toPosixCtxPath(ctx.home, "/home/user"),
          skipHostRealpath,
        }
      : skipHostRealpath
        ? { ...ctx, skipHostRealpath }
        : ctx;

  const posixRes = classifyPosixPath(rawPath, posixCtx);

  // DrvFs (`/mnt/<drive>/...`) and MSYS/Git Bash (`/c/...`, `/cygdrive/c/...`) cross-world checks
  const mapToWin = (p: string): string | null =>
    mapWslToWindowsPath(p, automount) ??
    (ctx.os === "windows" || p.startsWith("/cygdrive/") ? mapMsysToWindowsPath(p) : null);

  const mappedWin = mapToWin(posixRes.realPath) ?? mapToWin(posixRes.normalized);
  if (mappedWin) {
    const winWorktree = ctx.worktreeRoot
      ? /^[A-Za-z]:/.test(ctx.worktreeRoot) || ctx.worktreeRoot.startsWith("\\\\")
        ? ctx.worktreeRoot
        : (mapToWin(ctx.worktreeRoot) ?? undefined)
      : undefined;
    const winCwd =
      /^[A-Za-z]:/.test(ctx.cwd) || ctx.cwd.startsWith("\\\\")
        ? ctx.cwd
        : (mapToWin(ctx.cwd) ?? "C:\\");
    const winRes = classifyWindowsPath(mappedWin, {
      ...ctx,
      os: "windows",
      cwd: winCwd,
      worktreeRoot: winWorktree,
    });
    return {
      ...posixRes,
      inWorktree: posixRes.inWorktree || (Boolean(winWorktree) && winRes.inWorktree),
      isSensitive: posixRes.isSensitive || winRes.isSensitive,
      isProtected: posixRes.isProtected || winRes.isProtected,
      isPluginSelf: posixRes.isPluginSelf || winRes.isPluginSelf,
      windowsMappedPath: mappedWin,
      ...(winRes.adsStream ? { adsStream: winRes.adsStream } : {}),
      ...(winRes.hasUnresolvedShortName ? { hasUnresolvedShortName: true } : {}),
      ...(winRes.isReservedDevice ? { isReservedDevice: true } : {}),
      matchedRules: Array.from(new Set([...posixRes.matchedRules, ...winRes.matchedRules])),
    };
  }

  return posixRes;
}
