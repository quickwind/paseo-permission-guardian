import { win32, posix } from "node:path";
import { tmpdir } from "node:os";
import type { HostOs, Shell } from "../../shared/types.js";
import {
  classifyPosixPath,
  resolveAncestorRealPath,
  type PathClassification,
  type PathContext,
} from "./index.js";

export interface WindowsPathContext extends PathContext {
  os?: HostOs;
  shell?: Shell;
  wsl?: {
    distro?: string;
    user?: string;
    automountRoot?: string;
  };
  envSnapshot?: Record<string, string | undefined>;
}

export interface WindowsPathClassification extends PathClassification {
  isRemoteUnc?: boolean;
  isWslUnc?: boolean;
  wslMappedLinuxPath?: string;
  windowsMappedPath?: string;
  providerDrive?: string;
  adsStream?: string;
  isReservedDevice?: boolean;
  isDriveRelative?: boolean;
  hasUnresolvedShortName?: boolean;
}

const PROVIDER_DRIVE_NAMES = new Set([
  "env",
  "hklm",
  "hkcu",
  "hkcr",
  "hku",
  "hkcc",
  "cert",
  "variable",
  "function",
  "alias",
  "wsman",
]);

const RESERVED_DEVICE_NAMES = new Set([
  "CON",
  "PRN",
  "AUX",
  "NUL",
  "COM1",
  "COM2",
  "COM3",
  "COM4",
  "COM5",
  "COM6",
  "COM7",
  "COM8",
  "COM9",
  "LPT1",
  "LPT2",
  "LPT3",
  "LPT4",
  "LPT5",
  "LPT6",
  "LPT7",
  "LPT8",
  "LPT9",
]);

const SENSITIVE_BASENAMES_CASE_INSENSITIVE: readonly RegExp[] = [
  /^\.env(?:\..+)?$/i,
  /^id_(?:rsa|dsa|ecdsa|ed25519)(?:\..+)?$/i,
  /\.(?:pem|pfx|p12|key|jks|keystore|kdbx|ppk|rdp|ovpn)$/i,
  /^\.git-credentials$/i,
  /^\.netrc$/i,
  /^\.npmrc$/i,
  /^\.pypirc$/i,
];

const WINDOWS_SENSITIVE_SUBPATHS = [
  "appdata/roaming/microsoft/credentials",
  "appdata/roaming/microsoft/protect",
  "appdata/local/microsoft/credentials",
  "appdata/local/microsoft/vault",
  "appdata/roaming/microsoft/windows/powershell/psreadline/consolehost_history.txt",
  "appdata/roaming/nuget/nuget.config",
  "appdata/roaming/postgresql/pgpass.conf",
  "appdata/roaming/github cli/hosts.yml",
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

const WINDOWS_SENSITIVE_SYSTEM_SUFFIXES = [
  "/windows/system32/config/sam",
  "/windows/system32/config/system",
  "/windows/system32/config/security",
  "/windows/panther/unattend.xml",
  "/sysprep.inf",
];

const WINDOWS_PROTECTED_USER_SUBPATHS = [
  "documents/windowspowershell",
  "documents/powershell",
  "onedrive/documents/windowspowershell",
  "onedrive/documents/powershell",
  "appdata/roaming/microsoft/windows/start menu/programs/startup",
  "appdata/local/microsoft/windowsapps",
  "appdata/roaming/npm",
  ".cargo/bin",
  "go/bin",
  "scoop/shims",
  ".claude",
  ".devin",
  ".codex",
  ".cursor",
  ".bashrc",
  ".bash_profile",
  ".zshrc",
  ".profile",
  ".npmrc",
  ".paseo/permission-guardian",
];

const WINDOWS_PROTECTED_PROGRAM_SUBPATHS = [
  "/programdata/microsoft/windows/start menu/programs/startup",
  "/programdata/microsoft/vault",
  "/windows/system32/tasks",
  "/windows/system32/windowspowershell/v1.0",
  "/program files/powershell/modules",
  "/program files/windowspowershell/modules",
];

const REPO_PROTECTED_PREFIXES = [
  ".git",
  ".claude",
  ".devin",
  ".codex",
  ".cursor",
  ".github/workflows",
];

const HOME_SENSITIVE_POSIX = [
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

function toForwardSlash(p: string): string {
  return p.replaceAll("\\", "/");
}

function getEnvInsensitive(
  env: Record<string, string | undefined> | undefined,
  key: string,
): string | undefined {
  if (!env) return undefined;
  const target = key.toLowerCase();
  for (const [k, v] of Object.entries(env)) {
    if (k.toLowerCase() === target && typeof v === "string" && v.length > 0) {
      return v;
    }
  }
  return undefined;
}

export function stripProviderDrive(raw: string): { provider: string; remainder: string } | null {
  const trimmed = raw.trim();
  const qualMatch = trimmed.match(
    /^(?:Microsoft\.PowerShell\.Core\\)?(Environment|Registry)::(.*)$/i,
  );
  if (qualMatch) {
    const prov = qualMatch[1].toLowerCase() === "environment" ? "env" : "registry";
    return { provider: prov, remainder: qualMatch[2] };
  }

  const colonMatch = trimmed.match(/^([A-Za-z]{2,16}):(.*)$/);
  if (colonMatch) {
    const prov = colonMatch[1].toLowerCase();
    if (PROVIDER_DRIVE_NAMES.has(prov)) {
      return { provider: prov, remainder: colonMatch[2] };
    }
  }
  return null;
}

export function mapWindowsToWslPath(winPath: string, automountRoot = "/mnt"): string | null {
  let cleaned = winPath.trim();
  if (/^\\\\\?\\UNC\\/i.test(cleaned)) {
    cleaned = `\\\\${cleaned.slice(8)}`;
  } else if (/^\\\\\?\\/.test(cleaned)) {
    cleaned = cleaned.slice(4);
  }

  const wslUnc = cleaned.match(/^[\\/]{2}(?:wsl\$|wsl\.localhost)[\\/][^\\/]+(?:([\\/].*))?$/i);
  if (wslUnc) {
    const rest = (wslUnc[1] ?? "/").replaceAll("\\", "/");
    return posix.normalize(rest.startsWith("/") ? rest : `/${rest}`);
  }

  const driveMatch = cleaned.match(/^([A-Za-z]):([\\/].*)?$/);
  if (!driveMatch) {
    return null;
  }
  const drive = driveMatch[1].toLowerCase();
  const rest = (driveMatch[2] ?? "").replaceAll("\\", "/");
  const root = automountRoot.replaceAll("\\", "/").replace(/\/+$/, "") || "/mnt";
  const joined = `${root}/${drive}${rest.startsWith("/") ? rest : rest ? `/${rest}` : ""}`;
  return posix.normalize(joined).replace(/\/+$/, "") || "/";
}

export function mapWslToWindowsPath(linuxPath: string, automountRoot = "/mnt"): string | null {
  const norm = toForwardSlash(linuxPath.trim());
  const root = toForwardSlash(automountRoot).replace(/\/+$/, "") || "/mnt";
  const escapedRoot = root.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const rx = new RegExp(`^${escapedRoot}/([a-zA-Z])(?:/(.*))?$`);
  const match = norm.match(rx);
  if (!match) {
    return null;
  }
  const drive = match[1].toUpperCase();
  const rest = match[2] ? match[2].replaceAll("/", "\\") : "";
  return rest ? `${drive}:\\${rest}` : `${drive}:\\`;
}

/**
 * Map MSYS2 / Git Bash (`/c/Users/...`) or Cygwin (`/cygdrive/c/Users/...`) paths
 * to their Windows drive-letter equivalent (`C:\Users\...`).
 */
export function mapMsysToWindowsPath(linuxPath: string): string | null {
  const norm = toForwardSlash(linuxPath.trim());
  const cygMatch = norm.match(/^\/cygdrive\/([a-zA-Z])(?:\/(.*))?$/i);
  if (cygMatch) {
    const drive = cygMatch[1].toUpperCase();
    const rest = cygMatch[2] ? cygMatch[2].replaceAll("/", "\\") : "";
    return rest ? `${drive}:\\${rest}` : `${drive}:\\`;
  }
  const msysMatch = norm.match(/^\/([a-zA-Z])(?:\/(.*))?$/);
  if (!msysMatch) {
    return null;
  }
  const drive = msysMatch[1].toUpperCase();
  const rest = msysMatch[2] ? msysMatch[2].replaceAll("/", "\\") : "";
  return rest ? `${drive}:\\${rest}` : `${drive}:\\`;
}

function stripTrailingDotsAndSpaces(winNormalized: string): string {
  const driveMatch = winNormalized.match(/^([A-Za-z]:\\)(.*)$/);
  if (driveMatch) {
    const prefix = driveMatch[1];
    const parts = driveMatch[2]
      .split("\\")
      .filter((s) => s.length > 0)
      .map((seg) => (seg === "." || seg === ".." ? seg : seg.replace(/[. ]+$/, "")))
      .filter((seg) => seg.length > 0);
    return `${prefix}${parts.join("\\")}`;
  }

  const uncMatch = winNormalized.match(/^(\\\\[^\\]+\\[^\\]+)(?:\\(.*))?$/);
  if (uncMatch) {
    const prefix = uncMatch[1];
    const parts = (uncMatch[2] ?? "")
      .split("\\")
      .filter((s) => s.length > 0)
      .map((seg) => (seg === "." || seg === ".." ? seg : seg.replace(/[. ]+$/, "")))
      .filter((seg) => seg.length > 0);
    return parts.length > 0 ? `${prefix}\\${parts.join("\\")}` : prefix;
  }

  return winNormalized;
}

function extractAdsStream(candidate: string): { base: string; adsStream?: string } {
  const fsPrefixMatch = candidate.match(/^([A-Za-z]:|\\\\[^\\]+\\[^\\]+)(.*)$/);
  const prefix = fsPrefixMatch ? fsPrefixMatch[1] : "";
  const rest = fsPrefixMatch ? fsPrefixMatch[2] : candidate;

  const parts = rest.split(/([\\/])/);
  const streams: string[] = [];
  for (let i = 0; i < parts.length; i++) {
    const seg = parts[i];
    if (seg === "\\" || seg === "/" || seg.length === 0) continue;
    const colonIdx = seg.indexOf(":");
    if (colonIdx > 0) {
      streams.push(seg.slice(colonIdx + 1));
      parts[i] = seg.slice(0, colonIdx);
    }
  }
  if (streams.length > 0) {
    return { base: `${prefix}${parts.join("")}`, adsStream: streams.join(";") };
  }
  return { base: candidate };
}

function isWinPathUnder(candidateFwdLower: string, rootFwdLower: string): boolean {
  const normCand = candidateFwdLower.replace(/\/+$/, "");
  const normRoot = rootFwdLower.replace(/\/+$/, "");
  if (!normRoot) return false;
  return normCand === normRoot || normCand.startsWith(`${normRoot}/`);
}

function matchWindowsGlob(candidateFwdLower: string, patternRaw: string): boolean {
  const patternFwd = toForwardSlash(patternRaw).toLowerCase();
  const escaped = patternFwd
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "§GLOBSTAR§")
    .replace(/\*/g, "[^/]*")
    .replace(/§GLOBSTAR§/g, ".*");
  return new RegExp(`^${escaped}$`, "i").test(candidateFwdLower);
}

function expandWindowsMacros(
  rawPath: string,
  ctx: WindowsPathContext,
): string {
  const env = ctx.envSnapshot;
  const home =
    ctx.home ??
    getEnvInsensitive(env, "USERPROFILE") ??
    (process.platform === "win32" ? win32.resolve("C:\\Users\\user") : "C:\\Users\\user");

  const defaultAppData = win32.join(home, "AppData", "Roaming");
  const defaultLocalAppData = win32.join(home, "AppData", "Local");
  const defaultTemp =
    process.platform === "win32" ? tmpdir() : win32.join(home, "AppData", "Local", "Temp");

  const macroMap: Record<string, string> = {
    USERPROFILE: home,
    HOME: home,
    APPDATA: getEnvInsensitive(env, "APPDATA") ?? defaultAppData,
    LOCALAPPDATA: getEnvInsensitive(env, "LOCALAPPDATA") ?? defaultLocalAppData,
    PROGRAMDATA: getEnvInsensitive(env, "PROGRAMDATA") ?? "C:\\ProgramData",
    SYSTEMROOT: getEnvInsensitive(env, "SYSTEMROOT") ?? "C:\\Windows",
    WINDIR: getEnvInsensitive(env, "WINDIR") ?? "C:\\Windows",
    TEMP: getEnvInsensitive(env, "TEMP") ?? defaultTemp,
    TMP: getEnvInsensitive(env, "TMP") ?? defaultTemp,
    PROGRAMFILES: getEnvInsensitive(env, "ProgramFiles") ?? "C:\\Program Files",
    "PROGRAMFILES(X86)": getEnvInsensitive(env, "ProgramFiles(x86)") ?? "C:\\Program Files (x86)",
  };

  let out = rawPath.trim();
  if (out === "~") {
    return home;
  }
  if (out.startsWith("~/") || out.startsWith("~\\")) {
    out = win32.join(home, out.slice(2));
  }

  // Only expand `%VAR%` when not executing inside PowerShell (`pwsh` does not expand `%VAR%`),
  // and ONLY substitute known safe path macros (never arbitrary secrets from `envSnapshot`).
  if (ctx.shell !== "pwsh5" && ctx.shell !== "pwsh7") {
    out = out.replace(/%([A-Za-z0-9_()]+)%/g, (full, varName: string) => {
      const val = macroMap[varName.toUpperCase()];
      return val ?? full;
    });
  }

  // Only expand PowerShell `$env:VAR` / `$HOME` outside `cmd.exe`, and ONLY from `macroMap`.
  if (ctx.shell !== "cmd") {
    if (out === "$HOME" || out === "${HOME}") {
      out = home;
    } else if (out.startsWith("$HOME\\") || out.startsWith("$HOME/")) {
      out = win32.join(home, out.slice("$HOME/".length));
    } else if (out.startsWith("${HOME}\\") || out.startsWith("${HOME}/")) {
      out = win32.join(home, out.slice("${HOME}/".length));
    }
    out = out.replace(/\$env:([A-Za-z0-9_]+)|\$\{env:([A-Za-z0-9_]+)\}/gi, (full, a?: string, b?: string) => {
      const name = a ?? b ?? "";
      const val = macroMap[name.toUpperCase()];
      return val ?? full;
    });
  }

  return out;
}

function classifyProviderTarget(provider: string, remainder: string, rawPath: string): WindowsPathClassification {
  const cleanRem = remainder.replace(/^[\\/]+/, "").replaceAll("/", "\\");
  const matchedRules: string[] = [`provider:${provider}`];
  let isSensitive = false;
  let isProtected = false;

  if (provider === "env") {
    const lower = cleanRem.toLowerCase();
    if (!cleanRem || /[*?[\]]/.test(cleanRem)) {
      isSensitive = true;
      matchedRules.push("sensitive:provider:env_dump");
    } else if (
      /(?:key|token|secret|password|passwd|credential|auth|apikey|bearer|cookie|pwd)/i.test(lower)
    ) {
      isSensitive = true;
      matchedRules.push("sensitive:provider:env_var");
    }
  } else if (provider === "cert") {
    isSensitive = true;
    isProtected = /root/i.test(cleanRem);
    matchedRules.push("sensitive:provider:cert");
  } else if (provider === "hklm" || provider === "hkcu" || provider === "registry") {
    const lower = cleanRem.toLowerCase();
    if (
      /^(?:sam|security|system|hklm\\sam|hklm\\security|hklm\\system)\b/.test(lower) ||
      /\\winlogon\b|\\putty\\|\\winscp\\|\\realvnc\\|\\tightvnc\\/.test(`\\${lower}`) ||
      /^environment(?:\\|$)/.test(lower) ||
      /\\environment(?:\\|$)/.test(lower)
    ) {
      isSensitive = true;
      matchedRules.push("sensitive:provider:registry_secret");
    }
    if (
      /\\run(?:once)?(?:\\|$)|\\winlogon(?:\\|$)|\\image file execution options\\|\\appinit_dlls|\\command processor(?:\\|$)|\\services(?:\\|$)|\\environment(?:\\|$)/i.test(
        `\\${lower}`,
      ) ||
      /^(?:sam|security|system|hklm\\sam|hklm\\security|hklm\\system|software\\classes|environment)(?:\\|$)/i.test(
        cleanRem,
      )
    ) {
      isProtected = true;
      matchedRules.push("protected:provider:registry_persist");
    }
  }

  return {
    raw: rawPath,
    normalized: `${provider}:${cleanRem}`,
    realPath: `${provider}:${cleanRem}`,
    inWorktree: false,
    isTemp: false,
    isSensitive,
    isProtected,
    isPluginSelf: false,
    matchedRules,
    providerDrive: provider,
  };
}

export function classifyWindowsPath(
  rawPath: string,
  ctx: WindowsPathContext,
): WindowsPathClassification {
  let raw = rawPath.trim();

  // Strip FileSystem:: prefix if present
  const fsProvMatch = raw.match(/^(?:Microsoft\.PowerShell\.Core\\)?FileSystem::(.*)$/i);
  if (fsProvMatch) {
    raw = fsProvMatch[1];
  }

  const providerMatch = stripProviderDrive(raw);
  if (providerMatch) {
    return classifyProviderTarget(providerMatch.provider, providerMatch.remainder, rawPath);
  }

  // Local `file:///C:/...` URI -> local Windows path; remote `file://host/share` -> remote UNC
  const localFileUri = raw.match(/^file:\/\/\/([A-Za-z]:\/.*)$/i);
  if (localFileUri) {
    try {
      raw = decodeURIComponent(localFileUri[1]).replaceAll("/", "\\");
    } catch {
      raw = localFileUri[1].replaceAll("/", "\\");
    }
  } else {
    const fileUriMatch = raw.match(/^file:\/\/([^/]+)(\/.*)?$/i);
    if (fileUriMatch && fileUriMatch[1] && !/^(localhost|127\.0\.0\.1)$/i.test(fileUriMatch[1])) {
      return {
        raw: rawPath,
        normalized: raw,
        realPath: raw,
        inWorktree: false,
        isTemp: false,
        isSensitive: false,
        isProtected: false,
        isPluginSelf: false,
        matchedRules: ["remote_unc:file_uri"],
        isRemoteUnc: true,
      };
    }
  }

  let verbatim = false;
  if (/^\\\\\?\\UNC\\/i.test(raw)) {
    verbatim = true;
    raw = `\\\\${raw.slice(8)}`;
  } else if (/^\\\\\?\\/.test(raw)) {
    verbatim = true;
    raw = raw.slice(4);
  }

  let expanded = expandWindowsMacros(raw, ctx);

  // Check drive-relative path like `C:foo` (missing slash after colon)
  if (/^[A-Za-z]:(?![\\/])/.test(expanded)) {
    return {
      raw: rawPath,
      normalized: expanded,
      realPath: expanded,
      inWorktree: false,
      isTemp: false,
      isSensitive: false,
      isProtected: false,
      isPluginSelf: false,
      matchedRules: ["drive_relative_path"],
      isDriveRelative: true,
    };
  }

  // Normalize leading `//host/share` into `\\host\share`
  if (expanded.startsWith("//") && !expanded.startsWith("///")) {
    expanded = `\\\\${expanded.slice(2).replaceAll("/", "\\")}`;
  }

  // Handle UNC paths
  if (expanded.startsWith("\\\\")) {
    const uncClean = expanded.replaceAll("/", "\\");
    const uncParts = uncClean.slice(2).split("\\").filter(Boolean);
    const host = (uncParts[0] ?? "").toLowerCase();
    const share = (uncParts[1] ?? "").toLowerCase();

    // WSL UNC paths: NEVER call realpathSync.native (ADR-0004)
    if (host === "wsl$" || host === "wsl.localhost") {
      const linuxSub = uncParts.length > 2 ? `/${uncParts.slice(2).join("/")}` : "/";
      const linuxNorm = posix.normalize(linuxSub);
      const worktreeMapped = ctx.worktreeRoot ? mapWindowsToWslPath(ctx.worktreeRoot) : undefined;
      const posixRes = classifyPosixPath(linuxNorm, {
        cwd: "/",
        worktreeRoot: worktreeMapped ?? "/",
        home: "/root",
      });
      const matchedRules = [...posixRes.matchedRules, "wsl_unc"];
      let isSensitive = posixRes.isSensitive;
      let isProtected = posixRes.isProtected;

      // Also check any /home/<user>/... sensitive paths inside WSL without relying on Windows home
      for (const sub of HOME_SENSITIVE_POSIX) {
        if (new RegExp(`^/(?:home/[^/]+|root)/${sub.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:/|$)`, "i").test(linuxNorm)) {
          isSensitive = true;
          matchedRules.push(`sensitive:wsl_home:${sub}`);
        }
      }
      if (/^\/etc\/(?:shadow|sudoers|master\.passwd)$/.test(linuxNorm)) {
        isSensitive = true;
      }

      const normWt = worktreeMapped?.replace(/\/+$/, "");
      const inWslWorktree = Boolean(
        normWt && (linuxNorm === normWt || linuxNorm.startsWith(`${normWt}/`)),
      );

      return {
        raw: rawPath,
        normalized: uncClean,
        realPath: uncClean,
        inWorktree: inWslWorktree,
        isTemp: linuxNorm.startsWith("/tmp/") || linuxNorm === "/tmp",
        isSensitive,
        isProtected,
        isPluginSelf: posixRes.isPluginSelf,
        matchedRules: Array.from(new Set(matchedRules)),
        isWslUnc: true,
        wslMappedLinuxPath: linuxNorm,
      };
    }

    // Loopback admin share `\\localhost\c$\...` -> rewrite to local `C:\...`
    if ((host === "localhost" || host === "127.0.0.1") && /^[a-z]\$$/.test(share)) {
      const rest = uncParts.slice(2).join("\\");
      expanded = `${share[0].toUpperCase()}:\\${rest}`;
    } else {
      return {
        raw: rawPath,
        normalized: uncClean,
        realPath: uncClean,
        inWorktree: false,
        isTemp: false,
        isSensitive: false,
        isProtected: false,
        isPluginSelf: false,
        matchedRules: [`remote_unc:${host || "unknown"}`],
        isRemoteUnc: true,
      };
    }
  }

  // Strip Alternate Data Streams (`file::$DATA`, `file:Zone.Identifier`)
  const adsInfo = extractAdsStream(expanded);
  expanded = adsInfo.base;

  const cwdWin = ctx.cwd.replaceAll("/", "\\");
  const resolved = win32.isAbsolute(expanded)
    ? win32.normalize(expanded)
    : win32.resolve(cwdWin, expanded);

  let canonical = verbatim ? resolved : stripTrailingDotsAndSpaces(resolved);
  canonical = canonical.replace(/^([a-z]):/, (_, d: string) => `${d.toUpperCase()}:`);

  let realPath = canonical;
  if (process.platform === "win32" && !verbatim) {
    realPath = resolveAncestorRealPath(canonical);
  }

  const baseName = win32.basename(canonical);
  const baseNoExt = baseName.split(".")[0]?.trim() ?? "";
  const isReservedDevice = RESERVED_DEVICE_NAMES.has(baseNoExt.toUpperCase());

  const segmentsAfterDrive = canonical.replace(/^[A-Za-z]:\\?/, "").split("\\").filter(Boolean);
  const hasUnresolvedShortName = segmentsAfterDrive.some((seg) => /~[1-9](?:\.|$)/.test(seg));

  const homeWin = (ctx.home ?? getEnvInsensitive(ctx.envSnapshot, "USERPROFILE") ?? "C:\\Users\\user").replaceAll("/", "\\");
  const homeFwdLower = toForwardSlash(win32.normalize(homeWin)).toLowerCase();

  const worktreeRaw = (ctx.worktreeRoot ?? ctx.cwd).replaceAll("/", "\\");
  const worktreeReal = process.platform === "win32" ? resolveAncestorRealPath(worktreeRaw) : win32.normalize(worktreeRaw);
  const worktreeFwdLower = toForwardSlash(worktreeReal).toLowerCase();
  const realFwdLower = toForwardSlash(realPath).toLowerCase();
  const normFwdLower = toForwardSlash(canonical).toLowerCase();

  const inWorktree =
    isWinPathUnder(realFwdLower, worktreeFwdLower) || isWinPathUnder(normFwdLower, toForwardSlash(win32.normalize(worktreeRaw)).toLowerCase());

  const tempCandidates = new Set<string>([
    "c:/windows/temp",
    toForwardSlash(win32.normalize(getEnvInsensitive(ctx.envSnapshot, "TEMP") ?? "")).toLowerCase(),
    toForwardSlash(win32.normalize(getEnvInsensitive(ctx.envSnapshot, "TMP") ?? "")).toLowerCase(),
  ]);
  if (process.platform === "win32") {
    tempCandidates.add(toForwardSlash(resolveAncestorRealPath(tmpdir())).toLowerCase());
  }
  const isTemp = Array.from(tempCandidates).some(
    (t) => t.length > 0 && isWinPathUnder(realFwdLower, t),
  );

  const matchedRules: string[] = [];
  let isSensitive = false;
  let isProtected = false;
  let isPluginSelf = false;

  const candidates = Array.from(new Set([normFwdLower, realFwdLower]));

  for (const cand of candidates) {
    const userRel = cand.match(/^[a-z]:\/users\/[^/]+\/(.*)$/)?.[1];
    for (const sub of WINDOWS_SENSITIVE_SUBPATHS) {
      if (
        isWinPathUnder(cand, `${homeFwdLower}/${sub}`) ||
        (userRel !== undefined && (userRel === sub || userRel.startsWith(`${sub}/`)))
      ) {
        isSensitive = true;
        matchedRules.push(`sensitive:win_home:${sub}`);
      }
    }
    for (const sysSuffix of WINDOWS_SENSITIVE_SYSTEM_SUFFIXES) {
      if (cand.endsWith(sysSuffix)) {
        isSensitive = true;
        matchedRules.push(`sensitive:win_system:${sysSuffix}`);
      }
    }
    if (
      /\/appdata\/(?:local|roaming)\/(?:google\/chrome|microsoft\/edge|bravesoftware\/brave-browser)\/user data\/[^/]+\/(?:login data|cookies|network\/cookies|local state)$/.test(
        cand,
      ) ||
      /\/appdata\/roaming\/mozilla\/firefox\/profiles\/[^/]+\/(?:logins\.json|key4\.db|cookies\.sqlite)$/.test(
        cand,
      )
    ) {
      isSensitive = true;
      matchedRules.push("sensitive:browser_profile");
    }
    if (/\/appdata\/roaming\/[^/]+\/(?:web\.config)$/.test(cand) || cand.endsWith("/web.config")) {
      isSensitive = true;
      matchedRules.push("sensitive:web_config");
    }
  }

  for (const rx of SENSITIVE_BASENAMES_CASE_INSENSITIVE) {
    if (rx.test(baseName)) {
      isSensitive = true;
      matchedRules.push(`sensitive:basename:${baseName}`);
      break;
    }
  }

  const pluginDirRaw = (
    ctx.pluginDataDir ?? win32.join(homeWin, ".paseo", "permission-guardian")
  ).replaceAll("/", "\\");
  const pluginFwdLower = toForwardSlash(win32.normalize(pluginDirRaw)).toLowerCase();
  if (isWinPathUnder(realFwdLower, pluginFwdLower) || isWinPathUnder(normFwdLower, pluginFwdLower)) {
    isProtected = true;
    isPluginSelf = true;
    matchedRules.push("protected:plugin_self");
  }

  for (const cand of candidates) {
    const parts = cand.split("/").filter(Boolean);
    if (parts.includes(".git")) {
      isProtected = true;
      matchedRules.push("protected:.git");
    }
    for (const prefix of REPO_PROTECTED_PREFIXES) {
      if (isWinPathUnder(cand, `${worktreeFwdLower}/${prefix}`)) {
        isProtected = true;
        matchedRules.push(`protected:repo:${prefix}`);
      }
    }
    const userRelProt = cand.match(/^[a-z]:\/users\/[^/]+\/(.*)$/)?.[1];
    for (const sub of WINDOWS_PROTECTED_USER_SUBPATHS) {
      if (
        isWinPathUnder(cand, `${homeFwdLower}/${sub}`) ||
        (userRelProt !== undefined && (userRelProt === sub || userRelProt.startsWith(`${sub}/`)))
      ) {
        isProtected = true;
        if (sub === ".paseo/permission-guardian") {
          isPluginSelf = true;
        }
        matchedRules.push(`protected:win_home:${sub}`);
      }
    }
    for (const progSuffix of WINDOWS_PROTECTED_PROGRAM_SUBPATHS) {
      if (cand.includes(progSuffix)) {
        isProtected = true;
        matchedRules.push(`protected:win_system:${progSuffix}`);
      }
    }
    if (/\/(?:windowspowershell|powershell)\/.*profile.*\.ps1$/.test(cand)) {
      isProtected = true;
      matchedRules.push("protected:pwsh_profile");
    }
  }

  for (const pat of ctx.extraSensitivePatterns ?? []) {
    const expPat = expandWindowsMacros(pat, ctx);
    const fullPat = win32.isAbsolute(expPat) ? expPat : win32.resolve(worktreeRaw, expPat);
    if (matchWindowsGlob(realFwdLower, fullPat) || matchWindowsGlob(normFwdLower, fullPat)) {
      isSensitive = true;
      matchedRules.push(`sensitive:policy:${pat}`);
    }
  }

  for (const pat of ctx.extraProtectedPatterns ?? []) {
    const expPat = expandWindowsMacros(pat, ctx);
    const fullPat = win32.isAbsolute(expPat) ? expPat : win32.resolve(worktreeRaw, expPat);
    if (matchWindowsGlob(realFwdLower, fullPat) || matchWindowsGlob(normFwdLower, fullPat)) {
      isProtected = true;
      matchedRules.push(`protected:policy:${pat}`);
    }
  }

  if (adsInfo.adsStream) {
    matchedRules.push(`ntfs:ads:${adsInfo.adsStream}`);
  }
  if (isReservedDevice) {
    matchedRules.push(`ntfs:reserved_device:${baseNoExt}`);
  }
  if (hasUnresolvedShortName) {
    matchedRules.push("ntfs:unresolved_short_name");
  }

  return {
    raw: rawPath,
    normalized: canonical,
    realPath,
    inWorktree,
    isTemp,
    isSensitive,
    isProtected,
    isPluginSelf,
    matchedRules: Array.from(new Set(matchedRules)),
    ...(adsInfo.adsStream ? { adsStream: adsInfo.adsStream } : {}),
    ...(isReservedDevice ? { isReservedDevice: true } : {}),
    ...(hasUnresolvedShortName ? { hasUnresolvedShortName: true } : {}),
  };
}
