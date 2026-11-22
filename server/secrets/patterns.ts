export interface CredentialPatternSpec {
  kind: string;
  /** Stateless detection regex (must NOT carry the /g flag). */
  regex: RegExp;
  replacement: string;
}

export const REDACTED_MARKER = "[REDACTED]";
export const REDACTED_PEM_MARKER = "[REDACTED_PEM_KEY]";

/**
 * Stateless high-confidence credential literal patterns shared by both
 * deterministic classification (`effects.ts`) and audit redaction (`redact.ts`).
 *
 * IMPORTANT: None of these regexes may carry the `/g` flag, avoiding `lastIndex`
 * state corruption across `.test()` calls. Callers performing global string
 * replacement must construct fresh RegExp copies with `"g"`.
 */
export const CREDENTIAL_LITERAL_PATTERNS: readonly CredentialPatternSpec[] = [
  {
    kind: "pem_private_key",
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/,
    replacement: REDACTED_PEM_MARKER,
  },
  {
    kind: "putty_private_key",
    regex:
      /PuTTY-User-Key-File-\d+:[\s\S]*?(?:Private-MAC:\s*[0-9a-fA-F]+|Private-Lines:\s*\d+[\s\S]*)/i,
    replacement: REDACTED_PEM_MARKER,
  },
  {
    kind: "auth_header",
    regex: /\b((?:proxy-)?authorization\s*[:=]\s*(?:bearer|basic|token)\s+)([^\s"',;]+)/i,
    replacement: `$1${REDACTED_MARKER}`,
  },
  {
    kind: "bearer_token",
    regex: /\b(Bearer\s+)([A-Za-z0-9._~+/-]{12,}=*)/,
    replacement: `$1${REDACTED_MARKER}`,
  },
  {
    kind: "anthropic_key",
    regex: /\bsk-ant-[A-Za-z0-9_-]{16,}\b/,
    replacement: REDACTED_MARKER,
  },
  {
    kind: "openai_or_sk_key",
    regex: /\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b/,
    replacement: REDACTED_MARKER,
  },
  {
    kind: "stripe_key",
    regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/,
    replacement: REDACTED_MARKER,
  },
  {
    kind: "github_token",
    regex: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
    replacement: REDACTED_MARKER,
  },
  {
    kind: "github_pat",
    regex: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
    replacement: REDACTED_MARKER,
  },
  {
    kind: "gitlab_pat",
    regex: /\bglpat-[A-Za-z0-9_-]{16,}\b/,
    replacement: REDACTED_MARKER,
  },
  {
    kind: "huggingface_token",
    regex: /\bhf_[A-Za-z0-9]{20,}\b/,
    replacement: REDACTED_MARKER,
  },
  {
    kind: "npm_token",
    regex: /\bnpm_[A-Za-z0-9]{20,}\b/,
    replacement: REDACTED_MARKER,
  },
  {
    kind: "pypi_token",
    regex: /\bpypi-[A-Za-z0-9_-]{20,}\b/,
    replacement: REDACTED_MARKER,
  },
  {
    kind: "slack_token",
    regex: /\bxox[baprse]-[A-Za-z0-9-]{16,}\b/,
    replacement: REDACTED_MARKER,
  },
  {
    kind: "aws_access_key",
    regex: /\bAKIA[0-9A-Z]{16}\b/,
    replacement: REDACTED_MARKER,
  },
  {
    kind: "google_api_key",
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/,
    replacement: REDACTED_MARKER,
  },
  {
    kind: "entra_client_secret",
    regex: /\b[A-Za-z0-9_-]{3}8Q~[A-Za-z0-9_.-]{34}\b/,
    replacement: REDACTED_MARKER,
  },
  {
    kind: "azure_storage_account_key",
    regex: /\b(AccountKey\s*=\s*)([A-Za-z0-9+/]{40,}={0,2})/i,
    replacement: `$1${REDACTED_MARKER}`,
  },
  {
    kind: "azure_sas_token",
    regex: /(\bsv=\d{4}-\d{2}-\d{2}[^\s"'`;|]*?&sig=)([A-Za-z0-9%+/=_-]{20,})/i,
    replacement: `$1${REDACTED_MARKER}`,
  },
  {
    kind: "sql_connection_password",
    regex:
      /((?:(?:Server|Data Source|Initial Catalog|User ID|Uid|Host|Database)\s*=\s*[^;\s"']+\s*;\s*)+[^"']*?\b(?:Password|Pwd)\s*=\s*)([^;\s"']+)/i,
    replacement: `$1${REDACTED_MARKER}`,
  },
  {
    kind: "jwt",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
    replacement: REDACTED_MARKER,
  },
  {
    kind: "url_credentials",
    regex: /\b([a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:)([^/\s@]+)(@[^/\s@]+)/i,
    replacement: `$1${REDACTED_MARKER}$3`,
  },
];

/**
 * Low-confidence credential patterns used EXCLUSIVELY for audit redaction.
 * Never trigger deterministic P0 risk escalation (`detectCredentialLiterals`).
 * Stateless (must NOT carry `/g`).
 */
export const REDACTION_ONLY_CREDENTIAL_PATTERNS: readonly CredentialPatternSpec[] = [
  {
    kind: "generic_secret_kv",
    regex:
      /\b(password|passwd|client[_-]?secret|api[_-]?key|access[_-]?token|refresh[_-]?token|secret[_-]?key)(\s*[:=]\s*)(?!\[REDACTED)(?!["']?(?:\s|$))("[^"\n]{6,}"|'[^'\n]{6,}'|[^\s"',;]{6,})/i,
    replacement: `$1$2${REDACTED_MARKER}`,
  },
];

export function detectCredentialLiterals(text: string): string[] {
  if (!text) {
    return [];
  }
  const matched: string[] = [];
  for (const spec of CREDENTIAL_LITERAL_PATTERNS) {
    if (spec.regex.test(text)) {
      matched.push(spec.kind);
    }
  }
  return matched;
}

/**
 * Convert camelCase / PascalCase / kebab-case identifiers to UPPER_SNAKE_CASE
 * so `apiKey`, `authToken`, `DB_PASSWORD` are classified uniformly.
 */
export function normalizeEnvVarName(name: string): string {
  return name
    .trim()
    .replaceAll("-", "_")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .toUpperCase();
}

const SAFE_EXCLUDED_ENV_VARS = new Set([
  "PWD",
  "OLDPWD",
  "TOKENIZERS_PARALLELISM",
  "MAX_TOKENS",
  "KEYMAP",
  "SSH_AUTH_SOCK",
]);

const SAFE_EXCLUDED_ENV_PREFIXES = ["KEYBOARD_", "GIT_AUTHOR_", "GIT_COMMITTER_"];

const EXPLICIT_SENSITIVE_ENV_VARS = new Set([
  "PGPASSWORD",
  "MYSQL_PWD",
  "DB_PWD",
  "FTP_PWD",
  "SMTP_PWD",
  "DATABASE_URL",
  "REDIS_URL",
  "MONGODB_URI",
  "MONGO_URI",
]);

const SENSITIVE_SEGMENT_REGEX =
  /(?:^|_)(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|CREDENTIALS|AUTH|APIKEY|BEARER|COOKIE)(?:$|_)/;

// Excludes bare KEY and bare PWD (handled safely via segment / scoped *_PWD checks)
const SENSITIVE_SUFFIX_REGEX =
  /(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|CREDENTIALS?)$|_PWD$/;

function matchesSensitiveCatalog(upper: string): boolean {
  if (EXPLICIT_SENSITIVE_ENV_VARS.has(upper) || upper.endsWith("_DSN")) {
    return true;
  }
  if (SENSITIVE_SEGMENT_REGEX.test(upper)) {
    return true;
  }
  if (SENSITIVE_SUFFIX_REGEX.test(upper)) {
    return true;
  }
  return false;
}

export function isSensitiveEnvVarName(name: string): boolean {
  if (!name) return false;
  const rawUpper = name.trim().toUpperCase();
  const normalized = normalizeEnvVarName(name);
  if (!rawUpper && !normalized) return false;

  if (SAFE_EXCLUDED_ENV_VARS.has(rawUpper) || SAFE_EXCLUDED_ENV_VARS.has(normalized)) {
    return false;
  }
  if (
    SAFE_EXCLUDED_ENV_PREFIXES.some(
      (prefix) => rawUpper.startsWith(prefix) || normalized.startsWith(prefix),
    )
  ) {
    return false;
  }

  return matchesSensitiveCatalog(rawUpper) || matchesSensitiveCatalog(normalized);
}

const EXACT_EXEC_HIJACK_VARS = new Set([
  // POSIX & general tooling
  "NODE_OPTIONS",
  "NODE_PATH",
  "PYTHONPATH",
  "PYTHONSTARTUP",
  "PYTHONHOME",
  "PERL5LIB",
  "PERL5OPT",
  "RUBYOPT",
  "RUBYLIB",
  "JAVA_TOOL_OPTIONS",
  "_JAVA_OPTIONS",
  "BASH_ENV",
  "ENV",
  "ZDOTDIR",
  "PROMPT_COMMAND",
  "PATH",
  "HOME",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  "DOTNET_CLI_HOME",
  "SSH_AUTH_SOCK",
  "GIT_DIR",
  "GIT_WORK_TREE",
  "GIT_CONFIG_COUNT",
  "GIT_SSH",
  "GIT_EXEC_PATH",
  "GIT_TEMPLATE_DIR",
  "GIT_CONFIG_PARAMETERS",
  "GIT_CONFIG_GLOBAL",
  "GIT_CONFIG_SYSTEM",
  "GIT_EDITOR",
  "GIT_PAGER",
  "GIT_ASKPASS",
  "SSH_ASKPASS",
  "EDITOR",
  "VISUAL",
  "PAGER",
  "MANPAGER",
  "BROWSER",
  "LESSOPEN",
  "LESSCLOSE",
  "RUSTC_WRAPPER",
  "CARGO_BUILD_RUSTC_WRAPPER",
  "NPM_CONFIG_SCRIPT_SHELL",
  "NPM_CONFIG_NODE_OPTIONS",
  // Paseo / plugin self-location overrides
  "PASEO_HOME",
  "PASEO_PLUGIN_DIR",
  "PASEO_GUARDIAN_DATA_DIR",
  // Windows / PowerShell / .NET / MSBuild (ADR-0006)
  "USERPROFILE",
  "APPDATA",
  "LOCALAPPDATA",
  "PROGRAMDATA",
  "PSMODULEPATH",
  "PATHEXT",
  "COMSPEC",
  "SYSTEMROOT",
  "WINDIR",
  "DOTNET_STARTUP_HOOKS",
  "DOTNET_ADDITIONAL_DEPS",
  "DOTNET_SHARED_STORE",
  "DOTNET_ROOT",
  "DOTNET_ROOT_X86",
  "DOTNET_ROOT_X64",
  "DOTNET_ROOT(X86)",
  "DOTNET_ENABLE_PROFILING",
  "MSBUILD_EXE_PATH",
  "MSBUILDSDKSPATH",
  "MSBUILDEXTENSIONSPATH",
  "__PSLOCKDOWNPOLICY",
  "PSEXECUTIONPOLICYPREFERENCE",
]);

const EXEC_HIJACK_PREFIXES = [
  "LD_",
  "DYLD_",
  "BASH_FUNC_",
  "GIT_CONFIG_KEY_",
  "GIT_CONFIG_VALUE_",
  "COR_",
  "CORECLR_",
  "DOTNET_PROFILER",
  "COMPLUS_",
];

/**
 * Matches execution-hijack env vars using direct ASCII uppercase ONLY (never
 * camelCase-to-SNAKE conversion) so `PSModulePath` / `MSBuildSDKsPath` match accurately.
 */
export function isExecHijackEnvVar(name: string, value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return false;
  }
  const upper = name.trim().toUpperCase();
  if (!upper) {
    return false;
  }

  if (upper === "CC" || upper === "CXX") {
    return (
      trimmed.includes("/") ||
      trimmed.includes("\\") ||
      /^[A-Za-z]:/.test(trimmed) ||
      /\s/.test(trimmed)
    );
  }
  if (EXACT_EXEC_HIJACK_VARS.has(upper)) {
    return true;
  }
  if (EXEC_HIJACK_PREFIXES.some((prefix) => upper.startsWith(prefix))) {
    return true;
  }
  if (/^GIT_.*_COMMAND$/.test(upper) || /^CARGO_TARGET_.*_RUNNER$/.test(upper)) {
    return true;
  }
  return false;
}

const EXACT_REDIRECT_OR_TLS_VARS = new Set([
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "PIP_INDEX_URL",
  "PIP_EXTRA_INDEX_URL",
  "PIP_TRUSTED_HOST",
  "UV_INDEX_URL",
  "UV_INSECURE_HOST",
  "GOPROXY",
  "SSL_CERT_FILE",
  "NODE_EXTRA_CA_CERTS",
  "REQUESTS_CA_BUNDLE",
  "CURL_CA_BUNDLE",
]);

/**
 * Matches redirect, proxy, and TLS-bypass env vars using direct ASCII uppercase ONLY.
 */
export function isRedirectOrTlsEnvVar(name: string, value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return false;
  }
  const upper = name.trim().toUpperCase();
  if (!upper) {
    return false;
  }

  if (upper === "NODE_TLS_REJECT_UNAUTHORIZED") {
    return trimmed !== "1";
  }
  if (upper === "PYTHONHTTPSVERIFY") {
    // PEP 493 / Python 2.7.12+ defense-in-depth
    return trimmed === "0";
  }
  if (upper === "GIT_SSL_NO_VERIFY") {
    const lower = trimmed.toLowerCase();
    return lower !== "0" && lower !== "false";
  }
  if (upper === "DOTNET_NUGET_SIGNATURE_VERIFICATION") {
    const lower = trimmed.toLowerCase();
    return lower === "false" || lower === "0";
  }
  if (upper === "NUGET_CERT_REVOCATION_MODE") {
    return trimmed.toLowerCase() !== "online";
  }

  if (EXACT_REDIRECT_OR_TLS_VARS.has(upper)) {
    return true;
  }
  if (
    upper.endsWith("_BASE_URL") ||
    upper.endsWith("_API_BASE") ||
    upper.endsWith("_ENDPOINT") ||
    upper.startsWith("CARGO_REGISTRIES_")
  ) {
    return true;
  }
  if (
    upper.startsWith("NPM_CONFIG_") &&
    upper !== "NPM_CONFIG_SCRIPT_SHELL" &&
    upper !== "NPM_CONFIG_NODE_OPTIONS"
  ) {
    return true;
  }

  return false;
}

export function isTempDirEnvVar(name: string): boolean {
  const upper = name.trim().toUpperCase();
  return upper === "TEMP" || upper === "TMP" || upper === "TMPDIR";
}

export function isPersistentEnvTarget(target: string): "user" | "machine" | null {
  const norm = target.trim().toLowerCase();
  if (
    norm === "user" ||
    norm === "1" ||
    norm === "[environmentvariabletarget]::user" ||
    norm.startsWith("hkcu:") ||
    norm.startsWith("hkcu\\") ||
    norm.startsWith("hkey_current_user\\")
  ) {
    return "user";
  }
  if (
    norm === "machine" ||
    norm === "2" ||
    norm === "[environmentvariabletarget]::machine" ||
    norm.startsWith("hklm:") ||
    norm.startsWith("hklm\\") ||
    norm.startsWith("hkey_local_machine\\")
  ) {
    return "machine";
  }
  return null;
}

export function classifyExecutionPolicyEnvVar(
  name: string,
  value: string,
): "bypass" | "non_empty" | null {
  if (name.trim().toUpperCase() !== "PSEXECUTIONPOLICYPREFERENCE") {
    return null;
  }
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return null;
  }
  const lower = trimmed.toLowerCase();
  if (lower === "bypass" || lower === "unrestricted") {
    return "bypass";
  }
  return "non_empty";
}

export interface WslEnvClassification {
  hasSensitive: boolean;
  hasHijack: boolean;
  hasOther: boolean;
  sensitiveVars: string[];
  hijackVars: string[];
}

export function classifyWslEnvValue(value: string): WslEnvClassification {
  const trimmed = value.trim();
  if (!trimmed) {
    return {
      hasSensitive: false,
      hasHijack: false,
      hasOther: false,
      sensitiveVars: [],
      hijackVars: [],
    };
  }

  if (/[$%!]/.test(trimmed)) {
    return {
      hasSensitive: false,
      hasHijack: false,
      hasOther: true,
      sensitiveVars: [],
      hijackVars: [],
    };
  }

  const sensitiveVars: string[] = [];
  const hijackVars: string[] = [];
  let hasOther = false;

  for (const rawEntry of trimmed.split(":")) {
    const entry = rawEntry.trim();
    if (!entry) continue;
    const varName = entry.replace(/(?:\/[pwul]+)+$/i, "").trim();
    if (!varName) {
      hasOther = true;
      continue;
    }

    const isSens = isSensitiveEnvVarName(varName);
    const isHijack = isExecHijackEnvVar(varName, "x");
    if (isSens) {
      sensitiveVars.push(varName);
    }
    if (isHijack) {
      hijackVars.push(varName);
    }
    if (!isSens && !isHijack) {
      hasOther = true;
    }
  }

  return {
    hasSensitive: sensitiveVars.length > 0,
    hasHijack: hijackVars.length > 0,
    hasOther,
    sensitiveVars: Array.from(new Set(sensitiveVars)),
    hijackVars: Array.from(new Set(hijackVars)),
  };
}

const SENSITIVE_CLI_FLAG_EXACT = new Set([
  "PASSWORD",
  "PASSWD",
  "PASSPHRASE",
  "SECRET",
  "TOKEN",
  "API_KEY",
  "APIKEY",
  "ACCESS_KEY",
  "SECRET_KEY",
  "PRIVATE_KEY",
  "AUTH_TOKEN",
  "ACCESS_TOKEN",
  "REFRESH_TOKEN",
  "ID_TOKEN",
  "CLIENT_SECRET",
  "BEARER",
  "CREDENTIAL",
  "CREDENTIALS",
  "SESSION_TOKEN",
  "AUTH_HEADER",
  "AUTHORIZATION",
]);

const SENSITIVE_CLI_FLAG_SUFFIXES = [
  "_PASSWORD",
  "_PASSWD",
  "_PASSPHRASE",
  "_SECRET",
  "_TOKEN",
  "_API_KEY",
  "_APIKEY",
  "_ACCESS_KEY",
  "_SECRET_KEY",
  "_PRIVATE_KEY",
  "_CREDENTIAL",
  "_CREDENTIALS",
];

/**
 * Matches sensitive CLI flag names (e.g. `--password`, `--token`, `-Password`, `--api-key`),
 * while excluding benign flags like `--key`, `--author`, `--keymap`.
 */
export function isSensitiveCliFlag(flagName: string): boolean {
  const stripped = flagName.trim().replace(/^-+/, "");
  if (!stripped) return false;
  const upper = normalizeEnvVarName(stripped);
  if (!upper) return false;
  if (SENSITIVE_CLI_FLAG_EXACT.has(upper)) {
    return true;
  }
  return SENSITIVE_CLI_FLAG_SUFFIXES.some((suffix) => upper.endsWith(suffix));
}
