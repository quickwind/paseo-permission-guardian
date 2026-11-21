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

export function isSensitiveEnvVarName(name: string): boolean {
  if (!name) return false;
  const upper = normalizeEnvVarName(name);
  if (!upper) return false;

  if (SAFE_EXCLUDED_ENV_VARS.has(upper)) {
    return false;
  }
  if (SAFE_EXCLUDED_ENV_PREFIXES.some((prefix) => upper.startsWith(prefix))) {
    return false;
  }

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

const EXACT_EXEC_HIJACK_VARS = new Set([
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
]);

const EXEC_HIJACK_PREFIXES = ["LD_", "DYLD_", "BASH_FUNC_"];

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
    return trimmed.includes("/") || /\s/.test(trimmed);
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
  "GOPROXY",
  "SSL_CERT_FILE",
  "NODE_EXTRA_CA_CERTS",
  "REQUESTS_CA_BUNDLE",
  "CURL_CA_BUNDLE",
]);

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
    return trimmed === "0";
  }
  if (upper === "GIT_SSL_NO_VERIFY") {
    const lower = trimmed.toLowerCase();
    return lower !== "0" && lower !== "false";
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
