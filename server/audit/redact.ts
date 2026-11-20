const REDACTED = "[REDACTED]";

const SENSITIVE_KEY_PATTERN =
  /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|bearer|secret|client[_-]?secret|password|passwd|private[_-]?key|session[_-]?token)$/i;

const PEM_BLOCK_PATTERN =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;

const AUTH_HEADER_PATTERN =
  /\b((?:proxy-)?authorization\s*[:=]\s*(?:bearer|basic|token)\s+)([^\s"',;]+)/gi;

const BEARER_TOKEN_PATTERN = /\b(Bearer\s+)([A-Za-z0-9._~+/-]{12,}=*)/g;

const ENV_SECRET_ASSIGN_PATTERN =
  /\b([A-Z][A-Z0-9_]*(?:_KEY|_TOKEN|_SECRET|_PASSWORD|_PASSWD|_API_KEY|_PRIVATE_KEY)\s*=\s*)(?:"[^"]*"|'[^']*'|[^\s;&|]+)/g;

const KNOWN_TOKEN_PATTERNS: readonly RegExp[] = [
  /\bsk-ant-[A-Za-z0-9_-]{16,}\b/g,
  /\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{16,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
];

export function redactString(value: string): string {
  let out = value;
  out = out.replace(PEM_BLOCK_PATTERN, "[REDACTED_PEM_KEY]");
  out = out.replace(AUTH_HEADER_PATTERN, `$1${REDACTED}`);
  out = out.replace(BEARER_TOKEN_PATTERN, `$1${REDACTED}`);
  out = out.replace(ENV_SECRET_ASSIGN_PATTERN, `$1${REDACTED}`);
  for (const pattern of KNOWN_TOKEN_PATTERNS) {
    out = out.replace(pattern, REDACTED);
  }
  return out;
}

export function redactValue<T>(value: T, maxDepth = 12): T {
  const seen = new WeakSet<object>();

  function visit(current: unknown, depth: number): unknown {
    if (typeof current === "string") {
      return redactString(current);
    }
    if (current === null || typeof current !== "object") {
      return current;
    }
    if (depth >= maxDepth) {
      return "[TRUNCATED]";
    }
    if (seen.has(current)) {
      return "[CIRCULAR]";
    }
    seen.add(current);

    if (Array.isArray(current)) {
      return current.map((item) => visit(item, depth + 1));
    }

    const out: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(current as Record<string, unknown>)) {
      if (SENSITIVE_KEY_PATTERN.test(key)) {
        out[key] = REDACTED;
      } else {
        out[key] = visit(val, depth + 1);
      }
    }
    return out;
  }

  return visit(value, 0) as T;
}
