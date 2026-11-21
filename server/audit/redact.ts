import {
  CREDENTIAL_LITERAL_PATTERNS,
  REDACTED_MARKER,
  isSensitiveEnvVarName,
} from "../secrets/patterns.js";

const SENSITIVE_OBJECT_KEY_PATTERN =
  /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|bearer|secret|client[_-]?secret|password|passwd|private[_-]?key|session[_-]?token)$/i;

const ENV_ASSIGNMENT_CAPTURE_REGEX =
  /\b([A-Za-z_][A-Za-z0-9_]*)(\s*=\s*)("[^"]*"|'[^']*'|[^\s;&|]+)/g;

function toGlobalRegex(regex: RegExp): RegExp {
  const flags = regex.flags.includes("g") ? regex.flags : `${regex.flags}g`;
  return new RegExp(regex.source, flags);
}

export function redactString(value: string): string {
  let out = value;

  for (const spec of CREDENTIAL_LITERAL_PATTERNS) {
    out = out.replace(toGlobalRegex(spec.regex), spec.replacement);
  }

  out = out.replace(
    ENV_ASSIGNMENT_CAPTURE_REGEX,
    (full, name: string, eq: string, rawVal: string) => {
      const stripped =
        (rawVal.startsWith('"') && rawVal.endsWith('"')) ||
        (rawVal.startsWith("'") && rawVal.endsWith("'"))
          ? rawVal.slice(1, -1)
          : rawVal;
      if (stripped.trim().length === 0) {
        return full;
      }
      if (isSensitiveEnvVarName(name)) {
        return `${name}${eq}${REDACTED_MARKER}`;
      }
      return full;
    },
  );

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
      if (SENSITIVE_OBJECT_KEY_PATTERN.test(key) || isSensitiveEnvVarName(key)) {
        out[key] = REDACTED_MARKER;
      } else {
        out[key] = visit(val, depth + 1);
      }
    }
    return out;
  }

  return visit(value, 0) as T;
}
