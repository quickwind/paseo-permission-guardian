import {
  CREDENTIAL_LITERAL_PATTERNS,
  REDACTED_MARKER,
  REDACTION_ONLY_CREDENTIAL_PATTERNS,
  isSensitiveCliFlag,
  isSensitiveEnvVarName,
} from "../secrets/patterns.js";

const SENSITIVE_OBJECT_KEY_PATTERN =
  /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|bearer|secret|client[_-]?secret|password|passwd|private[_-]?key|session[_-]?token)$/i;

const ENV_ASSIGNMENT_CAPTURE_REGEX =
  /\b([A-Za-z_][A-Za-z0-9_]*)(\s*=\s*)("[^"]*"|'[^']*'|[^\s;&|]+)/g;

const CLI_FLAG_EQUALS_REGEX =
  /(^|\s)(--?[A-Za-z][A-Za-z0-9_-]*)=("[^"]*"|'[^']*'|[^\s;&|]+)/g;

const CLI_FLAG_SPACE_REGEX =
  /(^|\s)(--?[A-Za-z][A-Za-z0-9_-]*)(\s+)("[^"]*"|'[^']*'|[^\s-][^\s;&|]*)/g;

const MYSQL_ATTACHED_PASS_REGEX = /(\b(?:mysql|mariadb)\b[^\n;&|]*?\s-p)([^\s"'`;&|]+)/gi;
const SSHPASS_PASS_REGEX = /(\bsshpass\b[^\n;&|]*?\s-p\s*)("[^"]*"|'[^']*'|[^\s;&|]+)/gi;
const CURL_USER_PASS_REGEX =
  /(\b(?:curl|wget)\b[^\n;&|]*?\s(?:-u|--user)(?:=|\s+))("([^":\s]+):([^"]+)"|'([^':\s]+):([^']+)'|([^\s:@"'`;&|]+:)([^\s"'`;&|]+))/gi;
const URL_EMBEDDED_CREDS_REGEX =
  /(\b(?:https?|ftps?|wss?|socks5h?):\/\/[^\s/:@"'`;&|]+:)([^\s/@"'`;&|]+)(@)/gi;
const NET_USER_PASS_REGEX =
  /(\bnet(?:\.exe)?\s+user\s+(?:"[^"]+"|[^\s/;&|]+)\s+)(?![/*?])("[^"]*"|'[^']*'|[^\s/;&|][^\s;&|]*)/gi;
const NET_USE_AFTER_USER_REGEX =
  /(\bnet(?:\.exe)?\s+use\s+[^\n;&|]*?\/user:[^\s;&|]+\s+)(?![/*?])("[^"]*"|'[^']*'|[^\s/;&|][^\s;&|]*)/gi;
const NET_USE_BEFORE_USER_REGEX =
  /(\bnet(?:\.exe)?\s+use\s+[^\s;&|]+\s+)(?![/*?])("[^"]*"|'[^']*'|[^\s/;&|][^\s;&|]*)(\s+\/user:)/gi;
const SCHTASKS_OR_SETX_PASS_REGEX =
  /(\b(?:schtasks|setx)(?:\.exe)?\b[^\n;&|]*?\s\/(?:rp|p)\s+)("[^"]*"|'[^']*'|[^\s;&|]+)/gi;
const SC_PASSWORD_REGEX =
  /(\bsc(?:\.exe)?\b[^\n;&|]*?\bpassword=\s*)("[^"]*"|'[^']*'|[^\s;&|]+)/gi;
const CONVERT_SECURE_STRING_REGEX =
  /(\bConvertTo-SecureString\b(?:\s+-String)?\s+)("[^"]*"|'[^']*'|[^\s;&|]+)(\s+[^\n;&|]*?-AsPlainText\b)/gi;

function toGlobalRegex(regex: RegExp): RegExp {
  const flags = regex.flags.includes("g") ? regex.flags : `${regex.flags}g`;
  return new RegExp(regex.source, flags);
}

function stripOuterQuotes(rawVal: string): string {
  if (
    (rawVal.startsWith('"') && rawVal.endsWith('"')) ||
    (rawVal.startsWith("'") && rawVal.endsWith("'"))
  ) {
    return rawVal.slice(1, -1);
  }
  return rawVal;
}

export function redactString(value: string): string {
  let out = value;

  for (const spec of CREDENTIAL_LITERAL_PATTERNS) {
    out = out.replace(toGlobalRegex(spec.regex), spec.replacement);
  }

  for (const spec of REDACTION_ONLY_CREDENTIAL_PATTERNS) {
    out = out.replace(toGlobalRegex(spec.regex), spec.replacement);
  }

  out = out.replace(
    ENV_ASSIGNMENT_CAPTURE_REGEX,
    (full, name: string, eq: string, rawVal: string) => {
      const stripped = stripOuterQuotes(rawVal);
      if (stripped.trim().length === 0) {
        return full;
      }
      if (isSensitiveEnvVarName(name)) {
        return `${name}${eq}${REDACTED_MARKER}`;
      }
      return full;
    },
  );

  out = out.replace(
    CLI_FLAG_EQUALS_REGEX,
    (full, lead: string, flag: string, rawVal: string) => {
      if (!isSensitiveCliFlag(flag)) {
        return full;
      }
      if (stripOuterQuotes(rawVal).trim().length === 0) {
        return full;
      }
      return `${lead}${flag}=${REDACTED_MARKER}`;
    },
  );

  out = out.replace(
    CLI_FLAG_SPACE_REGEX,
    (full, lead: string, flag: string, space: string, rawVal: string) => {
      if (!isSensitiveCliFlag(flag)) {
        return full;
      }
      if (stripOuterQuotes(rawVal).trim().length === 0) {
        return full;
      }
      return `${lead}${flag}${space}${REDACTED_MARKER}`;
    },
  );

  out = out.replace(MYSQL_ATTACHED_PASS_REGEX, `$1${REDACTED_MARKER}`);
  out = out.replace(SSHPASS_PASS_REGEX, `$1${REDACTED_MARKER}`);
  out = out.replace(
    CURL_USER_PASS_REGEX,
    (
      _full,
      prefix: string,
      _whole: string,
      dqUser?: string,
      dqPass?: string,
      sqUser?: string,
      sqPass?: string,
      plainUserColon?: string,
      plainPass?: string,
    ) => {
      if (dqUser !== undefined && dqPass !== undefined) {
        return `${prefix}"${dqUser}:${REDACTED_MARKER}"`;
      }
      if (sqUser !== undefined && sqPass !== undefined) {
        return `${prefix}'${sqUser}:${REDACTED_MARKER}'`;
      }
      if (plainUserColon !== undefined && plainPass !== undefined) {
        return `${prefix}${plainUserColon}${REDACTED_MARKER}`;
      }
      return _full;
    },
  );

  out = out.replace(URL_EMBEDDED_CREDS_REGEX, `$1${REDACTED_MARKER}$3`);
  out = out.replace(NET_USER_PASS_REGEX, `$1${REDACTED_MARKER}`);
  out = out.replace(NET_USE_AFTER_USER_REGEX, `$1${REDACTED_MARKER}`);
  out = out.replace(NET_USE_BEFORE_USER_REGEX, `$1${REDACTED_MARKER}$3`);
  out = out.replace(SCHTASKS_OR_SETX_PASS_REGEX, `$1${REDACTED_MARKER}`);
  out = out.replace(SC_PASSWORD_REGEX, `$1${REDACTED_MARKER}`);
  out = out.replace(CONVERT_SECURE_STRING_REGEX, `$1${REDACTED_MARKER}$3`);

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
