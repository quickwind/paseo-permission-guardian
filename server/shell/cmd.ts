import { win32 } from "node:path";
import { mapWindowsToWslPath, stripProviderDrive } from "../paths/windows.js";
import type { AssignmentFact, CommandFact, PipelineFact, RedirectionFact } from "./types.js";

export const SAFE_CMD_SYSTEM_MACROS = new Set([
  "TEMP",
  "TMP",
  "USERPROFILE",
  "LOCALAPPDATA",
  "APPDATA",
  "PROGRAMFILES",
  "PROGRAMFILES(X86)",
  "PROGRAMDATA",
  "SYSTEMROOT",
  "WINDIR",
  "CD",
  "PATH",
  "ERRORLEVEL",
  "USERNAME",
  "COMPUTERNAME",
  "OS",
  "DATE",
  "TIME",
  "HOMEDRIVE",
  "HOMEPATH",
  "PROCESSOR_ARCHITECTURE",
  "NUMBER_OF_PROCESSORS",
]);

/**
 * Paseo path macros: substituted only when the env snapshot provides a value (so the Path Model
 * sees the real plugin-self root); unset ⇒ opaque `cmd_unknown_expansion` as before (N3).
 */
export const PASEO_PATH_ENV_MACROS = new Set(["PASEO_HOME", "PASEO_PLUGIN_DIR", "PASEO_GUARDIAN_DATA_DIR"]);

export interface CmdPercentScanOptions {
  isCommandName?: boolean;
  inControlBlock?: boolean;
  reassignedVars?: ReadonlySet<string>;
  envSnapshot?: Record<string, string | undefined>;
}

export interface CmdPercentScanResult {
  envReads: string[];
  opaque: string[];
  expandedText: string;
}

export interface CmdParseOptions {
  cwd?: string;
  home?: string;
  cwdUncertain?: boolean;
  envSnapshot?: Record<string, string | undefined>;
  ifDepth?: number;
}

export interface CmdParseOutput {
  commands: CommandFact[];
  pipelines: PipelineFact[];
  opaque: string[];
  envReads: string[];
  assignments: AssignmentFact[];
  unescapedSource: string;
}

function getEnvValueInsensitive(
  env: Record<string, string | undefined> | undefined,
  name: string,
): string | undefined {
  if (!env) return undefined;
  const target = name.toUpperCase();
  for (const [k, v] of Object.entries(env)) {
    if (k.toUpperCase() === target && typeof v === "string") {
      return v;
    }
  }
  return undefined;
}

/**
 * Scan cmd.exe percent (`%VAR%`) and delayed (`!VAR!`) variable expansions,
 * enforcing the 4 ADR-0006 guardrails for safe system macro allowlisting.
 */
export function scanCmdPercentExpansions(
  text: string,
  opts: CmdPercentScanOptions = {},
): CmdPercentScanResult {
  const envReads: string[] = [];
  const opaque: string[] = [];
  let expandedText = "";
  let inQuotes = false;
  let i = 0;

  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') {
      inQuotes = !inQuotes;
      expandedText += ch;
      i += 1;
      continue;
    }

    // Delayed expansion `!VAR!`
    if (ch === "!") {
      const end = text.indexOf("!", i + 1);
      if (end > i + 1) {
        const inner = text.slice(i + 1, end);
        const nameMatch = inner.match(/^([A-Za-z_][A-Za-z0-9_()]*)(?::.*)?$/);
        if (nameMatch) {
          const varName = nameMatch[1].toUpperCase();
          envReads.push(varName);
          opaque.push("cmd_delayed_expansion");
          expandedText += text.slice(i, end + 1);
          i = end + 1;
          continue;
        }
      }
      expandedText += ch;
      i += 1;
      continue;
    }

    if (ch === "%") {
      if (text[i + 1] === "%") {
        opaque.push("cmd_double_percent");
        expandedText += "%%";
        i += 2;
        continue;
      }

      const end = text.indexOf("%", i + 1);
      if (end > i + 1) {
        const inner = text.slice(i + 1, end);
        // Substring or replacement `%VAR:~n,m%` / `%VAR:a=b%` (including non-identifier names)
        const modMatch = inner.match(/^([^:\r\n=%]+):(.*)$/);
        if (modMatch) {
          const varName = modMatch[1].trim().toUpperCase();
          envReads.push(varName);
          opaque.push("cmd_substring_obfuscation");
          expandedText += text.slice(i, end + 1);
          i = end + 1;
          continue;
        }

        // Batch positional `%~dp0` or `%1`
        if (/^[~*0-9]/.test(inner)) {
          opaque.push("cmd_batch_arg_expansion");
          expandedText += text.slice(i, end + 1);
          i = end + 1;
          continue;
        }

        const varMatch = inner.match(/^([^%\r\n=]+)$/);
        if (varMatch) {
          const varName = varMatch[1].trim().toUpperCase();
          envReads.push(varName);

          const reassigned = opts.reassignedVars?.has(varName) ?? false;
          const snapVal = getEnvValueInsensitive(opts.envSnapshot, varName);
          const isSafeMacro =
            SAFE_CMD_SYSTEM_MACROS.has(varName) ||
            (PASEO_PATH_ENV_MACROS.has(varName) && snapVal !== undefined && snapVal.trim() !== "");

          let safeSnapshot = true;
          if (snapVal !== undefined) {
            safeSnapshot = inQuotes
              ? !/["%!]/.test(snapVal)
              : !/[&|<>^()%!"]/.test(snapVal);
          }

          const allowSubstitute =
            isSafeMacro &&
            !opts.isCommandName &&
            !opts.inControlBlock &&
            !reassigned &&
            safeSnapshot;

          if (!allowSubstitute) {
            opaque.push(`cmd_unknown_expansion:${varName}`);
          }

          expandedText +=
            allowSubstitute && snapVal !== undefined ? snapVal : text.slice(i, end + 1);
          i = end + 1;
          continue;
        }
      }
    }

    expandedText += ch;
    i += 1;
  }

  return {
    envReads: Array.from(new Set(envReads)),
    opaque: Array.from(new Set(opaque)),
    expandedText,
  };
}

function unescapeCmdCarets(raw: string): {
  unescaped: string;
  caretCountOutsideQuotes: number;
  hasBang: boolean;
} {
  let out = "";
  let inQuotes = false;
  let caretCount = 0;
  let hasBang = false;

  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch === "!") hasBang = true;
    if (ch === '"') {
      inQuotes = !inQuotes;
      out += ch;
      continue;
    }
    if (!inQuotes && ch === "^") {
      caretCount += 1;
      if (raw[i + 1] === "\r" && raw[i + 2] === "\n") {
        i += 2;
        continue;
      }
      if (raw[i + 1] === "\n") {
        i += 1;
        continue;
      }
      if (i + 1 < raw.length) {
        out += raw[i + 1];
        i += 1;
        continue;
      }
    }
    out += ch;
  }

  return { unescaped: out, caretCountOutsideQuotes: caretCount, hasBang };
}

interface RawSegment {
  text: string;
  opAfter: "&" | "&&" | "||" | "|" | ";" | null;
  parenDepth: number;
}

function splitCmdSegments(source: string): {
  segments: RawSegment[];
  unmatchedQuotes: boolean;
  hasCaretAndBang: boolean;
} {
  const segments: RawSegment[] = [];
  let inQuotes = false;
  let parenDepth = 0;
  let current = "";
  let hasCaretOutside = false;
  let hasBang = false;

  for (let i = 0; i < source.length; i++) {
    const ch = source[i];
    if (ch === "!") hasBang = true;

    if (ch === '"') {
      inQuotes = !inQuotes;
      current += ch;
      continue;
    }

    if (!inQuotes && ch === "^") {
      hasCaretOutside = true;
      if (source[i + 1] === "\r" && source[i + 2] === "\n") {
        i += 2;
        continue;
      }
      if (source[i + 1] === "\n") {
        i += 1;
        continue;
      }
      if (i + 1 < source.length) {
        // Keep caret intact in raw segment so tokenizers see escaped operators vs unescaped separators
        current += ch + source[i + 1];
        i += 1;
        continue;
      }
    }

    if (!inQuotes) {
      if (ch === "(") {
        parenDepth += 1;
        current += ch;
        continue;
      }
      if (ch === ")") {
        parenDepth = Math.max(0, parenDepth - 1);
        current += ch;
        continue;
      }

      if (ch === "&" && source[i + 1] === "&") {
        segments.push({ text: current, opAfter: "&&", parenDepth });
        current = "";
        i += 1;
        continue;
      }
      if (ch === "|" && source[i + 1] === "|") {
        segments.push({ text: current, opAfter: "||", parenDepth });
        current = "";
        i += 1;
        continue;
      }
      if (ch === "&") {
        // Check redirection like `2>&1` or `1>&2`
        if (/[0-9]>$/.test(current)) {
          current += ch;
          continue;
        }
        segments.push({ text: current, opAfter: "&", parenDepth });
        current = "";
        continue;
      }
      if (ch === "|") {
        segments.push({ text: current, opAfter: "|", parenDepth });
        current = "";
        continue;
      }
      if (ch === "\n") {
        segments.push({ text: current, opAfter: ";", parenDepth });
        current = "";
        continue;
      }
    }

    current += ch;
  }

  if (current.trim().length > 0 || segments.length === 0) {
    segments.push({ text: current, opAfter: null, parenDepth });
  }

  return {
    segments,
    unmatchedQuotes: inQuotes,
    hasCaretAndBang: hasCaretOutside && hasBang,
  };
}

interface TokenizedSegment {
  tokens: string[];
  rawTokens: string[];
  redirections: RedirectionFact[];
  caretCounts: number[];
}

const CMD_DELIM_BUILTINS = new Set([
  "cd",
  "chdir",
  "rd",
  "rmdir",
  "del",
  "erase",
  "dir",
  "type",
  "copy",
  "move",
  "ren",
  "rename",
  "md",
  "mkdir",
  "pushd",
  "popd",
]);

function splitChainedCmdSwitches(tok: string): string[] {
  if (/^\/[pqfsaw](?:\/[pqfsaw])+$/i.test(tok)) {
    return tok
      .slice(1)
      .split("/")
      .map((s) => `/${s}`);
  }
  return [tok];
}

function splitBuiltinRest(rest: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inQuotes = false;

  for (let idx = 0; idx < rest.length; idx++) {
    const ch = rest[idx];
    if (ch === '"') {
      inQuotes = !inQuotes;
      continue;
    }
    if (!inQuotes && (ch === "," || ch === ";" || ch === "=" || /\s/.test(ch))) {
      if (cur.length > 0) {
        out.push(...splitChainedCmdSwitches(cur));
        cur = "";
      }
      continue;
    }
    if (!inQuotes && ch === "^" && idx + 1 < rest.length) {
      cur += rest[idx + 1];
      idx += 1;
      continue;
    }
    cur += ch;
  }
  if (cur.length > 0) {
    out.push(...splitChainedCmdSwitches(cur));
  }
  return out;
}

function tokenizeSegment(segText: string): TokenizedSegment {
  const tokens: string[] = [];
  const rawTokens: string[] = [];
  const redirections: RedirectionFact[] = [];
  const caretCounts: number[] = [];

  let i = 0;
  const n = segText.length;
  let isDelimBuiltin: boolean = false;

  function readWord(): { clean: string; raw: string; carets: number } {
    let clean = "";
    let raw = "";
    let inQuotes = false;
    let carets = 0;

    while (i < n) {
      const ch = segText[i];
      if (!inQuotes && /\s/.test(ch)) {
        break;
      }
      if (!inQuotes && isDelimBuiltin && (ch === "," || ch === ";" || ch === "=")) {
        break;
      }
      if (!inQuotes && (ch === ">" || ch === "<")) {
        break;
      }
      if (
        !inQuotes &&
        (ch === "1" || ch === "2") &&
        segText[i + 1] === ">" &&
        clean.length === 0
      ) {
        break;
      }
      if (ch === '"') {
        inQuotes = !inQuotes;
        raw += ch;
        i += 1;
        continue;
      }
      if (!inQuotes && ch === "^" && i + 1 < n) {
        carets += 1;
        raw += ch + segText[i + 1];
        clean += segText[i + 1];
        i += 2;
        continue;
      }
      raw += ch;
      clean += ch;
      i += 1;
    }
    return { clean, raw, carets };
  }

  while (i < n) {
    while (
      i < n &&
      (/\s/.test(segText[i]) ||
        (isDelimBuiltin && (segText[i] === "," || segText[i] === ";" || segText[i] === "=")))
    ) {
      i += 1;
    }
    if (i >= n) break;

    const rest = segText.slice(i);
    const redirMatch = rest.match(/^([0-9]*>>|[0-9]*>&[0-9]+|[0-9]*>|<)/);
    if (redirMatch) {
      const op = redirMatch[1];
      i += op.length;
      if (/^[0-9]*>&[0-9]+$/.test(op)) {
        // Stream duplication like `2>&1` does not touch files
        continue;
      }
      while (i < n && /\s/.test(segText[i])) i += 1;
      const prevDelim: boolean = isDelimBuiltin;
      isDelimBuiltin = false;
      const dest = readWord();
      isDelimBuiltin = prevDelim;
      if (dest.clean) {
        redirections.push({
          operator: op,
          target: dest.clean,
          isWrite: op.includes(">"),
          isRead: op.includes("<"),
        });
      }
      continue;
    }

    const w = readWord();
    if (w.raw.length > 0) {
      if (tokens.length === 0) {
        const cleanFirst = w.clean.replace(/^@+/, "");
        const punctMatch =
          !/\.(?:exe|cmd|bat|com)$/i.test(cleanFirst) &&
          !w.raw.startsWith('"') &&
          cleanFirst.match(
            /^(cd|chdir|rd|rmdir|del|erase|dir|type|copy|move|ren|rename|md|mkdir|pushd|popd)([\\./,;:=+[\]].*)$/i,
          );
        if (punctMatch && CMD_DELIM_BUILTINS.has(punctMatch[1].toLowerCase())) {
          isDelimBuiltin = true;
          tokens.push(punctMatch[1]);
          rawTokens.push(punctMatch[1]);
          caretCounts.push(w.carets);
          for (const extra of splitBuiltinRest(punctMatch[2])) {
            tokens.push(extra);
            rawTokens.push(extra);
            caretCounts.push(0);
          }
          continue;
        }
        if (CMD_DELIM_BUILTINS.has(cleanFirst.toLowerCase())) {
          isDelimBuiltin = true;
        }
      }

      if (isDelimBuiltin && tokens.length > 0 && !w.raw.startsWith('"')) {
        for (const piece of splitChainedCmdSwitches(w.clean)) {
          tokens.push(piece);
          rawTokens.push(piece);
          caretCounts.push(w.carets);
        }
      } else {
        tokens.push(w.clean);
        rawTokens.push(w.raw);
        caretCounts.push(w.carets);
      }
    }
  }

  return { tokens, rawTokens, redirections, caretCounts };
}

function resolveStaticWindowsCwd(currentCwd: string, target: string): string | null {
  if (!target || target === "-" || /^\.{3,}$/.test(target.trim()) || /[$`%!]/.test(target) || stripProviderDrive(target)) {
    return null;
  }
  const cleanTarget = target.replaceAll("/", "\\");
  if (/^\\\\/.test(cleanTarget)) {
    return null; // UNC
  }
  if (/^[A-Za-z]:$/.test(cleanTarget) || /^[A-Za-z]:(?![\\/])/.test(cleanTarget)) {
    return null; // bare drive switch or drive-relative
  }
  const cwdClean = currentCwd.replaceAll("/", "\\");
  if (/^[A-Za-z]:/.test(cleanTarget)) {
    return win32.normalize(cleanTarget);
  }
  if (/^[A-Za-z]:/.test(cwdClean)) {
    return win32.resolve(cwdClean, cleanTarget);
  }
  return win32.resolve(cwdClean, cleanTarget);
}

function extractSetArithmeticReads(expr: string): string[] {
  const reads: string[] = [];
  // Match identifiers not starting with digit and not part of 0x... hex
  const rx = /\b([A-Za-z_][A-Za-z0-9_]*)\b/g;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(expr)) !== null) {
    if (m.index > 0 && expr[m.index - 1] === "0") continue;
    reads.push(m[1]);
  }
  return Array.from(new Set(reads));
}

function parseSetSegment(
  segText: string,
  tokenized: TokenizedSegment,
  depth: number,
): {
  fact: CommandFact;
  assignment?: AssignmentFact;
  extraEnvReads: string[];
  extraOpaque: string[];
} {
  const rawAfterSet = segText.replace(/^\s*(?:@)?[sS][eE][tT]\b\s*/, "");
  const extraOpaque: string[] = [];
  const extraEnvReads: string[] = [];
  const assignmentsMap: Record<string, string> = {};
  let assignment: AssignmentFact | undefined;

  if (!rawAfterSet.trim()) {
    return {
      fact: {
        name: "set",
        argv: [],
        rawText: segText.trim(),
        redirections: tokenized.redirections,
        assignments: assignmentsMap,
        envReads: [],
        depth,
        layer: "cmd",
      },
      extraEnvReads,
      extraOpaque,
    };
  }

  // Handle `set /a ...`
  const arithMatch = rawAfterSet.match(/^\/[aA]\s+(.*)$/);
  if (arithMatch) {
    extraOpaque.push("cmd_set_arithmetic");
    const expr = arithMatch[1].trim();
    const eqIdx = expr.indexOf("=");
    if (eqIdx > 0) {
      const lhs = expr.slice(0, eqIdx).trim().replace(/[+\-*/%&|^]$/, "").trim();
      const rhs = expr.slice(eqIdx + 1);
      if (/^[A-Za-z_][A-Za-z0-9_()]*$/.test(lhs)) {
        assignmentsMap[lhs] = rhs.trim();
        assignment = {
          name: lhs,
          value: rhs.trim(),
          standalone: true,
          depth,
          source: "standalone",
        };
      }
      extraEnvReads.push(...extractSetArithmeticReads(rhs));
    } else {
      extraEnvReads.push(...extractSetArithmeticReads(expr));
    }

    return {
      fact: {
        name: "set",
        argv: ["/a", expr],
        rawText: segText.trim(),
        redirections: tokenized.redirections,
        assignments: assignmentsMap,
        envReads: Array.from(new Set(extraEnvReads)),
        depth,
        layer: "cmd",
      },
      assignment,
      extraEnvReads,
      extraOpaque,
    };
  }

  // Handle `set /p var=...`
  const promptMatch = rawAfterSet.match(/^\/[pP]\s+([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$/);
  if (promptMatch) {
    const hasInputRedirect = tokenized.redirections.some((r) => r.isRead);
    if (!hasInputRedirect) {
      extraOpaque.push("cmd_set_prompt_stdin");
    }
    return {
      fact: {
        name: "set",
        argv: ["/p", promptMatch[1]],
        rawText: segText.trim(),
        redirections: tokenized.redirections,
        assignments: assignmentsMap,
        envReads: [],
        depth,
        layer: "cmd",
      },
      extraEnvReads,
      extraOpaque,
    };
  }

  // Handle `set "VAR=VAL"` (quotes wrap the whole pair and are stripped)
  const quotedAssign = rawAfterSet.match(/^\s*"([^"=]+)=([^"]*)"\s*(?:[<>].*)?$/);
  if (quotedAssign) {
    const name = quotedAssign[1].trim();
    const value = quotedAssign[2];
    assignmentsMap[name] = value;
    assignment = {
      name,
      value,
      standalone: true,
      depth,
      source: "standalone",
    };
    return {
      fact: {
        name: "set",
        argv: [`${name}=${value}`],
        rawText: segText.trim(),
        redirections: tokenized.redirections,
        assignments: assignmentsMap,
        envReads: [],
        depth,
        layer: "cmd",
      },
      assignment,
      extraEnvReads,
      extraOpaque,
    };
  }

  // Handle `set VAR=VAL` (preserves trailing spaces & literal quotes on RHS)
  const plainAssign = rawAfterSet.match(/^([^=\s][^=]*)=(.*)$/);
  if (plainAssign) {
    const name = plainAssign[1];
    // Strip trailing redirection if present outside quotes
    const rawVal = plainAssign[2].replace(/\s+[0-9]*[<>].*$/, "");
    assignmentsMap[name] = rawVal;
    assignment = {
      name,
      value: rawVal,
      standalone: true,
      depth,
      source: "standalone",
    };
    return {
      fact: {
        name: "set",
        argv: [`${name}=${rawVal}`],
        rawText: segText.trim(),
        redirections: tokenized.redirections,
        assignments: assignmentsMap,
        envReads: [],
        depth,
        layer: "cmd",
      },
      assignment,
      extraEnvReads,
      extraOpaque,
    };
  }

  // Otherwise `set PREFIX` -> env dump matching prefix
  return {
    fact: {
      name: "set",
      argv: tokenized.tokens.slice(1),
      rawText: segText.trim(),
      redirections: tokenized.redirections,
      assignments: assignmentsMap,
      envReads: [],
      depth,
      layer: "cmd",
    },
    extraEnvReads,
    extraOpaque,
  };
}

const CMD_IF_COMPARISONS = new Set(["==", "equ", "neq", "lss", "leq", "gtr", "geq"]);

function readRawCmdToken(
  input: string,
  start: number,
): { raw: string; unquoted: string; hasUnquotedEqEq: boolean; end: number } | null {
  const n = input.length;
  let idx = start;
  while (idx < n && /\s/.test(input[idx])) idx += 1;
  if (idx >= n) return null;

  const tokenStart = idx;
  let inQuotes = false;
  let unquoted = "";
  let hasUnquotedEqEq = false;
  let prevUnquotedChar = "";
  while (idx < n) {
    const ch = input[idx];
    if (!inQuotes && /\s/.test(ch)) break;
    if (!inQuotes && ch === "(" && idx > tokenStart) break;
    if (ch === '"') {
      inQuotes = !inQuotes;
      prevUnquotedChar = "";
      idx += 1;
      continue;
    }
    if (!inQuotes && ch === "^" && idx + 1 < n) {
      const escapedCh = input[idx + 1];
      if (escapedCh === "=" && (input[idx + 2] === "=" || prevUnquotedChar === "=")) {
        hasUnquotedEqEq = true;
      }
      prevUnquotedChar = escapedCh;
      unquoted += escapedCh;
      idx += 2;
      continue;
    }
    if (!inQuotes && ch === "=" && (input[idx + 1] === "=" || prevUnquotedChar === "=")) {
      hasUnquotedEqEq = true;
    }
    prevUnquotedChar = !inQuotes ? ch : "";
    unquoted += ch;
    idx += 1;
  }
  return { raw: input.slice(tokenStart, idx), unquoted, hasUnquotedEqEq, end: idx };
}

function splitCmdElseBranches(rest: string): string[] {
  let inQuotes = false;
  for (let i = 0; i < rest.length; i++) {
    const ch = rest[i];
    if (ch === '"') {
      inQuotes = !inQuotes;
      continue;
    }
    if (!inQuotes && ch === "^" && i + 1 < rest.length) {
      i += 1;
      continue;
    }
    if (!inQuotes) {
      const prevOk = i === 0 || rest[i - 1] === ")" || /\s/.test(rest[i - 1]);
      if (prevOk && /^else(?:$|\s|\()/i.test(rest.slice(i))) {
        const afterElse = rest[i + 4];
        if (afterElse === undefined || /\s/.test(afterElse) || afterElse === "(") {
          return [rest.slice(0, i), rest.slice(i + 4)];
        }
      }
    }
  }
  return [rest];
}

function extractCmdIfBranches(segTrim: string): string[] {
  let tok = readRawCmdToken(segTrim, 0);
  if (!tok || tok.unquoted.toLowerCase() !== "if") return [];
  let cursor = tok.end;

  tok = readRawCmdToken(segTrim, cursor);
  if (tok && tok.unquoted.toLowerCase() === "/i") {
    cursor = tok.end;
    tok = readRawCmdToken(segTrim, cursor);
  }
  if (tok && tok.unquoted.toLowerCase() === "not") {
    cursor = tok.end;
    tok = readRawCmdToken(segTrim, cursor);
  }
  if (!tok) return [];

  const condLower = tok.unquoted.toLowerCase();
  let bodyStart = tok.end;
  if (
    condLower === "exist" ||
    condLower === "defined" ||
    condLower === "errorlevel" ||
    condLower === "cmdextversion"
  ) {
    const argTok = readRawCmdToken(segTrim, tok.end);
    if (!argTok) return [];
    bodyStart = argTok.end;
  } else if (tok.hasUnquotedEqEq) {
    if (tok.unquoted.endsWith("==")) {
      const rhsTok = readRawCmdToken(segTrim, tok.end);
      if (!rhsTok) return [];
      bodyStart = rhsTok.end;
    } else {
      bodyStart = tok.end;
    }
  } else {
    const opTok = readRawCmdToken(segTrim, tok.end);
    if (!opTok) return [];
    if (opTok.hasUnquotedEqEq && opTok.unquoted.startsWith("==") && opTok.unquoted.length > 2) {
      bodyStart = opTok.end;
    } else if (CMD_IF_COMPARISONS.has(opTok.unquoted.toLowerCase())) {
      const rhsTok = readRawCmdToken(segTrim, opTok.end);
      if (!rhsTok) return [];
      bodyStart = rhsTok.end;
    } else {
      return [];
    }
  }

  const rest = segTrim.slice(bodyStart).trim();
  if (!rest) return [];

  return splitCmdElseBranches(rest)
    .map((branch) => branch.trim().replace(/^\(+\s*/, "").replace(/\s*\)+$/, "").trim())
    .filter(Boolean);
}

export function parseCmd(
  source: string,
  depth = 0,
  options: CmdParseOptions = {},
): CmdParseOutput {
  const opaque: string[] = [];
  const commands: CommandFact[] = [];
  const pipelines: PipelineFact[] = [];
  const envReads = new Set<string>();
  const assignments: AssignmentFact[] = [];

  if (!source.trim()) {
    return { commands, pipelines, opaque, envReads: [], assignments, unescapedSource: source };
  }

  const unescaped = unescapeCmdCarets(source);
  const split = splitCmdSegments(source);
  if (split.unmatchedQuotes) {
    opaque.push("parse_error");
  }
  if (split.hasCaretAndBang) {
    opaque.push("cmd_caret_obfuscation");
  }

  let currentCwd = options.cwd ?? "C:\\";
  let cwdUncertain = Boolean(options.cwdUncertain);
  const cwdStack: string[] = [];
  const reassignedVars = new Set<string>();

  // Also flag `setlocal enabledelayedexpansion`
  if (/\bsetlocal\s+enabledelayedexpansion\b/i.test(unescaped.unescaped)) {
    opaque.push("cmd_delayed_expansion");
  }

  let nextPipelineId = 1;
  let activePipelineId: number | undefined;
  let activePipelineCmds: string[] = [];
  let activePipelineIndex = 0;

  for (const seg of split.segments) {
    let segTrim = seg.text.trim();
    if (!segTrim) continue;

    const hadParens = seg.parenDepth > 0 || /[()]/.test(segTrim);
    // Strip leading `@` echo suppressor and opening parens `(`
    segTrim = segTrim.replace(/^@+/, "").replace(/^\(+\s*/, "").replace(/\s*\)+$/, "").trim();
    if (!segTrim) continue;

    // Skip comments
    if (segTrim.startsWith("::") || /^rem(?:\s|$)/i.test(segTrim)) {
      continue;
    }

    const tokenized = tokenizeSegment(segTrim);
    if (tokenized.tokens.length === 0) continue;

    const firstClean = tokenized.tokens[0].replace(/^@+/, "");
    const firstLower = firstClean.toLowerCase();
    const unquotedRawTokens = tokenized.rawTokens.filter((rt) => !rt.startsWith('"'));
    const hasIfKeyword =
      firstLower === "if" ||
      unquotedRawTokens.some((rt) => /^(?:if|else)$/i.test(rt.replace(/^[()]+|[()]+$/g, "")));
    const inControlBlock = hadParens || hasIfKeyword || firstLower === "for";

    if ((tokenized.caretCounts[0] ?? 0) >= 4) {
      opaque.push("cmd_caret_obfuscation");
    }

    // Check `%VAR%` and `!VAR!` expansions on command name vs arguments
    const cmdScan = scanCmdPercentExpansions(tokenized.rawTokens[0] ?? firstClean, {
      isCommandName: true,
      inControlBlock,
      reassignedVars,
      envSnapshot: options.envSnapshot,
    });
    for (const v of cmdScan.envReads) envReads.add(v);
    opaque.push(...cmdScan.opaque);

    const argRawSlice = tokenized.rawTokens.slice(1).join(" ");
    const argScan = scanCmdPercentExpansions(argRawSlice, {
      isCommandName: false,
      inControlBlock,
      reassignedVars,
      envSnapshot: options.envSnapshot,
    });
    for (const v of argScan.envReads) envReads.add(v);
    opaque.push(...argScan.opaque);

    // Strip cmd command-name extensions or bare drive switches
    if (/^[A-Za-z]:$/.test(firstClean)) {
      cwdUncertain = true;
      commands.push({
        name: firstClean,
        argv: [],
        rawText: segTrim,
        redirections: tokenized.redirections,
        assignments: {},
        envReads: [],
        depth,
        layer: "cmd",
        cwdChanged: true,
      });
      continue;
    }

    if (firstLower === "call" || firstLower === "goto" || firstLower === "for" || firstLower === "doskey") {
      opaque.push(`cmd_opaque_builtin:${firstLower}`);
    }

    if (hasIfKeyword) {
      cwdUncertain = true;
      opaque.push("cmd_control_flow_if");
    }

    if (/^cd[^a-z0-9_-]/i.test(firstLower) && firstLower !== "cd" && firstLower !== "chdir") {
      cwdUncertain = true;
    }

    // Pipeline bookkeeping
    const startsPipe = seg.opAfter === "|" && activePipelineId === undefined;
    const inPipe = activePipelineId !== undefined || seg.opAfter === "|";
    if (startsPipe) {
      activePipelineId = nextPipelineId++;
      activePipelineCmds = [];
      activePipelineIndex = 0;
    }
    const pipelineId = inPipe ? activePipelineId : undefined;
    const pipelineIndex = inPipe ? activePipelineIndex++ : undefined;

    if (firstLower === "set") {
      const parsedSet = parseSetSegment(segTrim, tokenized, depth);
      opaque.push(...parsedSet.extraOpaque);
      for (const r of parsedSet.extraEnvReads) envReads.add(r);
      if (parsedSet.assignment) {
        assignments.push(parsedSet.assignment);
        reassignedVars.add(parsedSet.assignment.name.toUpperCase());
      }
      const fact: CommandFact = {
        ...parsedSet.fact,
        ...(pipelineId !== undefined ? { pipelineId, pipelineIndex } : {}),
        effectiveCwd: currentCwd,
        ...(cwdUncertain ? { cwdChanged: true } : {}),
      };
      commands.push(fact);
      if (pipelineId !== undefined) activePipelineCmds.push(fact.name);
    } else {
      const argvExpanded = tokenized.tokens.slice(1).map((tok) => {
        const res = scanCmdPercentExpansions(tok, {
          isCommandName: false,
          inControlBlock,
          reassignedVars,
          envSnapshot: options.envSnapshot,
        });
        return res.expandedText;
      });

      const fact: CommandFact = {
        name: firstClean,
        argv: argvExpanded,
        rawText: segTrim,
        redirections: tokenized.redirections,
        assignments: {},
        envReads: Array.from(new Set([...cmdScan.envReads, ...argScan.envReads])),
        ...(pipelineId !== undefined ? { pipelineId, pipelineIndex } : {}),
        depth,
        layer: "cmd",
        effectiveCwd: currentCwd,
        ...(cwdUncertain ? { cwdChanged: true } : {}),
      };
      commands.push(fact);
      if (pipelineId !== undefined) activePipelineCmds.push(fact.name);

      if (firstLower === "if") {
        const curIfDepth = options.ifDepth ?? 0;
        if (curIfDepth >= 3) {
          opaque.push("cmd_if_depth_exceeded");
        } else {
          for (const branch of extractCmdIfBranches(segTrim)) {
            const sub = parseCmd(branch, depth, {
              ...options,
              cwd: currentCwd,
              cwdUncertain: true,
              ifDepth: curIfDepth + 1,
            });
            commands.push(...sub.commands);
            pipelines.push(...sub.pipelines);
            opaque.push(...sub.opaque);
            for (const er of sub.envReads) envReads.add(er);
            assignments.push(...sub.assignments);
          }
        }
      }

      // Update linear cwd on cd / chdir / pushd / popd across sequential chains
      if (seg.opAfter === "||") {
        cwdUncertain = true;
      } else if (firstLower === "cd" || firstLower === "chdir") {
        const hasSlashD = argvExpanded.some((a) => /^\/[dD]$/.test(a));
        const nonFlagArgs = argvExpanded.filter((a) => !/^\/[dD]$/.test(a));
        if (nonFlagArgs.length === 0) {
          // `cd` with no args prints cwd
        } else if (nonFlagArgs.length === 1) {
          const curDrive = currentCwd.match(/^([A-Za-z]):/)?.[1]?.toLowerCase();
          const tgtDrive = nonFlagArgs[0].replaceAll("/", "\\").match(/^([A-Za-z]):[\\/]/)?.[1]?.toLowerCase();
          if (curDrive && tgtDrive && curDrive !== tgtDrive && !hasSlashD) {
            // In cmd.exe, `cd D:\dir` without `/d` only changes D:'s drive dir, not process CWD (H-5)
          } else {
            const next = resolveStaticWindowsCwd(currentCwd, nonFlagArgs[0]);
            if (next) currentCwd = next;
            else cwdUncertain = true;
          }
        } else {
          cwdUncertain = true;
        }
      } else if (firstLower === "pushd") {
        if (argvExpanded.length === 1) {
          const next = resolveStaticWindowsCwd(currentCwd, argvExpanded[0]);
          if (next && !cwdUncertain) {
            cwdStack.push(currentCwd);
            currentCwd = next;
          } else {
            cwdUncertain = true;
          }
        } else {
          cwdUncertain = true;
        }
      } else if (firstLower === "popd") {
        if (!cwdUncertain && cwdStack.length > 0 && argvExpanded.length === 0) {
          currentCwd = cwdStack.pop()!;
        } else {
          cwdUncertain = true;
        }
      }
    }

    if (seg.opAfter !== "|" && activePipelineId !== undefined) {
      pipelines.push({
        id: activePipelineId,
        depth,
        commands: activePipelineCmds,
      });
      activePipelineId = undefined;
      activePipelineCmds = [];
      activePipelineIndex = 0;
    }

    if (seg.opAfter === "||") {
      cwdUncertain = true;
    }
  }

  return {
    commands,
    pipelines,
    opaque: Array.from(new Set(opaque)),
    envReads: Array.from(envReads),
    assignments,
    unescapedSource: unescaped.unescaped,
  };
}
