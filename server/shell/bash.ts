import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { basename, dirname, join } from "node:path";
import type { Language, Node as SyntaxNode, Parser } from "web-tree-sitter";
import { LinearCwdTracker } from "./cwd.js";
import type { AssignmentFact, CommandFact, PipelineFact, RedirectionFact } from "./types.js";

export interface BashParseOutput {
  commands: CommandFact[];
  pipelines: PipelineFact[];
  opaque: string[];
  envReads: string[];
  assignments: AssignmentFact[];
  pwdMutated: boolean;
  cdpathTouched: boolean;
}

export interface BashParseOptions {
  cwd?: string;
  home?: string;
  cwdUncertain?: boolean;
  pwdUncertain?: boolean;
  cdpathActive?: boolean;
  envSnapshot?: Record<string, string | undefined>;
}

function isStandardHeredocDelimiter(raw: string): boolean {
  return (
    /^[^'"\\]+$/.test(raw) ||
    /^'[^']+'$/.test(raw) ||
    /^"[^"\\]+"$/.test(raw) ||
    /^\\[^'"\\]+$/.test(raw)
  );
}

function unquoteHeredocDelimiter(raw: string): string {
  let out = "";
  let quote: "none" | "single" | "double" = "none";
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (quote === "none") {
      if (c === "'") {
        quote = "single";
      } else if (c === '"') {
        quote = "double";
      } else if (c === "\\" && i + 1 < raw.length) {
        i += 1;
        out += raw[i];
      } else {
        out += c;
      }
    } else if (quote === "single") {
      if (c === "'") {
        quote = "none";
      } else {
        out += c;
      }
    } else {
      if (c === "\\" && i + 1 < raw.length && /[\\"$`]/.test(raw[i + 1])) {
        i += 1;
        out += raw[i];
      } else if (c === '"') {
        quote = "none";
      } else {
        out += c;
      }
    }
  }
  return out;
}

function collectAndValidateAstHeredocs(root: SyntaxNode): { astEnds: string[]; hasMismatch: boolean } {
  const astEnds: string[] = [];
  let hasMismatch = false;

  function visit(node: SyntaxNode): void {
    if (node.type === "heredoc_redirect") {
      const startNode = node.namedChildren.find((c) => c.type === "heredoc_start");
      const endNode = node.namedChildren.find((c) => c.type === "heredoc_end");
      if (!startNode || !endNode) {
        hasMismatch = true;
      } else {
        if (!isStandardHeredocDelimiter(startNode.text)) {
          hasMismatch = true;
        }
        const expected = unquoteHeredocDelimiter(startNode.text);
        const actualEnd = endNode.text.replace(/\r$/, "").trim();
        if (actualEnd !== expected) {
          hasMismatch = true;
        }
        astEnds.push(actualEnd);
      }
    }
    for (const child of node.namedChildren) {
      visit(child);
    }
  }

  visit(root);
  return { astEnds, hasMismatch };
}

/**
 * Strips POSIX/bash unescaped `\<newline>` line continuations outside single quotes,
 * ANSI-C `$'...'` strings, `#` comments, and heredoc bodies (matching bash behavior while
 * keeping quoted apostrophes/heredocs synchronized), and tracks heredoc delimiter safety.
 */
function preprocessBashLineContinuations(source: string): {
  source: string;
  hasUnquotedHeredocTrailingBackslash: boolean;
  hasNonStandardHeredocDelimiter: boolean;
  expectedHeredocDelimiters: string[];
} {
  if (!/\\\r?\n/.test(source) && !source.includes("<<")) {
    return {
      source,
      hasUnquotedHeredocTrailingBackslash: false,
      hasNonStandardHeredocDelimiter: false,
      expectedHeredocDelimiters: [],
    };
  }

  let out = "";
  let i = 0;
  const n = source.length;
  let state: "normal" | "single" | "ansi_c" | "double" | "comment" = "normal";
  let hasUnquotedHeredocTrailingBackslash = false;
  let hasNonStandardHeredocDelimiter = false;
  const expectedHeredocDelimiters: string[] = [];
  const arithInnerParens: number[] = [];
  const pendingHeredocs: Array<{ delimiter: string; stripTabs: boolean; quoted: boolean }> = [];

  const hasOddTrailingBackslash = (line: string): boolean => {
    let bsCount = 0;
    for (let k = line.length - 1; k >= 0 && line[k] === "\\"; k -= 1) {
      bsCount += 1;
    }
    return bsCount % 2 === 1;
  };

  const consumeHeredocs = (): void => {
    while (pendingHeredocs.length > 0 && i < n) {
      const { delimiter, stripTabs, quoted } = pendingHeredocs.shift()!;
      while (i < n) {
        const lineEnd = source.indexOf("\n", i);
        if (lineEnd === -1) {
          const rest = source.slice(i);
          const lineContent = rest.endsWith("\r") ? rest.slice(0, -1) : rest;
          if (!quoted && hasOddTrailingBackslash(lineContent)) {
            hasUnquotedHeredocTrailingBackslash = true;
          }
          out += rest;
          i = n;
          break;
        }
        const rawLine = source.slice(i, lineEnd);
        const lineContent = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
        out += source.slice(i, lineEnd + 1);
        i = lineEnd + 1;
        const candidate = stripTabs ? lineContent.replace(/^\t+/, "") : lineContent;
        if (candidate === delimiter) {
          break;
        }
        if (!quoted && hasOddTrailingBackslash(lineContent)) {
          hasUnquotedHeredocTrailingBackslash = true;
        }
      }
    }
  };

  while (i < n) {
    const ch = source[i];

    if (state === "single") {
      out += ch;
      if (ch === "'") {
        state = "normal";
      }
      i += 1;
      continue;
    }

    if (state === "ansi_c") {
      if (ch === "\\" && i + 1 < n) {
        out += ch + source[i + 1];
        i += 2;
        continue;
      }
      out += ch;
      if (ch === "'") {
        state = "normal";
      }
      i += 1;
      continue;
    }

    if (state === "double") {
      if (ch === "\\" && source[i + 1] === "\n") {
        i += 2;
        continue;
      }
      if (ch === "\\" && source[i + 1] === "\r" && source[i + 2] === "\n") {
        i += 3;
        continue;
      }
      if (ch === "\\" && i + 1 < n) {
        out += ch + source[i + 1];
        i += 2;
        continue;
      }
      out += ch;
      if (ch === '"') {
        state = "normal";
      }
      i += 1;
      continue;
    }

    if (state === "comment") {
      out += ch;
      i += 1;
      if (ch === "\n") {
        state = "normal";
        if (pendingHeredocs.length > 0) {
          consumeHeredocs();
        }
      }
      continue;
    }

    // state === "normal"
    if (ch === "\\" && source[i + 1] === "\n") {
      i += 2;
      continue;
    }
    if (ch === "\\" && source[i + 1] === "\r" && source[i + 2] === "\n") {
      i += 3;
      continue;
    }
    if (ch === "\\" && i + 1 < n) {
      out += ch + source[i + 1];
      i += 2;
      continue;
    }

    if (ch === "$" && source[i + 1] === "(" && source[i + 2] === "(") {
      out += "$((";
      arithInnerParens.push(0);
      i += 3;
      continue;
    }
    if (
      ch === "(" &&
      source[i + 1] === "(" &&
      (out.length === 0 || /[\s;|&()]/.test(out[out.length - 1]))
    ) {
      out += "((";
      arithInnerParens.push(0);
      i += 2;
      continue;
    }
    if (arithInnerParens.length > 0) {
      if (ch === "(") {
        arithInnerParens[arithInnerParens.length - 1] += 1;
        out += ch;
        i += 1;
        continue;
      }
      if (ch === ")") {
        const top = arithInnerParens[arithInnerParens.length - 1];
        if (top > 0) {
          arithInnerParens[arithInnerParens.length - 1] = top - 1;
          out += ch;
          i += 1;
          continue;
        }
        if (source[i + 1] === ")") {
          arithInnerParens.pop();
          out += "))";
          i += 2;
          continue;
        }
        arithInnerParens.pop();
      }
    }

    if (ch === "$" && source[i + 1] === "'") {
      out += "$'";
      state = "ansi_c";
      i += 2;
      continue;
    }
    if (ch === "'") {
      out += "'";
      state = "single";
      i += 1;
      continue;
    }
    if (ch === '"') {
      out += '"';
      state = "double";
      i += 1;
      continue;
    }
    if (ch === "#" && (out.length === 0 || /[\s;|&()<>]/.test(out[out.length - 1]))) {
      out += "#";
      state = "comment";
      i += 1;
      continue;
    }

    if (ch === "<" && source[i + 1] === "<" && source[i + 2] === "<") {
      out += "<<<";
      i += 3;
      continue;
    }

    if (
      arithInnerParens.length === 0 &&
      ch === "<" &&
      source[i + 1] === "<" &&
      source[i + 2] !== "<" &&
      source[i + 2] !== "="
    ) {
      out += "<<";
      i += 2;
      let stripTabs = false;
      if (source[i] === "-") {
        stripTabs = true;
        out += "-";
        i += 1;
      }
      while (i < n && (source[i] === " " || source[i] === "\t")) {
        out += source[i];
        i += 1;
      }
      let delim = "";
      let rawDelim = "";
      let delimQuoted = false;
      let delimQuote: "none" | "single" | "double" = "none";
      while (i < n) {
        const dc = source[i];
        if (delimQuote === "none") {
          if (dc === "\\" && source[i + 1] === "\n") {
            i += 2;
            continue;
          }
          if (dc === "\\" && source[i + 1] === "\r" && source[i + 2] === "\n") {
            i += 3;
            continue;
          }
          if (dc === "\\" && i + 1 < n) {
            delimQuoted = true;
            delim += source[i + 1];
            rawDelim += dc + source[i + 1];
            out += dc + source[i + 1];
            i += 2;
            continue;
          }
          if (/[\s;|&()<>]/.test(dc)) {
            break;
          }
          if (dc === "'") {
            delimQuoted = true;
            delimQuote = "single";
            rawDelim += dc;
            out += dc;
            i += 1;
            continue;
          }
          if (dc === '"') {
            delimQuoted = true;
            delimQuote = "double";
            rawDelim += dc;
            out += dc;
            i += 1;
            continue;
          }
          delim += dc;
          rawDelim += dc;
          out += dc;
          i += 1;
        } else if (delimQuote === "single") {
          rawDelim += dc;
          out += dc;
          if (dc === "'") {
            delimQuote = "none";
          } else {
            delim += dc;
          }
          i += 1;
        } else {
          if (dc === "\\" && source[i + 1] === "\n") {
            i += 2;
            continue;
          }
          if (dc === "\\" && source[i + 1] === "\r" && source[i + 2] === "\n") {
            i += 3;
            continue;
          }
          if (dc === "\\" && i + 1 < n) {
            delim += source[i + 1];
            rawDelim += dc + source[i + 1];
            out += dc + source[i + 1];
            i += 2;
            continue;
          }
          rawDelim += dc;
          out += dc;
          if (dc === '"') {
            delimQuote = "none";
          } else {
            delim += dc;
          }
          i += 1;
        }
      }
      if (delim.length > 0) {
        if (!isStandardHeredocDelimiter(rawDelim)) {
          hasNonStandardHeredocDelimiter = true;
        }
        expectedHeredocDelimiters.push(delim);
        pendingHeredocs.push({ delimiter: delim, stripTabs, quoted: delimQuoted });
      }
      continue;
    }

    out += ch;
    i += 1;
    if (ch === "\n" && pendingHeredocs.length > 0) {
      consumeHeredocs();
    }
  }

  return {
    source: out,
    hasUnquotedHeredocTrailingBackslash,
    hasNonStandardHeredocDelimiter,
    expectedHeredocDelimiters,
  };
}

interface WebTreeSitterModule {
  Parser: typeof Parser;
  Language: typeof Language;
}

function getBaseRequire(): NodeRequire {
  if (typeof require === "function" && typeof require.resolve === "function") {
    return require;
  }

  const candidates: Array<string | URL> = [];
  if (typeof import.meta !== "undefined" && typeof import.meta.url === "string" && import.meta.url.length > 0) {
    candidates.push(import.meta.url);
  }
  if (typeof __filename === "string" && __filename.length > 0) {
    candidates.push(__filename);
  }
  if (typeof __dirname === "string" && __dirname.length > 0) {
    candidates.push(join(__dirname, "package.json"));
  }
  const pluginDir = process.env.PASEO_PLUGIN_DIR?.trim();
  if (pluginDir) {
    candidates.push(join(pluginDir, "package.json"));
  }
  candidates.push(join(process.cwd(), "package.json"));

  for (const base of candidates) {
    try {
      const req = createRequire(base);
      req.resolve("web-tree-sitter/web-tree-sitter.wasm");
      return req;
    } catch {
      // try next candidate
    }
  }
  return createRequire(join(process.cwd(), "package.json"));
}

function resolveModuleFile(specifier: string): string {
  const req = getBaseRequire();
  return req.resolve(specifier);
}

let treeSitterPromise: Promise<{ ParserCtor: typeof Parser; language: Language }> | null = null;

async function getBashRuntime(): Promise<{ ParserCtor: typeof Parser; language: Language }> {
  if (!treeSitterPromise) {
    treeSitterPromise = (async () => {
      const runtimeWasmPath = resolveModuleFile("web-tree-sitter/web-tree-sitter.wasm");
      const cjsPath = join(dirname(runtimeWasmPath), "web-tree-sitter.cjs");
      const req = getBaseRequire();
      const wts = req(cjsPath) as WebTreeSitterModule;

      const runtimeWasmBinary = readFileSync(runtimeWasmPath);
      await wts.Parser.init({
        wasmBinary: runtimeWasmBinary,
        locateFile: () => runtimeWasmPath,
      });

      const bashWasmPath = resolveModuleFile("@vscode/tree-sitter-wasm/wasm/tree-sitter-bash.wasm");
      const bashWasmBinary = readFileSync(bashWasmPath);
      const language = await wts.Language.load(bashWasmBinary);

      return { ParserCtor: wts.Parser, language };
    })();
  }
  return treeSitterPromise;
}

const DYNAMIC_NAME_NODE_TYPES = new Set([
  "simple_expansion",
  "expansion",
  "command_substitution",
  "process_substitution",
  "arithmetic_expansion",
  "brace_expression",
]);

const WRITE_REDIRECT_OPS = new Set([">", ">>", ">|", "&>", "&>>", "1>", "1>>", "2>", "2>>", "<>"]);
const READ_REDIRECT_OPS = new Set(["<", "<>"]);

const OBFUSCATION_PATTERNS: readonly { name: string; regex: RegExp }[] = [
  { name: "obfuscation_hex_escape", regex: /(?:\\x[0-9a-fA-F]{2}){6,}/ },
  { name: "obfuscation_long_base64", regex: /\b[A-Za-z0-9+/]{80,}={0,2}\b/ },
];

const CWD_BUILTINS = new Set(["cd", "pushd", "popd"]);

function stripQuotes(node: SyntaxNode): string {
  const text = node.text;
  if (node.type === "raw_string" && text.length >= 2 && text.startsWith("'") && text.endsWith("'")) {
    return text.slice(1, -1);
  }
  if (node.type === "string" && text.length >= 2 && text.startsWith('"') && text.endsWith('"')) {
    return text.slice(1, -1);
  }
  if (node.type === "concatenation") {
    return node.namedChildren.map((child) => stripQuotes(child)).join("");
  }
  return text;
}

function containsDynamicNode(node: SyntaxNode): boolean {
  if (DYNAMIC_NAME_NODE_TYPES.has(node.type)) {
    return true;
  }
  for (const child of node.namedChildren) {
    if (containsDynamicNode(child)) {
      return true;
    }
  }
  return false;
}

function buildUnquotedBraceMask(node: SyntaxNode): string {
  if (
    node.type === "raw_string" ||
    node.type === "string" ||
    node.type === "simple_expansion" ||
    node.type === "expansion" ||
    node.type === "command_substitution" ||
    node.type === "process_substitution" ||
    node.type === "arithmetic_expansion"
  ) {
    return "Q";
  }
  if (node.children.length > 0) {
    return node.children.map((ch) => buildUnquotedBraceMask(ch)).join("");
  }
  return node.text;
}

function hasUnquotedBraceExpansion(node: SyntaxNode): boolean {
  if (node.type === "brace_expression") {
    return true;
  }
  if (
    node.type === "raw_string" ||
    node.type === "string" ||
    node.type === "simple_expansion" ||
    node.type === "expansion" ||
    node.type === "command_substitution" ||
    node.type === "process_substitution" ||
    node.type === "arithmetic_expansion"
  ) {
    return false;
  }
  if (node.type === "concatenation" || node.type === "word") {
    const mask = buildUnquotedBraceMask(node);
    return /\{[^{}]*(?:,|\.\.)[^{}]*\}/.test(mask);
  }
  for (const child of node.namedChildren) {
    if (hasUnquotedBraceExpansion(child)) {
      return true;
    }
  }
  return false;
}

/**
 * Determines whether a path argument AST node contains runtime-dynamic syntax.
 * Simple `$HOME`, `${HOME}`, `$PWD`, `${PWD}` expansions remain static because
 * `LinearCwdTracker` / Path Model expand them deterministically (unless `PWD` was mutated).
 */
function isDynamicPathNode(node: SyntaxNode, allowStaticPwd = true): boolean {
  if (hasUnquotedBraceExpansion(node)) {
    return true;
  }
  if (node.type === "simple_expansion") {
    return !(node.text === "$HOME" || (allowStaticPwd && node.text === "$PWD"));
  }
  if (node.type === "expansion") {
    return !(node.text === "${HOME}" || (allowStaticPwd && node.text === "${PWD}"));
  }
  if (DYNAMIC_NAME_NODE_TYPES.has(node.type)) {
    return true;
  }
  for (const child of node.namedChildren) {
    if (isDynamicPathNode(child, allowStaticPwd)) {
      return true;
    }
  }
  return false;
}

const POSIX_SPECIAL_BUILTINS = new Set([
  ":",
  ".",
  "break",
  "continue",
  "eval",
  "exec",
  "exit",
  "export",
  "readonly",
  "return",
  "set",
  "shift",
  "times",
  "trap",
  "unset",
  "declare",
  "typeset",
  "local",
  "builtin",
  "command",
]);

const PWD_DECLARATION_KEYWORDS = new Set([
  "export",
  "declare",
  "typeset",
  "local",
  "readonly",
]);

const PWD_SHADOW_DECLARATION_KEYWORDS = new Set(["declare", "typeset", "local"]);
const PWD_READ_BUILTINS = new Set(["read", "mapfile", "readarray"]);
const READ_NON_VAR_SHORT_OPTS = new Set(["d", "i", "n", "N", "p", "t", "u"]);
const MAPFILE_NON_VAR_SHORT_OPTS = new Set(["d", "n", "O", "s", "u", "C", "c"]);

function groupAdjacentShellWords(nodes: SyntaxNode[]): SyntaxNode[][] {
  const groups: SyntaxNode[][] = [];
  for (const node of nodes) {
    const prev = groups[groups.length - 1];
    if (prev && prev[prev.length - 1].endIndex === node.startIndex) {
      prev.push(node);
    } else {
      groups.push([node]);
    }
  }
  return groups;
}

function evalStaticNode(node: SyntaxNode): { text: string; unquotedMask: string } | null {
  if (node.type === "raw_string") {
    const t = node.text;
    if (t.length >= 2 && t.startsWith("'") && t.endsWith("'")) {
      return { text: t.slice(1, -1), unquotedMask: "Q" };
    }
    return null;
  }

  if (node.type === "string") {
    const t = node.text;
    if (t.length < 2 || !t.startsWith('"') || !t.endsWith('"') || /\\\r?\n/.test(t)) {
      return null;
    }
    for (const child of node.namedChildren) {
      if (child.type !== "string_content") {
        return null;
      }
    }
    return { text: t.slice(1, -1).replace(/\\([\\"$`])/g, "$1"), unquotedMask: "Q" };
  }

  if (node.type === "word" || node.type === "variable_name" || node.type === "number") {
    if (node.namedChildren.length > 0 || /\\\r?\n/.test(node.text)) {
      return null;
    }
    let text = "";
    let unquotedMask = "";
    const raw = node.text;
    for (let i = 0; i < raw.length; i++) {
      if (raw[i] === "\\") {
        if (i + 1 >= raw.length) {
          return null;
        }
        i += 1;
        text += raw[i];
        unquotedMask += "Q";
      } else {
        text += raw[i];
        unquotedMask += raw[i];
      }
    }
    return { text, unquotedMask };
  }

  if (node.type === "concatenation" || node.type === "command_name") {
    if (node.namedChildren.length === 0) {
      return null;
    }
    let pos = node.startIndex;
    let text = "";
    let unquotedMask = "";
    for (const child of node.namedChildren) {
      if (child.startIndex !== pos) {
        return null;
      }
      const evaluated = evalStaticNode(child);
      if (!evaluated) {
        return null;
      }
      text += evaluated.text;
      unquotedMask += evaluated.unquotedMask;
      pos = child.endIndex;
    }
    if (pos !== node.endIndex) {
      return null;
    }
    return { text, unquotedMask };
  }

  return null;
}

function tryEvalStaticBashWord(
  nodes: SyntaxNode[],
  options?: { allowLiteralBracket?: boolean },
): string | null {
  if (nodes.length === 0) {
    return null;
  }
  if (options?.allowLiteralBracket && nodes.length === 1 && nodes[0].text === "[") {
    return "[";
  }

  let text = "";
  let unquotedMask = "";
  for (const node of nodes) {
    const evaluated = evalStaticNode(node);
    if (!evaluated) {
      return null;
    }
    text += evaluated.text;
    unquotedMask += evaluated.unquotedMask;
  }

  if (/[{}*?[]/.test(unquotedMask) || unquotedMask.startsWith("~")) {
    return null;
  }

  return text;
}

function isVarTargetToken(text: string, varName: string): boolean {
  return text === varName || text.startsWith(`${varName}[`);
}

function isVarAssignmentToken(text: string, varName: string): boolean {
  if (!text.startsWith(varName)) {
    return false;
  }
  const rest = text.slice(varName.length);
  return /^(?:\[[^\]]*\])?\+?=/.test(rest);
}

function isPotentialVarTarget(nodes: SyntaxNode[], varName: string): boolean {
  const staticVal = tryEvalStaticBashWord(nodes);
  return staticVal === null || isVarTargetToken(staticVal, varName);
}

function isStaticOtherVarAssignmentString(node: SyntaxNode, varName: string): boolean {
  if (node.type !== "string") {
    return false;
  }
  const match = node.text.match(/^"([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?\+?=/);
  return Boolean(match && match[1] !== varName);
}

function hasArithmeticVarMutation(text: string, varName: string): boolean {
  return new RegExp(
    `\\b${varName}(?:\\[[^\\]]*\\])?\\s*(?:\\+\\+|--|[+\\-*/%&|^]?=(?!=)|<<=|>>=)|(?:\\+\\+|--)\\s*${varName}\\b`,
  ).test(text);
}

function checkUnsetArgsForVar(argNodes: SyntaxNode[], varName: string): boolean {
  const groups = groupAdjacentShellWords(argNodes);
  let sawEndOfOpts = false;
  let hasFuncFlag = false;
  let hasVarFlag = false;
  let hasUnknownToken = false;
  const targets: SyntaxNode[][] = [];

  for (const group of groups) {
    const staticVal = tryEvalStaticBashWord(group);
    if (!sawEndOfOpts && staticVal !== null) {
      if (staticVal === "--") {
        sawEndOfOpts = true;
        continue;
      }
      if (staticVal.startsWith("-") && staticVal.length > 1) {
        if (staticVal.includes("f")) hasFuncFlag = true;
        if (staticVal.includes("v")) hasVarFlag = true;
        continue;
      }
    }
    if (staticVal === null) {
      hasUnknownToken = true;
    }
    targets.push(group);
  }

  if (hasFuncFlag && !hasVarFlag && !hasUnknownToken) {
    return false;
  }

  return targets.some((group) => isPotentialVarTarget(group, varName));
}

function checkDeclarationArgsForVar(keyword: string, argNodes: SyntaxNode[], varName: string): boolean {
  const groups = groupAdjacentShellWords(argNodes);
  let sawEndOfOpts = false;
  let hasPrintFlag = false;
  const staticTargets: string[] = [];

  for (const group of groups) {
    if (group.length === 1 && group[0].type === "variable_assignment") {
      const nameNode = group[0].childForFieldName("name");
      if (!nameNode) {
        return true;
      }
      if (nameNode.type === "subscript") {
        const inner = nameNode.childForFieldName("name");
        if (!inner || isPotentialVarTarget([inner], varName)) {
          return true;
        }
      } else if (isPotentialVarTarget([nameNode], varName)) {
        return true;
      }
      continue;
    }

    if (group.length === 1 && isStaticOtherVarAssignmentString(group[0], varName)) {
      continue;
    }

    const staticVal = tryEvalStaticBashWord(group);
    if (!sawEndOfOpts && staticVal !== null) {
      if (staticVal === "--") {
        sawEndOfOpts = true;
        continue;
      }
      if ((staticVal.startsWith("-") || staticVal.startsWith("+")) && staticVal.length > 1) {
        if (PWD_SHADOW_DECLARATION_KEYWORDS.has(keyword) && /^-[a-zA-Z]*n/.test(staticVal)) {
          return true;
        }
        if (/^-[a-zA-Z]*p/.test(staticVal)) {
          hasPrintFlag = true;
        }
        continue;
      }
    }

    if (staticVal === null) {
      return true;
    }
    if (isVarAssignmentToken(staticVal, varName)) {
      return true;
    }
    staticTargets.push(staticVal);
  }

  if (varName === "PWD" && PWD_SHADOW_DECLARATION_KEYWORDS.has(keyword) && !hasPrintFlag) {
    return staticTargets.some((target) => isVarTargetToken(target, varName));
  }

  return false;
}

function unwrapBuiltinCommandPrefix(
  initialNameNode: SyntaxNode,
  initialArgNodes: SyntaxNode[],
): { nameGroup: SyntaxNode[]; argNodes: SyntaxNode[]; dynamicCommandName: boolean; isQuery: boolean } {
  let nameGroup: SyntaxNode[] = [initialNameNode];
  let argGroups = groupAdjacentShellWords(initialArgNodes);

  for (let i = 0; i < 16; i++) {
    const evaluatedName = tryEvalStaticBashWord(nameGroup, { allowLiteralBracket: true });
    if (evaluatedName === null) {
      return {
        nameGroup,
        argNodes: argGroups.flat(),
        dynamicCommandName: true,
        isQuery: false,
      };
    }

    const base = basename(evaluatedName).toLowerCase();
    if (base !== "builtin" && base !== "command") {
      return {
        nameGroup,
        argNodes: argGroups.flat(),
        dynamicCommandName: false,
        isQuery: false,
      };
    }

    let idx = 0;
    let isQuery = false;
    while (idx < argGroups.length) {
      const tokGroup = argGroups[idx];
      const tokText = tryEvalStaticBashWord(tokGroup);
      if (tokText === null) {
        return {
          nameGroup: tokGroup,
          argNodes: argGroups.slice(idx + 1).flat(),
          dynamicCommandName: true,
          isQuery: false,
        };
      }
      if (tokText === "--") {
        idx += 1;
        break;
      }
      if (tokText.startsWith("-") && tokText.length > 1) {
        if (base === "command" && (tokText.includes("v") || tokText.includes("V"))) {
          isQuery = true;
        }
        idx += 1;
        continue;
      }
      break;
    }

    if (isQuery) {
      return {
        nameGroup,
        argNodes: argGroups.flat(),
        dynamicCommandName: false,
        isQuery: true,
      };
    }
    if (idx >= argGroups.length) {
      return {
        nameGroup,
        argNodes: [],
        dynamicCommandName: false,
        isQuery: false,
      };
    }

    nameGroup = argGroups[idx];
    argGroups = argGroups.slice(idx + 1);
  }

  const finalName = tryEvalStaticBashWord(nameGroup, { allowLiteralBracket: true });
  const finalBase = finalName ? basename(finalName).toLowerCase() : null;
  return {
    nameGroup,
    argNodes: argGroups.flat(),
    dynamicCommandName: finalName === null || finalBase === "builtin" || finalBase === "command",
    isQuery: false,
  };
}

function rootHasFunctionDefinition(root: SyntaxNode): boolean {
  let found = false;
  function scan(node: SyntaxNode): void {
    if (found) return;
    if (node.type === "function_definition") {
      found = true;
      return;
    }
    for (const child of node.namedChildren) {
      scan(child);
      if (found) return;
    }
  }
  scan(root);
  return found;
}

function detectBashVarMutations(root: SyntaxNode): { pwdMutated: boolean; cdpathTouched: boolean } {
  let pwdMutated = false;
  let cdpathTouched = false;
  const hasFnDef = rootHasFunctionDefinition(root);

  function visit(node: SyntaxNode): void {
    if (pwdMutated && cdpathTouched) return;

    if (node.type === "variable_assignment") {
      const nameNode = node.childForFieldName("name");
      const nameNodes = !nameNode
        ? null
        : nameNode.type === "subscript"
          ? (() => {
              const inner = nameNode.childForFieldName("name");
              return inner ? [inner] : null;
            })()
          : [nameNode];

      if (!pwdMutated) {
        const couldBePwd = !nameNodes || isPotentialVarTarget(nameNodes, "PWD");
        if (couldBePwd) {
          let exemptPrefix = false;
          if (node.parent?.type === "command" && !hasFnDef) {
            const parentNameNode = node.parent.childForFieldName("name");
            const parentName = parentNameNode
              ? tryEvalStaticBashWord([parentNameNode], { allowLiteralBracket: true })
              : null;
            if (parentName !== null) {
              const parentBase = basename(parentName).toLowerCase();
              if (!POSIX_SPECIAL_BUILTINS.has(parentBase)) {
                exemptPrefix = true;
              }
            }
          }
          if (!exemptPrefix) {
            pwdMutated = true;
          }
        }
      }

      if (!cdpathTouched) {
        const couldBeCdpath = !nameNodes || isPotentialVarTarget(nameNodes, "CDPATH");
        if (couldBeCdpath) {
          cdpathTouched = true;
        }
      }
    } else if (node.type === "declaration_command") {
      const keyword = (node.children[0]?.text ?? "export").toLowerCase();
      const argNodes = node.namedChildren.filter(
        (c) => c.type !== "file_redirect" && c.type !== "heredoc_redirect",
      );
      if (!pwdMutated && checkDeclarationArgsForVar(keyword, argNodes, "PWD")) {
        pwdMutated = true;
      }
      if (!cdpathTouched && checkDeclarationArgsForVar(keyword, argNodes, "CDPATH")) {
        cdpathTouched = true;
      }
    } else if (node.type === "unset_command") {
      if (!pwdMutated) {
        const argNodes = node.namedChildren.filter(
          (c) => c.type !== "file_redirect" && c.type !== "heredoc_redirect",
        );
        if (checkUnsetArgsForVar(argNodes, "PWD")) {
          pwdMutated = true;
        }
      }
    } else if (node.type === "for_statement") {
      const varNode = node.childForFieldName("variable");
      if (!pwdMutated && (!varNode || isPotentialVarTarget([varNode], "PWD"))) {
        pwdMutated = true;
      }
      if (!cdpathTouched && (!varNode || isPotentialVarTarget([varNode], "CDPATH"))) {
        cdpathTouched = true;
      }
    } else if (
      node.type === "c_style_for_statement" ||
      node.type === "arithmetic_expansion" ||
      (node.type === "test_command" && node.text.trimStart().startsWith("(("))
    ) {
      if (!pwdMutated && hasArithmeticVarMutation(node.text, "PWD")) {
        pwdMutated = true;
      }
      if (!cdpathTouched && hasArithmeticVarMutation(node.text, "CDPATH")) {
        cdpathTouched = true;
      }
    } else if (node.type === "expansion") {
      if (!pwdMutated && /^\$\{PWD(?:\[[^\]]*\])?:?=/.test(node.text)) {
        pwdMutated = true;
      }
      if (!cdpathTouched && /^\$\{CDPATH(?:\[[^\]]*\])?:?=/.test(node.text)) {
        cdpathTouched = true;
      }
    } else if (node.type === "command") {
      const nameNode = node.childForFieldName("name");
      if (nameNode) {
        const rawArgNodes = node.namedChildren.filter(
          (c) =>
            c.id !== nameNode.id &&
            c.type !== "variable_assignment" &&
            c.type !== "file_redirect" &&
            c.type !== "heredoc_redirect",
        );
        const unwrapped = unwrapBuiltinCommandPrefix(nameNode, rawArgNodes);
        if (unwrapped.dynamicCommandName) {
          pwdMutated = true;
          cdpathTouched = true;
          return;
        }
        if (!unwrapped.isQuery) {
          const cmdText = tryEvalStaticBashWord(unwrapped.nameGroup, { allowLiteralBracket: true });
          if (cmdText === null) {
            pwdMutated = true;
            cdpathTouched = true;
            return;
          }
          const cmdBase = basename(cmdText).toLowerCase();
          const argNodes = unwrapped.argNodes;
          const argGroups = groupAdjacentShellWords(argNodes);

          if (cmdBase === "unset") {
            if (!pwdMutated && checkUnsetArgsForVar(argNodes, "PWD")) {
              pwdMutated = true;
            }
          } else if (PWD_DECLARATION_KEYWORDS.has(cmdBase)) {
            if (!pwdMutated && checkDeclarationArgsForVar(cmdBase, argNodes, "PWD")) {
              pwdMutated = true;
            }
            if (!cdpathTouched && checkDeclarationArgsForVar(cmdBase, argNodes, "CDPATH")) {
              cdpathTouched = true;
            }
          } else if (PWD_READ_BUILTINS.has(cmdBase)) {
            let sawEndOfOpts = false;
            const nonVarOpts = cmdBase === "read" ? READ_NON_VAR_SHORT_OPTS : MAPFILE_NON_VAR_SHORT_OPTS;
            for (let idx = 0; idx < argGroups.length; idx++) {
              const group = argGroups[idx];
              const staticVal = tryEvalStaticBashWord(group);
              if (staticVal === null) {
                pwdMutated = true;
                cdpathTouched = true;
                break;
              }
              if (!sawEndOfOpts) {
                if (staticVal === "--") {
                  sawEndOfOpts = true;
                  continue;
                }
                if (staticVal.startsWith("-") && staticVal.length > 1) {
                  const inlineArray = cmdBase === "read" && staticVal.match(/^-[a-zA-Z]*a(.+)$/);
                  if (inlineArray) {
                    if (isVarTargetToken(inlineArray[1], "PWD")) pwdMutated = true;
                    if (isVarTargetToken(inlineArray[1], "CDPATH")) cdpathTouched = true;
                    continue;
                  }
                  const optCluster = staticVal.match(/^-[a-zA-Z]*([a-zA-Z])$/);
                  if (optCluster && nonVarOpts.has(optCluster[1])) {
                    idx += 1;
                  }
                  continue;
                }
              }
              if (isVarTargetToken(staticVal, "PWD")) pwdMutated = true;
              if (isVarTargetToken(staticVal, "CDPATH")) cdpathTouched = true;
            }
          } else if (cmdBase === "printf") {
            let sawEndOfOpts = false;
            for (let idx = 0; idx < argGroups.length; idx++) {
              const group = argGroups[idx];
              const staticVal = tryEvalStaticBashWord(group);
              if (sawEndOfOpts) {
                break;
              }
              if (staticVal === "--") {
                sawEndOfOpts = true;
                continue;
              }
              if (staticVal === "-v") {
                const targetGroup = argGroups[idx + 1];
                if (!targetGroup || isPotentialVarTarget(targetGroup, "PWD")) pwdMutated = true;
                if (!targetGroup || isPotentialVarTarget(targetGroup, "CDPATH")) cdpathTouched = true;
                idx += 1;
                continue;
              }
              if (staticVal !== null && staticVal.startsWith("-v") && staticVal.length > 2) {
                const targetVar = staticVal.slice(2);
                if (isVarTargetToken(targetVar, "PWD")) pwdMutated = true;
                if (isVarTargetToken(targetVar, "CDPATH")) cdpathTouched = true;
                continue;
              }
              if (staticVal !== null && !staticVal.startsWith("-")) {
                sawEndOfOpts = true;
                break;
              }
              if (staticVal === null) {
                const raw = group.map((n) => n.text).join("");
                if (/^["'\\]*-v/.test(raw)) {
                  pwdMutated = true;
                  cdpathTouched = true;
                  break;
                }
                if (idx + 1 < argGroups.length) {
                  if (isPotentialVarTarget(argGroups[idx + 1], "PWD")) pwdMutated = true;
                  if (isPotentialVarTarget(argGroups[idx + 1], "CDPATH")) cdpathTouched = true;
                }
                sawEndOfOpts = true;
                break;
              }
            }
          } else if (cmdBase === "let") {
            for (const group of argGroups) {
              const staticVal = tryEvalStaticBashWord(group);
              if (staticVal === null) {
                pwdMutated = true;
                cdpathTouched = true;
                break;
              }
              if (/\bPWD\b/.test(staticVal)) pwdMutated = true;
              if (/\bCDPATH\b/.test(staticVal)) cdpathTouched = true;
            }
          } else if (cmdBase === "eval" || cmdBase === "source" || cmdBase === ".") {
            pwdMutated = true;
            cdpathTouched = true;
          } else if (cmdBase === "coproc") {
            if (argGroups.length >= 2) {
              if (isPotentialVarTarget(argGroups[0], "PWD")) pwdMutated = true;
              if (isPotentialVarTarget(argGroups[0], "CDPATH")) cdpathTouched = true;
            }
          } else if (cmdBase === "exec") {
            for (const group of argGroups) {
              const raw = group.map((n) => n.text).join("");
              if (raw.includes("{")) {
                if (
                  group.length === 1 &&
                  group[0].type === "concatenation" &&
                  group[0].namedChildren.length >= 3 &&
                  group[0].namedChildren[0].text === "{" &&
                  group[0].namedChildren[group[0].namedChildren.length - 1].text === "}"
                ) {
                  const innerNodes = group[0].namedChildren.slice(1, -1);
                  if (isPotentialVarTarget(innerNodes, "PWD")) pwdMutated = true;
                  if (isPotentialVarTarget(innerNodes, "CDPATH")) cdpathTouched = true;
                } else {
                  pwdMutated = true;
                  cdpathTouched = true;
                  break;
                }
              }
            }
          } else if (cmdBase === "getopts") {
            if (argGroups.length >= 2) {
              if (isPotentialVarTarget(argGroups[1], "PWD")) pwdMutated = true;
              if (isPotentialVarTarget(argGroups[1], "CDPATH")) cdpathTouched = true;
            }
          } else if (cmdBase === "wait") {
            let sawEndOfOpts = false;
            for (let idx = 0; idx < argGroups.length; idx++) {
              const group = argGroups[idx];
              const staticVal = tryEvalStaticBashWord(group);
              if (sawEndOfOpts) {
                break;
              }
              if (staticVal === "--") {
                sawEndOfOpts = true;
                continue;
              }
              if (staticVal === "-p") {
                const targetGroup = argGroups[idx + 1];
                if (!targetGroup || isPotentialVarTarget(targetGroup, "PWD")) pwdMutated = true;
                if (!targetGroup || isPotentialVarTarget(targetGroup, "CDPATH")) cdpathTouched = true;
                idx += 1;
                continue;
              }
              if (staticVal !== null && staticVal.startsWith("-p") && staticVal.length > 2) {
                const targetVar = staticVal.slice(2);
                if (isVarTargetToken(targetVar, "PWD")) pwdMutated = true;
                if (isVarTargetToken(targetVar, "CDPATH")) cdpathTouched = true;
                continue;
              }
              if (staticVal === null) {
                pwdMutated = true;
                cdpathTouched = true;
                break;
              }
            }
          }
        }
      }
    }

    for (const child of node.namedChildren) {
      visit(child);
      if (pwdMutated && cdpathTouched) return;
    }
  }

  visit(root);
  return { pwdMutated, cdpathTouched };
}

function collectArithmeticVariables(node: SyntaxNode, out: Set<string>): void {
  if (node.type === "variable_name") {
    out.add(node.text);
  }
  for (const child of node.namedChildren) {
    collectArithmeticVariables(child, out);
  }
}

function collectEnvReads(node: SyntaxNode, out: Set<string>, opaqueOut?: string[]): void {
  // For variable_assignment, never treat the LHS variable name as a read; only inspect the value.
  if (node.type === "variable_assignment") {
    const valNode = node.childForFieldName("value");
    if (valNode) {
      collectEnvReads(valNode, out, opaqueOut);
    }
    return;
  }

  if (node.type === "simple_expansion") {
    const varNode = node.namedChildren.find((c) => c.type === "variable_name");
    if (varNode) {
      out.add(varNode.text);
    }
  } else if (node.type === "expansion") {
    if (node.text.startsWith("${!") && opaqueOut) {
      opaqueOut.push("indirect_var_ref");
    }
    const varNode = node.namedChildren.find((c) => c.type === "variable_name");
    if (varNode) {
      out.add(varNode.text);
    }
  } else if (node.type === "arithmetic_expansion") {
    collectArithmeticVariables(node, out);
  }

  for (const child of node.namedChildren) {
    collectEnvReads(child, out, opaqueOut);
  }
}

function extractRedirection(node: SyntaxNode, allowStaticPwd = true): RedirectionFact | null {
  if (node.type !== "file_redirect") {
    return null;
  }
  const dest = node.childForFieldName("destination");
  if (!dest) {
    return null;
  }
  let operator = "";
  for (const child of node.children) {
    if (!child.isNamed && /^[0-9]*[<>|&]+$/.test(child.text)) {
      operator = child.text;
      break;
    }
  }
  if (!operator) {
    const raw = node.text;
    const match = raw.match(/([0-9]*>>|[0-9]*>\||[0-9]*&>>|[0-9]*&>|[0-9]*>|<>|<)/);
    operator = match ? match[1] : ">";
  }

  const target = stripQuotes(dest);
  return {
    operator,
    target,
    isWrite: WRITE_REDIRECT_OPS.has(operator) || operator.includes(">"),
    isRead: READ_REDIRECT_OPS.has(operator) || operator === "<",
    ...(isDynamicPathNode(dest, allowStaticPwd) ? { dynamic: true } : {}),
  };
}

function isBareRelativeCdTarget(target: string): boolean {
  if (target === "" || target === "." || target === "..") {
    return false;
  }
  return (
    !target.startsWith("/") &&
    !target.startsWith("./") &&
    !target.startsWith("../") &&
    !target.startsWith("~") &&
    !target.startsWith("$HOME") &&
    !target.startsWith("${HOME}") &&
    !target.startsWith("$PWD") &&
    !target.startsWith("${PWD}")
  );
}

function buildUnquotedGlobMask(node: SyntaxNode): string {
  if (
    node.type === "raw_string" ||
    node.type === "string" ||
    node.type === "simple_expansion" ||
    node.type === "expansion" ||
    node.type === "command_substitution" ||
    node.type === "process_substitution" ||
    node.type === "arithmetic_expansion"
  ) {
    return "Q";
  }
  if (node.namedChildren.length === 0) {
    let mask = "";
    const raw = node.text;
    for (let i = 0; i < raw.length; i++) {
      if (raw[i] === "\\" && i + 1 < raw.length) {
        i += 1;
        mask += "Q";
      } else {
        mask += raw[i];
      }
    }
    return mask;
  }
  return node.children.map((ch) => buildUnquotedGlobMask(ch)).join("");
}

function containsAnsiCStrNode(node: SyntaxNode): boolean {
  if (node.type === "ansi_c_string") {
    return true;
  }
  for (const child of node.namedChildren) {
    if (containsAnsiCStrNode(child)) {
      return true;
    }
  }
  return false;
}

function unquoteCdTargetNode(node: SyntaxNode): string {
  const text = node.text;
  if (node.type === "raw_string" && text.length >= 2 && text.startsWith("'") && text.endsWith("'")) {
    return text.slice(1, -1);
  }
  if (node.type === "string" && text.length >= 2 && text.startsWith('"') && text.endsWith('"')) {
    return text.slice(1, -1).replace(/\\([\\"])/g, "$1");
  }
  if (node.type === "concatenation") {
    return node.namedChildren.map((child) => unquoteCdTargetNode(child)).join("");
  }
  return text.replace(/\\(.)/g, "$1");
}

function evalCdTargetGroup(
  group: SyntaxNode[],
  allowStaticPwd: boolean,
): { value: string; isDynamic: boolean } {
  if (group.length === 0) {
    return { value: "", isDynamic: true };
  }
  for (const node of group) {
    if (isDynamicPathNode(node, allowStaticPwd) || containsAnsiCStrNode(node)) {
      return { value: group.map(stripQuotes).join(""), isDynamic: true };
    }
  }
  const mask = group.map(buildUnquotedGlobMask).join("");
  if (/[*?[]/.test(mask) || /\{[^{}]*(?:,|\.\.)[^{}]*\}/.test(mask)) {
    return { value: group.map(stripQuotes).join(""), isDynamic: true };
  }
  const value = group.map(unquoteCdTargetNode).join("");
  return { value, isDynamic: false };
}

function applyNavigationBuiltin(
  cmdNode: SyntaxNode,
  tracker: LinearCwdTracker,
  allowStaticPwd: boolean,
  cdpathActive: boolean,
): void {
  const nameNode = cmdNode.childForFieldName("name");
  if (!nameNode) {
    return;
  }
  const rawArgNodes = cmdNode.namedChildren.filter(
    (c) =>
      c.id !== nameNode.id &&
      c.type !== "variable_assignment" &&
      c.type !== "file_redirect" &&
      c.type !== "heredoc_redirect",
  );
  const unwrapped = unwrapBuiltinCommandPrefix(nameNode, rawArgNodes);
  if (unwrapped.isQuery) {
    return;
  }
  if (unwrapped.dynamicCommandName) {
    tracker.markUncertain();
    return;
  }
  const cmdText = tryEvalStaticBashWord(unwrapped.nameGroup, { allowLiteralBracket: true });
  if (cmdText === null) {
    tracker.markUncertain();
    return;
  }
  const base = basename(cmdText).toLowerCase();

  if (base === "cd") {
    const groups = groupAdjacentShellWords(unwrapped.argNodes);
    const positionals: SyntaxNode[][] = [];
    let afterDoubleDash = false;

    for (const group of groups) {
      const staticVal = tryEvalStaticBashWord(group);
      if (!afterDoubleDash && staticVal !== null) {
        if (staticVal === "--") {
          afterDoubleDash = true;
          continue;
        }
        if (/^-[LPe@]+$/.test(staticVal)) {
          continue;
        }
        if (staticVal.startsWith("-") && staticVal.length > 1) {
          tracker.markUncertain();
          return;
        }
      }
      positionals.push(group);
    }

    if (positionals.length === 0) {
      tracker.applyCd(undefined, false);
      return;
    }
    if (positionals.length > 1) {
      tracker.markUncertain();
      return;
    }

    const pos = evalCdTargetGroup(positionals[0], allowStaticPwd);
    if (pos.isDynamic || (cdpathActive && isBareRelativeCdTarget(pos.value))) {
      tracker.markUncertain();
      return;
    }
    tracker.applyCd(pos.value, false);
    return;
  }

  if (base === "pushd") {
    const groups = groupAdjacentShellWords(unwrapped.argNodes);
    if (groups.length !== 1) {
      tracker.markUncertain();
      return;
    }
    const pos = evalCdTargetGroup(groups[0], allowStaticPwd);
    if (
      pos.isDynamic ||
      pos.value.startsWith("+") ||
      pos.value.startsWith("-") ||
      (cdpathActive && isBareRelativeCdTarget(pos.value))
    ) {
      tracker.markUncertain();
      return;
    }
    tracker.applyPushd(pos.value, false);
    return;
  }

  if (base === "popd") {
    if (unwrapped.argNodes.length > 0) {
      tracker.markUncertain();
      return;
    }
    tracker.applyPopd();
  }
}

function subtreeContainsCwdBuiltin(node: SyntaxNode): boolean {
  if (node.type === "command") {
    const nameNode = node.childForFieldName("name");
    if (nameNode) {
      const rawArgNodes = node.namedChildren.filter(
        (c) =>
          c.id !== nameNode.id &&
          c.type !== "variable_assignment" &&
          c.type !== "file_redirect" &&
          c.type !== "heredoc_redirect",
      );
      const unwrapped = unwrapBuiltinCommandPrefix(nameNode, rawArgNodes);
      if (!unwrapped.isQuery) {
        if (unwrapped.dynamicCommandName) {
          return true;
        }
        const cmdText = tryEvalStaticBashWord(unwrapped.nameGroup, { allowLiteralBracket: true });
        if (cmdText === null || CWD_BUILTINS.has(basename(cmdText).toLowerCase())) {
          return true;
        }
      }
    }
  }
  for (const child of node.namedChildren) {
    if (subtreeContainsCwdBuiltin(child)) {
      return true;
    }
  }
  return false;
}

function getListOperator(listNode: SyntaxNode): string {
  for (const child of listNode.children) {
    if (!child.isNamed && (child.text === "&&" || child.text === "||" || child.text === ";" || child.text === "&")) {
      return child.text;
    }
  }
  return ";";
}

export async function parseBash(
  source: string,
  depth = 0,
  options: BashParseOptions = {},
): Promise<BashParseOutput> {
  const opaque: string[] = [];
  const commands: CommandFact[] = [];
  const pipelines: PipelineFact[] = [];
  const globalEnvReads = new Set<string>();
  const allAssignments: AssignmentFact[] = [];
  const basePwdMutated = Boolean(options.pwdUncertain);
  const envHasCdpath = Boolean(options.envSnapshot?.CDPATH && options.envSnapshot.CDPATH.length > 0);
  const baseCdpathActive = Boolean(options.cdpathActive) || envHasCdpath;

  if (!source.trim()) {
    return {
      commands,
      pipelines,
      opaque,
      envReads: [],
      assignments: [],
      pwdMutated: basePwdMutated,
      cdpathTouched: baseCdpathActive,
    };
  }

  for (const obf of OBFUSCATION_PATTERNS) {
    if (obf.regex.test(source)) {
      opaque.push(obf.name);
    }
  }

  const {
    source: normalizedSource,
    hasUnquotedHeredocTrailingBackslash,
    hasNonStandardHeredocDelimiter,
    expectedHeredocDelimiters,
  } = preprocessBashLineContinuations(source);
  const { ParserCtor, language } = await getBashRuntime();
  const parser = new ParserCtor();
  parser.setLanguage(language);

  let tree;
  try {
    tree = parser.parse(normalizedSource);
  } finally {
    parser.delete();
  }

  if (!tree) {
    return {
      commands,
      pipelines,
      opaque: ["parse_null_tree"],
      envReads: [],
      assignments: [],
      pwdMutated: basePwdMutated,
      cdpathTouched: baseCdpathActive,
    };
  }

  const root = tree.rootNode;
  if (root.hasError) {
    opaque.push("parse_error");
  }
  const astHeredocs = collectAndValidateAstHeredocs(root);
  let heredocDelimiterMismatch =
    hasNonStandardHeredocDelimiter ||
    astHeredocs.hasMismatch ||
    expectedHeredocDelimiters.length > astHeredocs.astEnds.length;
  if (!heredocDelimiterMismatch && expectedHeredocDelimiters.length > 0) {
    let astIdx = 0;
    for (const expectedDelim of expectedHeredocDelimiters) {
      while (astIdx < astHeredocs.astEnds.length && astHeredocs.astEnds[astIdx] !== expectedDelim) {
        astIdx += 1;
      }
      if (astIdx >= astHeredocs.astEnds.length) {
        heredocDelimiterMismatch = true;
        break;
      }
      astIdx += 1;
    }
  }
  if (hasUnquotedHeredocTrailingBackslash) {
    opaque.push("heredoc_trailing_backslash");
  }
  if (heredocDelimiterMismatch) {
    opaque.push("heredoc_delimiter_mismatch");
  }

  // Root-level env-read scan covers heredocs, [[ ... ]], $((...)), case, for, and standalone assignments.
  collectEnvReads(root, globalEnvReads, opaque);
  const mutations = detectBashVarMutations(root);
  const heredocUnsafe = hasUnquotedHeredocTrailingBackslash || heredocDelimiterMismatch;
  const pwdMutated = basePwdMutated || heredocUnsafe || mutations.pwdMutated;
  const allowStaticPwd = !pwdMutated;
  const cdpathTouched = baseCdpathActive || mutations.cdpathTouched;

  let nextPipelineId = 1;

  function recordAssignmentNode(
    assignNode: SyntaxNode,
    standalone: boolean,
    assignSource: AssignmentFact["source"],
    tracker: LinearCwdTracker,
    targetMap?: Record<string, string>,
  ): void {
    const varName = assignNode.childForFieldName("name")?.text;
    const varValNode = assignNode.childForFieldName("value");
    if (varName) {
      const value = varValNode ? stripQuotes(varValNode) : "";
      if (targetMap) {
        targetMap[varName] = value;
      }
      allAssignments.push({
        name: varName,
        value,
        standalone,
        depth,
        source: assignSource,
      });
    }
    if (varValNode) {
      walkNestedSubstitutions(varValNode, tracker.clone());
    }
  }

  function extractCommand(
    cmdNode: SyntaxNode,
    extraRedirections: RedirectionFact[],
    tracker: LinearCwdTracker,
    pipelineId?: number,
    pipelineIndex?: number,
  ): CommandFact | null {
    const nameNode = cmdNode.childForFieldName("name");
    if (!nameNode) {
      return null;
    }

    const envReads = new Set<string>();
    collectEnvReads(cmdNode, envReads);

    if (containsDynamicNode(nameNode)) {
      opaque.push(`dynamic_command_name:${nameNode.text}`);
    }

    const name = stripQuotes(nameNode);
    const argv: string[] = [];
    const argvDynamic: boolean[] = [];
    const assignments: Record<string, string> = {};
    const redirections: RedirectionFact[] = [...extraRedirections];

    for (const child of cmdNode.namedChildren) {
      if (child.id === nameNode.id) continue;

      if (child.type === "variable_assignment") {
        recordAssignmentNode(child, false, "prefix", tracker, assignments);
        continue;
      }

      if (child.type === "file_redirect") {
        const redir = extractRedirection(child, allowStaticPwd);
        if (redir) redirections.push(redir);
        continue;
      }

      if (child.type === "heredoc_redirect") {
        continue;
      }

      argv.push(stripQuotes(child));
      argvDynamic.push(isDynamicPathNode(child, allowStaticPwd));
    }

    const fact: CommandFact = {
      name,
      argv,
      argvDynamic,
      rawText: cmdNode.text,
      redirections,
      assignments,
      envReads: Array.from(envReads),
      pipelineId,
      pipelineIndex,
      depth,
      layer: "bash",
      ...(tracker.isUncertain() ? { cwdChanged: true } : { effectiveCwd: tracker.getCwd() }),
    };
    commands.push(fact);

    for (const child of cmdNode.namedChildren) {
      if (child.type !== "variable_assignment") {
        walkNestedSubstitutions(child, tracker.clone());
      }
    }

    applyNavigationBuiltin(cmdNode, tracker, allowStaticPwd, cdpathTouched);
    return fact;
  }

  function extractDeclarationCommand(
    declNode: SyntaxNode,
    extraRedirections: RedirectionFact[],
    tracker: LinearCwdTracker,
    pipelineId?: number,
    pipelineIndex?: number,
  ): CommandFact {
    const keywordNode = declNode.children[0];
    const keyword = keywordNode ? keywordNode.text : "export";
    const argv: string[] = [];
    const assignments: Record<string, string> = {};
    const redirections: RedirectionFact[] = [...extraRedirections];
    const envReads = new Set<string>();
    collectEnvReads(declNode, envReads);

    for (const child of declNode.namedChildren) {
      if (child.type === "variable_assignment") {
        recordAssignmentNode(child, true, "declaration", tracker, assignments);
        continue;
      }
      if (child.type === "variable_name") {
        argv.push(child.text);
        continue;
      }
      if (child.type === "file_redirect") {
        const redir = extractRedirection(child, allowStaticPwd);
        if (redir) redirections.push(redir);
        continue;
      }
      argv.push(stripQuotes(child));
      walkNestedSubstitutions(child, tracker.clone());
    }

    const fact: CommandFact = {
      name: keyword,
      argv,
      rawText: declNode.text,
      redirections,
      assignments,
      envReads: Array.from(envReads),
      pipelineId,
      pipelineIndex,
      depth,
      layer: "bash",
      ...(tracker.isUncertain() ? { cwdChanged: true } : { effectiveCwd: tracker.getCwd() }),
    };
    commands.push(fact);
    return fact;
  }

  function walkNestedSubstitutions(node: SyntaxNode, tracker: LinearCwdTracker): void {
    if (node.type === "command_substitution" || node.type === "process_substitution") {
      for (const child of node.namedChildren) {
        walk(child, [], tracker);
      }
      return;
    }
    for (const child of node.namedChildren) {
      walkNestedSubstitutions(child, tracker);
    }
  }

  function walkHeredocRedirect(heredocNode: SyntaxNode, tracker: LinearCwdTracker): void {
    for (const hc of heredocNode.namedChildren) {
      if (hc.type === "heredoc_start" || hc.type === "heredoc_end") {
        continue;
      }
      if (hc.type === "heredoc_body") {
        walkNestedSubstitutions(hc, tracker.clone());
      } else {
        // Commands/pipelines trailing `<<EOF` on the same line (e.g. `cat <<EOF | curl ...`)
        walk(hc, [], tracker);
      }
    }
  }

  function emitStandaloneRedirections(
    redirects: RedirectionFact[],
    rawText: string,
    tracker: LinearCwdTracker,
  ): void {
    if (redirects.length === 0) {
      return;
    }
    commands.push({
      name: ":",
      argv: [],
      rawText,
      redirections: redirects,
      assignments: {},
      envReads: [],
      depth,
      layer: "bash",
      preclassified: true,
      ...(tracker.isUncertain() ? { cwdChanged: true } : { effectiveCwd: tracker.getCwd() }),
    });
  }

  function walk(
    node: SyntaxNode,
    pendingRedirects: RedirectionFact[] = [],
    tracker: LinearCwdTracker,
  ): void {
    if (node.type === "list") {
      const left = node.namedChildren[0];
      const right = node.namedChildren[1];
      const op = getListOperator(node);
      const leftRedirects = right ? [] : pendingRedirects;
      const rightRedirects = right ? pendingRedirects : [];

      if (op === "||") {
        const before = tracker.snapshot();
        const leftTracker = tracker.clone();
        if (left) walk(left, leftRedirects, leftTracker);

        const rightTracker = tracker.clone();
        if (leftTracker.isUncertain() || leftTracker.getCwd() !== before.cwd) {
          rightTracker.markUncertain();
        }
        if (right) walk(right, rightRedirects, rightTracker);

        tracker.mergeBranch(before, leftTracker.snapshot());
        tracker.mergeBranch(before, rightTracker.snapshot());
        return;
      }

      if (op === "&") {
        if (left) walk(left, leftRedirects, tracker.clone());
        if (right) walk(right, rightRedirects, tracker);
        return;
      }

      if (left) walk(left, leftRedirects, tracker);
      if (right) walk(right, rightRedirects, tracker);
      return;
    }

    if (node.type === "compound_statement") {
      emitStandaloneRedirections(pendingRedirects, node.text, tracker);
      for (const child of node.namedChildren) {
        walk(child, [], tracker);
      }
      return;
    }

    if (node.type === "subshell") {
      emitStandaloneRedirections(pendingRedirects, node.text, tracker);
      const subTracker = tracker.clone();
      for (const child of node.namedChildren) {
        walk(child, [], subTracker);
      }
      return;
    }

    if (node.type === "if_statement") {
      emitStandaloneRedirections(pendingRedirects, node.text, tracker);
      const before = tracker.snapshot();
      const condNode = node.childForFieldName("condition");
      const condTracker = tracker.clone();
      if (condNode) {
        walk(condNode, [], condTracker);
      }
      tracker.mergeBranch(before, condTracker.snapshot());

      for (const child of node.namedChildren) {
        if (condNode && child.id === condNode.id) continue;
        const branchTracker = condTracker.clone();
        walk(child, [], branchTracker);
        tracker.mergeBranch(before, branchTracker.snapshot());
      }
      return;
    }

    if (node.type === "case_statement") {
      emitStandaloneRedirections(pendingRedirects, node.text, tracker);
      const before = tracker.snapshot();
      const valNode = node.childForFieldName("value");
      if (valNode) {
        walkNestedSubstitutions(valNode, tracker.clone());
      }
      for (const child of node.namedChildren) {
        if (valNode && child.id === valNode.id) continue;
        const branchTracker = tracker.clone();
        walk(child, [], branchTracker);
        tracker.mergeBranch(before, branchTracker.snapshot());
      }
      return;
    }

    if (
      node.type === "for_statement" ||
      node.type === "c_style_for_statement" ||
      node.type === "while_statement"
    ) {
      emitStandaloneRedirections(pendingRedirects, node.text, tracker);
      const hasCwdMutation = subtreeContainsCwdBuiltin(node);
      const loopTracker = tracker.clone();
      if (hasCwdMutation) {
        loopTracker.markUncertain();
        tracker.markUncertain();
      }
      for (const child of node.namedChildren) {
        walk(child, [], loopTracker);
      }
      return;
    }

    if (node.type === "function_definition") {
      emitStandaloneRedirections(pendingRedirects, node.text, tracker);
      const before = tracker.snapshot();
      const fnTracker = tracker.clone();
      for (const child of node.namedChildren) {
        walk(child, [], fnTracker);
      }
      if (fnTracker.isUncertain() || fnTracker.getCwd() !== before.cwd) {
        tracker.markUncertain();
      }
      return;
    }

    if (node.type === "pipeline") {
      const pipelineId = nextPipelineId++;
      const pipeCmdNames: string[] = [];
      let index = 0;
      const before = tracker.snapshot();
      const pipeTracker = tracker.clone();
      const children = node.namedChildren;

      for (let ci = 0; ci < children.length; ci++) {
        const child = children[ci];
        const childRedirects = ci === children.length - 1 ? pendingRedirects : [];
        if (child.type === "command") {
          const fact = extractCommand(child, childRedirects, pipeTracker, pipelineId, index++);
          if (fact) pipeCmdNames.push(fact.name);
        } else if (child.type === "declaration_command") {
          const fact = extractDeclarationCommand(child, childRedirects, pipeTracker, pipelineId, index++);
          pipeCmdNames.push(fact.name);
        } else if (child.type === "redirected_statement") {
          const body = child.childForFieldName("body");
          const redirects: RedirectionFact[] = [...childRedirects];
          for (const rc of child.namedChildren) {
            if (rc.type === "file_redirect") {
              const r = extractRedirection(rc, allowStaticPwd);
              if (r) redirects.push(r);
            } else if (rc.type === "heredoc_redirect") {
              walkHeredocRedirect(rc, pipeTracker.clone());
            }
          }
          if (body?.type === "command") {
            const fact = extractCommand(body, redirects, pipeTracker, pipelineId, index++);
            if (fact) pipeCmdNames.push(fact.name);
          } else if (body?.type === "declaration_command") {
            const fact = extractDeclarationCommand(body, redirects, pipeTracker, pipelineId, index++);
            pipeCmdNames.push(fact.name);
          } else if (body) {
            walk(body, redirects, pipeTracker);
          }
        } else {
          walk(child, childRedirects, pipeTracker);
        }
      }

      if (pipeTracker.isUncertain() || pipeTracker.getCwd() !== before.cwd) {
        tracker.markUncertain();
      }

      if (pipeCmdNames.length > 0) {
        pipelines.push({ id: pipelineId, depth, commands: pipeCmdNames });
      }
      return;
    }

    if (node.type === "redirected_statement") {
      const body = node.childForFieldName("body");
      const redirects: RedirectionFact[] = [...pendingRedirects];
      for (const child of node.namedChildren) {
        if (child.type === "file_redirect") {
          const r = extractRedirection(child, allowStaticPwd);
          if (r) redirects.push(r);
        } else if (child.type === "heredoc_redirect") {
          walkHeredocRedirect(child, tracker.clone());
        }
      }
      if (body) {
        walk(body, redirects, tracker);
      }
      return;
    }

    if (node.type === "command") {
      extractCommand(node, pendingRedirects, tracker);
      return;
    }

    if (node.type === "declaration_command") {
      extractDeclarationCommand(node, pendingRedirects, tracker);
      return;
    }

    if (node.type === "variable_assignment") {
      recordAssignmentNode(node, true, "standalone", tracker);
      return;
    }

    for (const child of node.namedChildren) {
      walk(child, pendingRedirects, tracker);
    }
  }

  const rootTracker = new LinearCwdTracker({
    cwd: options.cwd ?? "/",
    home: options.home,
    uncertain: Boolean(options.cwdUncertain) || heredocUnsafe,
  });

  walk(root, [], rootTracker);
  tree.delete();

  return {
    commands,
    pipelines,
    opaque: Array.from(new Set(opaque)),
    envReads: Array.from(globalEnvReads),
    assignments: allAssignments,
    pwdMutated,
    cdpathTouched,
  };
}
