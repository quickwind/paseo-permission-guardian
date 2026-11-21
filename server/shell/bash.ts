import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import type { Language, Node as SyntaxNode, Parser } from "web-tree-sitter";
import type { AssignmentFact, CommandFact, PipelineFact, RedirectionFact } from "./types.js";

export interface BashParseOutput {
  commands: CommandFact[];
  pipelines: PipelineFact[];
  opaque: string[];
  envReads: string[];
  assignments: AssignmentFact[];
}

interface WebTreeSitterModule {
  Parser: typeof Parser;
  Language: typeof Language;
}

function getBaseRequire(): NodeRequire {
  const candidates: Array<string | URL> = [];
  if (typeof import.meta !== "undefined" && typeof import.meta.url === "string" && import.meta.url.length > 0) {
    candidates.push(import.meta.url);
  }
  if (typeof __filename === "string" && __filename.length > 0) {
    candidates.push(__filename);
  }
  candidates.push(join(process.cwd(), "package.json"));

  for (const base of candidates) {
    try {
      return createRequire(base);
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
]);

const WRITE_REDIRECT_OPS = new Set([">", ">>", ">|", "&>", "&>>", "1>", "1>>", "2>", "2>>", "<>"]);
const READ_REDIRECT_OPS = new Set(["<", "<>"]);

const OBFUSCATION_PATTERNS: readonly { name: string; regex: RegExp }[] = [
  { name: "obfuscation_hex_escape", regex: /(?:\\x[0-9a-fA-F]{2}){6,}/ },
  { name: "obfuscation_long_base64", regex: /\b[A-Za-z0-9+/]{80,}={0,2}\b/ },
];

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

function extractRedirection(node: SyntaxNode): RedirectionFact | null {
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
  };
}

export async function parseBash(source: string, depth = 0): Promise<BashParseOutput> {
  const opaque: string[] = [];
  const commands: CommandFact[] = [];
  const pipelines: PipelineFact[] = [];
  const globalEnvReads = new Set<string>();
  const allAssignments: AssignmentFact[] = [];

  if (!source.trim()) {
    return { commands, pipelines, opaque, envReads: [], assignments: [] };
  }

  for (const obf of OBFUSCATION_PATTERNS) {
    if (obf.regex.test(source)) {
      opaque.push(obf.name);
    }
  }

  const { ParserCtor, language } = await getBashRuntime();
  const parser = new ParserCtor();
  parser.setLanguage(language);

  let tree;
  try {
    tree = parser.parse(source);
  } finally {
    parser.delete();
  }

  if (!tree) {
    return { commands, pipelines, opaque: ["parse_null_tree"], envReads: [], assignments: [] };
  }

  const root = tree.rootNode;
  if (root.hasError) {
    opaque.push("parse_error");
  }

  // Root-level env-read scan covers heredocs, [[ ... ]], $((...)), case, for, and standalone assignments.
  collectEnvReads(root, globalEnvReads, opaque);

  let nextPipelineId = 1;

  function recordAssignmentNode(
    assignNode: SyntaxNode,
    standalone: boolean,
    assignSource: AssignmentFact["source"],
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
      walkNestedSubstitutions(varValNode);
    }
  }

  function extractCommand(
    cmdNode: SyntaxNode,
    extraRedirections: RedirectionFact[],
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
    const assignments: Record<string, string> = {};
    const redirections: RedirectionFact[] = [...extraRedirections];

    for (const child of cmdNode.namedChildren) {
      if (child.id === nameNode.id) continue;

      if (child.type === "variable_assignment") {
        recordAssignmentNode(child, false, "prefix", assignments);
        continue;
      }

      if (child.type === "file_redirect") {
        const redir = extractRedirection(child);
        if (redir) redirections.push(redir);
        continue;
      }

      if (child.type === "heredoc_redirect") {
        continue;
      }

      argv.push(stripQuotes(child));
    }

    const fact: CommandFact = {
      name,
      argv,
      rawText: cmdNode.text,
      redirections,
      assignments,
      envReads: Array.from(envReads),
      pipelineId,
      pipelineIndex,
      depth,
      layer: "bash",
    };
    commands.push(fact);

    for (const child of cmdNode.namedChildren) {
      if (child.type !== "variable_assignment") {
        walkNestedSubstitutions(child);
      }
    }

    return fact;
  }

  function extractDeclarationCommand(
    declNode: SyntaxNode,
    extraRedirections: RedirectionFact[],
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
        recordAssignmentNode(child, true, "declaration", assignments);
        continue;
      }
      if (child.type === "variable_name") {
        argv.push(child.text);
        continue;
      }
      if (child.type === "file_redirect") {
        const redir = extractRedirection(child);
        if (redir) redirections.push(redir);
        continue;
      }
      argv.push(stripQuotes(child));
      walkNestedSubstitutions(child);
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
    };
    commands.push(fact);
    return fact;
  }

  function walkNestedSubstitutions(node: SyntaxNode): void {
    if (node.type === "command_substitution" || node.type === "process_substitution") {
      for (const child of node.namedChildren) {
        walk(child);
      }
      return;
    }
    for (const child of node.namedChildren) {
      walkNestedSubstitutions(child);
    }
  }

  function walkHeredocRedirect(heredocNode: SyntaxNode): void {
    for (const hc of heredocNode.namedChildren) {
      if (hc.type === "heredoc_start" || hc.type === "heredoc_end") {
        continue;
      }
      if (hc.type === "heredoc_body") {
        walkNestedSubstitutions(hc);
      } else {
        // Commands/pipelines trailing `<<EOF` on the same line (e.g. `cat <<EOF | curl ...`)
        walk(hc);
      }
    }
  }

  function walk(node: SyntaxNode, pendingRedirects: RedirectionFact[] = []): void {
    if (node.type === "pipeline") {
      const pipelineId = nextPipelineId++;
      const pipeCmdNames: string[] = [];
      let index = 0;

      for (const child of node.namedChildren) {
        if (child.type === "command") {
          const fact = extractCommand(child, [], pipelineId, index++);
          if (fact) pipeCmdNames.push(fact.name);
        } else if (child.type === "declaration_command") {
          const fact = extractDeclarationCommand(child, [], pipelineId, index++);
          pipeCmdNames.push(fact.name);
        } else if (child.type === "redirected_statement") {
          const body = child.childForFieldName("body");
          const redirects: RedirectionFact[] = [];
          for (const rc of child.namedChildren) {
            if (rc.type === "file_redirect") {
              const r = extractRedirection(rc);
              if (r) redirects.push(r);
            } else if (rc.type === "heredoc_redirect") {
              walkHeredocRedirect(rc);
            }
          }
          if (body?.type === "command") {
            const fact = extractCommand(body, redirects, pipelineId, index++);
            if (fact) pipeCmdNames.push(fact.name);
          } else if (body?.type === "declaration_command") {
            const fact = extractDeclarationCommand(body, redirects, pipelineId, index++);
            pipeCmdNames.push(fact.name);
          } else if (body) {
            walk(body, redirects);
          }
        } else {
          walk(child);
        }
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
          const r = extractRedirection(child);
          if (r) redirects.push(r);
        } else if (child.type === "heredoc_redirect") {
          walkHeredocRedirect(child);
        }
      }
      if (body) {
        walk(body, redirects);
      }
      return;
    }

    if (node.type === "command") {
      extractCommand(node, pendingRedirects);
      return;
    }

    if (node.type === "declaration_command") {
      extractDeclarationCommand(node, pendingRedirects);
      return;
    }

    if (node.type === "variable_assignment") {
      recordAssignmentNode(node, true, "standalone");
      return;
    }

    for (const child of node.namedChildren) {
      walk(child, pendingRedirects);
    }
  }

  walk(root);
  tree.delete();

  return {
    commands,
    pipelines,
    opaque: Array.from(new Set(opaque)),
    envReads: Array.from(globalEnvReads),
    assignments: allAssignments,
  };
}
