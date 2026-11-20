import { createRequire } from "node:module";
import { join } from "node:path";
import { Language, Parser, type Node as SyntaxNode } from "web-tree-sitter";
import type { CommandFact, PipelineFact, RedirectionFact } from "./types.js";

export interface BashParseOutput {
  commands: CommandFact[];
  pipelines: PipelineFact[];
  opaque: string[];
  envReads: string[];
}

function resolveModuleFile(specifier: string): string {
  const candidates: Array<string | URL> = [];
  if (typeof import.meta !== "undefined" && typeof import.meta.url === "string" && import.meta.url.length > 0) {
    candidates.push(import.meta.url);
  }
  if (typeof __filename === "string" && __filename.length > 0) {
    candidates.push(__filename);
  }
  candidates.push(join(process.cwd(), "package.json"));

  let lastError: unknown;
  for (const base of candidates) {
    try {
      const req = createRequire(base);
      return req.resolve(specifier);
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError instanceof Error
    ? lastError
    : new Error(`Unable to resolve module file: ${specifier}`);
}

let bashLanguagePromise: Promise<Language> | null = null;

async function getBashLanguage(): Promise<Language> {
  if (!bashLanguagePromise) {
    bashLanguagePromise = (async () => {
      const runtimeWasm = resolveModuleFile("web-tree-sitter/web-tree-sitter.wasm");
      await Parser.init({
        locateFile: () => runtimeWasm,
      });
      const bashWasmPath = resolveModuleFile("@vscode/tree-sitter-wasm/wasm/tree-sitter-bash.wasm");
      return Language.load(bashWasmPath);
    })();
  }
  return bashLanguagePromise;
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

function collectEnvReads(node: SyntaxNode, out: Set<string>): void {
  if (node.type === "simple_expansion" || node.type === "expansion") {
    const varNode = node.namedChildren.find((c) => c.type === "variable_name");
    if (varNode) {
      out.add(varNode.text);
    }
  }
  for (const child of node.namedChildren) {
    collectEnvReads(child, out);
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

  if (!source.trim()) {
    return { commands, pipelines, opaque, envReads: [] };
  }

  for (const obf of OBFUSCATION_PATTERNS) {
    if (obf.regex.test(source)) {
      opaque.push(obf.name);
    }
  }

  const lang = await getBashLanguage();
  const parser = new Parser();
  parser.setLanguage(lang);

  let tree;
  try {
    tree = parser.parse(source);
  } finally {
    parser.delete();
  }

  if (!tree) {
    return { commands, pipelines, opaque: ["parse_null_tree"], envReads: [] };
  }

  const root = tree.rootNode;
  if (root.hasError) {
    opaque.push("parse_error");
  }

  let nextPipelineId = 1;

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
    for (const v of envReads) globalEnvReads.add(v);

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
        const varName = child.childForFieldName("name")?.text;
        const varVal = child.childForFieldName("value");
        if (varName) {
          assignments[varName] = varVal ? stripQuotes(varVal) : "";
        }
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
      walkNestedSubstitutions(child);
    }

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

  function walk(node: SyntaxNode, pendingRedirects: RedirectionFact[] = []): void {
    if (node.type === "pipeline") {
      const pipelineId = nextPipelineId++;
      const pipeCmdNames: string[] = [];
      let index = 0;

      for (const child of node.namedChildren) {
        if (child.type === "command") {
          const fact = extractCommand(child, [], pipelineId, index++);
          if (fact) pipeCmdNames.push(fact.name);
        } else if (child.type === "redirected_statement") {
          const body = child.childForFieldName("body");
          const redirects: RedirectionFact[] = [];
          for (const rc of child.namedChildren) {
            if (rc.type === "file_redirect") {
              const r = extractRedirection(rc);
              if (r) redirects.push(r);
            }
          }
          if (body?.type === "command") {
            const fact = extractCommand(body, redirects, pipelineId, index++);
            if (fact) pipeCmdNames.push(fact.name);
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
          walkNestedSubstitutions(child);
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

    if (node.type === "variable_assignment") {
      collectEnvReads(node, globalEnvReads);
      walkNestedSubstitutions(node);
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
  };
}
