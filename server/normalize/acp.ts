import type { AgentPermissionRequest } from "@getpaseo/protocol/agent-types";
import type { Action, ActionKind } from "../../shared/types.js";
import {
  asNonEmptyString,
  asRecord,
  collectPathsFromObject,
  defaultExecShell,
  parseMcpToolName,
  type NormalizeContext,
  type NormalizeResult,
} from "./types.js";

const KNOWN_ACP_PROVIDERS = [
  "acp",
  "antigravity",
  "agy",
  "devin",
  "cursor",
  "gemini",
  "kiro",
  "goose",
];

const ACP_EXEC_KINDS = new Set(["execute", "exec", "shell", "bash", "run_command", "terminal"]);
const ACP_READ_KINDS = new Set(["read", "search", "view_file", "list_dir", "find_by_name", "grep_search"]);
const ACP_EDIT_KINDS = new Set([
  "edit",
  "write",
  "write_to_file",
  "replace_file_content",
  "multi_replace_file_content",
  "create_file",
]);
const ACP_DELETE_KINDS = new Set(["delete", "remove", "remove_file"]);
const ACP_FETCH_KINDS = new Set(["fetch", "web_fetch", "read_url_content", "search_web"]);

export function isAcpRequest(request: AgentPermissionRequest, provider: string): boolean {
  const lower = (request.provider || provider).toLowerCase();
  if (KNOWN_ACP_PROVIDERS.some((prefix) => lower === prefix || lower.startsWith(`${prefix}-`) || lower.startsWith(`${prefix}/`) || lower.includes("acp"))) {
    return true;
  }
  const metadata = asRecord(request.metadata);
  const rawRequest = asRecord(metadata?.rawRequest);
  return Boolean(asRecord(rawRequest?.toolCall));
}

function extractAcpToolInfo(request: AgentPermissionRequest): {
  kindHint: string;
  toolTitle?: string;
  rawInput?: Record<string, unknown>;
  locations: string[];
} {
  const metadata = asRecord(request.metadata);
  const rawRequest = asRecord(metadata?.rawRequest);
  const toolCall = asRecord(rawRequest?.toolCall);
  const rawInput = asRecord(toolCall?.rawInput) ?? asRecord(request.input);

  const kindHint =
    asNonEmptyString(toolCall?.kind) ??
    asNonEmptyString(request.name) ??
    "other";

  const toolTitle =
    asNonEmptyString(toolCall?.title) ??
    asNonEmptyString(request.title);

  const locations: string[] = [];
  if (Array.isArray(toolCall?.locations)) {
    for (const loc of toolCall.locations) {
      const locRec = asRecord(loc);
      const locPath = asNonEmptyString(locRec?.path);
      if (locPath) locations.push(locPath);
    }
  }

  return { kindHint, toolTitle, rawInput, locations };
}

export function normalizeAcpRequest(
  request: AgentPermissionRequest,
  ctx: NormalizeContext,
): NormalizeResult | null {
  if (!isAcpRequest(request, ctx.provider)) {
    return null;
  }

  const warnings: string[] = [];
  const { kindHint, toolTitle, rawInput, locations } = extractAcpToolInfo(request);
  const lowerKind = kindHint.toLowerCase();
  const toolName = toolTitle ?? request.name ?? kindHint;

  const base: Omit<Action, "kind"> = {
    provider: request.provider || ctx.provider,
    agentId: ctx.agentId,
    requestId: request.id,
    toolName,
    host: { os: ctx.hostOs },
    cwd: asNonEmptyString(rawInput?.cwd) ?? asNonEmptyString(rawInput?.Cwd) ?? ctx.cwd,
    worktreeRoot: ctx.worktreeRoot,
    ...(ctx.includeRaw ? { raw: request } : {}),
  };

  // Detect MCP tools surfaced through ACP (e.g. mcp__server__tool or mcp_server_tool)
  const mcpParts = parseMcpToolName(request.name) ?? (toolTitle ? parseMcpToolName(toolTitle) : null);
  if (mcpParts) {
    return {
      action: {
        ...base,
        kind: "mcp",
        mcp: {
          server: mcpParts.server,
          tool: mcpParts.tool,
          args: rawInput ?? {},
        },
      },
      normalizedBy: "acp",
      warnings,
    };
  }

  if (ACP_EXEC_KINDS.has(lowerKind) || request.detail?.type === "shell") {
    const command =
      asNonEmptyString(rawInput?.command) ??
      asNonEmptyString(rawInput?.CommandLine) ??
      asNonEmptyString(rawInput?.cmd) ??
      (request.detail?.type === "shell" ? asNonEmptyString(request.detail.command) : undefined);

    const shellHint = asNonEmptyString(rawInput?.shell) ?? asNonEmptyString(rawInput?.Shell);
    const shell = defaultExecShell(ctx, shellHint);

    if (!command) {
      warnings.push("missing_acp_exec_command");
    }
    if (!shell) {
      warnings.push("unknown_shell");
    }

    return {
      action: {
        ...base,
        kind: command && shell ? "exec" : "other",
        ...(command && shell ? { exec: { shell, source: command } } : {}),
      },
      normalizedBy: "acp",
      warnings,
    };
  }

  const allPaths = Array.from(new Set([...locations, ...collectPathsFromObject(rawInput)]));

  if (ACP_DELETE_KINDS.has(lowerKind)) {
    return {
      action: {
        ...base,
        kind: "delete",
        ...(allPaths.length > 0 ? { paths: allPaths } : {}),
      },
      normalizedBy: "acp",
      warnings,
    };
  }

  if (ACP_EDIT_KINDS.has(lowerKind) || request.detail?.type === "edit" || request.detail?.type === "write") {
    if ((request.detail?.type === "edit" || request.detail?.type === "write") && request.detail.filePath) {
      if (!allPaths.includes(request.detail.filePath)) {
        allPaths.push(request.detail.filePath);
      }
    }
    return {
      action: {
        ...base,
        kind: "edit",
        ...(allPaths.length > 0 ? { paths: allPaths } : {}),
      },
      normalizedBy: "acp",
      warnings,
    };
  }

  if (ACP_READ_KINDS.has(lowerKind) || request.detail?.type === "read" || request.detail?.type === "search") {
    if (request.detail?.type === "read" && request.detail.filePath) {
      if (!allPaths.includes(request.detail.filePath)) {
        allPaths.push(request.detail.filePath);
      }
    }
    return {
      action: {
        ...base,
        kind: "read",
        ...(allPaths.length > 0 ? { paths: allPaths } : {}),
      },
      normalizedBy: "acp",
      warnings,
    };
  }

  if (ACP_FETCH_KINDS.has(lowerKind) || request.detail?.type === "fetch") {
    const href =
      asNonEmptyString(rawInput?.url) ??
      asNonEmptyString(rawInput?.Url) ??
      asNonEmptyString(rawInput?.href) ??
      (request.detail?.type === "fetch" ? asNonEmptyString(request.detail.url) : undefined);

    return {
      action: {
        ...base,
        kind: "fetch",
        ...(href
          ? {
              url: {
                href,
                method: asNonEmptyString(rawInput?.method),
                hasBody: rawInput?.body !== undefined,
              },
            }
          : {}),
      },
      normalizedBy: "acp",
      warnings,
    };
  }

  const fallbackKind: ActionKind = "other";
  warnings.push(`unrecognized_acp_kind:${kindHint}`);
  return {
    action: {
      ...base,
      kind: fallbackKind,
      ...(allPaths.length > 0 ? { paths: allPaths } : {}),
    },
    normalizedBy: "acp",
    warnings,
  };
}
