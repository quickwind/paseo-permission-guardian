import { hasSandboxBypassFlag } from "./sandbox.js";
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

const CLAUDE_READ_TOOLS = new Set(["read", "glob", "grep", "ls", "view", "notebookread"]);
const CLAUDE_EDIT_TOOLS = new Set(["edit", "write", "multiedit", "notebookedit"]);
const CLAUDE_FETCH_TOOLS = new Set(["webfetch", "websearch"]);

export function isClaudeProvider(provider: string): boolean {
  const lower = provider.toLowerCase();
  return lower === "claude" || lower.startsWith("claude-") || lower.startsWith("claude/");
}

export function normalizeClaudeRequest(
  request: AgentPermissionRequest,
  ctx: NormalizeContext,
): NormalizeResult | null {
  if (!isClaudeProvider(request.provider || ctx.provider)) {
    return null;
  }

  const warnings: string[] = [];
  const toolName = request.name || "unknown";
  const lowerTool = toolName.toLowerCase();
  const input = asRecord(request.input);

  const base: Omit<Action, "kind"> = {
    provider: request.provider || ctx.provider,
    agentId: ctx.agentId,
    requestId: request.id,
    toolName,
    host: { os: ctx.hostOs },
    cwd: ctx.cwd,
    worktreeRoot: ctx.worktreeRoot,
    ...(hasSandboxBypassFlag(input) ? { sandboxBypass: true } : {}),
    ...(ctx.includeRaw ? { raw: request } : {}),
  };

  if (lowerTool === "askuserquestion") {
    return { action: { ...base, kind: "question" }, normalizedBy: "claude", warnings };
  }
  if (lowerTool === "exitplanmode" || lowerTool === "enterplanmode") {
    return { action: { ...base, kind: "plan" }, normalizedBy: "claude", warnings };
  }

  const mcpParts = parseMcpToolName(toolName);
  if (mcpParts) {
    return {
      action: {
        ...base,
        kind: "mcp",
        mcp: {
          server: mcpParts.server,
          tool: mcpParts.tool,
          args: request.input ?? {},
        },
      },
      normalizedBy: "claude",
      warnings,
    };
  }

  if (lowerTool === "bash" || lowerTool === "powershell" || lowerTool === "pwsh" || lowerTool === "cmd" || lowerTool === "shell") {
    const command =
      asNonEmptyString(input?.command) ??
      (request.detail?.type === "shell" ? asNonEmptyString(request.detail.command) : undefined);
    const shell = defaultExecShell(ctx, lowerTool);
    if (!command) {
      warnings.push("missing_exec_command");
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
      normalizedBy: "claude",
      warnings,
    };
  }

  if (CLAUDE_READ_TOOLS.has(lowerTool)) {
    const paths = collectPathsFromObject(input);
    if (request.detail?.type === "read" && request.detail.filePath) {
      if (!paths.includes(request.detail.filePath)) {
        paths.push(request.detail.filePath);
      }
    }
    return {
      action: {
        ...base,
        kind: "read",
        ...(paths.length > 0 ? { paths } : {}),
      },
      normalizedBy: "claude",
      warnings,
    };
  }

  if (CLAUDE_EDIT_TOOLS.has(lowerTool)) {
    const paths = collectPathsFromObject(input);
    if ((request.detail?.type === "edit" || request.detail?.type === "write") && request.detail.filePath) {
      if (!paths.includes(request.detail.filePath)) {
        paths.push(request.detail.filePath);
      }
    }
    return {
      action: {
        ...base,
        kind: "edit",
        ...(paths.length > 0 ? { paths } : {}),
      },
      normalizedBy: "claude",
      warnings,
    };
  }

  if (CLAUDE_FETCH_TOOLS.has(lowerTool)) {
    const href =
      asNonEmptyString(input?.url) ??
      (request.detail?.type === "fetch" ? asNonEmptyString(request.detail.url) : undefined);
    return {
      action: {
        ...base,
        kind: "fetch",
        ...(href ? { url: { href, method: asNonEmptyString(input?.method) } } : {}),
      },
      normalizedBy: "claude",
      warnings,
    };
  }

  // Fallback to Paseo's normalized detail if present on an unfamiliar Claude tool
  const fallbackKind = inferKindFromDetail(request);
  if (fallbackKind === "other") {
    warnings.push(`unrecognized_claude_tool:${toolName}`);
  }
  return {
    action: {
      ...base,
      kind: fallbackKind,
    },
    normalizedBy: "claude",
    warnings,
  };
}

function inferKindFromDetail(request: AgentPermissionRequest): ActionKind {
  switch (request.detail?.type) {
    case "shell":
      return "exec";
    case "read":
    case "search":
      return "read";
    case "edit":
    case "write":
      return "edit";
    case "fetch":
      return "fetch";
    case "plan":
      return "plan";
    default:
      return "other";
  }
}
