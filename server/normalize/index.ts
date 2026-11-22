import type { AgentPermissionRequest } from "@getpaseo/protocol/agent-types";
import type { Action } from "../../shared/types.js";
import { normalizeAcpRequest } from "./acp.js";
import { normalizeClaudeRequest } from "./claude.js";
import {
  asNonEmptyString,
  defaultExecShell,
  type NormalizeContext,
  type NormalizeResult,
} from "./types.js";

export type { NormalizeContext, NormalizeResult } from "./types.js";
export { detectHostOs } from "./types.js";

/**
 * Normalize a provider-specific AgentPermissionRequest into a unified Action.
 * Never throws; unsupported payloads map safely to kind: "other" (fail-to-human).
 */
export function normalizePermissionRequest(
  request: AgentPermissionRequest,
  ctx: NormalizeContext,
): NormalizeResult {
  const provider = request.provider || ctx.provider;

  // Non-tool requests (question, plan, mode) are never auto-answered.
  if (request.kind === "question" || request.kind === "plan" || request.kind === "mode") {
    return {
      action: {
        provider,
        agentId: ctx.agentId,
        requestId: request.id,
        kind: request.kind,
        toolName: request.name || request.kind,
        host: { os: ctx.hostOs },
        cwd: ctx.cwd,
        worktreeRoot: ctx.worktreeRoot,
        ...(ctx.includeRaw ? { raw: request } : {}),
      },
      normalizedBy: "kind-passthrough",
      warnings: [],
    };
  }

  const claudeResult = normalizeClaudeRequest(request, ctx);
  if (claudeResult) {
    return claudeResult;
  }

  const acpResult = normalizeAcpRequest(request, ctx);
  if (acpResult) {
    return acpResult;
  }

  return normalizeGenericFallback(request, ctx);
}

function normalizeGenericFallback(
  request: AgentPermissionRequest,
  ctx: NormalizeContext,
): NormalizeResult {
  const warnings: string[] = [`unsupported_provider:${request.provider || ctx.provider}`];
  const base: Omit<Action, "kind"> = {
    provider: request.provider || ctx.provider,
    agentId: ctx.agentId,
    requestId: request.id,
    toolName: request.name || "unknown",
    host: { os: ctx.hostOs },
    cwd: ctx.cwd,
    worktreeRoot: ctx.worktreeRoot,
    ...(ctx.includeRaw ? { raw: request } : {}),
  };

  if (request.detail?.type === "shell") {
    const command = asNonEmptyString(request.detail.command);
    const shell = defaultExecShell(ctx);
    if (command && shell) {
      return {
        action: {
          ...base,
          kind: "exec",
          exec: { shell, source: command },
        },
        normalizedBy: "generic-detail",
        warnings,
      };
    }
  }

  if (request.detail?.type === "read") {
    return {
      action: {
        ...base,
        kind: "read",
        paths: [request.detail.filePath],
      },
      normalizedBy: "generic-detail",
      warnings,
    };
  }

  if (request.detail?.type === "edit" || request.detail?.type === "write") {
    return {
      action: {
        ...base,
        kind: "edit",
        paths: [request.detail.filePath],
      },
      normalizedBy: "generic-detail",
      warnings,
    };
  }

  if (request.detail?.type === "fetch") {
    return {
      action: {
        ...base,
        kind: "fetch",
        url: { href: request.detail.url },
      },
      normalizedBy: "generic-detail",
      warnings,
    };
  }

  return {
    action: {
      ...base,
      kind: "other",
    },
    normalizedBy: "generic-fallback",
    warnings,
  };
}
