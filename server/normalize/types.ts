import type { AgentPermissionRequest } from "@getpaseo/protocol/agent-types";
import type { Action, HostOs, Shell } from "../../shared/types.js";

export interface NormalizeContext {
  agentId: string;
  provider: string;
  cwd: string;
  worktreeRoot?: string;
  hostOs: HostOs;
  windowsDefaultShell?: Extract<Shell, "pwsh7" | "pwsh5" | "cmd">;
  includeRaw?: boolean;
}

export interface NormalizeResult {
  action: Action;
  normalizedBy: string;
  warnings: string[];
}

export type ProviderNormalizer = (
  request: AgentPermissionRequest,
  ctx: NormalizeContext,
) => NormalizeResult | null;

export function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return undefined;
}

export function asNonEmptyString(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim().length > 0) {
    return value;
  }
  return undefined;
}

export function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
}

export function detectHostOs(platform: string = process.platform): HostOs {
  if (platform === "win32") return "windows";
  if (platform === "darwin") return "darwin";
  return "linux";
}

export function defaultExecShell(ctx: NormalizeContext, hint?: string): Shell | undefined {
  const normalizedHint = hint?.toLowerCase();
  if (normalizedHint) {
    if (normalizedHint.includes("pwsh7") || normalizedHint === "pwsh") return "pwsh7";
    if (normalizedHint.includes("pwsh5") || normalizedHint.includes("powershell")) {
      return ctx.hostOs === "windows" ? (ctx.windowsDefaultShell === "pwsh5" ? "pwsh5" : "pwsh7") : "pwsh7";
    }
    if (normalizedHint === "cmd" || normalizedHint === "cmd.exe") return "cmd";
    if (
      normalizedHint.includes("bash") ||
      normalizedHint === "sh" ||
      normalizedHint === "zsh" ||
      normalizedHint === "posix"
    ) {
      return "bash";
    }
  }
  if (ctx.hostOs === "windows") {
    return ctx.windowsDefaultShell ?? "pwsh7";
  }
  return "bash";
}

export function parseMcpToolName(name: string): { server: string; tool: string } | null {
  if (!name.startsWith("mcp__")) {
    return null;
  }
  const rest = name.slice("mcp__".length);
  const separatorIndex = rest.indexOf("__");
  if (separatorIndex <= 0 || separatorIndex === rest.length - 2) {
    return null;
  }
  return {
    server: rest.slice(0, separatorIndex),
    tool: rest.slice(separatorIndex + 2),
  };
}

export function collectPathsFromObject(input: Record<string, unknown> | undefined): string[] {
  if (!input) return [];
  const candidates: string[] = [];
  const singleKeys = [
    "file_path",
    "filePath",
    "path",
    "Path",
    "target_file",
    "targetFile",
    "TargetFile",
    "AbsolutePath",
    "DirectoryPath",
    "SearchPath",
    "notebook_path",
    "notebookPath",
  ];
  for (const key of singleKeys) {
    const val = asNonEmptyString(input[key]);
    if (val) candidates.push(val);
  }
  const arrayKeys = ["paths", "file_paths", "filePaths", "files"];
  for (const key of arrayKeys) {
    candidates.push(...asStringArray(input[key]));
  }
  return Array.from(new Set(candidates));
}
