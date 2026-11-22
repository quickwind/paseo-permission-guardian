import type { AuditRecord, GateEntry } from "../../shared/types.js";

/** Display limits for gate entries (values come from already-redacted audit records). */
export const ENTRY_SUMMARY_MAX = 200;
const ENTRY_MESSAGE_MAX = 500;

function clip(value: string, max: number): string {
  return value.length > max ? value.slice(0, max) : value;
}

/** Exec source (≤200), paths, URL, or MCP `server:tool` of a recorded action. */
export function summarizeAction(action: AuditRecord["action"]): string | undefined {
  if (!action) return undefined;
  const src = action.exec?.source;
  if (typeof src === "string") return clip(src, ENTRY_SUMMARY_MAX);
  if (Array.isArray(action.paths) && action.paths.length > 0) {
    return clip(action.paths.filter((p) => typeof p === "string").join(", "), ENTRY_SUMMARY_MAX);
  }
  if (typeof action.url?.href === "string") return clip(action.url.href, ENTRY_SUMMARY_MAX);
  if (action.mcp && typeof action.mcp.server === "string" && typeof action.mcp.tool === "string") {
    return clip(`${action.mcp.server}:${action.mcp.tool}`, ENTRY_SUMMARY_MAX);
  }
  return undefined;
}

/**
 * Builds a gate entry with everything a human needs to judge it: when, provider, agent, tool,
 * what was requested, and how the human resolved it. Display only — never used for gate decisions.
 */
export function buildGateEntry(
  record: AuditRecord,
  kind: GateEntry["kind"],
  effects: string[],
  key: string = record.requestId,
): GateEntry {
  const e: GateEntry = { requestId: record.requestId, effects, kind, key };
  if (typeof record.requestedAt === "string") e.requestedAt = record.requestedAt;
  const src = record.action?.exec?.source;
  if (typeof src === "string") e.command = clip(src, ENTRY_SUMMARY_MAX);
  const res = record.resolution;
  if (res && typeof res.resolvedAt === "string") e.resolvedAt = res.resolvedAt;
  if (typeof record.provider === "string" && record.provider) e.provider = record.provider;
  if (typeof record.agentId === "string" && record.agentId) e.agentId = record.agentId;
  if (typeof record.agentTitle === "string" && record.agentTitle) e.agentTitle = record.agentTitle;
  if (typeof record.action?.toolName === "string" && record.action.toolName) e.toolName = record.action.toolName;
  const summary = summarizeAction(record.action);
  if (summary !== undefined) e.summary = summary;
  if (res && (res.behavior === "allow" || res.behavior === "deny")) {
    e.resolution = { behavior: res.behavior };
    if (typeof res.selectedActionId === "string") e.resolution.selectedActionId = res.selectedActionId;
    if (typeof res.message === "string") e.resolution.message = clip(res.message, ENTRY_MESSAGE_MAX);
  }
  const oc = record.orphanContext;
  // Orphan context describes orphan denials only; never shown on any other entry kind.
  if (kind === "orphan_deny" && oc && typeof oc === "object") {
    e.orphanContext = {};
    if (oc.unavailable === true) e.orphanContext.unavailable = true;
    for (const k of ["toolName", "summary", "callId", "matchedBy"] as const) {
      const v = oc[k];
      if (typeof v === "string") e.orphanContext[k] = clip(v, ENTRY_SUMMARY_MAX);
    }
  }
  return e;
}

/** Re-reads display fields from the latest record while keeping the entry's identity and effects. */
export function refreshGateEntry(entry: GateEntry, record: AuditRecord | undefined): GateEntry {
  if (!record || !entry.requestId || record.requestId !== entry.requestId) return entry;
  return buildGateEntry(record, entry.kind, entry.effects, entry.key);
}
