import type { AgentTimelineItem } from "@getpaseo/protocol/agent-types";
import type { OrphanContext } from "../../shared/types.js";
import { redactString } from "../audit/redact.js";

/**
 * Best-effort recovery of what an orphan human denial (an `after` without a `before`) was about,
 * from the agent timeline. Display only: never changes gate semantics.
 */

export interface TimelineEntry {
  item: AgentTimelineItem;
  timestamp?: string;
}

/** Fetches the agent's latest turn(s) with timestamps (same query as the before-hook fetcher). */
export type TimelineEntriesFetcher = (agentId: string, signal?: AbortSignal) => Promise<TimelineEntry[]>;

export interface OrphanMatchOptions {
  resolvedAtMs: number;
  /** Accept entries without a timestamp (only when fetching right after the resolution). */
  allowUntimed?: boolean;
  /** Oldest accepted call relative to resolvedAt (default 10 minutes). */
  maxAgeMs?: number;
  /** Clock skew tolerance after resolvedAt (default 5 seconds). */
  skewMs?: number;
}

const SUMMARY_MAX = 200;
const DENIED_RE = /\b(?:denied|deny|rejected|reject|declined|permission|not allowed)\b/i;

type ToolCall = Extract<AgentTimelineItem, { type: "tool_call" }>;

function clip(s: string): string {
  return redactString(s.length > SUMMARY_MAX ? s.slice(0, SUMMARY_MAX) : s).slice(0, SUMMARY_MAX);
}

function safeJson(v: unknown): string {
  try {
    return JSON.stringify(v) ?? "";
  } catch {
    return "";
  }
}

export function summarizeToolCall(item: ToolCall): string | undefined {
  const d = item.detail as Record<string, unknown> | undefined;
  if (!d || typeof d !== "object") return undefined;
  const pick = (...keys: string[]): string | undefined => {
    for (const k of keys) {
      const v = d[k];
      if (typeof v === "string" && v.trim()) return v;
    }
    return undefined;
  };
  let text: string | undefined;
  switch (d.type) {
    case "shell":
      text = pick("command");
      break;
    case "read":
    case "edit":
    case "write":
      text = pick("filePath");
      break;
    case "fetch":
      text = pick("url");
      break;
    case "search":
      text = pick("query");
      break;
    case "sub_agent":
      text = pick("description", "subAgentType");
      break;
    case "plain_text":
      text = pick("text", "label");
      break;
    case "plan":
      text = pick("text");
      break;
    case "worktree_setup":
      text = pick("worktreePath");
      break;
    default:
      text = d.input !== undefined ? safeJson(d.input) : undefined;
  }
  return text ? clip(text) : undefined;
}

function tier(item: ToolCall): { rank: number; matchedBy: string } {
  if (item.status === "failed" || item.status === "canceled") {
    const errorText = typeof item.error === "string" ? item.error : safeJson(item.error);
    if (DENIED_RE.test(`${errorText} ${safeJson(item.metadata ?? null)}`)) {
      return { rank: 0, matchedBy: "permission_denied" };
    }
    return { rank: 1, matchedBy: "failed_or_canceled" };
  }
  if (item.status === "running") return { rank: 2, matchedBy: "running" };
  return { rank: 3, matchedBy: "nearest_before" };
}

/**
 * Picks the tool call that best matches a denied request: a call whose status/error mentions a
 * denial, then a failed/canceled call, then a still-running call, then any call — each preferring
 * the one nearest before `resolvedAt`. Calls outside the time window are ignored. Returns null
 * when nothing plausible is found.
 */
export function matchOrphanToolCall(entries: TimelineEntry[], opts: OrphanMatchOptions): OrphanContext | null {
  const maxAge = opts.maxAgeMs ?? 10 * 60_000;
  const skew = opts.skewMs ?? 5_000;
  let best: { rank: number; matchedBy: string; time: number; order: number; item: ToolCall } | null = null;
  entries.forEach((entry, order) => {
    const item = entry?.item as AgentTimelineItem | undefined;
    if (!item || item.type !== "tool_call") return;
    const ms = typeof entry.timestamp === "string" ? Date.parse(entry.timestamp) : Number.NaN;
    let time: number;
    if (Number.isNaN(ms)) {
      if (!opts.allowUntimed) return;
      time = Number.NEGATIVE_INFINITY;
    } else {
      if (ms > opts.resolvedAtMs + skew || ms < opts.resolvedAtMs - maxAge) return;
      time = ms;
    }
    const t = tier(item);
    const better =
      !best ||
      t.rank < best.rank ||
      (t.rank === best.rank && (time > best.time || (time === best.time && order > best.order)));
    if (better) best = { ...t, time, order, item };
  });
  if (!best) return null;
  const chosen = best as { matchedBy: string; item: ToolCall };
  const out: OrphanContext = { matchedBy: chosen.matchedBy };
  if (typeof chosen.item.name === "string" && chosen.item.name) out.toolName = clip(chosen.item.name);
  const summary = summarizeToolCall(chosen.item);
  if (summary) out.summary = summary;
  if (typeof chosen.item.callId === "string" && chosen.item.callId) out.callId = clip(chosen.item.callId);
  return out;
}

/** Runs the fetcher with a timeout and the caller's signal; any failure or no match ⇒ unavailable. */
export async function recoverOrphanContext(
  fetcher: TimelineEntriesFetcher,
  agentId: string,
  opts: OrphanMatchOptions & { timeoutMs?: number; signal?: AbortSignal },
): Promise<OrphanContext> {
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  if (opts.signal) {
    if (opts.signal.aborted) controller.abort();
    else opts.signal.addEventListener("abort", onAbort, { once: true });
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    if (controller.signal.aborted) return { unavailable: true };
    const aborted = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new Error("orphan_context_timeout"));
      }, opts.timeoutMs ?? 3_000);
      controller.signal.addEventListener("abort", () => reject(new Error("orphan_context_aborted")), {
        once: true,
      });
    });
    aborted.catch(() => undefined);
    const entries = await Promise.race([fetcher(agentId, controller.signal), aborted]);
    if (!Array.isArray(entries)) return { unavailable: true };
    return matchOrphanToolCall(entries, opts) ?? { unavailable: true };
  } catch {
    return { unavailable: true };
  } finally {
    if (timer) clearTimeout(timer);
    opts.signal?.removeEventListener("abort", onAbort);
  }
}
