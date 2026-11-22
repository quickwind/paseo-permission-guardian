import type {
  ActionKind,
  AuditRecord,
  AuditResolution,
  GateEntry,
  GuardianVerdict,
  RiskLevel,
} from "../../shared/types.js";
import type { AuditWindow } from "../audit/reader.js";
import type { SessionState } from "../context/session.js";
import { decideAction } from "../decide.js";
import type { PwshHostLike, PwshShellVariant } from "../shell/pwsh-host.js";

/**
 * Replay (spec §3.3–§3.4): re-evaluates recorded audit history with the current engine to compute
 * evidence-gate metrics. Results feed gate metrics only — never a live answer.
 */

export interface ReplayDecision {
  verdict: GuardianVerdict;
  level: RiskLevel;
  reasons: string[];
  /** Replay decision effect tags as `tag[:detail]` strings. */
  effects: string[];
}

export type ReplayDecide = (record: AuditRecord) => Promise<ReplayDecision | { error: string }>;

/** A ReplayDecide that owns isolated PowerShell hosts; call `dispose()` when done with it. */
export interface ReplayDecideHandle extends ReplayDecide {
  dispose(): Promise<void>;
}

/** Returns true when a non-plugin `deny` resolution is a confirmed bulk cancellation, not a human denial. */
export type CancellationSignature = (resolution: AuditResolution, record: AuditRecord) => boolean;

/**
 * Confirmed cancellation signatures. Starts EMPTY (spec §3.3): entries may only be added from
 * captured real payloads (fixture + test). Until then every non-plugin deny is a human denial.
 */
export const CONFIRMED_CANCELLATION_SIGNATURES: CancellationSignature[] = [];

export type ReplayUnavailableReason =
  | "replay_truncated"
  | "corrupt_audit_line"
  | "orphan_human_deny"
  | "human_deny_unevaluable";

export interface ReplayResult {
  samples: number;
  falseAllows: GateEntry[];
  falseDenyCount: number;
  integrity: GateEntry[];
  skippedAllow: number;
  /**
   * Non-null ⇒ the gate is `unavailable`; the counters above are informational only and must not be
   * used to open the gate. Precedence: replay_truncated > corrupt_audit_line > orphan_human_deny >
   * human_deny_unevaluable.
   */
  unavailableReason: ReplayUnavailableReason | null;
}

const COMMAND_MAX = 200;
const PWSH_HOST_FAILURE_PREFIX = "opaque:pwsh_host_";

const KNOWN_KINDS = new Set<ActionKind>([
  "exec",
  "read",
  "edit",
  "delete",
  "fetch",
  "mcp",
  "plan",
  "question",
  "mode",
  "other",
]);

function commandOf(record: AuditRecord): string | undefined {
  const src = record.action?.exec?.source;
  return typeof src === "string" ? src.slice(0, COMMAND_MAX) : undefined;
}

function entry(record: AuditRecord, kind: GateEntry["kind"], effects: string[]): GateEntry {
  const e: GateEntry = { requestId: record.requestId, effects, kind, key: record.requestId };
  if (record.requestedAt !== undefined) e.requestedAt = record.requestedAt;
  const command = commandOf(record);
  if (command !== undefined) e.command = command;
  return e;
}

async function safeDecide(
  decide: ReplayDecide,
  record: AuditRecord,
): Promise<ReplayDecision | { error: string }> {
  try {
    return await decide(record);
  } catch (err) {
    return { error: `replay_threw:${err instanceof Error ? err.message : String(err)}` };
  }
}

function hasHostFailure(decision: ReplayDecision): boolean {
  return decision.reasons.some((r) => r.startsWith(PWSH_HOST_FAILURE_PREFIX));
}

export async function replayWindow(
  window: AuditWindow,
  decide: ReplayDecide,
  opts: { cancellationSignatures: CancellationSignature[] },
): Promise<ReplayResult> {
  const annotated = (key: string) => window.annotations.get(key) === "not_safety";

  let samples = 0;
  let falseDenyCount = 0;
  let skippedAllow = 0;
  const falseAllows: GateEntry[] = [];
  const integrity: GateEntry[] = [];
  let corrupt = false;
  let orphan = false;
  let unevaluable = false;

  for (const line of window.corruptLines) {
    if (annotated(line.key)) continue;
    corrupt = true;
    integrity.push({ requestId: "", effects: [], kind: "corrupt_line", key: line.key });
  }

  for (const record of window.records) {
    const resolution = record.resolution;
    // Pending requests (no `after`) are ignored; plugin-answered requests are ignored entirely.
    if (!resolution || resolution.actor === "plugin") continue;

    if (resolution.behavior === "deny") {
      if (opts.cancellationSignatures.some((sig) => sig(resolution, record))) continue;
      // Human denial. A `not_safety` annotation excludes it from every gate rule.
      if (annotated(record.requestId)) continue;

      if (!record.decision) {
        orphan = true;
        integrity.push(entry(record, "orphan_deny", []));
        continue;
      }

      const replayed = await safeDecide(decide, record);
      if ("error" in replayed || hasHostFailure(replayed)) {
        unevaluable = true;
        continue;
      }
      if (replayed.verdict === "allow") {
        falseAllows.push(entry(record, "false_allow", replayed.effects));
      }
      continue;
    }

    // Human allow. Only an explicit human actor counts (an `unknown` actor never adds samples).
    if (resolution.behavior !== "allow" || resolution.actor !== "human") continue;
    if (!record.decision) continue; // orphan allow: nothing to replay, never a sample

    const replayed = await safeDecide(decide, record);
    if ("error" in replayed) {
      skippedAllow += 1;
      continue;
    }
    if (replayed.level === "L3") falseDenyCount += 1;
    if (replayed.verdict === "allow") {
      const snapshot = record.contextSnapshot;
      const hasUsableSnapshot = snapshot !== undefined && !snapshot.modifiedFilesTruncated;
      if (hasUsableSnapshot || record.decision.verdict === "allow") samples += 1;
    }
  }

  const unavailableReason: ReplayUnavailableReason | null = window.truncated
    ? "replay_truncated"
    : corrupt
      ? "corrupt_audit_line"
      : orphan
        ? "orphan_human_deny"
        : unevaluable
          ? "human_deny_unevaluable"
          : null;

  return { samples, falseAllows, falseDenyCount, integrity, skippedAllow, unavailableReason };
}

function sessionFromRecord(record: AuditRecord): SessionState {
  const snap = record.contextSnapshot;
  return {
    agentId: record.agentId,
    untrustedTaint: snap?.untrustedTaint === true,
    secretTaint: snap?.secretTaint === true,
    taintEpoch: 0,
    worktreeMutationEpoch: 0,
    scopeGrantVersion: 0,
    modifiedFiles: new Set(snap?.modifiedFiles ?? []),
    modifiedEntrypoints: new Set(snap?.modifiedEntrypoints ?? []),
    seenCallIds: new Set(),
  };
}

/**
 * Real-engine ReplayDecide. Uses `skipHostRealpath` (no dependency on current filesystem state), a
 * fresh session built from the record's `contextSnapshot`, and replay-only PowerShell hosts from
 * `pwshHostFactory` (one cached per shell for the handle's lifetime; never the shared live host).
 * The returned function carries `dispose()` which disposes the cached hosts.
 */
export function createReplayDecide(opts: {
  pwshHostFactory: (shell: PwshShellVariant) => PwshHostLike | null;
  home: string;
  pluginDataDir: string;
}): ReplayDecideHandle {
  const hosts = new Map<PwshShellVariant, PwshHostLike | null>();
  const provider = (shell: PwshShellVariant): PwshHostLike | null => {
    if (!hosts.has(shell)) hosts.set(shell, opts.pwshHostFactory(shell));
    return hosts.get(shell) ?? null;
  };

  const decide = async (record: AuditRecord): Promise<ReplayDecision | { error: string }> => {
    const action = record.action;
    if (!action) return { error: "action_missing" };
    if (!KNOWN_KINDS.has(action.kind)) return { error: "unknown_action_kind" };
    if (!action.host || typeof action.cwd !== "string") return { error: "action_incomplete" };
    try {
      const result = await decideAction(action, {
        pathCtx: {
          cwd: action.cwd,
          worktreeRoot: action.worktreeRoot ?? action.cwd,
          home: opts.home,
          pluginDataDir: opts.pluginDataDir,
          skipHostRealpath: true,
          os: action.host.os,
        },
        session: sessionFromRecord(record),
        denyAsAsk: false,
        pwshHostProvider: provider,
      });
      const d = result.decision;
      const effects = Array.from(
        new Set((d.effects ?? []).map((e) => (e.detail ? `${e.tag}:${e.detail}` : e.tag))),
      );
      return { verdict: d.verdict, level: d.level, reasons: d.reasons, effects };
    } catch (err) {
      return { error: `decide_threw:${err instanceof Error ? err.message : String(err)}` };
    }
  };

  const handle = decide as ReplayDecideHandle;
  handle.dispose = async () => {
    const owned = Array.from(hosts.values()).filter((h): h is PwshHostLike => h !== null);
    hosts.clear();
    await Promise.all(owned.map((h) => h.dispose().catch(() => undefined)));
  };
  return handle;
}
