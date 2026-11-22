import { mkdir, appendFile, stat, writeFile, rename, readFile, rm, open } from "node:fs/promises";
import { join } from "node:path";
import type {
  Action,
  AgreementOutcome,
  AuditMetricsSummary,
  ActOutcome,
  ContextSnapshot,
  OfferedAction,
  OrphanContext,
  AuditRecord,
  AuditResolution,
  GuardianDecision,
  GuardianMode,
} from "../../shared/types.js";
import { computeAgreement } from "./agreement.js";
import { readAuditDir } from "./reader.js";

export { computeAgreement };
import { redactString, redactValue } from "./redact.js";

export interface AuditStoreOptions {
  dataDir: string;
  pluginVersion: string;
  maxFileBytes?: number;
  maxInMemoryRecords?: number;
  now?: () => Date;
  /** Injectable append function (tests simulate slow filesystems). */
  writeFn?: (path: string, line: string) => Promise<void>;
}

export interface RecordBeforeInput {
  requestId: string;
  agentId: string;
  provider: string;
  mode: GuardianMode;
  requestedAt: string;
  latencyMs: number;
  normalizedBy: string;
  warnings: string[];
  action: Action;
  decision: GuardianDecision;
  offeredActions?: OfferedAction[];
  contextSnapshot?: ContextSnapshot;
  /** Agent title from the hook payload (display only; redacted). */
  agentTitle?: string | null;
}

export type MergeListener = (record: AuditRecord, previous: AuditRecord | undefined) => void;

export interface RecordAfterInput {
  requestId: string;
  agentId: string;
  provider: string;
  mode: GuardianMode;
  resolution: AuditResolution;
  agentTitle?: string | null;
}

const AGENT_TITLE_MAX = 200;

function redactTitle(title: string | null | undefined): string | undefined {
  if (typeof title !== "string" || title.trim() === "") return undefined;
  return redactString(title.slice(0, AGENT_TITLE_MAX));
}

const PERSIST_FAILURE_FILE = "persist-failure.json";
const DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024; // 10 MiB
const DEFAULT_MAX_IN_MEMORY_RECORDS = 5_000;

function emptyMetrics(): AuditMetricsSummary {
  return {
    totalRequests: 0,
    reconciledCount: 0,
    pendingCount: 0,
    wouldAllowCount: 0,
    wouldAskCount: 0,
    wouldDenyCount: 0,
    humanAllowCount: 0,
    humanDenyCount: 0,
    falseAllowCount: 0,
    falseDenyCount: 0,
    agreementCount: 0,
    outOfOrderCount: 0,
    lastUpdatedAt: null,
  };
}

/**
 * Redacts only the path lists of a context snapshot. `redactValue` on the whole object would replace
 * the boolean `secretTaint` (its key matches the sensitive-name pattern) with a marker, and replay
 * would then read it as "not tainted".
 */
function redactSnapshot(snap: ContextSnapshot): ContextSnapshot {
  return {
    secretTaint: snap.secretTaint === true,
    untrustedTaint: snap.untrustedTaint === true,
    modifiedEntrypoints: redactValue([...snap.modifiedEntrypoints]),
    modifiedFiles: redactValue([...snap.modifiedFiles]),
    modifiedFilesTruncated: snap.modifiedFilesTruncated === true,
    ...(snap.contextUnavailable !== undefined ? { contextUnavailable: snap.contextUnavailable === true } : {}),
    ...(snap.deleteTargetsClean ? { deleteTargetsClean: redactDeleteTargets(snap.deleteTargetsClean) } : {}),
  };
}

/** Keys are redacted like other paths; values stay booleans. A key collision keeps `false`. */
function redactDeleteTargets(map: Record<string, boolean>): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const [key, value] of Object.entries(map)) {
    const redacted = redactString(key);
    const clean = value === true;
    out[redacted] = Object.prototype.hasOwnProperty.call(out, redacted) ? out[redacted] === true && clean : clean;
  }
  return out;
}

export class AuditStore {
  private readonly dataDir: string;
  private readonly pluginVersion: string;
  private readonly maxFileBytes: number;
  private readonly maxInMemoryRecords: number;
  private readonly now: () => Date;
  private readonly writeFn: (path: string, line: string) => Promise<void>;
  private readonly listeners = new Set<MergeListener>();

  private readonly records = new Map<string, AuditRecord>();
  private writeQueue: Promise<void> = Promise.resolve();
  private dirReady = false;
  private activeDateKey = "";
  private activeFileIndex = 0;

  private metrics: AuditMetricsSummary = emptyMetrics();
  private persistFailure: { count: number; firstAt: string; lastError: string } | null = null;
  private touched: Set<string> | null = null;
  private readonly checkedFiles = new Set<string>();

  constructor(options: AuditStoreOptions) {
    this.dataDir = options.dataDir;
    this.pluginVersion = options.pluginVersion;
    this.maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
    this.maxInMemoryRecords = options.maxInMemoryRecords ?? DEFAULT_MAX_IN_MEMORY_RECORDS;
    this.now = options.now ?? (() => new Date());
    this.writeFn = options.writeFn ?? ((path, line) => appendFile(path, line, "utf8"));
  }

  onMerged(listener: MergeListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  setActOutcome(requestId: string, outcome: ActOutcome): void {
    const existing = this.records.get(requestId);
    if (!existing) {
      console.error(`[paseo-permission-guardian] setActOutcome: unknown requestId ${requestId}`);
      return;
    }
    const next: AuditRecord = { ...existing, actOutcome: outcome };
    this.records.set(requestId, next);
    this.touched?.add(requestId);
    void this.enqueueAppend({ event: "update", record: next }).catch(() => {});
  }

  /**
   * Display-only orphan context (best-effort timeline recovery). Written as an `update` event; does
   * not notify merge listeners, so it never changes gate state. Ignored once the record has a
   * decision (no longer an orphan).
   */
  setOrphanContext(requestId: string, context: OrphanContext): void {
    const existing = this.records.get(requestId);
    if (!existing || existing.decision) return;
    const next: AuditRecord = { ...existing, orphanContext: redactValue({ ...context }) };
    this.records.set(requestId, next);
    this.touched?.add(requestId);
    void this.enqueueAppend({ event: "update", record: next }).catch(() => {});
  }

  async appendEvent(event: { event: "gate" | "annotation"; [k: string]: unknown }): Promise<void> {
    await this.enqueueAppend(event);
  }

  getPersistFailure(): { count: number; firstAt: string; lastError: string } | null {
    return this.persistFailure ? { ...this.persistFailure } : null;
  }

  async clearPersistFailure(): Promise<void> {
    this.persistFailure = null;
    await rm(join(this.dataDir, PERSIST_FAILURE_FILE), { force: true });
  }

  async loadFromDisk(): Promise<void> {
    this.touched = new Set();
    try {
      const { records, lastWrittenAt } = await readAuditDir(this.dataDir);
      // Memory wins for records merged after load started.
      for (const id of this.touched) {
        const mem = this.records.get(id);
        if (mem) {
          records.delete(id);
          records.set(id, mem);
        }
      }
      this.metrics = emptyMetrics();
      for (const rec of records.values()) this.adjustMetrics(rec, 1);
      this.records.clear();
      for (const rec of [...records.values()].slice(-this.maxInMemoryRecords)) {
        this.records.set(rec.requestId, rec);
      }
      this.metrics.lastUpdatedAt = this.touched.size > 0 ? this.now().toISOString() : lastWrittenAt;
    } finally {
      this.touched = null;
    }
    try {
      const marker = JSON.parse(await readFile(join(this.dataDir, PERSIST_FAILURE_FILE), "utf8"));
      if (marker && typeof marker.firstAt === "string") {
        this.persistFailure = {
          count: Number(marker.count) || 1,
          firstAt: marker.firstAt,
          lastError: String(marker.lastError ?? ""),
        };
      }
    } catch {
      // no marker
    }
  }

  private notifyMerged(record: AuditRecord, previous: AuditRecord | undefined): void {
    for (const listener of [...this.listeners]) {
      try {
        listener(record, previous);
      } catch (error) {
        console.error("[paseo-permission-guardian] onMerged listener failed:", error);
      }
    }
  }

  getDataDir(): string {
    return this.dataDir;
  }

  getMetrics(): AuditMetricsSummary {
    return { ...this.metrics };
  }

  getRecord(requestId: string): AuditRecord | undefined {
    return this.records.get(requestId);
  }

  async recordBefore(input: RecordBeforeInput): Promise<AuditRecord> {
    const existing = this.records.get(input.requestId);
    const hadResolutionFirst = Boolean(existing?.resolution && !existing.decision);

    const redactedAction = redactValue(input.action);
    const redactedDecision = redactValue(input.decision);
    const redactedWarnings =
      input.warnings.length > 0 ? redactValue(input.warnings) : undefined;
    const merged: AuditRecord = {
      version: 1,
      pluginVersion: this.pluginVersion,
      requestId: input.requestId,
      agentId: input.agentId,
      ...(redactTitle(input.agentTitle) ?? existing?.agentTitle
        ? { agentTitle: redactTitle(input.agentTitle) ?? existing?.agentTitle }
        : {}),
      provider: input.provider,
      mode: input.mode,
      requestedAt: input.requestedAt,
      latencyMs: input.latencyMs,
      normalizedBy: input.normalizedBy,
      warnings: redactedWarnings,
      action: redactedAction,
      decision: redactedDecision,
      resolution: existing?.resolution,
      agreement: computeAgreement(redactedDecision, existing?.resolution),
      ...(input.offeredActions ? { offeredActions: input.offeredActions.map((o) => ({ ...o })) } : {}),
      ...(input.contextSnapshot ? { contextSnapshot: redactSnapshot(input.contextSnapshot) } : {}),
      ...(existing?.actOutcome ? { actOutcome: existing.actOutcome } : {}),
      // A record that gains a decision is no longer an orphan: its orphanContext is dropped.
      ...(hadResolutionFirst || existing?.outOfOrder ? { outOfOrder: true } : {}),
    };

    this.upsertAndUpdateMetrics(existing, merged);
    void this.enqueueAppend({ event: "before", record: merged }).catch(() => {});
    this.notifyMerged(merged, existing);
    return merged;
  }

  async recordAfter(input: RecordAfterInput): Promise<AuditRecord> {
    const existing = this.records.get(input.requestId);
    const arrivedBeforeRequest = !existing || !existing.decision;

    const redactedResolution = redactValue(input.resolution);
    const merged: AuditRecord = {
      version: 1,
      pluginVersion: this.pluginVersion,
      requestId: input.requestId,
      agentId: existing?.agentId ?? input.agentId,
      ...(existing?.agentTitle ?? redactTitle(input.agentTitle)
        ? { agentTitle: existing?.agentTitle ?? redactTitle(input.agentTitle) }
        : {}),
      provider: existing?.provider ?? input.provider,
      mode: existing?.mode ?? input.mode,
      requestedAt: existing?.requestedAt,
      latencyMs: existing?.latencyMs,
      normalizedBy: existing?.normalizedBy,
      warnings: existing?.warnings,
      action: existing?.action,
      decision: existing?.decision,
      resolution: redactedResolution,
      agreement: computeAgreement(existing?.decision, redactedResolution),
      ...(existing?.offeredActions ? { offeredActions: existing.offeredActions } : {}),
      ...(existing?.contextSnapshot ? { contextSnapshot: existing.contextSnapshot } : {}),
      ...(existing?.actOutcome ? { actOutcome: existing.actOutcome } : {}),
      ...(existing?.orphanContext ? { orphanContext: existing.orphanContext } : {}),
      ...(arrivedBeforeRequest || existing?.outOfOrder ? { outOfOrder: true } : {}),
    };

    this.upsertAndUpdateMetrics(existing, merged);
    void this.enqueueAppend({ event: "after", record: merged }).catch(() => {});
    this.notifyMerged(merged, existing);
    return merged;
  }

  async flush(): Promise<void> {
    await this.writeQueue;
  }

  private upsertAndUpdateMetrics(previous: AuditRecord | undefined, next: AuditRecord): void {
    if (previous) {
      this.adjustMetrics(previous, -1);
    }
    this.records.set(next.requestId, next);
    this.touched?.add(next.requestId);
    this.adjustMetrics(next, 1);
    this.metrics.lastUpdatedAt = this.now().toISOString();

    if (this.records.size > this.maxInMemoryRecords) {
      const oldestKey = this.records.keys().next().value;
      if (oldestKey !== undefined && oldestKey !== next.requestId) {
        this.records.delete(oldestKey);
      }
    }
  }

  private adjustMetrics(record: AuditRecord, delta: 1 | -1): void {
    this.metrics.totalRequests += delta;

    const hasBefore = Boolean(record.decision);
    const hasAfter = Boolean(record.resolution);
    if (hasBefore && hasAfter) {
      this.metrics.reconciledCount += delta;
    } else {
      this.metrics.pendingCount += delta;
    }

    if (record.decision) {
      if (record.decision.verdict === "allow") this.metrics.wouldAllowCount += delta;
      else if (record.decision.verdict === "ask") this.metrics.wouldAskCount += delta;
      else if (record.decision.verdict === "deny") this.metrics.wouldDenyCount += delta;
    }

    if (record.resolution && record.resolution.actor !== "plugin") {
      if (record.resolution.behavior === "allow") this.metrics.humanAllowCount += delta;
      else if (record.resolution.behavior === "deny") this.metrics.humanDenyCount += delta;
    }

    if (record.agreement === "agree") this.metrics.agreementCount += delta;
    else if (record.agreement === "false_allow") this.metrics.falseAllowCount += delta;
    else if (record.agreement === "false_deny") this.metrics.falseDenyCount += delta;

    if (record.outOfOrder) {
      this.metrics.outOfOrderCount += delta;
    }
  }

  private enqueueAppend(entry: { event: string; [k: string]: unknown }): Promise<void> {
    const task = this.writeQueue.then(async () => {
      try {
        await this.ensureDir();
        const targetPath = await this.resolveActiveLogFile();
        await this.repairTrailingNewline(targetPath);
        const line = `${JSON.stringify({ ...entry, writtenAt: this.now().toISOString() })}\n`;
        await this.writeFn(targetPath, line);
      } catch (error) {
        await this.notePersistFailure(error);
        throw error;
      }
      try {
        await this.writeSummarySnapshot();
      } catch (error) {
        console.error("[paseo-permission-guardian] Failed to write audit summary:", error);
      }
    });
    // Keep queue alive even if one write fails
    this.writeQueue = task.catch((error) => {
      console.error("[paseo-permission-guardian] Failed to write audit entry:", error);
    });
    return task;
  }

  private async repairTrailingNewline(path: string): Promise<void> {
    if (this.checkedFiles.has(path)) return;
    try {
      const info = await stat(path);
      if (info.size > 0) {
        const fh = await open(path, "r");
        try {
          const buf = Buffer.alloc(1);
          await fh.read(buf, 0, 1, info.size - 1);
          if (buf[0] !== 0x0a) await this.writeFn(path, "\n");
        } finally {
          await fh.close();
        }
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== "ENOENT") throw error;
    }
    this.checkedFiles.add(path);
  }

  private async notePersistFailure(error: unknown): Promise<void> {
    const lastError = error instanceof Error ? error.message : String(error);
    const prev = this.persistFailure;
    this.persistFailure = {
      count: (prev?.count ?? 0) + 1,
      firstAt: prev?.firstAt ?? this.now().toISOString(),
      lastError,
    };
    try {
      await mkdir(this.dataDir, { recursive: true });
      const tmp = join(this.dataDir, `${PERSIST_FAILURE_FILE}.tmp.${process.pid}`);
      await writeFile(tmp, JSON.stringify(this.persistFailure), "utf8");
      await rename(tmp, join(this.dataDir, PERSIST_FAILURE_FILE));
    } catch (markerError) {
      console.error("[paseo-permission-guardian] Failed to write persist-failure marker:", markerError);
    }
  }

  private async ensureDir(): Promise<void> {
    if (this.dirReady) return;
    await mkdir(this.dataDir, { recursive: true });
    this.dirReady = true;
  }

  private async resolveActiveLogFile(): Promise<string> {
    const dateKey = this.now().toISOString().slice(0, 10);
    if (dateKey !== this.activeDateKey) {
      this.activeDateKey = dateKey;
      this.activeFileIndex = 0;
    }

    while (true) {
      const filename =
        this.activeFileIndex === 0
          ? `audit-${dateKey}.jsonl`
          : `audit-${dateKey}.${this.activeFileIndex}.jsonl`;
      const fullPath = join(this.dataDir, filename);
      try {
        const info = await stat(fullPath);
        if (info.size < this.maxFileBytes) {
          return fullPath;
        }
        this.activeFileIndex += 1;
      } catch {
        return fullPath;
      }
    }
  }

  private async writeSummarySnapshot(): Promise<void> {
    const summaryPath = join(this.dataDir, "summary.json");
    const tmpPath = join(this.dataDir, `summary.json.tmp.${process.pid}`);
    await writeFile(tmpPath, JSON.stringify(this.metrics, null, 2), "utf8");
    await rename(tmpPath, summaryPath);
  }
}
