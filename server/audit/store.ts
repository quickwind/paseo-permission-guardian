import { mkdir, appendFile, stat, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";
import type {
  Action,
  AgreementOutcome,
  AuditMetricsSummary,
  AuditRecord,
  AuditResolution,
  GuardianDecision,
  GuardianMode,
} from "../../shared/types.js";
import { redactValue } from "./redact.js";

export interface AuditStoreOptions {
  dataDir: string;
  pluginVersion: string;
  maxFileBytes?: number;
  maxInMemoryRecords?: number;
  now?: () => Date;
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
}

export interface RecordAfterInput {
  requestId: string;
  agentId: string;
  provider: string;
  mode: GuardianMode;
  resolution: AuditResolution;
}

const DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024; // 10 MiB
const DEFAULT_MAX_IN_MEMORY_RECORDS = 5_000;

export function computeAgreement(
  decision: GuardianDecision | undefined,
  resolution: AuditResolution | undefined,
): AgreementOutcome {
  if (!decision || !resolution) {
    return "pending";
  }

  if (resolution.actor === "plugin") {
    return "agree";
  }

  if (decision.verdict === "allow") {
    return resolution.behavior === "allow" ? "agree" : "false_allow";
  }

  if (decision.verdict === "deny") {
    return resolution.behavior === "deny" ? "agree" : "false_deny";
  }

  if (decision.verdict === "ask") {
    return resolution.behavior === "allow"
      ? "plugin_ask_human_allow"
      : "plugin_ask_human_deny";
  }

  return "unknown";
}

export class AuditStore {
  private readonly dataDir: string;
  private readonly pluginVersion: string;
  private readonly maxFileBytes: number;
  private readonly maxInMemoryRecords: number;
  private readonly now: () => Date;

  private readonly records = new Map<string, AuditRecord>();
  private writeQueue: Promise<void> = Promise.resolve();
  private dirReady = false;
  private activeDateKey = "";
  private activeFileIndex = 0;

  private metrics: AuditMetricsSummary = {
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

  constructor(options: AuditStoreOptions) {
    this.dataDir = options.dataDir;
    this.pluginVersion = options.pluginVersion;
    this.maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
    this.maxInMemoryRecords = options.maxInMemoryRecords ?? DEFAULT_MAX_IN_MEMORY_RECORDS;
    this.now = options.now ?? (() => new Date());
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
      ...(hadResolutionFirst || existing?.outOfOrder ? { outOfOrder: true } : {}),
    };

    this.upsertAndUpdateMetrics(existing, merged);
    await this.enqueueAppend({ event: "before", record: merged });
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
      ...(arrivedBeforeRequest || existing?.outOfOrder ? { outOfOrder: true } : {}),
    };

    this.upsertAndUpdateMetrics(existing, merged);
    await this.enqueueAppend({ event: "after", record: merged });
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

  private enqueueAppend(entry: { event: "before" | "after"; record: AuditRecord }): Promise<void> {
    const task = this.writeQueue.then(async () => {
      await this.ensureDir();
      const targetPath = await this.resolveActiveLogFile();
      const line = `${JSON.stringify({ ...entry, writtenAt: this.now().toISOString() })}\n`;
      await appendFile(targetPath, line, "utf8");
      await this.writeSummarySnapshot();
    });
    // Keep queue alive even if one write fails
    this.writeQueue = task.catch((error) => {
      console.error("[paseo-permission-guardian] Failed to write audit entry:", error);
    });
    return task;
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
