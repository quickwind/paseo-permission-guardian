import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { AuditRecord } from "../../shared/types.js";
import { computeAgreement } from "./agreement.js";

export interface AuditWindow {
  records: AuditRecord[];
  annotations: Map<string, "not_safety">;
  corruptLines: { key: string; file: string }[];
  truncated: boolean;
}

export interface AuditDirContents {
  /** Merged records in order of most recent line (latest before/after/update line per requestId wins). */
  records: Map<string, AuditRecord>;
  annotations: Map<string, "not_safety">;
  corruptLines: { key: string; file: string }[];
  /** Latest `writtenAt` seen across all lines, if any. */
  lastWrittenAt: string | null;
}

const FILE_RE = /^audit-(\d{4}-\d{2}-\d{2})(?:\.(\d+))?\.jsonl$/;

interface AuditFile {
  name: string;
  date: string;
  index: number;
}

async function listAuditFiles(dataDir: string): Promise<AuditFile[]> {
  let names: string[];
  try {
    names = await readdir(dataDir);
  } catch {
    return [];
  }
  const files: AuditFile[] = [];
  for (const name of names) {
    const m = FILE_RE.exec(name);
    if (m) files.push({ name, date: m[1]!, index: m[2] ? Number(m[2]) : 0 });
  }
  files.sort((a, b) => (a.date === b.date ? a.index - b.index : a.date < b.date ? -1 : 1));
  return files;
}

/** Shared parse/merge logic used by the window reader and AuditStore.loadFromDisk. */
export async function readAuditDir(
  dataDir: string,
  opts: { minDate?: string } = {},
): Promise<AuditDirContents> {
  const all = await listAuditFiles(dataDir);
  const files = opts.minDate ? all.filter((f) => f.date >= opts.minDate!) : all;

  const records = new Map<string, AuditRecord>();
  const annotations = new Map<string, "not_safety">();
  const corruptLines: { key: string; file: string }[] = [];
  let lastWrittenAt: string | null = null;

  for (const file of files) {
    let text: string;
    try {
      text = await readFile(join(dataDir, file.name), "utf8");
    } catch {
      corruptLines.push({ key: `${file.name}#unreadable`, file: file.name });
      continue;
    }
    const lines = text.split("\n").filter((l) => l.trim() !== "");
    for (let i = 0; i < lines.length; i += 1) {
      const raw = lines[i]!;
      let parsed: any;
      try {
        parsed = JSON.parse(raw);
      } catch {
        // Every unparsable line is corrupt, including a crash-truncated final line: it may be a
        // human denial, so the gate must not silently drop it (ruling R13, fail to human).
        corruptLines.push({
          key: `${file.name}#${createHash("sha256").update(raw).digest("hex")}`,
          file: file.name,
        });
        continue;
      }
      const ev = parsed?.event;
      if (ev === "before" || ev === "after" || ev === "update") {
        const rec = parsed.record;
        const badDate = (v: unknown) => v !== undefined && v !== null && (typeof v !== "string" || Number.isNaN(Date.parse(v)));
        if (!rec || typeof rec.requestId !== "string" || badDate(rec.requestedAt) || badDate(rec.resolution?.resolvedAt)) {
          corruptLines.push({
            key: `${file.name}#${createHash("sha256").update(raw).digest("hex")}`,
            file: file.name,
          });
          continue;
        }
        // Field-wise merge: a later line that lacks a field (e.g. an `after` line written after
        // the in-memory record was evicted) must not erase it; later defined values win.
        const prev = records.get(rec.requestId);
        const merged: Record<string, unknown> = { ...(prev ?? {}) };
        for (const [k, v] of Object.entries(rec as Record<string, unknown>)) {
          if (v !== undefined) merged[k] = v;
        }
        const out = merged as unknown as AuditRecord;
        // A record that has a decision is not an orphan: a stale orphanContext from an earlier
        // update line must not survive a reload.
        if (out.decision && out.orphanContext !== undefined) delete out.orphanContext;
        if (prev) {
          const line = rec as AuditRecord;
          if ((line.decision === undefined && out.decision) || (line.resolution === undefined && out.resolution)) {
            out.agreement = computeAgreement(out.decision, out.resolution);
          }
          if (prev.outOfOrder || (rec as AuditRecord).outOfOrder) {
            // An after line synthesised without the evicted decision claims out-of-order; the
            // disk already had the before line, so it is in order.
            const inOrderAfter = ev === "after" && Boolean(prev.decision) && !prev.resolution && !prev.outOfOrder;
            if (inOrderAfter) delete out.outOfOrder;
            else out.outOfOrder = true;
          }
        }
        records.delete(rec.requestId);
        records.set(rec.requestId, out);
      } else if (ev === "annotation" && typeof parsed.key === "string") {
        if (parsed.annotation === "not_safety") annotations.set(parsed.key, "not_safety");
        else if (parsed.annotation === null) annotations.delete(parsed.key);
      }
      if (typeof parsed?.writtenAt === "string" && (!lastWrittenAt || parsed.writtenAt > lastWrittenAt)) {
        lastWrittenAt = parsed.writtenAt;
      }
    }
  }
  return { records, annotations, corruptLines, lastWrittenAt };
}

export async function readAuditWindow(
  dataDir: string,
  sinceMs: number,
  opts: { maxRecords?: number } = {},
): Promise<AuditWindow> {
  const minDate = new Date(sinceMs).toISOString().slice(0, 10);
  const { records, annotations, corruptLines } = await readAuditDir(dataDir, { minDate });

  let inWindow: AuditRecord[] = [];
  for (const rec of records.values()) {
    const stamp = rec.requestedAt ?? rec.resolution?.resolvedAt;
    const ms = stamp ? Date.parse(stamp) : Number.NaN;
    if (!Number.isNaN(ms) && ms >= sinceMs) inWindow.push(rec);
  }
  let truncated = false;
  if (opts.maxRecords !== undefined && inWindow.length > opts.maxRecords) {
    truncated = true;
    inWindow = inWindow.slice(inWindow.length - opts.maxRecords);
  }
  return { records: inWindow, annotations, corruptLines, truncated };
}
