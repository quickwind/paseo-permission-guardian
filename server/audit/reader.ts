import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { AuditRecord } from "../../shared/types.js";

export interface AuditWindow {
  records: AuditRecord[];
  annotations: Map<string, "not_safety">;
  corruptLines: { key: string; file: string }[];
  truncated: boolean;
}

export interface AuditDirContents {
  /** Merged records in chronological first-seen order (latest line per requestId wins). */
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
  const newest = all[all.length - 1]?.name;
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
        if (file.name === newest && i === lines.length - 1) continue;
        corruptLines.push({
          key: `${file.name}#${createHash("sha256").update(raw).digest("hex")}`,
          file: file.name,
        });
        continue;
      }
      const ev = parsed?.event;
      if (ev === "before" || ev === "after") {
        const rec = parsed.record;
        if (!rec || typeof rec.requestId !== "string") {
          corruptLines.push({
            key: `${file.name}#${createHash("sha256").update(raw).digest("hex")}`,
            file: file.name,
          });
          continue;
        }
        records.delete(rec.requestId);
        records.set(rec.requestId, rec as AuditRecord);
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
  opts: { maxRecords?: number; now?: () => number } = {},
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
