import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readAuditWindow } from "../server/audit/reader.js";
import { AuditStore, type RecordBeforeInput } from "../server/audit/store.js";
import type { AuditRecord } from "../shared/types.js";

const dirs: string[] = [];
async function tmp(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "p2a-audit-"));
  dirs.push(d);
  return d;
}
afterEach(async () => {
  while (dirs.length) await rm(dirs.pop()!, { recursive: true, force: true });
});

const T = "2026-11-20T12:00:00.000Z";
function before(id: string, extra: Partial<RecordBeforeInput> = {}): RecordBeforeInput {
  return {
    requestId: id,
    agentId: "a",
    provider: "claude",
    mode: "act",
    requestedAt: T,
    latencyMs: 1,
    normalizedBy: "claude",
    warnings: [],
    action: {
      provider: "claude",
      agentId: "a",
      requestId: id,
      kind: "exec",
      toolName: "Bash",
      host: { os: "darwin" },
      cwd: "/repo",
      exec: { shell: "bash", source: "ls" },
    },
    decision: { level: "L0", verdict: "allow", reasons: ["t"] },
    offeredActions: [{ id: "allow_once", behavior: "allow" }],
    contextSnapshot: {
      secretTaint: false,
      untrustedTaint: false,
      modifiedEntrypoints: [],
      modifiedFiles: [],
      modifiedFilesTruncated: false,
    },
    ...extra,
  };
}
function rec(id: string, requestedAt: string): AuditRecord {
  return {
    version: 1,
    pluginVersion: "0",
    requestId: id,
    agentId: "a",
    provider: "claude",
    mode: "act",
    requestedAt,
    agreement: "pending",
  };
}
const line = (event: string, record: AuditRecord) => JSON.stringify({ event, record, writtenAt: T });

describe("AuditStore p2a extensions", () => {
  it("persists offeredActions and redacted contextSnapshot", async () => {
    const dir = await tmp();
    const store = new AuditStore({ dataDir: dir, pluginVersion: "0", now: () => new Date(T) });
    const r = await store.recordBefore(
      before("r1", {
        contextSnapshot: {
          secretTaint: true,
          untrustedTaint: false,
          modifiedEntrypoints: [],
          modifiedFiles: ["/repo/run.sh API_TOKEN=supersecret99"],
          modifiedFilesTruncated: false,
        },
      }),
    );
    await store.flush();
    expect(r.offeredActions).toEqual([{ id: "allow_once", behavior: "allow" }]);
    expect(JSON.stringify(r.contextSnapshot)).not.toContain("supersecret99");
    const disk = await readFile(join(dir, "audit-2026-11-20.jsonl"), "utf8");
    expect(disk).not.toContain("supersecret99");
    expect(disk).toContain("allow_once");
  });

  it("recordBefore resolves before the append flushes", async () => {
    const dir = await tmp();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const store = new AuditStore({
      dataDir: dir,
      pluginVersion: "0",
      now: () => new Date(T),
      writeFn: async () => {
        await gate;
      },
    });
    await store.recordBefore(before("slow"));
    expect(store.getRecord("slow")?.decision?.verdict).toBe("allow");
    release();
    await store.flush();
  });

  it("onMerged fires for before-then-after and after-then-before, and survives throwing listeners", async () => {
    const dir = await tmp();
    const store = new AuditStore({ dataDir: dir, pluginVersion: "0", now: () => new Date(T) });
    const seen: string[] = [];
    store.onMerged(() => {
      throw new Error("boom");
    });
    const off = store.onMerged((r, prev) => seen.push(`${r.requestId}:${prev ? "prev" : "none"}`));
    const resolution = { behavior: "allow" as const, resolvedAt: T, actor: "human" as const };
    await store.recordBefore(before("a1"));
    await store.recordAfter({ requestId: "a1", agentId: "a", provider: "claude", mode: "act", resolution });
    await store.recordAfter({ requestId: "b1", agentId: "a", provider: "claude", mode: "act", resolution });
    await store.recordBefore(before("b1"));
    expect(seen).toEqual(["a1:none", "a1:prev", "b1:none", "b1:prev"]);
    off();
    await store.recordBefore(before("c1"));
    expect(seen).toHaveLength(4);
    await store.flush();
  });

  it("loadFromDisk restores metrics", async () => {
    const dir = await tmp();
    const s1 = new AuditStore({ dataDir: dir, pluginVersion: "0", now: () => new Date(T) });
    await s1.recordBefore(before("x1"));
    await s1.recordBefore(before("x2", { decision: { level: "L2", verdict: "ask", reasons: [] } }));
    await s1.recordAfter({
      requestId: "x2",
      agentId: "a",
      provider: "claude",
      mode: "act",
      resolution: { behavior: "allow", resolvedAt: T, actor: "human" },
    });
    await s1.flush();
    const s2 = new AuditStore({ dataDir: dir, pluginVersion: "0", now: () => new Date(T) });
    await s2.loadFromDisk();
    expect(s2.getMetrics()).toEqual(s1.getMetrics());
    expect(s2.getRecord("x2")?.resolution?.behavior).toBe("allow");
  });

  it("appendEvent writes gate/annotation lines", async () => {
    const dir = await tmp();
    const store = new AuditStore({ dataDir: dir, pluginVersion: "0", now: () => new Date(T) });
    await store.appendEvent({ event: "annotation", key: "k", annotation: "not_safety", at: T });
    const disk = await readFile(join(dir, "audit-2026-11-20.jsonl"), "utf8");
    expect(JSON.parse(disk.trim()).event).toBe("annotation");
  });
});

describe("readAuditWindow", () => {
  const since = Date.parse("2026-11-20T00:00:00.000Z");

  it("merges rotated files, skips old records, applies annotations", async () => {
    const dir = await tmp();
    await writeFile(
      join(dir, "audit-2026-11-19.jsonl"),
      `${line("before", rec("old", "2026-11-19T10:00:00.000Z"))}\n`,
    );
    await writeFile(
      join(dir, "audit-2026-11-20.jsonl"),
      [
        line("before", rec("r1", "2026-11-20T01:00:00.000Z")),
        line("before", rec("old2", "2026-11-19T23:00:00.000Z")),
        JSON.stringify({ event: "annotation", key: "k1", annotation: "not_safety", at: T }),
        JSON.stringify({ event: "annotation", key: "k2", annotation: "not_safety", at: T }),
        JSON.stringify({ event: "annotation", key: "k2", annotation: null, at: T }),
        JSON.stringify({ event: "gate", x: 1 }),
      ].join("\n") + "\n",
    );
    const resolved = { ...rec("r1", "2026-11-20T01:00:00.000Z"), agreement: "agree" as const };
    await writeFile(join(dir, "audit-2026-11-20.1.jsonl"), `${line("after", resolved)}\n`);
    const w = await readAuditWindow(dir, since);
    expect(w.records.map((r) => r.requestId)).toEqual(["r1"]);
    expect(w.records[0]!.agreement).toBe("agree");
    expect([...w.annotations.keys()]).toEqual(["k1"]);
    expect(w.corruptLines).toEqual([]);
    expect(w.truncated).toBe(false);
  });

  it("uses resolvedAt for orphan resolutions", async () => {
    const dir = await tmp();
    const orphan = { ...rec("o", ""), requestedAt: undefined, resolution: { behavior: "allow", resolvedAt: "2026-11-20T05:00:00.000Z", actor: "human" } };
    await writeFile(join(dir, "audit-2026-11-20.jsonl"), `${line("after", orphan as AuditRecord)}\n`);
    expect((await readAuditWindow(dir, since)).records).toHaveLength(1);
  });

  it("reports corrupt middle line, tolerates truncated last line of newest file", async () => {
    const dir = await tmp();
    const bad = '{"event":"before","rec';
    await writeFile(
      join(dir, "audit-2026-11-20.jsonl"),
      `${line("before", rec("a", "2026-11-20T01:00:00.000Z"))}\n${bad}\n${line("before", rec("b", "2026-11-20T02:00:00.000Z"))}\n`,
    );
    await writeFile(
      join(dir, "audit-2026-11-21.jsonl"),
      `${line("before", rec("c", "2026-11-21T02:00:00.000Z"))}\n{"event":"bef`,
    );
    const w = await readAuditWindow(dir, since);
    expect(w.records.map((r) => r.requestId)).toEqual(["a", "b", "c"]);
    expect(w.corruptLines).toEqual([
      {
        key: `audit-2026-11-20.jsonl#${createHash("sha256").update(bad).digest("hex")}`,
        file: "audit-2026-11-20.jsonl",
      },
    ]);
  });

  it("sets truncated when maxRecords exceeded", async () => {
    const dir = await tmp();
    await writeFile(
      join(dir, "audit-2026-11-20.jsonl"),
      ["a", "b", "c"].map((id) => line("before", rec(id, "2026-11-20T01:00:00.000Z"))).join("\n") + "\n",
    );
    const w = await readAuditWindow(dir, since, { maxRecords: 2 });
    expect(w.truncated).toBe(true);
    expect(w.records).toHaveLength(2);
  });
});

describe("fix round 1", () => {
  const failing = async () => {
    throw new Error("disk full");
  };

  it("surfaces persist failures, persists marker, clears", async () => {
    const dir = await tmp();
    const s = new AuditStore({ dataDir: dir, pluginVersion: "0", now: () => new Date(T), writeFn: failing });
    expect(s.getPersistFailure()).toBeNull();
    await s.recordBefore(before("f1"));
    await s.recordBefore(before("f2"));
    await s.flush();
    const f = s.getPersistFailure();
    expect(f?.count).toBe(2);
    expect(f?.firstAt).toBe(T);
    expect(f?.lastError).toContain("disk full");
    const s2 = new AuditStore({ dataDir: dir, pluginVersion: "0", now: () => new Date(T) });
    await s2.loadFromDisk();
    expect(s2.getPersistFailure()?.firstAt).toBe(T);
    await s2.clearPersistFailure();
    expect(s2.getPersistFailure()).toBeNull();
    const s3 = new AuditStore({ dataDir: dir, pluginVersion: "0" });
    await s3.loadFromDisk();
    expect(s3.getPersistFailure()).toBeNull();
  });

  it("setActOutcome appends update line; unresolved on reload; later after keeps outcome; unknown id no-ops", async () => {
    const dir = await tmp();
    const s = new AuditStore({ dataDir: dir, pluginVersion: "0", now: () => new Date(T) });
    await s.recordBefore(before("u1"));
    s.setActOutcome("u1", "answered");
    s.setActOutcome("nope", "answered");
    await s.flush();
    const disk = (await readFile(join(dir, "audit-2026-11-20.jsonl"), "utf8")).trim().split("\n");
    expect(disk.map((l) => JSON.parse(l).event)).toEqual(["before", "update"]);
    const s2 = new AuditStore({ dataDir: dir, pluginVersion: "0", now: () => new Date(T) });
    await s2.loadFromDisk();
    expect(s2.getRecord("u1")?.resolution).toBeUndefined();
    expect(s2.getRecord("u1")?.actOutcome).toBe("answered");
    expect(s2.getRecord("nope")).toBeUndefined();
    const after = await s2.recordAfter({
      requestId: "u1", agentId: "a", provider: "claude", mode: "act",
      resolution: { behavior: "deny", resolvedAt: T, actor: "human" },
    });
    expect(after.actOutcome).toBe("answered");
    await s2.flush();
  });

  it("writes a newline before appending to a crash-truncated file", async () => {
    const dir = await tmp();
    await writeFile(join(dir, "audit-2026-11-20.jsonl"), '{"event":"bef');
    const s = new AuditStore({ dataDir: dir, pluginVersion: "0", now: () => new Date(T) });
    await s.recordBefore(before("n1"));
    await s.flush();
    const lines = (await readFile(join(dir, "audit-2026-11-20.jsonl"), "utf8")).split("\n");
    expect(lines[0]).toBe('{"event":"bef');
    expect(JSON.parse(lines[1]!).record.requestId).toBe("n1");
  });

  it("loadFromDisk keeps records merged while it was in flight", async () => {
    const dir = await tmp();
    const s1 = new AuditStore({ dataDir: dir, pluginVersion: "0", now: () => new Date(T) });
    await s1.recordBefore(before("d1"));
    await s1.flush();
    const s2 = new AuditStore({ dataDir: dir, pluginVersion: "0", now: () => new Date(T) });
    const p = s2.loadFromDisk();
    await s2.recordBefore(before("live"));
    await p;
    await s2.flush();
    expect(s2.getRecord("d1")).toBeDefined();
    expect(s2.getRecord("live")).toBeDefined();
    expect(s2.getMetrics().totalRequests).toBe(2);
  });

  it("reports lines with unparsable dates as corrupt", async () => {
    const dir = await tmp();
    await writeFile(
      join(dir, "audit-2026-11-20.jsonl"),
      `${line("before", rec("bad", "not-a-date"))}\n${line("before", rec("ok", "2026-11-20T01:00:00.000Z"))}\n`,
    );
    const w = await readAuditWindow(dir, Date.parse("2026-11-20T00:00:00.000Z"));
    expect(w.records.map((r) => r.requestId)).toEqual(["ok"]);
    expect(w.corruptLines).toHaveLength(1);
  });
});
