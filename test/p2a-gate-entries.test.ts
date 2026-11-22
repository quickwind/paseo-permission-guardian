import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AgentTimelineItem } from "@getpaseo/protocol/agent-types";
import { afterEach, describe, expect, it } from "vitest";
import { AuditStore } from "../server/audit/store.js";
import { readAuditDir } from "../server/audit/reader.js";
import { matchOrphanToolCall, type TimelineEntry } from "../server/context/orphan-context.js";
import { buildGateEntry } from "../server/gate/entry.js";
import { GateController } from "../server/gate/gate.js";
import { replayWindow, type ReplayDecideHandle } from "../server/gate/replay.js";
import { PermissionGuardianService } from "../server/guardian.js";
import { GateStatusSchema } from "../shared/rpc.js";
import { DEFAULT_GUARDIAN_SETTINGS } from "../shared/settings.js";
import type { AuditRecord } from "../shared/types.js";

const dirs: string[] = [];
afterEach(async () => {
  while (dirs.length) await rm(dirs.pop() as string, { recursive: true, force: true });
});
async function tmp(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "pg-entries-"));
  dirs.push(d);
  return d;
}

const T0 = Date.parse("2026-11-23T10:00:00.000Z");
const iso = (ms: number) => new Date(ms).toISOString();

function record(over: Partial<AuditRecord> = {}): AuditRecord {
  return {
    version: 1,
    pluginVersion: "0",
    requestId: "r1",
    agentId: "agent-1234567890",
    agentTitle: "Fix the build",
    provider: "agy",
    mode: "shadow",
    requestedAt: iso(T0),
    agreement: "false_allow",
    action: {
      provider: "agy",
      agentId: "agent-1234567890",
      requestId: "r1",
      kind: "exec",
      toolName: "Bash",
      host: { os: "darwin" },
      cwd: "/repo",
      exec: { shell: "bash", source: "x".repeat(300) },
    },
    decision: { level: "L0", verdict: "allow", reasons: [] },
    resolution: {
      behavior: "deny",
      selectedActionId: "reject_once",
      message: "no thanks",
      resolvedAt: iso(T0 + 5_000),
      actor: "human",
    },
    ...over,
  };
}

function toolCall(
  callId: string,
  status: "running" | "completed" | "failed" | "canceled",
  command: string,
  error: unknown = null,
): AgentTimelineItem {
  return {
    type: "tool_call",
    callId,
    name: "Bash",
    status,
    error,
    detail: { type: "shell", command },
  } as AgentTimelineItem;
}

describe("B: gate entries carry enough to decide", () => {
  it("buildGateEntry includes time, provider, agent, tool, summary and resolution", () => {
    const e = buildGateEntry(record(), "false_allow", ["read"]);
    expect(e).toMatchObject({
      requestId: "r1",
      kind: "false_allow",
      key: "r1",
      effects: ["read"],
      requestedAt: iso(T0),
      resolvedAt: iso(T0 + 5_000),
      provider: "agy",
      agentId: "agent-1234567890",
      agentTitle: "Fix the build",
      toolName: "Bash",
      resolution: { behavior: "deny", selectedActionId: "reject_once", message: "no thanks" },
    });
    expect(e.summary).toBe("x".repeat(200));
    expect(GateStatusSchema.shape.entries.parse([e])[0]).toEqual(e);
  });

  it("summaries for paths, URL and MCP", () => {
    const base = record().action as NonNullable<AuditRecord["action"]>;
    const p = buildGateEntry(record({ action: { ...base, kind: "delete", exec: undefined, paths: ["/repo/a", "/repo/b"] } }), "false_allow", []);
    expect(p.summary).toBe("/repo/a, /repo/b");
    const u = buildGateEntry(record({ action: { ...base, kind: "fetch", exec: undefined, url: { href: "https://x.test/a" } } }), "false_allow", []);
    expect(u.summary).toBe("https://x.test/a");
    const m = buildGateEntry(record({ action: { ...base, kind: "mcp", exec: undefined, mcp: { server: "gh", tool: "create_issue", args: {} } } }), "false_allow", []);
    expect(m.summary).toBe("gh:create_issue");
  });

  it("replay false_allow and orphan_deny entries carry the new fields", async () => {
    const decide = (async () => ({ verdict: "allow", level: "L0", reasons: [], effects: ["read"] })) as unknown as ReplayDecideHandle;
    const orphan = record({
      requestId: "o1",
      action: undefined,
      decision: undefined,
      requestedAt: undefined,
      orphanContext: { toolName: "Bash", summary: "rm x", callId: "c9", matchedBy: "failed_status" },
    });
    const res = await replayWindow(
      { records: [record(), orphan], annotations: new Map(), corruptLines: [], truncated: false },
      decide,
      { cancellationSignatures: [] },
    );
    expect(res.falseAllows[0]).toMatchObject({ agentTitle: "Fix the build", provider: "agy", toolName: "Bash", resolvedAt: iso(T0 + 5_000) });
    const o = res.integrity.find((e) => e.kind === "orphan_deny");
    expect(o).toMatchObject({
      requestId: "o1",
      agentTitle: "Fix the build",
      resolvedAt: iso(T0 + 5_000),
      resolution: { behavior: "deny", message: "no thanks" },
      orphanContext: { summary: "rm x", callId: "c9" },
    });
  });
});

describe("B: orphan tool-call matching", () => {
  const resolvedAt = T0 + 60_000;
  it("prefers a denied/canceled/failed call nearest before resolvedAt", () => {
    const entries: TimelineEntry[] = [
      { item: toolCall("c1", "completed", "ls"), timestamp: iso(T0 + 10_000) },
      { item: toolCall("c2", "failed", "rm old.txt", "Permission denied by user"), timestamp: iso(T0 + 20_000) },
      { item: toolCall("c3", "canceled", "rm a.txt"), timestamp: iso(T0 + 50_000) },
      { item: toolCall("c4", "completed", "cat b"), timestamp: iso(T0 + 55_000) },
      { item: toolCall("c5", "failed", "rm later.txt", "denied"), timestamp: iso(resolvedAt + 120_000) },
    ];
    const m = matchOrphanToolCall(entries, { resolvedAtMs: resolvedAt });
    expect(m).toEqual({ toolName: "Bash", summary: "rm old.txt", callId: "c2", matchedBy: "permission_denied" });
    const m2 = matchOrphanToolCall(entries.filter((e) => (e.item as { callId?: string }).callId !== "c2"), { resolvedAtMs: resolvedAt });
    expect(m2).toMatchObject({ callId: "c3", matchedBy: "failed_or_canceled" });
    const m3 = matchOrphanToolCall([entries[0]!, entries[3]!], { resolvedAtMs: resolvedAt });
    expect(m3).toMatchObject({ callId: "c4", matchedBy: "nearest_before" });
  });

  it("no tool call in the time window ⇒ null; redacts summaries", () => {
    expect(matchOrphanToolCall([{ item: toolCall("c1", "failed", "rm x"), timestamp: iso(T0 - 3_600_000) }], { resolvedAtMs: T0 })).toBeNull();
    expect(matchOrphanToolCall([{ item: { type: "assistant_message", text: "hi" } as AgentTimelineItem }], { resolvedAtMs: T0 })).toBeNull();
    const token = "ghp_" + "b".repeat(36);
    const m = matchOrphanToolCall([{ item: toolCall("c1", "canceled", `curl -H "x: ${token}"`), timestamp: iso(T0 - 1000) }], { resolvedAtMs: T0 });
    expect(m?.summary).not.toContain(token);
    // M5: a token straddling the 200-char limit is redacted before truncation.
    const straddle = matchOrphanToolCall(
      [{ item: toolCall("c2", "canceled", `${"a".repeat(190)} ${token}`), timestamp: iso(T0 - 1000) }],
      { resolvedAtMs: T0 },
    );
    expect(straddle?.summary).not.toContain("ghp_bbbb");
    expect(straddle?.summary?.length).toBeLessThanOrEqual(200);
  });

  it("untimed entries are only used when allowed (live), never for backfill", () => {
    const entries: TimelineEntry[] = [{ item: toolCall("c1", "canceled", "rm a") }];
    expect(matchOrphanToolCall(entries, { resolvedAtMs: T0, allowUntimed: false })).toBeNull();
    expect(matchOrphanToolCall(entries, { resolvedAtMs: T0, allowUntimed: true })).toMatchObject({ callId: "c1" });
  });
});

describe("B: guardian enrichment", () => {
  const agent = {
    id: "agent-1",
    workspaceId: "w",
    parentAgentId: null,
    provider: "agy",
    cwd: "/repo",
    title: "Refactor parser",
    background: false,
    metadata: {},
  };

  async function setup(clock: { now: number }) {
    const dataDir = await tmp();
    const store = new AuditStore({ dataDir, pluginVersion: "0", now: () => new Date(clock.now) });
    const service = new PermissionGuardianService({
      auditStore: store,
      pluginVersion: "0",
      initialSettings: DEFAULT_GUARDIAN_SETTINGS,
      now: () => clock.now,
      gitStateProvider: async () => ({}),
    });
    return { dataDir, store, service };
  }

  it("stores agentTitle on before and after records", async () => {
    const clock = { now: T0 };
    const { store, service } = await setup(clock);
    await service.handlePermissionBefore({
      agent,
      request: { id: "q1", provider: "agy", name: "Bash", kind: "tool", input: { command: "ls" } },
    });
    expect(store.getRecord("q1")?.agentTitle).toBe("Refactor parser");
    await service.handlePermissionAfter({ agent, requestId: "q2", resolution: { behavior: "allow" } });
    expect(store.getRecord("q2")?.agentTitle).toBe("Refactor parser");
    await store.flush();
  });

  it("orphan human deny is enriched from the timeline via an update event, without changing the gate", async () => {
    const clock = { now: T0 + 60_000 };
    const { dataDir, store, service } = await setup(clock);
    const decide = (async () => ({ verdict: "ask", level: "L1", reasons: [], effects: [] })) as unknown as ReplayDecideHandle;
    decide.dispose = async () => {};
    const gate = new GateController({ store, dataDir, replayDecide: decide, now: () => clock.now, debounceMs: 60_000 });
    gate.configure({
      settings: { ...DEFAULT_GUARDIAN_SETTINGS, mode: "act" },
      settingsValid: true,
      fingerprint: "fp",
    });
    let mergeEvents = 0;
    store.onMerged(() => {
      mergeEvents += 1;
    });
    const fetched: string[] = [];
    await service.handlePermissionAfter(
      { agent, requestId: "orph", resolution: { behavior: "deny", message: "nope" } },
      {
        fetchTimelineEntries: async (agentId) => {
          fetched.push(agentId);
          return [
            { item: toolCall("c1", "completed", "ls"), timestamp: iso(T0 + 10_000) },
            { item: toolCall("c2", "canceled", "rm -rf build"), timestamp: iso(T0 + 50_000) },
          ];
        },
      },
    );
    await service.whenEnrichmentsIdle();
    expect(fetched).toEqual(["agent-1"]);
    expect(mergeEvents).toBe(1);
    const before = gate.status();
    const rec = store.getRecord("orph");
    expect(rec?.orphanContext).toEqual({ toolName: "Bash", summary: "rm -rf build", callId: "c2", matchedBy: "failed_or_canceled" });
    const entry = before.entries.find((e) => e.requestId === "orph");
    expect(entry).toMatchObject({ kind: "orphan_deny", agentTitle: "Refactor parser", orphanContext: { callId: "c2" } });
    expect(before.state).toBe("unavailable");
    await store.flush();
    const disk = await readAuditDir(dataDir);
    expect(disk.records.get("orph")?.orphanContext?.callId).toBe("c2");
    await gate.dispose();
  });

  it("fetch failure or timeout ⇒ orphanContext { unavailable: true }", async () => {
    const clock = { now: T0 };
    const { store, service } = await setup(clock);
    await service.handlePermissionAfter(
      { agent, requestId: "o1", resolution: { behavior: "deny" } },
      { fetchTimelineEntries: async () => Promise.reject(new Error("boom")) },
    );
    await service.whenEnrichmentsIdle();
    expect(store.getRecord("o1")?.orphanContext).toEqual({ unavailable: true });
    await service.handlePermissionAfter(
      { agent, requestId: "o2", resolution: { behavior: "deny" } },
      { fetchTimelineEntries: () => new Promise(() => {}), timeoutMs: 20 },
    );
    await service.whenEnrichmentsIdle();
    expect(store.getRecord("o2")?.orphanContext).toEqual({ unavailable: true });
    // Allows and non-orphans are never enriched.
    await service.handlePermissionAfter(
      { agent, requestId: "o3", resolution: { behavior: "allow" } },
      { fetchTimelineEntries: async () => { throw new Error("must not be called"); } },
    );
    expect(store.getRecord("o3")?.orphanContext).toBeUndefined();
    await store.flush();
  });

  it("the after hook does not wait for the timeline fetch (M4)", async () => {
    const clock = { now: T0 + 60_000 };
    const { store, service } = await setup(clock);
    let release!: () => void;
    const gateP = new Promise<void>((r) => {
      release = r;
    });
    await service.handlePermissionAfter(
      { agent, requestId: "slow", resolution: { behavior: "deny" } },
      {
        fetchTimelineEntries: async () => {
          await gateP;
          return [{ item: toolCall("c1", "canceled", "rm q"), timestamp: iso(T0 + 59_000) }];
        },
      },
    );
    expect(store.getRecord("slow")?.resolution?.behavior).toBe("deny");
    expect(store.getRecord("slow")?.orphanContext).toBeUndefined();
    release();
    await service.flush();
    expect(store.getRecord("slow")?.orphanContext).toMatchObject({ callId: "c1" });
  });

  it("a record that gains a decision drops its orphanContext (M6)", async () => {
    const clock = { now: T0 };
    const { store, service } = await setup(clock);
    await service.handlePermissionAfter(
      { agent, requestId: "late", resolution: { behavior: "deny" } },
      { fetchTimelineEntries: async () => Promise.reject(new Error("x")) },
    );
    await service.whenEnrichmentsIdle();
    expect(store.getRecord("late")?.orphanContext).toEqual({ unavailable: true });
    await service.handlePermissionBefore({
      agent,
      request: { id: "late", provider: "agy", name: "Bash", kind: "tool", input: { command: "ls" } },
    });
    expect(store.getRecord("late")?.decision).toBeDefined();
    expect(store.getRecord("late")?.orphanContext).toBeUndefined();
    await store.flush();
  });

  it("backfill enriches an orphan lacking orphanContext once per id", async () => {
    const clock = { now: T0 + 60_000 };
    const { store, service } = await setup(clock);
    await service.handlePermissionAfter({ agent, requestId: "old", resolution: { behavior: "deny" } });
    expect(store.getRecord("old")?.orphanContext).toBeUndefined();
    let calls = 0;
    const fetcher = async () => {
      calls += 1;
      return [{ item: toolCall("c7", "failed", "rm z", "denied"), timestamp: iso(T0 + 59_000) }];
    };
    await service.backfillOrphanContexts(["old", "missing"], fetcher);
    await service.backfillOrphanContexts(["old"], fetcher);
    expect(calls).toBe(1);
    expect(store.getRecord("old")?.orphanContext).toMatchObject({ callId: "c7", matchedBy: "permission_denied" });
    await store.flush();
  });
});

describe("Fix round 2: stale orphanContext and enrichment signal", () => {
  const agent = { id: "agent-1", workspaceId: "w", parentAgentId: null, provider: "agy", cwd: "/repo", title: "T", background: false, metadata: {} };
  const good = async () => [{ item: toolCall("c1", "canceled", "rm q"), timestamp: iso(T0 + 59_000) }];

  async function setup() {
    const dataDir = await tmp();
    const clock = { now: T0 + 60_000 };
    const store = new AuditStore({ dataDir, pluginVersion: "0", now: () => new Date(clock.now) });
    const service = new PermissionGuardianService({
      auditStore: store,
      pluginVersion: "0",
      initialSettings: DEFAULT_GUARDIAN_SETTINGS,
      now: () => clock.now,
      gitStateProvider: async () => ({}),
    });
    return { dataDir, store, service };
  }

  it("R1: a reload after a late before drops the stale orphanContext; non-orphan entries never show it", async () => {
    const { dataDir, store, service } = await setup();
    await service.handlePermissionAfter({ agent, requestId: "late", resolution: { behavior: "deny" } }, { fetchTimelineEntries: good });
    await service.whenEnrichmentsIdle();
    expect(store.getRecord("late")?.orphanContext).toMatchObject({ callId: "c1" });
    await service.handlePermissionBefore({
      agent,
      request: { id: "late", provider: "agy", name: "Bash", kind: "tool", input: { command: "ls" } },
    });
    await service.flush();
    const disk = await readAuditDir(dataDir);
    expect(disk.records.get("late")?.decision).toBeDefined();
    expect(disk.records.get("late")?.orphanContext).toBeUndefined();
    const reloaded = new AuditStore({ dataDir, pluginVersion: "0" });
    await reloaded.loadFromDisk();
    expect(reloaded.getRecord("late")?.orphanContext).toBeUndefined();

    const withStale = record({ orphanContext: { summary: "stale", callId: "x" } });
    expect(buildGateEntry(withStale, "false_allow", []).orphanContext).toBeUndefined();
    expect(buildGateEntry(withStale, "orphan_deny", []).orphanContext).toMatchObject({ callId: "x" });
  });

  it("R2: background enrichment ignores an aborted hook signal", async () => {
    const { store, service } = await setup();
    const ac = new AbortController();
    ac.abort();
    await service.handlePermissionAfter(
      { agent, requestId: "o", resolution: { behavior: "deny" } },
      { fetchTimelineEntries: good, signal: ac.signal },
    );
    await service.whenEnrichmentsIdle();
    expect(store.getRecord("o")?.orphanContext).toMatchObject({ callId: "c1" });
    await store.flush();
  });

  it("R2: backfill retries an unavailable orphanContext at most once per run", async () => {
    const { store, service } = await setup();
    await service.handlePermissionAfter(
      { agent, requestId: "u1", resolution: { behavior: "deny" } },
      { fetchTimelineEntries: async () => Promise.reject(new Error("x")) },
    );
    await service.handlePermissionAfter(
      { agent, requestId: "u2", resolution: { behavior: "deny" } },
      { fetchTimelineEntries: async () => Promise.reject(new Error("x")) },
    );
    await service.whenEnrichmentsIdle();
    expect(store.getRecord("u1")?.orphanContext).toEqual({ unavailable: true });
    await service.backfillOrphanContexts(["u1"], good);
    expect(store.getRecord("u1")?.orphanContext).toMatchObject({ callId: "c1" });
    let failing = 0;
    const bad = async () => {
      failing += 1;
      throw new Error("still down");
    };
    await service.backfillOrphanContexts(["u2"], bad);
    await service.backfillOrphanContexts(["u2"], bad);
    expect(failing).toBe(1);
    expect(store.getRecord("u2")?.orphanContext).toEqual({ unavailable: true });
    await store.flush();
  });
});

describe("agent title resolution (entry UX)", () => {
  const agent = { id: "agent-9", workspaceId: "w", parentAgentId: null, provider: "agy", cwd: "/repo", title: "", background: false, metadata: {} };
  async function setup() {
    const dataDir = await tmp();
    const clock = { now: T0 + 60_000 };
    const store = new AuditStore({ dataDir, pluginVersion: "0", now: () => new Date(clock.now) });
    const service = new PermissionGuardianService({
      auditStore: store,
      pluginVersion: "0",
      initialSettings: DEFAULT_GUARDIAN_SETTINGS,
      now: () => clock.now,
      gitStateProvider: async () => ({}),
    });
    return { store, service };
  }

  it("resolves a missing agentTitle once per agent, caches it, and redacts it", async () => {
    const { store, service } = await setup();
    await service.handlePermissionAfter({ agent, requestId: "a", resolution: { behavior: "deny" } });
    await service.handlePermissionAfter({ agent, requestId: "b", resolution: { behavior: "deny" } });
    expect(store.getRecord("a")?.agentTitle).toBeUndefined();
    let calls = 0;
    const resolver = async (id: string) => {
      calls += 1;
      return id === "agent-9" ? "Fix the build" : undefined;
    };
    await service.backfillAgentTitles(["a", "b"], resolver);
    await service.backfillAgentTitles(["a", "b"], resolver);
    expect(calls).toBe(1);
    expect(store.getRecord("a")?.agentTitle).toBe("Fix the build");
    expect(store.getRecord("b")?.agentTitle).toBe("Fix the build");
    await store.flush();
  });

  it("does not retry an unresolvable agent and never overwrites an existing title", async () => {
    const { store, service } = await setup();
    await service.handlePermissionAfter({ agent, requestId: "a", resolution: { behavior: "deny" } });
    await service.handlePermissionAfter({ agent: { ...agent, id: "agent-1", title: "Kept" }, requestId: "k", resolution: { behavior: "deny" } });
    let calls = 0;
    const resolver = async () => {
      calls += 1;
      return undefined;
    };
    await service.backfillAgentTitles(["a", "k"], resolver);
    await service.backfillAgentTitles(["a"], resolver);
    expect(calls).toBe(1);
    expect(store.getRecord("a")?.agentTitle).toBeUndefined();
    expect(store.getRecord("k")?.agentTitle).toBe("Kept");
    await store.flush();
  });
});
