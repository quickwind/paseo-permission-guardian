import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { PluginHookAgent } from "@getpaseo/plugin/server";
import { afterEach, describe, expect, it } from "vitest";
import { AuditStore } from "../server/audit/store.js";
import { SessionContextStore } from "../server/context/session.js";
import { PermissionGuardianService } from "../server/guardian.js";
import { DEFAULT_GUARDIAN_SETTINGS } from "../shared/settings.js";

const tempDirs: string[] = [];
afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) await rm(dir, { recursive: true, force: true });
  }
});

const agent: PluginHookAgent = {
  id: "agent-ctx",
  workspaceId: "ws-1",
  parentAgentId: null,
  provider: "claude",
  cwd: "/repo/project",
  title: "T",
  background: false,
  metadata: {},
};

async function makeService(mode: "off" | "shadow" | "act" = "shadow") {
  const dir = await mkdtemp(join(tmpdir(), "paseo-guardian-ctx-"));
  tempDirs.push(dir);
  const store = new AuditStore({ dataDir: dir, pluginVersion: "0.1.0" });
  const service = new PermissionGuardianService({
    auditStore: store,
    pluginVersion: "0.1.0",
    initialSettings: { ...DEFAULT_GUARDIAN_SETTINGS, mode } as never,
  });
  return { service, store };
}

const ctx = { cwd: "/repo/project", worktreeRoot: "/repo/project", home: "/home/u" };

describe("P2a context and settings fail-safes", () => {
  it("timeline fetch failure marks context unavailable => exec becomes L1", async () => {
    const { service, store } = await makeService();
    await service.handlePermissionBefore(
      {
        agent,
        request: {
          id: "r1",
          provider: "claude",
          name: "Bash",
          kind: "tool",
          input: { command: "ls" },
        },
      },
      () => Promise.reject(new Error("x")),
    );
    await service.flush();
    expect(store.getRecord("r1")?.decision?.reasons).toContain("opaque:context_unavailable");
    // M5: the snapshot records that context was unavailable.
    expect(store.getRecord("r1")?.contextSnapshot?.contextUnavailable).toBe(true);
  });

  it("M5: snapshot has contextUnavailable false when the timeline synced", async () => {
    const { service, store } = await makeService();
    await service.handlePermissionBefore(
      { agent, request: { id: "r2", provider: "claude", name: "Bash", kind: "tool", input: { command: "ls" } } },
      async () => [],
    );
    await service.flush();
    expect(store.getRecord("r2")?.contextSnapshot?.contextUnavailable).toBe(false);
  });

  it("completed unknown-type tool calls set untrusted taint", async () => {
    const store = new SessionContextStore();
    const { state } = await store.syncFromTimeline("a", ctx, async () => [
      {
        type: "tool_call",
        callId: "c1",
        name: "Mystery",
        status: "completed",
        error: null,
        detail: { type: "unknown", input: null, output: null },
      } as never,
    ]);
    expect(state.untrustedTaint).toBe(true);
  });

  it("M1: running/pending unknown-type tool calls do not taint until completed", async () => {
    const store = new SessionContextStore();
    const item = (status: string) =>
      ({
        type: "tool_call", callId: "c9", name: "Mystery", status, error: null,
        detail: { type: "unknown", input: null, output: null },
      }) as never;
    for (const status of ["running", "pending"]) {
      const { state } = await store.syncFromTimeline("a", ctx, async () => [item(status)]);
      expect(state.untrustedTaint, status).toBe(false);
    }
    const { state } = await store.syncFromTimeline("a", ctx, async () => [item("completed")]);
    expect(state.untrustedTaint).toBe(true);
  });

  it("failed unknown-type tool calls do not taint", async () => {
    const store = new SessionContextStore();
    const { state } = await store.syncFromTimeline("a", ctx, async () => [
      {
        type: "tool_call",
        callId: "c1",
        name: "Mystery",
        status: "failed",
        error: { message: "x" },
        detail: { type: "unknown", input: null, output: null },
      } as never,
    ]);
    expect(state.untrustedTaint).toBe(false);
  });

  it("completed non-web search and non-sensitive read do not taint", async () => {
    const store = new SessionContextStore();
    const { state } = await store.syncFromTimeline("a", ctx, async () => [
      {
        type: "tool_call",
        callId: "s1",
        name: "Grep",
        status: "completed",
        error: null,
        detail: { type: "search", query: "foo", toolName: "grep" },
      } as never,
      {
        type: "tool_call",
        callId: "r1",
        name: "Read",
        status: "completed",
        error: null,
        detail: { type: "read", filePath: "/repo/project/README.md" },
      } as never,
    ]);
    expect(state.untrustedTaint).toBe(false);
    expect(state.secretTaint).toBe(false);
  });

  it("invalid settings force effective shadow", async () => {
    const { service } = await makeService("act");
    service.markSettingsInvalid("bad");
    expect(service.getStatus().effectiveMode).toBe("shadow");
    expect(service.getEffectiveBaseMode()).toBe("shadow");
    expect(service.getSettingsInvalidReason()).toBe("bad");
    service.updateSettings({ ...DEFAULT_GUARDIAN_SETTINGS, mode: "act" } as never);
    expect(service.getEffectiveBaseMode()).toBe("act");
    expect(service.getSettingsInvalidReason()).toBeNull();
  });
});
