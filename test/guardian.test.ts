import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { PluginHookAgent } from "@getpaseo/plugin/server";
import { afterEach, describe, expect, it } from "vitest";
import { AuditStore } from "../server/audit/store.js";
import { PermissionGuardianService } from "../server/guardian.js";
import { DEFAULT_GUARDIAN_SETTINGS } from "../shared/settings.js";

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "paseo-guardian-svc-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

const sampleAgent: PluginHookAgent = {
  id: "agent-42",
  workspaceId: "ws-1",
  parentAgentId: null,
  provider: "claude",
  cwd: "/repo/project",
  title: "Test Agent",
  background: false,
  metadata: {},
};

describe("PermissionGuardianService", () => {
  it("records shadow-mode requests and reconciles human vs plugin actor attribution", async () => {
    const dataDir = await makeTempDir();
    let clock = 1_700_000_000_000;
    const store = new AuditStore({
      dataDir,
      pluginVersion: "0.1.0",
      now: () => new Date(clock),
    });
    const service = new PermissionGuardianService({
      auditStore: store,
      pluginVersion: "0.1.0",
      initialSettings: DEFAULT_GUARDIAN_SETTINGS,
      answeredTtlMs: 1_000,
      now: () => clock,
    });

    // Human-resolved request
    await service.handlePermissionBefore({
      agent: sampleAgent,
      request: {
        id: "req-human",
        provider: "claude",
        name: "Bash",
        kind: "tool",
        input: { command: "ls -la" },
      },
    });
    await service.handlePermissionAfter({
      agent: sampleAgent,
      requestId: "req-human",
      resolution: { behavior: "allow" },
    });

    // Plugin-marked request resolved within TTL
    service.markAnsweredByPlugin("req-plugin", "allow");
    await service.handlePermissionBefore({
      agent: sampleAgent,
      request: {
        id: "req-plugin",
        provider: "claude",
        name: "Read",
        kind: "tool",
        input: { file_path: "/repo/project/README.md" },
      },
    });
    await service.handlePermissionAfter({
      agent: sampleAgent,
      requestId: "req-plugin",
      resolution: { behavior: "allow" },
    });

    // Plugin-marked request whose TTL expired before after hook
    service.markAnsweredByPlugin("req-expired", "allow");
    clock += 2_000;
    await service.handlePermissionAfter({
      agent: sampleAgent,
      requestId: "req-expired",
      resolution: { behavior: "allow" },
    });

    await service.flush();

    expect(store.getRecord("req-human")?.resolution?.actor).toBe("human");
    expect(store.getRecord("req-plugin")?.resolution?.actor).toBe("plugin");
    expect(store.getRecord("req-expired")?.resolution?.actor).toBe("human");
    expect(service.getStatus().effectiveMode).toBe("shadow");
  });

  it("marks question/plan/mode requests as neverAutoAnswer", async () => {
    const dataDir = await makeTempDir();
    const store = new AuditStore({ dataDir, pluginVersion: "0.1.0" });
    const service = new PermissionGuardianService({
      auditStore: store,
      pluginVersion: "0.1.0",
    });

    await service.handlePermissionBefore({
      agent: sampleAgent,
      request: {
        id: "req-q",
        provider: "claude",
        name: "AskUserQuestion",
        kind: "question",
      },
    });
    await service.flush();

    const record = store.getRecord("req-q");
    expect(record?.decision?.neverAutoAnswer).toBe(true);
    expect(record?.decision?.verdict).toBe("ask");
    expect(record?.decision?.level).toBe("L2");
  });

  it("does nothing when mode is off", async () => {
    const dataDir = await makeTempDir();
    const store = new AuditStore({ dataDir, pluginVersion: "0.1.0" });
    const service = new PermissionGuardianService({
      auditStore: store,
      pluginVersion: "0.1.0",
      initialSettings: { ...DEFAULT_GUARDIAN_SETTINGS, mode: "off" },
    });

    await service.handlePermissionBefore({
      agent: sampleAgent,
      request: {
        id: "req-off",
        provider: "claude",
        name: "Bash",
        kind: "tool",
        input: { command: "echo hi" },
      },
    });
    await service.flush();

    expect(service.getStatus().effectiveMode).toBe("off");
    expect(store.getMetrics().totalRequests).toBe(0);
  });
});
