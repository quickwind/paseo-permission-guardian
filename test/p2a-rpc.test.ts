import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuditStore } from "../server/audit/store.js";
import { GateController } from "../server/gate/gate.js";
import type { ReplayDecideHandle } from "../server/gate/replay.js";
import { PermissionGuardianService } from "../server/guardian.js";
import { registerGateRpcs } from "../server/rpc-handlers.js";
import { gateAnnotate, gateReplay } from "../shared/rpc.js";
import { DEFAULT_GUARDIAN_SETTINGS } from "../shared/settings.js";

let dir: string;
let store: AuditStore;
let gate: GateController;
let guardian: PermissionGuardianService;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "rpc-"));
  store = new AuditStore({ dataDir: dir, pluginVersion: "0.0.0-test" });
  const decide = (async () => ({ verdict: "ask", level: "L1", reasons: [], effects: [] })) as unknown as ReplayDecideHandle;
  decide.dispose = async () => undefined;
  gate = new GateController({ store, dataDir: dir, replayDecide: decide, debounceMs: 60_000 });
  guardian = new PermissionGuardianService({
    auditStore: store,
    pluginVersion: "0",
    initialSettings: { ...DEFAULT_GUARDIAN_SETTINGS, mode: "act" },
    gate,
  });
});

afterEach(async () => {
  await gate.dispose();
  await store.flush();
  await rm(dir, { recursive: true, force: true });
});

function fakeServer() {
  const handlers = new Map<string, (input: unknown) => Promise<unknown>>();
  return {
    handlers,
    handle: (def: { name: string }, fn: (input: unknown) => Promise<unknown>) => {
      handlers.set(def.name, fn);
    },
  };
}

describe("gate RPCs", () => {
  it("getStatus on fresh act-mode service is effective shadow, replaying/collecting", () => {
    const s = guardian.getStatus();
    expect(s.mode).toBe("act");
    expect(s.effectiveMode).toBe("shadow");
    expect(["replaying", "collecting"]).toContain(s.gate.state);
  });

  it("replay handler returns status with lastReplayAt set, after storeReady", async () => {
    const server = fakeServer();
    let ready = false;
    const storeReady = Promise.resolve().then(() => {
      ready = true;
    });
    registerGateRpcs(server as never, { gate, storeReady: storeReady.then(() => expect(ready).toBe(true)) });
    const out = (await server.handlers.get(gateReplay.name)!({})) as { lastReplayAt: string | null };
    expect(out.lastReplayAt).not.toBeNull();
  });

  it("annotate handler writes an annotation event and returns status", async () => {
    const server = fakeServer();
    registerGateRpcs(server as never, { gate, storeReady: Promise.resolve() });
    const out = (await server.handlers.get(gateAnnotate.name)!({ key: "k1", annotation: "not_safety" })) as {
      lastReplayAt: string | null;
    };
    expect(out.lastReplayAt).not.toBeNull();
    await store.flush();
    const files = await readdir(dir);
    let text = "";
    for (const f of files) if (f.endsWith(".jsonl")) text += await readFile(join(dir, f), "utf8");
    expect(text).toContain('"event":"annotation"');
    expect(text).toContain('"key":"k1"');
  });

  it("errors propagate to the caller", async () => {
    const server = fakeServer();
    const failing = { replay: async () => { throw new Error("nope"); }, annotate: async () => { throw new Error("nope2"); } };
    registerGateRpcs(server as never, { gate: failing as never, storeReady: Promise.resolve() });
    await expect(server.handlers.get(gateReplay.name)!({})).rejects.toThrow("nope");
    await expect(server.handlers.get(gateAnnotate.name)!({ key: "k", annotation: null })).rejects.toThrow("nope2");
  });
});
