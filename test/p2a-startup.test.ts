import { mkdtemp, rm } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import contribute from "../index.server.js";
import { computeEnvDigest, computeFingerprint } from "../server/gate/fingerprint.js";
import { readGateState, writeGateState } from "../server/gate/state-file.js";
import { getGuardianStatus } from "../shared/rpc.js";
import { DEFAULT_GUARDIAN_SETTINGS, type GuardianSettings } from "../shared/settings.js";
import type { GuardianStatusSnapshot } from "../shared/types.js";
import pkg from "../package.json" with { type: "json" };

let dir: string;
let prevEnv: string | undefined;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "startup-"));
  prevEnv = process.env.PASEO_GUARDIAN_DATA_DIR;
  process.env.PASEO_GUARDIAN_DATA_DIR = dir;
});
afterEach(async () => {
  if (prevEnv === undefined) delete process.env.PASEO_GUARDIAN_DATA_DIR;
  else process.env.PASEO_GUARDIAN_DATA_DIR = prevEnv;
  await rm(dir, { recursive: true, force: true });
});

function fakeServer(readResult: () => Promise<unknown>) {
  const handlers = new Map<string, (input: unknown) => Promise<unknown>>();
  return {
    handlers,
    registerSettings: () => ({ read: readResult, subscribe: () => () => undefined }),
    addHook: () => () => undefined,
    handle: (def: { name: string }, fn: (input: unknown) => Promise<unknown>) => {
      handlers.set(def.name, fn);
    },
  };
}

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("F7 startup ordering", () => {
  it("a latch for F(denyAsAsk:false) survives startup when stored settings have denyAsAsk:false", async () => {
    const stored: GuardianSettings = { ...DEFAULT_GUARDIAN_SETTINGS, mode: "act", denyAsAsk: false };
    expect(DEFAULT_GUARDIAN_SETTINGS.denyAsAsk).toBe(true);
    const fp = computeFingerprint({
      pluginVersion: pkg.version,
      policyHash: null,
      denyAsAsk: false,
      windowsDefaultShell: stored.windowsDefaultShell,
      envDigest: computeEnvDigest(process.env, homedir(), dir),
    });
    await writeGateState(dir, {
      version: 1,
      latched: true,
      fingerprint: fp,
      minSamplesAtLatch: 200,
      latchedAt: new Date().toISOString(),
      suspendedBy: [],
      lastReplay: null,
    });
    const server = fakeServer(async () => {
      await delay(150);
      return { status: "ready", values: stored };
    });
    const cleanup = contribute(server as never);
    try {
      // Before settings load the gate is unconfigured ⇒ shadow.
      const early = (await server.handlers.get(getGuardianStatus.name)!({})) as GuardianStatusSnapshot;
      expect(early.effectiveMode).toBe("shadow");
      await delay(400);
      const state = await readGateState(dir);
      expect(state?.latched).toBe(true);
      expect(state?.fingerprint).toBe(fp);
      const s = (await server.handlers.get(getGuardianStatus.name)!({})) as GuardianStatusSnapshot;
      expect(s.gate.fingerprint).toBe(fp);
      expect(s.gate.latched).toBe(true);
      expect(s.effectiveMode).toBe("act");
    } finally {
      await cleanup();
    }
  });

  it("invalid stored settings at startup do not clear an existing latch (engine identity unknown)", async () => {
    const fp = computeFingerprint({
      pluginVersion: pkg.version,
      policyHash: null,
      denyAsAsk: false,
      windowsDefaultShell: "pwsh7",
      envDigest: computeEnvDigest(process.env, homedir(), dir),
    });
    await writeGateState(dir, {
      version: 1, latched: true, fingerprint: fp, minSamplesAtLatch: 200,
      latchedAt: new Date().toISOString(), suspendedBy: [], lastReplay: null,
    });
    const server = fakeServer(async () => ({ status: "invalid", error: "schema" }));
    const cleanup = contribute(server as never);
    try {
      await delay(300);
      const s = (await server.handlers.get(getGuardianStatus.name)!({})) as GuardianStatusSnapshot;
      expect(s.effectiveMode).toBe("shadow");
      expect(s.gate.reason).toBe("settings_invalid:schema");
      const state = await readGateState(dir);
      expect(state?.latched).toBe(true);
      expect(state?.fingerprint).toBe(fp);
    } finally {
      await cleanup();
    }
  });

  it("a settings read failure leaves the gate shadow with settings_invalid", async () => {
    const server = fakeServer(async () => {
      throw new Error("boom");
    });
    const cleanup = contribute(server as never);
    try {
      await delay(100);
      const s = (await server.handlers.get(getGuardianStatus.name)!({})) as GuardianStatusSnapshot;
      expect(s.effectiveMode).toBe("shadow");
      expect(s.gate.reason).toMatch(/^settings_invalid:/);
    } finally {
      await cleanup();
    }
  });
});

describe("F10 plugin version", () => {
  it("PLUGIN_VERSION is read from package.json", async () => {
    const mod = await import("../index.server.js");
    expect(mod.PLUGIN_VERSION).toBe(pkg.version);
  });
});
