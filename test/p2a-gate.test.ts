import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditStore } from "../server/audit/store.js";
import { GateController } from "../server/gate/gate.js";
import type { ReplayDecideHandle, ReplayDecision } from "../server/gate/replay.js";
import { GATE_STATE_FILE, readGateState, writeGateState } from "../server/gate/state-file.js";
import { DEFAULT_GUARDIAN_SETTINGS, type GuardianSettings } from "../shared/settings.js";
import type { AuditRecord, GuardianVerdict } from "../shared/types.js";

const DAY = 86_400_000;
const FP = "fp-aaaaaaaaaaaaaaaaaaaaaaaa";
const FP2 = "fp-bbbbbbbbbbbbbbbbbbbbbbbb";

let dir: string;
let store: AuditStore;
let clock: number;
let replayVerdicts: Map<string, GuardianVerdict>;
let disposeCalls: number;
const controllers: GateController[] = [];

function fakeDecide(): ReplayDecideHandle {
  const fn = (async (record: AuditRecord): Promise<ReplayDecision> => {
    const v = replayVerdicts.get(record.requestId) ?? record.decision?.verdict ?? "ask";
    return { verdict: v, level: v === "allow" ? "L0" : v === "deny" ? "L3" : "L1", reasons: [], effects: [] };
  }) as ReplayDecideHandle;
  fn.dispose = async () => {
    disposeCalls += 1;
  };
  return fn;
}

function controlledDecide() {
  let calls = 0;
  const holds: { from: number; p: Promise<void> }[] = [];
  const base = fakeDecide();
  const fn = (async (record: AuditRecord) => {
    calls += 1;
    const i = calls;
    const h = [...holds].reverse().find((x) => x.from <= i);
    if (h) await h.p;
    return base(record);
  }) as ReplayDecideHandle;
  fn.dispose = base.dispose;
  return {
    fn,
    calls: () => calls,
    /** Blocks decide calls numbered ≥ from (until a later hold) until the returned release is called. */
    holdFrom(from: number): () => void {
      let release!: () => void;
      const p = new Promise<void>((r) => {
        release = r;
      });
      holds.push({ from, p });
      return release;
    },
  };
}

function makeGate(
  opts: { debounceMs?: number; decide?: ReplayDecideHandle; writeState?: typeof writeGateState } = {},
): GateController {
  const g = new GateController({
    store,
    dataDir: dir,
    replayDecide: opts.decide ?? fakeDecide(),
    now: () => clock,
    debounceMs: opts.debounceMs ?? 60_000,
    ...(opts.writeState ? { writeState: opts.writeState } : {}),
  });
  controllers.push(g);
  return g;
}

function settings(over: {
  mode?: GuardianSettings["mode"];
  actGate?: Partial<GuardianSettings["actGate"]>;
  actOverride?: Partial<GuardianSettings["actOverride"]>;
} = {}): GuardianSettings {
  return {
    ...DEFAULT_GUARDIAN_SETTINGS,
    mode: over.mode ?? "act",
    actGate: { ...DEFAULT_GUARDIAN_SETTINGS.actGate, ...(over.actGate ?? {}) },
    actOverride: { ...DEFAULT_GUARDIAN_SETTINGS.actOverride, ...(over.actOverride ?? {}) },
  };
}

function configure(g: GateController, s: GuardianSettings = settings(), fingerprint = FP, settingsValid = true, settingsInvalidReason?: string) {
  g.configure({ settings: s, settingsValid, fingerprint, settingsInvalidReason });
}

async function seed(id: string, recorded: GuardianVerdict, human: "allow" | "deny", atMs = clock) {
  const at = new Date(atMs).toISOString();
  await store.recordBefore({
    requestId: id,
    agentId: "a",
    provider: "claude",
    mode: "shadow",
    requestedAt: at,
    latencyMs: 1,
    normalizedBy: "test",
    warnings: [],
    action: {
      provider: "claude",
      agentId: "a",
      requestId: id,
      kind: "exec",
      toolName: "Bash",
      host: { os: "darwin" },
      cwd: "/repo",
      exec: { shell: "bash", source: `cmd-${id}` },
    } as AuditRecord["action"] & object,
    decision: {
      level: recorded === "allow" ? "L0" : recorded === "deny" ? "L3" : "L1",
      verdict: recorded,
      reasons: [],
    },
  });
  await store.recordAfter({
    requestId: id,
    agentId: "a",
    provider: "claude",
    mode: "shadow",
    resolution: { behavior: human, resolvedAt: at, actor: "human" },
  });
}

async function seedSamples(n: number, prefix = "s") {
  for (let i = 0; i < n; i += 1) await seed(`${prefix}${i}`, "allow", "allow");
  await store.flush();
}

async function latchedGate(): Promise<GateController> {
  await seedSamples(200);
  const g = makeGate();
  configure(g);
  await g.replay();
  expect(g.status().state).toBe("latched");
  return g;
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "gate-"));
  clock = Date.now();
  store = new AuditStore({ dataDir: dir, pluginVersion: "0.0.0-test" });
  replayVerdicts = new Map();
  disposeCalls = 0;
});

afterEach(async () => {
  for (const g of controllers.splice(0)) await g.dispose();
  await store.flush();
  await rm(dir, { recursive: true, force: true });
});

describe("GateController — §3.2 states", () => {
  it("fresh dir, mode act ⇒ replaying then collecting, effective shadow", async () => {
    const g = makeGate();
    configure(g);
    expect(g.status().state).toBe("replaying");
    expect(g.effectiveMode()).toBe("shadow");
    const s = await g.replay();
    expect(s.state).toBe("collecting");
    expect(g.effectiveMode()).toBe("shadow");
    expect(s.fingerprint).toBe(FP);
  });

  it("not configured ⇒ shadow", () => {
    const g = makeGate();
    expect(g.effectiveMode()).toBe("shadow");
  });

  it("200 samples ⇒ latched, act, gate-state.json minSamplesAtLatch 200", async () => {
    const g = await latchedGate();
    expect(g.effectiveMode()).toBe("act");
    expect(g.status()).toMatchObject({ samples: 200, latched: true, suspended: false });
    await g.dispose();
    const fs = await readGateState(dir);
    expect(fs).toMatchObject({ latched: true, fingerprint: FP, minSamplesAtLatch: 200, suspendedBy: [] });
  });

  it("samples ≥ minSamples in mode shadow ⇒ passed, no latch written", async () => {
    await seedSamples(200);
    const g = makeGate();
    configure(g, settings({ mode: "shadow" }));
    const s = await g.replay();
    expect(s.state).toBe("passed");
    expect(g.effectiveMode()).toBe("shadow");
    await g.dispose();
    expect((await readGateState(dir))?.latched ?? false).toBe(false);
  });

  it("mode off ⇒ off; mode shadow ⇒ shadow", async () => {
    const g = await latchedGate();
    configure(g, settings({ mode: "off" }));
    expect(g.effectiveMode()).toBe("off");
    configure(g, settings({ mode: "shadow" }));
    expect(g.effectiveMode()).toBe("shadow");
    configure(g, settings());
    expect(g.effectiveMode()).toBe("act");
  });

  it("raise minSamples to 300 while latched ⇒ not latched, collecting (immediately)", async () => {
    const g = await latchedGate();
    configure(g, settings({ actGate: { minSamples: 300 } }));
    expect(g.effectiveMode()).toBe("shadow");
    expect(g.status()).toMatchObject({ state: "collecting", latched: false });
    await g.replay();
    expect(g.status().state).toBe("collecting");
    // lowering again does not resurrect the cleared latch retroactively
    configure(g, settings({ actGate: { minSamples: 250 } }));
    await g.replay();
    expect(g.status().state).toBe("collecting");
    expect(g.effectiveMode()).toBe("shadow");
  });

  it("lowering minSamples while latched keeps the latch", async () => {
    const g = await latchedGate();
    configure(g, settings({ actGate: { minSamples: 100 } }));
    expect(g.effectiveMode()).toBe("act");
    await g.replay();
    expect(g.status().state).toBe("latched");
  });

  it("false-allow before latching ⇒ failed_false_allow, shadow even with override", async () => {
    await seedSamples(200);
    await seed("bad", "allow", "deny");
    await store.flush();
    const g = makeGate();
    configure(g, settings({ actOverride: { accepted: true, fingerprint: FP } }));
    const s = await g.replay();
    expect(s.state).toBe("failed_false_allow");
    expect(s.falseAllowCount).toBe(1);
    expect(s.entries.some((e) => e.kind === "false_allow" && e.requestId === "bad")).toBe(true);
    expect(g.effectiveMode()).toBe("shadow");
    expect(s.latched).toBe(false);
  });

  it("false-allow while latched ⇒ suspended, shadow; annotate ⇒ latched, act", async () => {
    const g = await latchedGate();
    await seed("bad", "allow", "deny");
    await store.flush();
    // immediate fallback via reconciliation (before any replay)
    expect(g.effectiveMode()).toBe("shadow");
    expect(g.status().state).toBe("suspended");
    const s1 = await g.replay();
    expect(s1).toMatchObject({ state: "suspended", suspended: true, falseAllowCount: 1 });
    expect(g.effectiveMode()).toBe("shadow");
    expect((await g.dispose().then(() => readGateState(dir)))?.suspendedBy).toEqual(["bad"]);

    const g2 = makeGate();
    configure(g2);
    await g2.replay();
    expect(g2.status().state).toBe("suspended");
    const s2 = await g2.annotate("bad", "not_safety");
    expect(s2).toMatchObject({ state: "latched", suspended: false, falseAllowCount: 0 });
    expect(g2.effectiveMode()).toBe("act");
    await g2.dispose();
    expect((await readGateState(dir))?.suspendedBy).toEqual([]);
  });

  it("false-allow found only by replay (recorded ask, replay allow) while latched ⇒ suspended + fallback event", async () => {
    const g = await latchedGate();
    await seed("d1", "ask", "deny");
    expect(g.effectiveMode()).toBe("act");
    replayVerdicts.set("d1", "allow");
    const s = await g.replay();
    expect(s.state).toBe("suspended");
    expect(g.effectiveMode()).toBe("shadow");
    await store.flush();
    expect(await readAll()).toMatch(/"type":"fallback_false_allow"/);
  });

  it("override does not help while suspended", async () => {
    const g = await latchedGate();
    configure(g, settings({ actOverride: { accepted: true, fingerprint: FP } }));
    await seed("bad", "allow", "deny");
    await g.replay();
    expect(g.effectiveMode()).toBe("shadow");
  });

  it("suspending entry ages out unannotated ⇒ latch cleared, collecting", async () => {
    const g = await latchedGate();
    await seed("bad", "allow", "deny");
    await g.replay();
    expect(g.status().state).toBe("suspended");
    clock += 31 * DAY;
    const s = await g.replay();
    expect(s).toMatchObject({ state: "collecting", latched: false, suspended: false });
    expect(g.effectiveMode()).toBe("shadow");
    await g.dispose();
    expect((await readGateState(dir))?.latched).toBe(false);
  });

  it("autoFallbackOnFalseAllow false + latched + false-allow ⇒ act with false_allow_reported", async () => {
    const g = await latchedGate();
    configure(g, settings({ actGate: { autoFallbackOnFalseAllow: false } }));
    await seed("bad", "allow", "deny");
    expect(g.effectiveMode()).toBe("act");
    const s = await g.replay();
    expect(g.effectiveMode()).toBe("act");
    expect(s.reason).toContain("false_allow_reported");
    expect(s.falseAllowCount).toBe(1);
    // turning auto-fallback back on applies the fallback immediately
    configure(g, settings());
    expect(g.effectiveMode()).toBe("shadow");
    expect(g.status().state).toBe("suspended");
  });

  it("autoFallback false + false-allow + no latch/override ⇒ shadow; with override ⇒ act", async () => {
    await seed("bad", "allow", "deny");
    const g = makeGate();
    configure(g, settings({ actGate: { autoFallbackOnFalseAllow: false } }));
    await g.replay();
    expect(g.effectiveMode()).toBe("shadow");
    configure(
      g,
      settings({ actGate: { autoFallbackOnFalseAllow: false }, actOverride: { accepted: true, fingerprint: FP } }),
    );
    expect(g.effectiveMode()).toBe("act");
    expect(g.status().reason).toContain("false_allow_reported");
  });
});

describe("GateController — override", () => {
  it("valid override in collecting ⇒ act, no latch written", async () => {
    const g = makeGate();
    configure(g, settings({ actOverride: { accepted: true, acceptedAt: "x", fingerprint: FP } }));
    await g.replay();
    expect(g.status().state).toBe("collecting");
    expect(g.status().override).toEqual({ valid: true, accepted: true, acceptedAt: "x" });
    expect(g.effectiveMode()).toBe("act");
    await g.dispose();
    expect((await readGateState(dir))?.latched ?? false).toBe(false);
  });

  it("override with stale fingerprint ⇒ shadow", async () => {
    const g = makeGate();
    configure(g, settings({ actOverride: { accepted: true, fingerprint: FP2 } }));
    await g.replay();
    expect(g.status().override.valid).toBe(false);
    expect(g.effectiveMode()).toBe("shadow");
  });

  it("allowOverride false ⇒ override invalid (immediately)", async () => {
    const g = makeGate();
    configure(g, settings({ actOverride: { accepted: true, fingerprint: FP } }));
    await g.replay();
    expect(g.effectiveMode()).toBe("act");
    configure(g, settings({ actGate: { allowOverride: false }, actOverride: { accepted: true, fingerprint: FP } }));
    expect(g.effectiveMode()).toBe("shadow");
  });

  it("override during replaying ⇒ shadow", () => {
    const g = makeGate();
    configure(g, settings({ actOverride: { accepted: true, fingerprint: FP } }));
    expect(g.status().state).toBe("replaying");
    expect(g.effectiveMode()).toBe("shadow");
  });

  it("override during unavailable (corrupt line) ⇒ shadow", async () => {
    const day = new Date(clock).toISOString().slice(0, 10);
    await writeFile(join(dir, `audit-${day}.jsonl`), "{not json\n{\"event\":\"gate\"}\n", "utf8");
    const g = makeGate();
    configure(g, settings({ actOverride: { accepted: true, fingerprint: FP } }));
    const s = await g.replay();
    expect(s.state).toBe("unavailable");
    expect(s.reason).toContain("corrupt_audit_line");
    expect(g.effectiveMode()).toBe("shadow");
  });

  it("emits override accepted / revoked gate events", async () => {
    const g = makeGate();
    configure(g, settings({ actOverride: { accepted: true, fingerprint: FP } }));
    configure(g, settings());
    await store.flush();
    const text = await readAll();
    expect(text).toContain('"type":"override_accepted"');
    expect(text).toContain('"type":"override_revoked"');
  });
});

describe("GateController — fingerprint & restart", () => {
  it("fingerprint change ⇒ latch cleared, override invalid", async () => {
    const g = await latchedGate();
    configure(g, settings({ actOverride: { accepted: true, fingerprint: FP } }));
    expect(g.effectiveMode()).toBe("act");
    configure(g, settings({ actOverride: { accepted: true, fingerprint: FP } }), FP2);
    expect(g.effectiveMode()).toBe("shadow");
    expect(g.status().state).toBe("replaying");
    expect(g.status().override.valid).toBe(false);
    const s = await g.replay();
    // samples still ≥ 200 under the new engine ⇒ re-earns a latch for FP2 (entry condition)
    expect(s.fingerprint).toBe(FP2);
    await g.dispose();
    const fs = await readGateState(dir);
    expect(fs?.fingerprint).toBe(FP2);
  });

  it("fingerprint change without enough samples ⇒ latch cleared on disk, collecting", async () => {
    await writeGateState(dir, {
      version: 1,
      latched: true,
      fingerprint: FP,
      minSamplesAtLatch: 200,
      latchedAt: new Date(clock).toISOString(),
      suspendedBy: [],
      lastReplay: null,
    });
    const g = makeGate();
    configure(g, settings(), FP2);
    const s = await g.replay();
    expect(s.state).toBe("collecting");
    expect(g.effectiveMode()).toBe("shadow");
    await g.dispose();
    expect((await readGateState(dir))?.latched).toBe(false);
  });

  it("restart with valid latch ⇒ shadow until replay resolves, then act", async () => {
    await writeGateState(dir, {
      version: 1,
      latched: true,
      fingerprint: FP,
      minSamplesAtLatch: 200,
      latchedAt: new Date(clock).toISOString(),
      suspendedBy: [],
      lastReplay: null,
    });
    const g = makeGate();
    configure(g);
    expect(g.effectiveMode()).toBe("shadow");
    expect(g.status().state).toBe("replaying");
    const s = await g.replay();
    expect(s.state).toBe("latched");
    expect(g.effectiveMode()).toBe("act");
  });

  it.each([5, 19, 200.5, -1])("latch file with minSamplesAtLatch %s is not latched", async (bad) => {
    await writeGateState(dir, {
      version: 1,
      latched: true,
      fingerprint: FP,
      minSamplesAtLatch: bad,
      latchedAt: null,
      suspendedBy: [],
      lastReplay: null,
    });
    const g = makeGate();
    configure(g, settings({ actGate: { minSamples: 20 } }));
    const s = await g.replay();
    expect(s.latched).toBe(false);
    expect(g.effectiveMode()).toBe("shadow");
  });

  it("corrupt gate-state.json ⇒ not latched", async () => {
    await writeFile(join(dir, GATE_STATE_FILE), "garbage", "utf8");
    const g = makeGate();
    configure(g);
    await g.replay();
    expect(g.effectiveMode()).toBe("shadow");
  });

  it("dispose disposes the replay decide handle", async () => {
    const g = makeGate();
    await g.dispose();
    expect(disposeCalls).toBe(1);
  });
});

describe("GateController — settings, responder, auto-deny", () => {
  it("settings invalid ⇒ shadow with settings_invalid:<reason>", async () => {
    const g = await latchedGate();
    configure(g, settings(), FP, false, "parse_error");
    expect(g.effectiveMode()).toBe("shadow");
    expect(g.status().reason).toBe("settings_invalid:parse_error");
  });

  it("3 consecutive unconfirmed ⇒ shadow (responder_unconfirmed) until a manual replay (R12)", async () => {
    const g = await latchedGate();
    g.noteActOutcome("unconfirmed");
    g.noteActOutcome("unconfirmed");
    g.noteActOutcome("answered");
    g.noteActOutcome("unconfirmed");
    g.noteActOutcome("unconfirmed");
    expect(g.effectiveMode()).toBe("act");
    g.noteActOutcome("unconfirmed");
    expect(g.effectiveMode()).toBe("shadow");
    expect(g.status().reason).toBe("responder_unconfirmed");
    expect(g.status().unconfirmedCount).toBe(3);
    g.noteActOutcome("answered");
    expect(g.effectiveMode()).toBe("shadow");
    await g.replay();
    expect(g.effectiveMode()).toBe("shadow");
    await g.replay({ manual: true });
    expect(g.effectiveMode()).toBe("act");
    expect(g.status().unconfirmedCount).toBe(0);
  });

  it("F4: a reconciliation-triggered replay does not unpause", async () => {
    await seedSamples(200);
    const g = makeGate({ debounceMs: 1 });
    configure(g);
    await g.replay();
    for (let i = 0; i < 3; i += 1) g.noteActOutcome("unconfirmed");
    expect(g.status().reason).toBe("responder_unconfirmed");
    await seed("late", "allow", "allow"); // schedules a debounced replay
    await new Promise((r) => setTimeout(r, 30));
    await g.replay(); // let the scheduled replay settle
    expect(g.effectiveMode()).toBe("shadow");
    expect(g.status().reason).toBe("responder_unconfirmed");
  });

  it("F4: a manual replay that is unavailable does not unpause", async () => {
    const g = await latchedGate();
    for (let i = 0; i < 3; i += 1) g.noteActOutcome("unconfirmed");
    await writeFile(join(dir, "audit-2099-01-01.jsonl"), "{not json\n");
    clock = Date.parse("2099-01-01T12:00:00.000Z") - 1000;
    await g.replay({ manual: true });
    expect(g.status().state).toBe("unavailable");
    expect(g.effectiveMode()).toBe("shadow");
    expect(g.status().unconfirmedCount).toBe(3);
  });

  it("F4: lost_race with matching behavior counts toward the unconfirmed streak", async () => {
    const g = await latchedGate();
    g.noteActOutcome("lost_race");
    g.noteActOutcome("unconfirmed");
    g.noteActOutcome("lost_race");
    expect(g.effectiveMode()).toBe("shadow");
    expect(g.status().reason).toBe("responder_unconfirmed");
  });

  it("canAutoDeny false when any false-deny; true when act and none", async () => {
    const g = await latchedGate();
    expect(g.canAutoDeny()).toBe(true);
    replayVerdicts.set("s0", "deny"); // human allowed, engine now says L3
    const s = await g.replay();
    expect(s.falseDenyCount).toBe(1);
    expect(g.effectiveMode()).toBe("act");
    expect(g.canAutoDeny()).toBe(false);
  });

  it("canAutoDeny false when not act", async () => {
    const g = makeGate();
    configure(g);
    await g.replay();
    expect(g.canAutoDeny()).toBe(false);
  });
});

describe("GateController — persist failure (R4)", () => {
  it("persist failure ⇒ unavailable with integrity entry; annotate clears it", async () => {
    const g = await latchedGate();
    let fail = true;
    const failing = new AuditStore({
      dataDir: dir,
      pluginVersion: "0",
      writeFn: async (p, l) => {
        if (fail) throw new Error("disk");
        const { appendFile } = await import("node:fs/promises");
        await appendFile(p, l, "utf8");
      },
    });
    await failing.appendEvent({ event: "gate", type: "x" }).catch(() => {});
    const pf = failing.getPersistFailure();
    expect(pf).not.toBeNull();
    fail = false;
    // reload the marker into the controller's store
    await store.loadFromDisk();
    expect(store.getPersistFailure()).not.toBeNull();
    expect(g.effectiveMode()).toBe("shadow");
    const s = g.status();
    expect(s.state).toBe("unavailable");
    expect(s.reason).toContain("audit_persist_failure");
    const key = `persist_failure#${pf!.firstAt}`;
    expect(s.entries).toContainEqual({ kind: "corrupt_line", key, requestId: "", effects: [] });
    const s2 = await g.annotate(key, "not_safety");
    expect(store.getPersistFailure()).toBeNull();
    expect(s2.state).toBe("latched");
    expect(g.effectiveMode()).toBe("act");
  });
});

describe("GateController — reconciliation, annotations, events", () => {
  it("orphan human deny via reconciliation ⇒ immediate shadow", async () => {
    const g = await latchedGate();
    await store.recordAfter({
      requestId: "orph",
      agentId: "a",
      provider: "claude",
      mode: "act",
      resolution: { behavior: "deny", resolvedAt: new Date(clock).toISOString(), actor: "human" },
    });
    expect(g.effectiveMode()).toBe("shadow");
    const s = await g.replay();
    expect(s.state).toBe("unavailable");
  });

  it("human deny of a recorded ask does not change mode immediately", async () => {
    const g = await latchedGate();
    await seed("d1", "ask", "deny");
    expect(g.effectiveMode()).toBe("act");
  });

  it("plugin-actor resolutions are ignored", async () => {
    const g = await latchedGate();
    await store.recordBefore({
      requestId: "p1", agentId: "a", provider: "claude", mode: "act",
      requestedAt: new Date(clock).toISOString(), latencyMs: 1, normalizedBy: "t", warnings: [],
      action: { provider: "claude", agentId: "a", requestId: "p1", kind: "exec", toolName: "Bash", host: { os: "darwin" }, cwd: "/r" } as never,
      decision: { level: "L0", verdict: "allow", reasons: [] },
    });
    await store.recordAfter({
      requestId: "p1", agentId: "a", provider: "claude", mode: "act",
      resolution: { behavior: "deny", resolvedAt: new Date(clock).toISOString(), actor: "plugin" },
    });
    expect(g.effectiveMode()).toBe("act");
  });

  it("reconciliation schedules a debounced replay that updates samples", async () => {
    await seedSamples(199);
    const g = makeGate({ debounceMs: 5 });
    configure(g);
    await g.replay();
    expect(g.status().state).toBe("collecting");
    await seed("last", "allow", "allow");
    await new Promise((r) => setTimeout(r, 100));
    await g.replay(); // waits for any in-flight debounced replay
    expect(g.status().samples).toBe(200);
    expect(g.effectiveMode()).toBe("act");
  });

  it("un-annotating a false-allow reverts to shadow (replaying until replay done)", async () => {
    const g = await latchedGate();
    await seed("bad", "allow", "deny");
    await g.annotate("bad", "not_safety");
    expect(g.effectiveMode()).toBe("act");
    const p = g.annotate("bad", null);
    expect(g.effectiveMode()).toBe("shadow");
    const s = await p;
    expect(s.state).toBe("suspended");
  });

  it("writes annotation and gate events to the audit log", async () => {
    const g = await latchedGate();
    await seed("bad", "allow", "deny");
    await g.replay();
    await g.annotate("bad", "not_safety");
    await store.flush();
    const text = await readAll();
    expect(text).toContain('"event":"annotation"');
    expect(text).toMatch(/"type":"latch_written"/);
    expect(text).toMatch(/"type":"suspended"/);
    expect(text).toMatch(/"type":"resumed"/);
    expect(text).toMatch(/"type":"fallback_false_allow"/);
    expect(text).toMatch(/"type":"replay"/);
  });

  it("latch cleared event carries reason", async () => {
    const g = await latchedGate();
    configure(g, settings({ actGate: { minSamples: 300 } }));
    await store.flush();
    expect(await readAll()).toMatch(/"type":"latch_cleared"[^\n]*"reason":"min_samples_raised"/);
  });

  it("windowDays change ⇒ replaying until a new replay completes", async () => {
    const g = await latchedGate();
    configure(g, settings({ actGate: { windowDays: 60 } }));
    expect(g.status().state).toBe("replaying");
    expect(g.effectiveMode()).toBe("shadow");
    await g.replay();
    expect(g.effectiveMode()).toBe("act");
  });

  it("replay error ⇒ unavailable", async () => {
    const g = new GateController({
      store,
      dataDir: dir,
      replayDecide: Object.assign(
        async () => {
          throw new Error("x");
        },
        { dispose: async () => {} },
      ) as unknown as ReplayDecideHandle,
      now: () => clock,
    });
    controllers.push(g);
    await seed("bad", "allow", "deny");
    configure(g, settings({ actOverride: { accepted: true, fingerprint: FP } }));
    const s = await g.replay();
    expect(s.state).toBe("unavailable");
    expect(g.effectiveMode()).toBe("shadow");
  });

  it("serializes gate-state writes (final file reflects last state)", async () => {
    const g = await latchedGate();
    for (let i = 0; i < 5; i += 1) {
      configure(g, settings({ actGate: { minSamples: 300 } }));
      configure(g, settings());
      await g.replay();
    }
    await g.dispose();
    const raw = JSON.parse(await readFile(join(dir, GATE_STATE_FILE), "utf8"));
    expect(raw.latched).toBe(true);
    expect(raw.minSamplesAtLatch).toBe(200);
  });
});

async function readAll(): Promise<string> {
  const { readdir } = await import("node:fs/promises");
  const names = (await readdir(dir)).filter((n) => n.startsWith("audit-"));
  let out = "";
  for (const n of names) out += await readFile(join(dir, n), "utf8");
  return out;
}

async function makePersistFailure(): Promise<string> {
  const failing = new AuditStore({
    dataDir: dir,
    pluginVersion: "0",
    writeFn: async () => {
      throw new Error("disk");
    },
  });
  await failing.appendEvent({ event: "gate", type: "x" }).catch(() => {});
  const pf = failing.getPersistFailure();
  await store.loadFromDisk();
  return `persist_failure#${pf!.firstAt}`;
}

async function latchedControlled() {
  const ctl = controlledDecide();
  await seedSamples(200);
  const g = makeGate({ decide: ctl.fn });
  configure(g);
  await g.replay();
  expect(g.status().state).toBe("latched");
  expect(ctl.calls()).toBe(200);
  return { g, ctl };
}

describe("GateController — fix round 1", () => {
  it("I1: gate-state write failure ⇒ unavailable/shadow until a later write succeeds", async () => {
    await seedSamples(200);
    let failWrites = false;
    const g = makeGate({
      writeState: async (d, st) => {
        if (failWrites) throw new Error("EIO");
        await writeGateState(d, st);
      },
    });
    configure(g);
    await g.replay();
    expect(g.effectiveMode()).toBe("act");
    failWrites = true;
    configure(g, settings({ actGate: { autoFallbackOnFalseAllow: false } }));
    await g.replay(); // lastReplay write fails
    await vi.waitFor(() => expect(g.status().reason).toBe("gate_state_write_failure"));
    expect(g.status().state).toBe("unavailable");
    expect(g.effectiveMode()).toBe("shadow");
    await store.flush();
    expect(await readAll()).toMatch(/"type":"state_write_failure"/);

    failWrites = false;
    await g.replay();
    await vi.waitFor(() => expect(g.status().state).toBe("latched"));
    expect(g.effectiveMode()).toBe("act");
  });

  it("I1: failed suspension write keeps shadow, and the recovered write persists the suspension", async () => {
    await seedSamples(200);
    let failWrites = false;
    const g = makeGate({
      writeState: async (d, st) => {
        if (failWrites) throw new Error("EIO");
        await writeGateState(d, st);
      },
    });
    configure(g);
    await g.replay();
    failWrites = true;
    await seed("bad", "allow", "deny");
    await vi.waitFor(() => expect(g.status().reason).toBe("gate_state_write_failure"));
    expect((await readGateState(dir))?.suspendedBy).toEqual([]);
    // still failing: no latch-state change is trusted, gate stays shadow
    await g.replay();
    expect(g.effectiveMode()).toBe("shadow");
    failWrites = false;
    await g.replay();
    await vi.waitFor(() => expect(g.status().state).toBe("suspended"));
    await g.dispose();
    expect((await readGateState(dir))?.suspendedBy).toEqual(["bad"]);
  });

  it("I2: replay that read the window before annotate(null) is discarded", async () => {
    const { g, ctl } = await latchedControlled();
    await seed("bad", "allow", "deny");
    await g.annotate("bad", "not_safety"); // calls 201..400 (bad is skipped as annotated)
    expect(g.effectiveMode()).toBe("act");
    const release1 = ctl.holdFrom(401);
    const p1 = g.replay();
    await vi.waitFor(() => expect(ctl.calls()).toBeGreaterThanOrEqual(401));
    const release2 = ctl.holdFrom(601);
    const pa = g.annotate("bad", null);
    expect(g.effectiveMode()).toBe("shadow");
    await store.flush();
    release1();
    await p1;
    expect(g.status().state).toBe("replaying");
    expect(g.effectiveMode()).toBe("shadow");
    release2();
    const s = await pa;
    expect(s.state).toBe("suspended");
    expect(g.effectiveMode()).toBe("shadow");
  });

  it("R6: suspension is not lifted when replay stops reporting the id; only annotation lifts it", async () => {
    const g = await latchedGate();
    await seed("bad", "allow", "deny");
    await g.replay();
    expect(g.status().state).toBe("suspended");
    replayVerdicts.set("bad", "ask"); // replay no longer reports it as a false-allow
    const s = await g.replay();
    expect(s.falseAllowCount).toBe(1); // still counted while it suspends
    expect(s).toMatchObject({ state: "suspended", suspended: true });
    configure(g, settings({ actOverride: { accepted: true, fingerprint: FP } }));
    expect(g.effectiveMode()).toBe("shadow"); // override does not help while suspended
    expect(s.entries.some((e) => e.requestId === "bad" && e.kind === "false_allow")).toBe(true);
    expect(g.effectiveMode()).toBe("shadow");
    const s2 = await g.annotate("bad", "not_safety");
    expect(s2).toMatchObject({ state: "latched", suspended: false });
    expect(g.effectiveMode()).toBe("act");
  });

  it("R6: a suspending id the replay no longer reports still ages out ⇒ latch cleared", async () => {
    const g = await latchedGate();
    await seed("bad", "allow", "deny");
    await g.replay();
    replayVerdicts.set("bad", "ask");
    await g.replay();
    expect(g.status().state).toBe("suspended");
    clock += 31 * DAY;
    const s = await g.replay();
    expect(s).toMatchObject({ state: "collecting", latched: false });
  });

  it("M1: fingerprint switch while a replay is in flight ⇒ stale result discarded, no latch under new fp", async () => {
    const ctl = controlledDecide();
    await seedSamples(200);
    const g = makeGate({ decide: ctl.fn });
    const release1 = ctl.holdFrom(1);
    configure(g);
    const p1 = g.replay();
    await vi.waitFor(() => expect(ctl.calls()).toBeGreaterThanOrEqual(1));
    const release2 = ctl.holdFrom(201);
    configure(g, settings(), FP2);
    release1();
    await p1;
    expect(g.status()).toMatchObject({ state: "replaying", latched: false, fingerprint: FP2 });
    expect(g.effectiveMode()).toBe("shadow");
    expect((await readGateState(dir))?.latched ?? false).toBe(false);
    release2();
    const s = await g.replay();
    expect(s.state).toBe("latched");
    await g.dispose();
    expect(await readGateState(dir)).toMatchObject({ latched: true, fingerprint: FP2 });
  });

  it("M1: onReconciled false-allow during an in-flight replay survives that replay", async () => {
    const { g, ctl } = await latchedControlled();
    const release = ctl.holdFrom(201);
    const p1 = g.replay();
    await vi.waitFor(() => expect(ctl.calls()).toBeGreaterThanOrEqual(201));
    await seed("bad", "allow", "deny");
    expect(g.effectiveMode()).toBe("shadow");
    release();
    await p1;
    expect(g.status()).toMatchObject({ state: "suspended", latched: true });
    expect(g.effectiveMode()).toBe("shadow");
    await g.replay();
    expect(g.status()).toMatchObject({ state: "suspended", falseAllowCount: 1 });
  });

  it("M3: human allow of a recorded-L3 request ⇒ canAutoDeny false immediately", async () => {
    const g = await latchedGate();
    expect(g.canAutoDeny()).toBe(true);
    await seed("l3", "deny", "allow");
    expect(g.canAutoDeny()).toBe(false);
    expect(g.status().falseDenyCount).toBe(1);
    expect(g.effectiveMode()).toBe("act");
    await g.replay(); // replay confirms L3
    expect(g.canAutoDeny()).toBe(false);
    replayVerdicts.set("l3", "allow"); // engine no longer L3 ⇒ replay clears it
    await g.replay();
    expect(g.canAutoDeny()).toBe(true);
  });

  it("M4: acknowledging a persist failure holds shadow until a fresh replay completes", async () => {
    const { g, ctl } = await latchedControlled();
    const key = await makePersistFailure();
    expect(g.status().state).toBe("unavailable");
    const release = ctl.holdFrom(201);
    const pa = g.annotate(key, "not_safety");
    await vi.waitFor(() => expect(ctl.calls()).toBeGreaterThanOrEqual(201));
    expect(store.getPersistFailure()).toBeNull();
    expect(g.status().state).toBe("replaying");
    expect(g.effectiveMode()).toBe("shadow");
    release();
    const s = await pa;
    expect(s.state).toBe("latched");
    expect(g.effectiveMode()).toBe("act");
  });
});

describe("GateController — fix round 2 (M4 ordering)", () => {
  it("shadow while the persist-failure marker removal is pending", async () => {
    const g = await latchedGate();
    const key = await makePersistFailure();
    let release!: () => void;
    const hold = new Promise<void>((r) => {
      release = r;
    });
    // Mirror AuditStore.clearPersistFailure: null the failure synchronously, then await the rm.
    const spy = vi.spyOn(store, "clearPersistFailure").mockImplementation(async () => {
      (store as unknown as { persistFailure: unknown }).persistFailure = null;
      await hold;
    });
    const pa = g.annotate(key, "not_safety");
    expect(store.getPersistFailure()).toBeNull();
    expect(g.effectiveMode()).toBe("shadow");
    expect(g.canAutoDeny()).toBe(false);
    release();
    const s = await pa;
    spy.mockRestore();
    expect(s.state).toBe("latched");
    expect(g.effectiveMode()).toBe("act");
  });

  it("rejecting clearPersistFailure leaves the gate in shadow and propagates", async () => {
    const g = await latchedGate();
    const key = await makePersistFailure();
    const spy = vi.spyOn(store, "clearPersistFailure").mockImplementation(async () => {
      (store as unknown as { persistFailure: unknown }).persistFailure = null;
      throw new Error("EPERM");
    });
    await expect(g.annotate(key, "not_safety")).rejects.toThrow("EPERM");
    spy.mockRestore();
    expect(g.effectiveMode()).toBe("shadow");
    expect(g.canAutoDeny()).toBe(false);
    expect(g.status().state).toBe("replaying");
  });
});
