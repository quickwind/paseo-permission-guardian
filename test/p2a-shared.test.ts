import { describe, expect, it } from "vitest";
import { GuardianSettingsSchema } from "../shared/settings.js";
import { GateStatusSchema, gateAnnotate, gateReplay, getGuardianStatus } from "../shared/rpc.js";
import { emptyGateStatus } from "../shared/types.js";

describe("p2a shared settings", () => {
  it("defaults", () => {
    const s = GuardianSettingsSchema.parse({});
    expect(s.actGate.minSamples).toBe(200);
    expect(s.actGate.windowDays).toBe(30);
    expect(s.actGate.autoFallbackOnFalseAllow).toBe(true);
    expect(s.actGate.allowOverride).toBe(true);
    expect(s.actOverride.accepted).toBe(false);
    expect(s.actOverride.acceptedAt).toBeNull();
    expect(s.actOverride.fingerprint).toBeNull();
  });
  it("bounds", () => {
    const p = (actGate: object) => GuardianSettingsSchema.safeParse({ actGate }).success;
    expect(p({ minSamples: 19 })).toBe(false);
    expect(p({ minSamples: 20 })).toBe(true);
    expect(p({ minSamples: 5001 })).toBe(false);
    expect(p({ windowDays: 0 })).toBe(false);
    expect(p({ windowDays: 366 })).toBe(false);
    expect(p({ windowDays: 365 })).toBe(true);
  });
  it("legacy stored v1 settings still parse", () => {
    const s = GuardianSettingsSchema.parse({ mode: "act", denyAsAsk: false });
    expect(s.mode).toBe("act");
    expect(s.actGate.minSamples).toBe(200);
  });
});

describe("p2a shared rpc", () => {
  it("emptyGateStatus satisfies GateStatusSchema", () => {
    expect(GateStatusSchema.parse(emptyGateStatus())).toEqual(emptyGateStatus());
  });
  it("status output accepts act effectiveMode and gate", () => {
    const out = getGuardianStatus.output;
    const base = {
      pluginVersion: "x", mode: "act", effectiveMode: "act", dataDir: "/d",
      metrics: {
        totalRequests: 0, reconciledCount: 0, pendingCount: 0, wouldAllowCount: 0,
        wouldAskCount: 0, wouldDenyCount: 0, humanAllowCount: 0, humanDenyCount: 0,
        falseAllowCount: 0, falseDenyCount: 0, agreementCount: 0, outOfOrderCount: 0,
        lastUpdatedAt: null,
      },
      gate: emptyGateStatus(),
    };
    expect(out.safeParse(base).success).toBe(true);
  });
  it("annotate input", () => {
    expect(gateAnnotate.input.safeParse({ key: "r1", annotation: "not_safety" }).success).toBe(true);
    expect(gateAnnotate.input.safeParse({ key: "r1", annotation: null }).success).toBe(true);
    expect(gateAnnotate.input.safeParse({ key: "r1", annotation: "x" }).success).toBe(false);
    expect(gateReplay.input.safeParse({}).success).toBe(true);
  });
});

describe("F9 unevaluable_deny entry kind", () => {
  it("GateStatusSchema accepts an unevaluable_deny entry", async () => {
    const { GateStatusSchema: S } = await import("../shared/rpc.js");
    const st = { ...emptyGateStatus(), entries: [{ requestId: "r", effects: [], kind: "unevaluable_deny", key: "r" }] };
    expect(S.safeParse(st).success).toBe(true);
  });
});
