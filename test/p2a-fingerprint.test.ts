import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ENGINE_DATA_VERSION, computeFingerprint } from "../server/gate/fingerprint.js";
import { type GateStateFile, readGateState, writeGateState } from "../server/gate/state-file.js";

const dirs: string[] = [];
async function tmp(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "p2a-fingerprint-"));
  dirs.push(d);
  return d;
}
afterEach(async () => {
  while (dirs.length) await rm(dirs.pop()!, { recursive: true, force: true });
});

const base = {
  pluginVersion: "0.1.0",
  policyHash: "abc123",
  denyAsAsk: false,
  windowsDefaultShell: "powershell",
};

describe("computeFingerprint", () => {
  it("exposes ENGINE_DATA_VERSION = 1", () => {
    expect(ENGINE_DATA_VERSION).toBe(1);
  });

  it("is a 64-char lowercase sha256 hex digest", () => {
    expect(computeFingerprint(base)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is stable for equal input", () => {
    expect(computeFingerprint({ ...base })).toBe(computeFingerprint({ ...base }));
  });

  it("does not depend on object key order", () => {
    const reordered = {
      windowsDefaultShell: "powershell",
      denyAsAsk: false,
      policyHash: "abc123",
      pluginVersion: "0.1.0",
    };
    expect(computeFingerprint(reordered)).toBe(computeFingerprint(base));
  });

  it("changes when pluginVersion changes", () => {
    expect(computeFingerprint({ ...base, pluginVersion: "0.2.0" })).not.toBe(
      computeFingerprint(base),
    );
  });

  it("changes when policyHash changes", () => {
    expect(computeFingerprint({ ...base, policyHash: "def456" })).not.toBe(
      computeFingerprint(base),
    );
  });

  it("changes when denyAsAsk changes", () => {
    expect(computeFingerprint({ ...base, denyAsAsk: true })).not.toBe(computeFingerprint(base));
  });

  it("changes when windowsDefaultShell changes", () => {
    expect(computeFingerprint({ ...base, windowsDefaultShell: "cmd" })).not.toBe(
      computeFingerprint(base),
    );
  });

  it("treats null policyHash the same as the builtin marker", () => {
    expect(computeFingerprint({ ...base, policyHash: null })).toBe(
      computeFingerprint({ ...base, policyHash: "builtin" }),
    );
  });

  it("treats undefined policyHash the same as the builtin marker", () => {
    const { policyHash: _omit, ...rest } = base;
    expect(computeFingerprint(rest)).toBe(computeFingerprint({ ...base, policyHash: "builtin" }));
  });
});

const sample: GateStateFile = {
  version: 1,
  latched: true,
  fingerprint: "f".repeat(64),
  minSamplesAtLatch: 25,
  latchedAt: "2026-11-22T10:00:00.000Z",
  suspendedBy: ["drift", "manual"],
  lastReplay: null,
};

describe("readGateState / writeGateState", () => {
  it("returns null when the file is missing", async () => {
    expect(await readGateState(await tmp())).toBeNull();
  });

  it("round-trips a valid file", async () => {
    const dir = await tmp();
    await writeGateState(dir, sample);
    expect(await readGateState(dir)).toEqual(sample);
  });

  it("writes gate-state.json in dataDir, creating the directory if needed", async () => {
    const dir = join(await tmp(), "nested", "data");
    await writeGateState(dir, sample);
    const raw = JSON.parse(await readFile(join(dir, "gate-state.json"), "utf8"));
    expect(raw).toEqual(sample);
  });

  it("leaves no tmp file behind after a write", async () => {
    const dir = await tmp();
    await writeGateState(dir, sample);
    const { readdir } = await import("node:fs/promises");
    const names = await readdir(dir);
    expect(names.filter((n) => n.includes(".tmp"))).toEqual([]);
  });

  it("returns null for garbage (non-JSON) content", async () => {
    const dir = await tmp();
    await writeFile(join(dir, "gate-state.json"), "not json {{{", "utf8");
    expect(await readGateState(dir)).toBeNull();
  });

  it("returns null for an unknown version", async () => {
    const dir = await tmp();
    await writeFile(
      join(dir, "gate-state.json"),
      JSON.stringify({ ...sample, version: 2 }),
      "utf8",
    );
    expect(await readGateState(dir)).toBeNull();
  });

  it("returns null when fingerprint is missing", async () => {
    const dir = await tmp();
    const { fingerprint: _omit, ...rest } = sample;
    await writeFile(join(dir, "gate-state.json"), JSON.stringify(rest), "utf8");
    expect(await readGateState(dir)).toBeNull();
  });

  it("returns null when a field has the wrong type", async () => {
    const dir = await tmp();
    await writeFile(
      join(dir, "gate-state.json"),
      JSON.stringify({ ...sample, latched: "yes" }),
      "utf8",
    );
    expect(await readGateState(dir)).toBeNull();
  });

  it("returns null when minSamplesAtLatch is not a number", async () => {
    const dir = await tmp();
    await writeFile(
      join(dir, "gate-state.json"),
      JSON.stringify({ ...sample, minSamplesAtLatch: "25" }),
      "utf8",
    );
    expect(await readGateState(dir)).toBeNull();
  });

  it("returns null when suspendedBy is not an array of strings", async () => {
    const dir = await tmp();
    await writeFile(
      join(dir, "gate-state.json"),
      JSON.stringify({ ...sample, suspendedBy: [1, 2] }),
      "utf8",
    );
    expect(await readGateState(dir)).toBeNull();
  });

  it("returns null when latchedAt is neither string nor null", async () => {
    const dir = await tmp();
    await writeFile(
      join(dir, "gate-state.json"),
      JSON.stringify({ ...sample, latchedAt: 12 }),
      "utf8",
    );
    expect(await readGateState(dir)).toBeNull();
  });
});
