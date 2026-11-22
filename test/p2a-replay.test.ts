import { mkdtemp, rm } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import type { PluginHookAgent } from "@getpaseo/plugin/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuditStore } from "../server/audit/store.js";
import { PermissionGuardianService } from "../server/guardian.js";
import { DEFAULT_GUARDIAN_SETTINGS } from "../shared/settings.js";
import type { AuditWindow } from "../server/audit/reader.js";
import {
  CONFIRMED_CANCELLATION_SIGNATURES,
  createReplayDecide,
  replayWindow,
  type ReplayDecide,
  type ReplayDecision,
} from "../server/gate/replay.js";
import { createIsolatedPwshHost, type PwshHostLike } from "../server/shell/pwsh-host.js";
import type { AuditRecord, AuditResolution, GuardianVerdict, RiskLevel } from "../shared/types.js";

const sharedHostCalls = vi.hoisted(() => ({ count: 0 }));
vi.mock("../server/shell/pwsh-host.js", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../server/shell/pwsh-host.js")>();
  return {
    ...orig,
    getSharedPwshHost: (...args: Parameters<typeof orig.getSharedPwshHost>) => {
      sharedHostCalls.count += 1;
      return orig.getSharedPwshHost(...args);
    },
  };
});

const T = "2026-11-20T12:00:00.000Z";

function rec(
  id: string,
  opts: {
    recorded?: GuardianVerdict | null;
    resolution?: Partial<AuditResolution> | null;
    snapshot?: boolean | "truncated";
    source?: string;
    noAction?: boolean;
  } = {},
): AuditRecord {
  const recorded = opts.recorded === undefined ? "ask" : opts.recorded;
  const r: AuditRecord = {
    version: 1,
    pluginVersion: "0",
    requestId: id,
    agentId: "a",
    provider: "claude",
    mode: "shadow",
    requestedAt: T,
    agreement: "pending",
  };
  if (!opts.noAction) {
    r.action = {
      provider: "claude",
      agentId: "a",
      requestId: id,
      kind: "exec",
      toolName: "Bash",
      host: { os: "darwin" },
      cwd: "/repo",
      exec: { shell: "bash", source: opts.source ?? `cmd-${id}` },
    };
  }
  if (recorded !== null) {
    r.decision = {
      level: recorded === "allow" ? "L0" : recorded === "deny" ? "L3" : "L1",
      verdict: recorded,
      reasons: [],
    };
  }
  if (opts.resolution !== null) {
    r.resolution = {
      behavior: "allow",
      resolvedAt: T,
      actor: "human",
      ...(opts.resolution ?? {}),
    };
  }
  const snap = opts.snapshot === undefined ? true : opts.snapshot;
  if (snap) {
    r.contextSnapshot = {
      secretTaint: false,
      untrustedTaint: false,
      modifiedEntrypoints: [],
      modifiedFiles: [],
      modifiedFilesTruncated: snap === "truncated",
    };
  }
  return r;
}

const DENY = { behavior: "deny" as const, selectedActionId: "deny_once" };
const DENY_NO_ID = { behavior: "deny" as const };

function win(records: AuditRecord[], extra: Partial<AuditWindow> = {}): AuditWindow {
  return { records, annotations: new Map(), corruptLines: [], truncated: false, ...extra };
}

type Scripted = ReplayDecision | { error: string } | "throw";
function fake(map: Record<string, Scripted>, fallback: Scripted = ok("allow")): ReplayDecide {
  return async (record) => {
    const s = map[record.requestId] ?? fallback;
    if (s === "throw") throw new Error("boom");
    return s;
  };
}
function ok(verdict: GuardianVerdict, level?: RiskLevel, reasons: string[] = [], effects: string[] = []): ReplayDecision {
  return {
    verdict,
    level: level ?? (verdict === "allow" ? "L0" : verdict === "deny" ? "L3" : "L1"),
    reasons,
    effects,
  };
}

const NO_SIGS = { cancellationSignatures: CONFIRMED_CANCELLATION_SIGNATURES };

describe("replayWindow — samples", () => {
  it("human allow + replay allow + snapshot ⇒ sample", async () => {
    const r = await replayWindow(win([rec("1")]), fake({ "1": ok("allow") }), NO_SIGS);
    expect(r.samples).toBe(1);
    expect(r.falseAllows).toEqual([]);
    expect(r.unavailableReason).toBeNull();
  });

  it("human allow + replay ask ⇒ not a sample", async () => {
    const r = await replayWindow(win([rec("1")]), fake({ "1": ok("ask") }), NO_SIGS);
    expect(r.samples).toBe(0);
  });

  it("legacy (no snapshot) recorded ask + replay allow + human allow ⇒ not a sample", async () => {
    const r = await replayWindow(
      win([rec("1", { snapshot: false, recorded: "ask" })]),
      fake({ "1": ok("allow") }),
      NO_SIGS,
    );
    expect(r.samples).toBe(0);
  });

  it("legacy (no snapshot) recorded allow + replay allow + human allow ⇒ sample", async () => {
    const r = await replayWindow(
      win([rec("1", { snapshot: false, recorded: "allow" })]),
      fake({ "1": ok("allow") }),
      NO_SIGS,
    );
    expect(r.samples).toBe(1);
  });

  it("truncated snapshot is treated as no snapshot", async () => {
    const r = await replayWindow(
      win([
        rec("1", { snapshot: "truncated", recorded: "ask" }),
        rec("2", { snapshot: "truncated", recorded: "allow" }),
      ]),
      fake({}),
      NO_SIGS,
    );
    expect(r.samples).toBe(1);
  });

  it("plugin-actor records are ignored entirely", async () => {
    const r = await replayWindow(
      win([
        rec("1", { resolution: { actor: "plugin" } }),
        rec("2", { resolution: { ...DENY, actor: "plugin" } }),
      ]),
      fake({ "1": ok("allow"), "2": ok("allow") }),
      NO_SIGS,
    );
    expect(r).toMatchObject({ samples: 0, falseAllows: [], falseDenyCount: 0, skippedAllow: 0 });
    expect(r.unavailableReason).toBeNull();
  });

  it("pending records (no resolution) are ignored", async () => {
    const decide = vi.fn(fake({}));
    const r = await replayWindow(win([rec("1", { resolution: null })]), decide, NO_SIGS);
    expect(r.samples).toBe(0);
    expect(decide).not.toHaveBeenCalled();
  });

  it("skipped human allow (decide error or throw) only counts as skippedAllow", async () => {
    const r = await replayWindow(
      win([rec("1"), rec("2")]),
      fake({ "1": { error: "no_action" }, "2": "throw" }),
      NO_SIGS,
    );
    expect(r).toMatchObject({ samples: 0, skippedAllow: 2, unavailableReason: null });
  });
});

describe("replayWindow — false-allows", () => {
  it("human deny + replay allow ⇒ false-allow entry with command and effects", async () => {
    const r = await replayWindow(
      win([rec("1", { resolution: DENY, recorded: "allow", source: "rm -rf x" })]),
      fake({ "1": ok("allow", "L0", [], ["write_worktree", "read:foo"]) }),
      NO_SIGS,
    );
    expect(r.falseAllows).toEqual([
      {
        requestId: "1",
        requestedAt: T,
        command: "rm -rf x",
        effects: ["write_worktree", "read:foo"],
        kind: "false_allow",
        key: "1",
      },
    ]);
    expect(r.samples).toBe(0);
  });

  it("human deny + replay ask ⇒ not a false-allow", async () => {
    const r = await replayWindow(win([rec("1", { resolution: DENY })]), fake({ "1": ok("ask") }), NO_SIGS);
    expect(r.falseAllows).toEqual([]);
    expect(r.unavailableReason).toBeNull();
  });

  it("legacy recorded ask + replay allow + human deny ⇒ false-allow (replay verdict alone)", async () => {
    const r = await replayWindow(
      win([rec("1", { resolution: DENY, recorded: "ask", snapshot: false })]),
      fake({ "1": ok("allow") }),
      NO_SIGS,
    );
    expect(r.falseAllows.map((e) => e.requestId)).toEqual(["1"]);
  });

  it("annotated false-allow is excluded", async () => {
    const r = await replayWindow(
      win([rec("1", { resolution: DENY })], { annotations: new Map([["1", "not_safety"]]) }),
      fake({ "1": ok("allow") }),
      NO_SIGS,
    );
    expect(r.falseAllows).toEqual([]);
  });

  it("deny without selectedActionId counts as human denial while signatures list is empty", async () => {
    expect(CONFIRMED_CANCELLATION_SIGNATURES).toEqual([]);
    const r = await replayWindow(
      win([rec("1", { resolution: DENY_NO_ID })]),
      fake({ "1": ok("allow") }),
      NO_SIGS,
    );
    expect(r.falseAllows.map((e) => e.requestId)).toEqual(["1"]);
  });

  it("deny with actor unknown counts as human denial", async () => {
    const r = await replayWindow(
      win([rec("1", { resolution: { ...DENY, actor: "unknown" } })]),
      fake({ "1": ok("allow") }),
      NO_SIGS,
    );
    expect(r.falseAllows.map((e) => e.requestId)).toEqual(["1"]);
  });

  it("a matching cancellation signature excludes the denial", async () => {
    const sig = vi.fn((res: AuditResolution) => res.behavior === "deny" && res.selectedActionId === undefined);
    const r = await replayWindow(
      win([rec("1", { resolution: DENY_NO_ID }), rec("2", { resolution: DENY })]),
      fake({}),
      { cancellationSignatures: [sig] },
    );
    expect(r.falseAllows.map((e) => e.requestId)).toEqual(["2"]);
    expect(sig).toHaveBeenCalled();
  });

  it("command is truncated to 200 chars", async () => {
    const r = await replayWindow(
      win([rec("1", { resolution: DENY, source: "x".repeat(500) })]),
      fake({}),
      NO_SIGS,
    );
    expect(r.falseAllows[0]!.command).toHaveLength(200);
  });
});

describe("replayWindow — false-denies", () => {
  it("replay L3 + human allow ⇒ false-deny (even when verdict mapped to ask)", async () => {
    const r = await replayWindow(
      win([rec("1"), rec("2")]),
      fake({ "1": ok("ask", "L3"), "2": ok("deny", "L3") }),
      NO_SIGS,
    );
    expect(r.falseDenyCount).toBe(2);
  });

  it("replay L2 + human allow ⇒ not a false-deny; L3 + human deny ⇒ not a false-deny", async () => {
    const r = await replayWindow(
      win([rec("1"), rec("2", { resolution: DENY })]),
      fake({ "1": ok("ask", "L2"), "2": ok("deny", "L3") }),
      NO_SIGS,
    );
    expect(r.falseDenyCount).toBe(0);
  });
});

describe("replayWindow — integrity and unavailability", () => {
  it("truncated window ⇒ replay_truncated", async () => {
    const r = await replayWindow(win([rec("1")], { truncated: true }), fake({}), NO_SIGS);
    expect(r.unavailableReason).toBe("replay_truncated");
  });

  it("unannotated corrupt line ⇒ corrupt_audit_line + integrity entry", async () => {
    const r = await replayWindow(
      win([], { corruptLines: [{ key: "audit-2026-11-20.jsonl#abc", file: "audit-2026-11-20.jsonl" }] }),
      fake({}),
      NO_SIGS,
    );
    expect(r.unavailableReason).toBe("corrupt_audit_line");
    expect(r.integrity).toEqual([
      { requestId: "", effects: [], kind: "corrupt_line", key: "audit-2026-11-20.jsonl#abc" },
    ]);
  });

  it("annotated corrupt line is excluded", async () => {
    const key = "audit-2026-11-20.jsonl#abc";
    const r = await replayWindow(
      win([], {
        corruptLines: [{ key, file: "audit-2026-11-20.jsonl" }],
        annotations: new Map([[key, "not_safety"]]),
      }),
      fake({}),
      NO_SIGS,
    );
    expect(r.unavailableReason).toBeNull();
    expect(r.integrity).toEqual([]);
  });

  it("orphan human denial (deny, no decision) ⇒ orphan_human_deny + integrity entry, not replayed", async () => {
    const decide = vi.fn(fake({}));
    const r = await replayWindow(
      win([rec("1", { resolution: DENY, recorded: null, source: "curl x" })]),
      decide,
      NO_SIGS,
    );
    expect(r.unavailableReason).toBe("orphan_human_deny");
    expect(r.integrity).toEqual([
      { requestId: "1", requestedAt: T, command: "curl x", effects: [], kind: "orphan_deny", key: "1" },
    ]);
    expect(r.falseAllows).toEqual([]);
    expect(decide).not.toHaveBeenCalled();
  });

  it("annotated orphan human denial is excluded", async () => {
    const r = await replayWindow(
      win([rec("1", { resolution: DENY, recorded: null })], { annotations: new Map([["1", "not_safety"]]) }),
      fake({}),
      NO_SIGS,
    );
    expect(r.unavailableReason).toBeNull();
    expect(r.integrity).toEqual([]);
  });

  it("orphan human allow and plugin orphan deny do not make the gate unavailable", async () => {
    const r = await replayWindow(
      win([
        rec("1", { recorded: null }),
        rec("2", { recorded: null, resolution: { ...DENY, actor: "plugin" } }),
      ]),
      fake({}),
      NO_SIGS,
    );
    expect(r.unavailableReason).toBeNull();
    expect(r.samples).toBe(0);
  });

  it("human denial whose replay errored or threw ⇒ human_deny_unevaluable", async () => {
    for (const s of [{ error: "no_action" }, "throw"] as Scripted[]) {
      const r = await replayWindow(win([rec("1", { resolution: DENY })]), fake({ "1": s }), NO_SIGS);
      expect(r.unavailableReason).toBe("human_deny_unevaluable");
    }
  });

  it("human denial with an opaque:pwsh_host_* reason ⇒ human_deny_unevaluable", async () => {
    for (const reason of ["opaque:pwsh_host_timeout", "opaque:pwsh_host_circuit_open", "opaque:pwsh_host_unavailable"]) {
      const r = await replayWindow(
        win([rec("1", { resolution: DENY })]),
        fake({ "1": ok("ask", "L1", ["x", reason]) }),
        NO_SIGS,
      );
      expect(r.unavailableReason).toBe("human_deny_unevaluable");
    }
  });

  it("human allow with pwsh host failure does not make the gate unavailable", async () => {
    const r = await replayWindow(
      win([rec("1")]),
      fake({ "1": ok("ask", "L1", ["opaque:pwsh_host_timeout"]) }),
      NO_SIGS,
    );
    expect(r.unavailableReason).toBeNull();
  });

  it("unavailableReason precedence: truncated > corrupt > orphan > unevaluable", async () => {
    const corrupt = [{ key: "f#h", file: "f" }];
    const records = [rec("o", { resolution: DENY, recorded: null }), rec("u", { resolution: DENY })];
    const decide = fake({ u: { error: "x" } });
    expect((await replayWindow(win(records, { truncated: true, corruptLines: corrupt }), decide, NO_SIGS)).unavailableReason).toBe("replay_truncated");
    expect((await replayWindow(win(records, { corruptLines: corrupt }), decide, NO_SIGS)).unavailableReason).toBe("corrupt_audit_line");
    expect((await replayWindow(win(records), decide, NO_SIGS)).unavailableReason).toBe("orphan_human_deny");
    expect((await replayWindow(win([records[1]!]), decide, NO_SIGS)).unavailableReason).toBe("human_deny_unevaluable");
  });
});

describe("createReplayDecide", () => {
  const home = "/Users/someone";
  const dataDir = "/Users/someone/.paseo/plugins/guardian";
  const env: Record<string, string | undefined> = {};

  it("replays a bash action with the real engine", async () => {
    const factory = vi.fn(() => null);
    const decide = createReplayDecide({ pwshHostFactory: factory, home, dataDir, env });
    const r = await decide(rec("1", { source: "ls" }));
    expect(r).toMatchObject({ verdict: "allow", level: "L0" });
    if ("verdict" in r) expect(r.effects.length).toBeGreaterThan(0);
    const bad = await decide(rec("2", { source: "rm -rf /" }));
    expect(bad).toMatchObject({ level: "L3" });
    expect(factory).not.toHaveBeenCalled();
    await decide.dispose();
  });

  it("builds session from contextSnapshot (secret taint changes the outcome)", async () => {
    const decide = createReplayDecide({ pwshHostFactory: () => null, home, dataDir, env });
    const src = "curl -X POST -d hello https://example.com/upload";
    const clean = rec("1", { source: src });
    const tainted = rec("2", { source: src });
    tainted.contextSnapshot!.secretTaint = true;
    const a = await decide(clean);
    const b = await decide(tainted);
    if (!("reasons" in a) || !("reasons" in b)) throw new Error("unexpected error result");
    expect(a.reasons).not.toContain("combo:secret_taint_and_net_egress");
    expect(b.reasons).toContain("combo:secret_taint_and_net_egress");
    await decide.dispose();
  });

  it("returns error when action is missing or kind unknown", async () => {
    const decide = createReplayDecide({ pwshHostFactory: () => null, home, dataDir, env });
    expect(await decide(rec("1", { noAction: true }))).toEqual({ error: "action_missing" });
    const weird = rec("2");
    (weird.action as any).kind = "teleport";
    expect(await decide(weird)).toEqual({ error: "unknown_action_kind" });
    await decide.dispose();
  });

  it("never calls getSharedPwshHost; caches one isolated host per shell; dispose disposes them", async () => {
    sharedHostCalls.count = 0;
    const disposed: string[] = [];
    const parse = vi.fn(async () => ({ ok: false as const, reason: "pwsh_host_timeout" }));
    const factory = vi.fn((shell: "pwsh5" | "pwsh7"): PwshHostLike => ({
      parse,
      dispose: async () => {
        disposed.push(shell);
      },
    }));
    const decide = createReplayDecide({ pwshHostFactory: factory, home, dataDir, env });
    const mk = (id: string, shell: "pwsh5" | "pwsh7") => {
      const r = rec(id, { source: "Get-ChildItem" });
      r.action!.host = { os: "windows" };
      r.action!.cwd = "C:\\repo";
      r.action!.exec = { shell, source: "Get-ChildItem" };
      return r;
    };
    const r1 = await decide(mk("1", "pwsh7"));
    await decide(mk("2", "pwsh7"));
    await decide(mk("3", "pwsh5"));
    expect(sharedHostCalls.count).toBe(0);
    expect(factory).toHaveBeenCalledTimes(2);
    expect(parse).toHaveBeenCalledTimes(3);
    expect("reasons" in r1 && r1.reasons.some((x) => x.startsWith("opaque:pwsh_host_"))).toBe(true);
    await decide.dispose();
    expect(disposed.sort()).toEqual(["pwsh5", "pwsh7"]);
  });
});

describe("createIsolatedPwshHost", () => {
  it("returns a fresh unshared host per call, or null without a verified binary", async () => {
    sharedHostCalls.count = 0;
    expect(createIsolatedPwshHost("pwsh7", { binaryPath: "/nonexistent/pwsh" })).toBeNull();
    const a = createIsolatedPwshHost("pwsh7", { binaryPath: process.execPath });
    const b = createIsolatedPwshHost("pwsh7", { binaryPath: process.execPath });
    expect(a).not.toBeNull();
    expect(a).not.toBe(b);
    expect(sharedHostCalls.count).toBe(0);
    await a!.dispose();
    await b!.dispose();
  });
});

describe("replay shares the live decide context (R5)", () => {
  const home = "/Users/someone";
  const dataDir = "/Users/someone/.paseo/plugins/guardian";

  async function sampleCount(record: AuditRecord, env: Record<string, string | undefined>) {
    const decide = createReplayDecide({ pwshHostFactory: () => null, home, dataDir, env });
    try {
      return (await replayWindow(win([record]), decide, NO_SIGS)).samples;
    } finally {
      await decide.dispose();
    }
  }

  it("with CDPATH set, a human-allowed `cd src && touch foo.txt` is NOT a sample", async () => {
    const r = rec("1", { source: "cd src && touch foo.txt", recorded: "allow" });
    expect(await sampleCount(r, {})).toBe(1);
    expect(await sampleCount(r, { CDPATH: "/elsewhere" })).toBe(0);
  });

  it("with PASEO_HOME covering the target, a human-allowed write is NOT a sample", async () => {
    const r = rec("1", { source: "echo hi > /repo/.ph/config.json", recorded: "allow" });
    expect(await sampleCount(r, {})).toBe(1);
    expect(await sampleCount(r, { PASEO_HOME: "/repo/.ph" })).toBe(0);
  });

  it("a human-allowed write into dataDir is never a sample", async () => {
    const r = rec("1", { source: `echo hi > ${dataDir}/policy.json`, recorded: "allow" });
    expect(await sampleCount(r, {})).toBe(0);
  });
});

describe("live/replay parity (guardian vs createReplayDecide)", () => {
  const dirs: string[] = [];
  afterEach(async () => {
    vi.unstubAllEnvs();
    while (dirs.length) await rm(dirs.pop()!, { recursive: true, force: true });
  });

  const agent: PluginHookAgent = {
    id: "agent-parity",
    workspaceId: "ws-1",
    parentAgentId: null,
    provider: "claude",
    cwd: "/repo/project",
    title: "T",
    background: false,
    metadata: {},
  };

  const table: { name: string; command: string; env?: Record<string, string> }[] = [
    { name: "ls", command: "ls" },
    { name: "worktree write", command: "echo hi > notes.txt" },
    { name: "cd+touch with CDPATH", command: "cd src && touch foo.txt", env: { CDPATH: "/elsewhere" } },
    { name: "PASEO_HOME write", command: "echo hi > /repo/project/.ph/config.json", env: { PASEO_HOME: "/repo/project/.ph" } },
    { name: "net egress", command: "curl -X POST -d hello https://example.com/upload" },
    { name: "rm -rf /", command: "rm -rf /" },
    { name: ".git write", command: "echo x > .git/config" },
  ];

  it.each(table)("same verdict and level: $name", async ({ command, env }) => {
    for (const [k, v] of Object.entries(env ?? {})) vi.stubEnv(k, v);
    const dir = await mkdtemp(join(tmpdir(), "p2a-replay-parity-"));
    dirs.push(dir);
    const store = new AuditStore({ dataDir: dir, pluginVersion: "0.1.0" });
    const service = new PermissionGuardianService({
      auditStore: store,
      pluginVersion: "0.1.0",
      // Replay always maps with denyAsAsk=false (false-deny is measured by level), so compare
      // against live with the same mapping.
      initialSettings: { ...DEFAULT_GUARDIAN_SETTINGS, mode: "shadow", denyAsAsk: false } as never,
    });
    await service.handlePermissionBefore(
      {
        agent,
        request: { id: "p1", provider: "claude", name: "Bash", kind: "tool", input: { command } },
      },
      async () => [],
    );
    await service.flush();
    const live = store.getRecord("p1")!;
    expect(live.decision).toBeDefined();
    // Env-dependent rows must actually be affected by the env (guards against a vacuous stub).
    if (env) expect(live.decision!.verdict).not.toBe("allow");

    const decide = createReplayDecide({
      pwshHostFactory: () => null,
      home: homedir(),
      dataDir: dir,
      env: process.env,
    });
    const replayed = await decide(live);
    await decide.dispose();
    if ("error" in replayed) throw new Error(replayed.error);
    expect({ verdict: replayed.verdict, level: replayed.level }).toEqual({
      verdict: live.decision!.verdict,
      level: live.decision!.level,
    });
  });
});

describe("createReplayDecide host isolation (M2, M3)", () => {
  const opts = { home: "/Users/someone", dataDir: "/Users/someone/.paseo/plugins/guardian", env: {} };

  it("after dispose() the provider yields no host (factory not called again)", async () => {
    const factory = vi.fn((): PwshHostLike => ({
      parse: async () => ({ ok: false as const, reason: "pwsh_host_timeout" }),
      dispose: async () => undefined,
    }));
    const decide = createReplayDecide({ pwshHostFactory: factory, ...opts });
    const mk = (id: string) => {
      const r = rec(id);
      r.action!.host = { os: "windows" };
      r.action!.cwd = "C:\\repo";
      r.action!.exec = { shell: "pwsh7", source: "Get-ChildItem" };
      return r;
    };
    await decide(mk("1"));
    expect(factory).toHaveBeenCalledTimes(1);
    await decide.dispose();
    const after = await decide(mk("2"));
    expect(factory).toHaveBeenCalledTimes(1);
    if ("error" in after) throw new Error(after.error);
    expect(after.reasons).toContain("opaque:pwsh_host_unavailable");
  });

  it("nested pwsh layer (bash wrapping `pwsh -c ...`) uses the factory, not getSharedPwshHost", async () => {
    sharedHostCalls.count = 0;
    const parse = vi.fn(async () => ({ ok: false as const, reason: "pwsh_host_timeout" }));
    const factory = vi.fn((): PwshHostLike => ({ parse, dispose: async () => undefined }));
    const decide = createReplayDecide({ pwshHostFactory: factory, ...opts });
    const r = await decide(rec("1", { source: "pwsh -c 'Get-ChildItem'" }));
    await decide.dispose();
    expect(sharedHostCalls.count).toBe(0);
    expect(factory).toHaveBeenCalled();
    expect(parse).toHaveBeenCalled();
    if ("error" in r) throw new Error(r.error);
    expect(r.reasons.some((x) => x.startsWith("opaque:pwsh_host_"))).toBe(true);
  });
});

describe("replayWindow — R10 actOutcome exclusion", () => {
  const withOutcome = (id: string, outcome: string | undefined, res: Partial<AuditResolution> = {}) => {
    const r = rec(id, { resolution: res });
    if (outcome !== undefined) (r as { actOutcome?: string }).actOutcome = outcome;
    return r;
  };

  it.each(["unconfirmed", "lost_race"])("human allow with actOutcome %s is not a sample", async (o) => {
    const r = await replayWindow(win([withOutcome("1", o)]), fake({ "1": ok("allow") }), NO_SIGS);
    expect(r.samples).toBe(0);
  });

  it.each(["answered", undefined])("human allow with actOutcome %s still counts", async (o) => {
    const r = await replayWindow(win([withOutcome("1", o)]), fake({ "1": ok("allow") }), NO_SIGS);
    expect(r.samples).toBe(1);
  });

  it("human deny with unconfirmed outcome still yields a false-allow", async () => {
    const r = await replayWindow(
      win([withOutcome("1", "unconfirmed", { behavior: "deny", selectedActionId: "deny_once" })]),
      fake({ "1": ok("allow") }),
      NO_SIGS,
    );
    expect(r.falseAllows).toHaveLength(1);
  });
});
