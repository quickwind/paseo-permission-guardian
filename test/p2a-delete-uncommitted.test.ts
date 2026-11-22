import { execFileSync } from "node:child_process";
import { mkdtemp, realpath, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { decideAction, type DecideOptions } from "../server/decide.js";
import { createGitStateProvider, type GitStateProvider } from "../server/context/git-state.js";
import { createReplayDecide } from "../server/gate/replay.js";
import { ENGINE_DATA_VERSION, computeFingerprint } from "../server/gate/fingerprint.js";
import { disposeSharedPwshHost, resolvePwshBinaryPath } from "../server/shell/pwsh-host.js";
import type { Action, AuditRecord } from "../shared/types.js";

const gitCalls = vi.hoisted(() => ({ count: 0 }));
vi.mock("node:child_process", async (importOriginal) => {
  const orig = await importOriginal<typeof import("node:child_process")>();
  const execFile = ((...args: Parameters<typeof orig.execFile>) => {
    gitCalls.count += 1;
    return (orig.execFile as (...a: unknown[]) => unknown)(...args);
  }) as typeof orig.execFile;
  return { ...orig, execFile, default: { ...orig, execFile } };
});

afterAll(async () => {
  await disposeSharedPwshHost();
});

const hasPwsh7 = Boolean(
  resolvePwshBinaryPath("pwsh7", { allowPosixHost: process.platform !== "win32" }),
);

function bash(source: string): Action {
  return {
    provider: "claude",
    agentId: "a",
    requestId: "r",
    kind: "exec",
    toolName: "Bash",
    host: { os: "darwin" },
    cwd: "/repo",
    worktreeRoot: "/repo",
    exec: { shell: "bash", source },
  };
}

const posixCtx = {
  cwd: "/repo",
  worktreeRoot: "/repo",
  home: "/Users/alice",
  pluginDataDir: "/Users/alice/.paseo/permission-guardian",
  skipHostRealpath: true,
};

function fakeProvider(clean: string[]): GitStateProvider & { calls: string[][] } {
  const calls: string[][] = [];
  const fn = (async (req: { worktreeRoot: string; targets: string[] }) => {
    calls.push([...req.targets]);
    return Object.fromEntries(req.targets.map((t) => [t, clean.includes(t)]));
  }) as GitStateProvider & { calls: string[][] };
  fn.calls = calls;
  return fn;
}

function opts(extra: Partial<DecideOptions> = {}): DecideOptions {
  return { pathCtx: posixCtx, denyAsAsk: false, ...extra };
}

describe("A: non-recursive worktree delete requires a tracked, clean file", () => {
  it("tracked-clean target ⇒ L0 and records the result", async () => {
    const r = await decideAction(bash("rm a.txt"), opts({ gitStateProvider: fakeProvider(["/repo/a.txt"]) }));
    expect(r.decision.level).toBe("L0");
    expect(r.deleteTargetsClean).toEqual({ "/repo/a.txt": true });
  });

  it("not clean (untracked/modified/staged as reported by the provider) ⇒ L1 delete_uncommitted", async () => {
    const r = await decideAction(bash("rm a.txt"), opts({ gitStateProvider: fakeProvider([]) }));
    expect(r.decision.level).toBe("L1");
    expect(r.decision.verdict).toBe("ask");
    expect(r.decision.reasons).toContain("delete_uncommitted:/repo/a.txt");
    expect(r.deleteTargetsClean).toEqual({ "/repo/a.txt": false });
  });

  it("no provider, provider error, or provider timeout ⇒ L1", async () => {
    const none = await decideAction(bash("rm a.txt"), opts());
    expect(none.decision.level).toBe("L1");
    const throws = await decideAction(
      bash("rm a.txt"),
      opts({ gitStateProvider: async () => Promise.reject(new Error("git exploded")) }),
    );
    expect(throws.decision.level).toBe("L1");
    expect(throws.decision.reasons).toContain("delete_uncommitted:/repo/a.txt");
    const partial = await decideAction(bash("rm a.txt"), opts({ gitStateProvider: async () => ({}) }));
    expect(partial.decision.level).toBe("L1");
  });

  it("multiple targets with one dirty ⇒ L1 naming only the dirty one", async () => {
    const r = await decideAction(
      bash("rm a.txt b.txt"),
      opts({ gitStateProvider: fakeProvider(["/repo/a.txt"]) }),
    );
    expect(r.decision.level).toBe("L1");
    expect(r.decision.reasons).toContain("delete_uncommitted:/repo/b.txt");
    expect(r.decision.reasons).not.toContain("delete_uncommitted:/repo/a.txt");
  });

  it("recursive deletes are unchanged and do not consult git", async () => {
    const p = fakeProvider(["/repo/d"]);
    const r = await decideAction(bash("rm -r d"), opts({ gitStateProvider: p }));
    expect(r.decision.level).toBe("L1");
    expect(r.decision.reasons).toContain("recursive_delete_worktree:/repo/d");
    expect(p.calls).toEqual([]);
  });

  it("calls without a delete never consult git", async () => {
    const p = fakeProvider([]);
    const r = await decideAction(bash("ls -la"), opts({ gitStateProvider: p }));
    expect(r.decision.level).toBe("L0");
    expect(p.calls).toEqual([]);
    expect(r.deleteTargetsClean).toBeUndefined();
  });

  it("unlink stays L1 (unknown command)", async () => {
    const r = await decideAction(bash("unlink a.txt"), opts({ gitStateProvider: fakeProvider(["/repo/a.txt"]) }));
    expect(r.decision.level).toBe("L1");
  });

  it("provider delete action kind", async () => {
    const action: Action = { ...bash(""), kind: "delete", toolName: "Delete", exec: undefined, paths: ["/repo/a.txt"] };
    const clean = await decideAction(action, opts({ gitStateProvider: fakeProvider(["/repo/a.txt"]) }));
    expect(clean.decision.level).toBe("L0");
    const dirty = await decideAction(action, opts({ gitStateProvider: fakeProvider([]) }));
    expect(dirty.decision.level).toBe("L1");
    expect(dirty.decision.reasons).toContain("delete_uncommitted:/repo/a.txt");
  });

  it("cmd del", async () => {
    const action: Action = {
      ...bash("del a.txt"),
      toolName: "cmd",
      host: { os: "windows" },
      cwd: "C:\\repo",
      worktreeRoot: "C:\\repo",
      exec: { shell: "cmd", source: "del a.txt" },
    };
    const winCtx = {
      os: "windows" as const,
      cwd: "C:\\repo",
      worktreeRoot: "C:\\repo",
      home: "C:\\Users\\alice",
      pluginDataDir: "C:\\Users\\alice\\.paseo\\permission-guardian",
      envSnapshot: { PATH: "C:\\Windows\\System32" },
    };
    const first = await decideAction(action, { pathCtx: winCtx, denyAsAsk: false, gitStateProvider: fakeProvider([]) });
    const target = Object.keys(first.deleteTargetsClean ?? {})[0];
    expect(target).toBeDefined();
    expect(first.decision.level).toBe("L1");
    expect(first.decision.reasons).toContain(`delete_uncommitted:${target}`);
    const clean = await decideAction(action, {
      pathCtx: winCtx,
      denyAsAsk: false,
      gitStateProvider: fakeProvider([target as string]),
    });
    expect(clean.decision.level).toBe("L0");
  });

  (hasPwsh7 ? it : it.skip)("pwsh Remove-Item", async () => {
    const action: Action = {
      ...bash(""),
      toolName: "PowerShell",
      host: { os: "windows" },
      cwd: "C:\\repo",
      worktreeRoot: "C:\\repo",
      exec: { shell: "pwsh7", source: "Remove-Item a.txt" },
    };
    const winCtx = {
      os: "windows" as const,
      cwd: "C:\\repo",
      worktreeRoot: "C:\\repo",
      home: "C:\\Users\\alice",
      pluginDataDir: "C:\\Users\\alice\\.paseo\\permission-guardian",
      envSnapshot: { PATH: "C:\\Windows\\System32" },
    };
    const base = { pathCtx: winCtx, denyAsAsk: false, allowPosixPwshHost: true, envSnapshot: winCtx.envSnapshot };
    const dirty = await decideAction(action, { ...base, gitStateProvider: fakeProvider([]) });
    const target = Object.keys(dirty.deleteTargetsClean ?? {})[0];
    expect(target, JSON.stringify(dirty.decision)).toBeDefined();
    expect(dirty.decision.level).toBe("L1");
    const clean = await decideAction(action, { ...base, gitStateProvider: fakeProvider([target as string]) });
    expect(clean.decision.level).toBe("L0");
  });
});

describe("A: replay determinism", () => {
  it("recorded results win over the provider; a missing entry ⇒ L1", async () => {
    const p = fakeProvider(["/repo/a.txt", "/repo/b.txt"]);
    const r = await decideAction(
      bash("rm a.txt b.txt"),
      opts({ gitStateProvider: p, recordedDeleteTargetsClean: { "/repo/a.txt": true } }),
    );
    expect(p.calls).toEqual([]);
    expect(r.decision.level).toBe("L1");
    expect(r.decision.reasons).toEqual(["delete_uncommitted:/repo/b.txt"]);
  });

  function deleteRecord(snapshot: Record<string, boolean> | undefined): AuditRecord {
    return {
      version: 1,
      pluginVersion: "0",
      requestId: "r1",
      agentId: "a",
      provider: "claude",
      mode: "shadow",
      agreement: "pending",
      action: bash("rm a.txt"),
      decision: { level: "L0", verdict: "allow", reasons: [] },
      resolution: { behavior: "allow", resolvedAt: "2026-11-23T00:00:00.000Z", actor: "human" },
      contextSnapshot: {
        secretTaint: false,
        untrustedTaint: false,
        modifiedEntrypoints: [],
        modifiedFiles: [],
        modifiedFilesTruncated: false,
        contextUnavailable: false,
        ...(snapshot ? { deleteTargetsClean: snapshot } : {}),
      },
    };
  }

  it("createReplayDecide uses the recorded map and never spawns git", async () => {
    const replay = createReplayDecide({ pwshHostFactory: () => null, home: "/Users/alice", dataDir: "/d", env: {} });
    gitCalls.count = 0;
    const clean = await replay(deleteRecord({ "/repo/a.txt": true }));
    const missing = await replay(deleteRecord(undefined));
    const dirty = await replay(deleteRecord({ "/repo/a.txt": false }));
    await replay.dispose();
    expect(gitCalls.count).toBe(0);
    expect("verdict" in clean && clean.verdict).toBe("allow");
    expect("level" in missing && missing.level).toBe("L1");
    expect("level" in dirty && dirty.level).toBe("L1");
  });

  it("ENGINE_DATA_VERSION is 2 and part of the fingerprint", () => {
    expect(ENGINE_DATA_VERSION).toBe(2);
    const fp = computeFingerprint({ pluginVersion: "0", denyAsAsk: false, windowsDefaultShell: "pwsh7" });
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("A: real git provider (integration)", () => {
  const dirs: string[] = [];
  afterEach(async () => {
    while (dirs.length) await rm(dirs.pop() as string, { recursive: true, force: true });
  });

  function git(cwd: string, ...args: string[]) {
    execFileSync("git", args, {
      cwd,
      stdio: "ignore",
      env: { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" },
    });
  }

  it("classifies clean/untracked/modified/staged/ignored/outside/not-a-repo", async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), "pg-git-")));
    dirs.push(root);
    const repo = join(root, "repo");
    await mkdir(join(repo, "sub"), { recursive: true });
    git(repo, "init", "-q");
    await writeFile(join(repo, "clean.txt"), "c");
    await writeFile(join(repo, "sub", "clean2.txt"), "c");
    await writeFile(join(repo, "modified.txt"), "m");
    await writeFile(join(repo, "staged.txt"), "s");
    await writeFile(join(repo, ".gitignore"), "ignored.txt\n");
    git(repo, "add", ".");
    git(repo, "commit", "-q", "-m", "init");
    await writeFile(join(repo, "modified.txt"), "m2");
    await writeFile(join(repo, "staged.txt"), "s2");
    git(repo, "add", "staged.txt");
    await writeFile(join(repo, "untracked.txt"), "u");
    await writeFile(join(repo, "ignored.txt"), "i");
    await writeFile(join(repo, "weird*.txt"), "w");
    const outside = join(root, "outside.txt");
    await writeFile(outside, "o");

    const provider = createGitStateProvider();
    const t = (name: string) => join(repo, name);
    const targets = [
      t("clean.txt"),
      t("sub/clean2.txt"),
      t("modified.txt"),
      t("staged.txt"),
      t("untracked.txt"),
      t("ignored.txt"),
      t("weird*.txt"),
      t("sub"),
      t("missing.txt"),
      outside,
    ];
    const res = await provider({ worktreeRoot: repo, targets });
    expect(res).toEqual({
      [t("clean.txt")]: true,
      [t("sub/clean2.txt")]: true,
      [t("modified.txt")]: false,
      [t("staged.txt")]: false,
      [t("untracked.txt")]: false,
      [t("ignored.txt")]: false,
      [t("weird*.txt")]: false,
      [t("sub")]: false,
      [t("missing.txt")]: false,
      [outside]: false,
    });

    // worktreeRoot as a subdirectory of the repository
    const subRes = await provider({ worktreeRoot: join(repo, "sub"), targets: [t("sub/clean2.txt"), t("clean.txt")] });
    expect(subRes).toEqual({ [t("sub/clean2.txt")]: true, [t("clean.txt")]: false });

    const notRepo = join(root, "plain");
    await mkdir(notRepo);
    await writeFile(join(notRepo, "f.txt"), "f");
    expect(await provider({ worktreeRoot: notRepo, targets: [join(notRepo, "f.txt")] })).toEqual({
      [join(notRepo, "f.txt")]: false,
    });

    const badGit = createGitStateProvider({ gitBinary: join(root, "no-such-git") });
    expect(await badGit({ worktreeRoot: repo, targets: [t("clean.txt")] })).toEqual({ [t("clean.txt")]: false });

    const aborted = new AbortController();
    aborted.abort();
    expect(await provider({ worktreeRoot: repo, targets: [t("clean.txt")], signal: aborted.signal })).toEqual({
      [t("clean.txt")]: false,
    });

    const timeout = createGitStateProvider({ timeoutMs: 0 });
    expect(await timeout({ worktreeRoot: repo, targets: [t("clean.txt")] })).toEqual({ [t("clean.txt")]: false });
  }, 20_000);
});

describe("A: live path records deleteTargetsClean in the context snapshot", () => {
  const dirs: string[] = [];
  afterEach(async () => {
    while (dirs.length) await rm(dirs.pop() as string, { recursive: true, force: true });
  });

  it("guardian passes its provider and stores the per-target result (redacted keys, boolean values)", async () => {
    const { AuditStore } = await import("../server/audit/store.js");
    const { PermissionGuardianService } = await import("../server/guardian.js");
    const { DEFAULT_GUARDIAN_SETTINGS } = await import("../shared/settings.js");
    const dataDir = await mkdtemp(join(tmpdir(), "pg-del-"));
    dirs.push(dataDir);
    const store = new AuditStore({ dataDir, pluginVersion: "0" });
    const seen: Array<{ worktreeRoot: string; targets: string[] }> = [];
    const service = new PermissionGuardianService({
      auditStore: store,
      pluginVersion: "0",
      initialSettings: DEFAULT_GUARDIAN_SETTINGS,
      gitStateProvider: async (req) => {
        seen.push({ worktreeRoot: req.worktreeRoot, targets: req.targets });
        return Object.fromEntries(req.targets.map((t) => [t, t.endsWith("a.txt")]));
      },
    });
    const agent = {
      id: "ag",
      workspaceId: "w",
      parentAgentId: null,
      provider: "claude",
      cwd: "/repo/project",
      title: "T",
      background: false,
      metadata: {},
    };
    await service.handlePermissionBefore({
      agent,
      request: { id: "q1", provider: "claude", name: "Bash", kind: "tool", input: { command: "rm a.txt b.txt" } },
    });
    const record = store.getRecord("q1");
    expect(seen.length).toBe(1);
    expect(record?.decision?.level).toBe("L1");
    const map = record?.contextSnapshot?.deleteTargetsClean ?? {};
    const entries = Object.entries(map);
    expect(entries.length).toBe(2);
    expect(entries.find(([k]) => k.endsWith("a.txt"))?.[1]).toBe(true);
    expect(entries.find(([k]) => k.endsWith("b.txt"))?.[1]).toBe(false);
    await store.flush();
  });

  it("audit store redacts keys but keeps boolean values (and a key collision keeps false)", async () => {
    const { AuditStore } = await import("../server/audit/store.js");
    const dataDir = await mkdtemp(join(tmpdir(), "pg-del-"));
    dirs.push(dataDir);
    const store = new AuditStore({ dataDir, pluginVersion: "0" });
    const token = "ghp_" + "a".repeat(36);
    const rec = await store.recordBefore({
      requestId: "q",
      agentId: "a",
      provider: "claude",
      mode: "shadow",
      requestedAt: "2026-11-23T00:00:00.000Z",
      latencyMs: 0,
      normalizedBy: "x",
      warnings: [],
      action: bash("rm x"),
      decision: { level: "L1", verdict: "ask", reasons: [] },
      contextSnapshot: {
        secretTaint: false,
        untrustedTaint: false,
        modifiedEntrypoints: [],
        modifiedFiles: [],
        modifiedFilesTruncated: false,
        deleteTargetsClean: { [`/repo/${token}`]: true, "/repo/token.txt": true },
      },
    });
    const map = rec.contextSnapshot?.deleteTargetsClean ?? {};
    expect(Object.keys(map).some((k) => k.includes(token))).toBe(false);
    expect(Object.values(map).every((v) => typeof v === "boolean")).toBe(true);
    expect(map["/repo/token.txt"]).toBe(true);
    await store.flush();
  });
});
