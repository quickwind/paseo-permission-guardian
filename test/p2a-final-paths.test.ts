import { afterAll, describe, expect, it } from "vitest";
import { decideAction, type DecideOptions } from "../server/decide.js";
import { buildDecidePathCtx } from "../server/decide-context.js";
import { classifyWindowsPath } from "../server/paths/index.js";
import { disposeSharedPwshHost, resolvePwshBinaryPath } from "../server/shell/pwsh-host.js";
import type { Action } from "../shared/types.js";

afterAll(async () => {
  await disposeSharedPwshHost();
});
const hasPwsh7 = Boolean(
  resolvePwshBinaryPath("pwsh7", { allowPosixHost: process.platform !== "win32" }),
);

// F1 / R11 — Paseo home roots protect only specific subpaths.
const HOME = "/Users/alice";
const WT = `${HOME}/.paseo/worktrees/x/repo`;

function posixOpts(env: Record<string, string> = {}, wt = WT): DecideOptions {
  const action = { cwd: wt, worktreeRoot: wt } as Action;
  return {
    pathCtx: {
      ...buildDecidePathCtx({ action, dataDir: `${HOME}/.paseo/permission-guardian`, home: HOME, env }),
      home: HOME,
      skipHostRealpath: true,
    },
    denyAsAsk: false,
    envSnapshot: env,
  };
}
function posixAction(kind: "edit" | "read", p: string, wt = WT): Action {
  return {
    provider: "claude",
    agentId: "a",
    requestId: "r",
    toolName: "Tool",
    host: { os: "darwin" },
    cwd: wt,
    worktreeRoot: wt,
    kind,
    paths: [p],
  };
}

describe("F1 R11 narrowed Paseo self roots (POSIX)", () => {
  it("editing a file in a Paseo worktree under ~/.paseo/worktrees is L0", async () => {
    const r = await decideAction(posixAction("edit", `${WT}/src/a.ts`), posixOpts());
    expect(r.decision.level, JSON.stringify(r.decision.reasons)).toBe("L0");
  });
  it("reading the repo's own config.json in a Paseo worktree is not a secret read", async () => {
    const r = await decideAction(posixAction("read", `${WT}/config.json`), posixOpts());
    expect(r.touchedSecret).toBe(false);
    expect(r.decision.level).toBe("L0");
  });
  it("writing the guardian plugin-settings file is L3", async () => {
    const r = await decideAction(
      posixAction("edit", `${HOME}/.paseo/plugin-settings/paseo-permission-guardian/guardian.json`),
      posixOpts(),
    );
    expect(r.decision.level).toBe("L3");
  });
  it("reading the guardian plugin-settings file is read_secret", async () => {
    const r = await decideAction(
      posixAction("read", `${HOME}/.paseo/plugin-settings/paseo-permission-guardian/guardian.json`),
      posixOpts(),
    );
    expect(r.touchedSecret).toBe(true);
  });
  it.each(["config.json", "settings.json", "plugins/x/index.js", "permission-guardian/a.jsonl", "daemon.json", "daemon-state.json", "server.key", "tls.pem", "state/x"])(
    "writing ~/.paseo/%s is L3",
    async (sub) => {
      const r = await decideAction(posixAction("edit", `${HOME}/.paseo/${sub}`), posixOpts());
      expect(r.decision.level).toBe("L3");
    },
  );
  it("editing a file under $PASEO_HOME/worktrees is L0", async () => {
    const env = { PASEO_HOME: "/ph" };
    const wt = "/ph/worktrees/y/repo";
    const r = await decideAction(posixAction("edit", `${wt}/src/a.ts`, wt), posixOpts(env, wt));
    expect(r.decision.level, JSON.stringify(r.decision.reasons)).toBe("L0");
  });
  it("$PASEO_HOME/config.json write stays L3 and read is a secret read", async () => {
    const env = { PASEO_HOME: "/ph" };
    const w = await decideAction(posixAction("edit", "/ph/config.json"), posixOpts(env));
    expect(w.decision.level).toBe("L3");
    const r = await decideAction(posixAction("read", "/ph/config.json"), posixOpts(env));
    expect(r.touchedSecret).toBe(true);
  });
  it("PASEO_PLUGIN_DIR / PASEO_GUARDIAN_DATA_DIR stay whole-root", async () => {
    const env = { PASEO_PLUGIN_DIR: "/pd", PASEO_GUARDIAN_DATA_DIR: "/gd" };
    for (const p of ["/pd/any/file.ts", "/gd/worktrees/x"]) {
      const r = await decideAction(posixAction("edit", p), posixOpts(env));
      expect(r.decision.level).toBe("L3");
    }
  });
  it("a worktree located inside a protected subtree keeps the protection (fail to human)", async () => {
    const wt = `${HOME}/.paseo/plugins/myplugin`;
    const r = await decideAction(posixAction("edit", `${wt}/index.ts`, wt), posixOpts({}, wt));
    expect(r.decision.level).toBe("L3");
  });
});

// F2 — Windows parity.
const winEnv = { USERPROFILE: "C:\\Users\\alice" };
const winCtx = {
  os: "windows" as const,
  cwd: "C:\\Users\\alice\\.paseo\\worktrees\\x\\repo",
  worktreeRoot: "C:\\Users\\alice\\.paseo\\worktrees\\x\\repo",
  home: "C:\\Users\\alice",
  pluginDataDir: "C:\\Users\\alice\\.paseo\\permission-guardian",
  envSnapshot: winEnv,
};

describe("F2 R11 on Windows paths", () => {
  it("~\\.paseo\\config.json is protected plugin-self and sensitive", () => {
    const c = classifyWindowsPath("C:\\Users\\alice\\.paseo\\config.json", winCtx);
    expect(c.isProtected).toBe(true);
    expect(c.isPluginSelf).toBe(true);
    expect(c.isSensitive).toBe(true);
  });
  it("%USERPROFILE%\\.paseo\\plugin-settings\\...\\guardian.json is protected and sensitive", () => {
    const c = classifyWindowsPath(
      "%USERPROFILE%\\.paseo\\plugin-settings\\paseo-permission-guardian\\guardian.json",
      { ...winCtx, shell: "cmd" },
    );
    expect(c.isProtected).toBe(true);
    expect(c.isPluginSelf).toBe(true);
    expect(c.isSensitive).toBe(true);
  });
  it("a Paseo worktree file under ~\\.paseo\\worktrees is neither protected nor sensitive", () => {
    const c = classifyWindowsPath("C:\\Users\\alice\\.paseo\\worktrees\\x\\repo\\config.json", winCtx);
    expect(c.isProtected).toBe(false);
    expect(c.isSensitive).toBe(false);
    expect(c.inWorktree).toBe(true);
  });
  it("$env:PASEO_HOME / %PASEO_HOME% expand to the protected set", () => {
    const ctx = { ...winCtx, envSnapshot: { ...winEnv, PASEO_HOME: "D:\\ph" } };
    expect(classifyWindowsPath("$env:PASEO_HOME\\settings.json", { ...ctx, shell: "pwsh7" }).isProtected).toBe(true);
    expect(classifyWindowsPath("%PASEO_HOME%\\plugins\\x.js", { ...ctx, shell: "cmd" }).isPluginSelf).toBe(true);
    expect(classifyWindowsPath("D:\\ph\\worktrees\\a\\b.ts", ctx).isProtected).toBe(false);
  });
  it("PASEO_GUARDIAN_DATA_DIR on Windows is a whole plugin-self root", () => {
    const ctx = { ...winCtx, envSnapshot: { ...winEnv, PASEO_GUARDIAN_DATA_DIR: "D:\\gd" } };
    expect(classifyWindowsPath("D:\\gd\\anything.txt", ctx).isPluginSelf).toBe(true);
  });
  it("Windows write/read of ~\\.paseo\\config.json via decide", async () => {
    const base: Omit<Action, "kind"> = {
      provider: "claude",
      agentId: "a",
      requestId: "r",
      toolName: "Tool",
      host: { os: "windows" },
      cwd: winCtx.cwd,
      worktreeRoot: winCtx.worktreeRoot,
    };
    const opts: DecideOptions = { pathCtx: winCtx, denyAsAsk: false, envSnapshot: winEnv };
    const w = await decideAction({ ...base, kind: "edit", paths: ["C:\\Users\\alice\\.paseo\\config.json"] }, opts);
    expect(w.decision.level).toBe("L3");
    const r = await decideAction({ ...base, kind: "read", paths: ["C:\\Users\\alice\\.paseo\\config.json"] }, opts);
    expect(r.touchedSecret).toBe(true);
    const ok = await decideAction({ ...base, kind: "edit", paths: [`${winCtx.cwd}\\src\\a.ts`] }, opts);
    expect(ok.decision.level).toBe("L0");
  });

  (hasPwsh7 ? it : it.skip)(
    "pwsh inner .NET IO paths carry paseoRoots/pluginDataDir from the outer context",
    async () => {
      const action: Action = {
        provider: "claude",
        agentId: "a",
        requestId: "r",
        kind: "exec",
        toolName: "PowerShell",
        host: { os: "windows" },
        cwd: "C:\\repo",
        worktreeRoot: "C:\\repo",
        exec: { shell: "pwsh7", source: "[System.IO.File]::WriteAllText('D:\\custom\\data\\x.json', 'a')" },
      };
      const r = await decideAction(action, {
        denyAsAsk: false,
        allowPosixPwshHost: true,
        envSnapshot: winEnv,
        pathCtx: {
          os: "windows",
          cwd: "C:\\repo",
          worktreeRoot: "C:\\repo",
          home: "C:\\Users\\alice",
          pluginDataDir: "D:\\custom\\data",
          paseoRoots: ["D:\\custom\\data"],
          envSnapshot: winEnv,
        },
      });
      expect(r.decision.level, JSON.stringify(r.decision.reasons)).toBe("L3");
    },
  );
});

describe("M3 .husky is a protected repo prefix", () => {
  it("POSIX edit of .husky/pre-commit is protected", async () => {
    const wt = "/repo";
    const r = await decideAction(posixAction("edit", "/repo/.husky/pre-commit", wt), posixOpts({}, wt));
    expect(r.decision.level).not.toBe("L0");
    expect(r.decision.reasons.join(",")).toMatch(/write_protected/);
  });
  it("Windows .husky path is protected", () => {
    const c = classifyWindowsPath("C:\\repo\\.husky\\pre-commit", { ...winCtx, cwd: "C:\\repo", worktreeRoot: "C:\\repo" });
    expect(c.isProtected).toBe(true);
  });
});
