import { afterAll, describe, expect, it } from "vitest";
import { disposeSharedPwshHost, resolvePwshBinaryPath } from "../server/shell/pwsh-host.js";
import { decideAction, type DecideOptions } from "../server/decide.js";
import { collectPathsFromObject } from "../server/normalize/types.js";
import { isBuildOrScriptEntrypoint, resolvePaseoSelfRoots } from "../server/paths/index.js";
import { isExecHijackEnvVar } from "../server/secrets/patterns.js";
import type { Action } from "../shared/types.js";

afterAll(async () => {
  await disposeSharedPwshHost();
});
const hasPwsh7 = Boolean(
  resolvePwshBinaryPath("pwsh7", { allowPosixHost: process.platform !== "win32" }),
);

function base(): Omit<Action, "kind"> {
  return {
    provider: "claude",
    agentId: "agent-1",
    requestId: "req-1",
    toolName: "Tool",
    host: { os: "darwin" },
    cwd: "/repo",
    worktreeRoot: "/repo",
  };
}
const readAction = (o: Partial<Action> = {}): Action => ({ ...base(), kind: "read", ...o });
const editAction = (p: string): Action => ({ ...base(), kind: "edit", paths: [p] });
const opts: DecideOptions = {
  pathCtx: { cwd: "/repo", worktreeRoot: "/repo", home: "/home/u" },
  denyAsAsk: false,
};
const optsWithEnv = (env: Record<string, string>): DecideOptions => ({
  ...opts,
  envSnapshot: env,
  pathCtx: { ...opts.pathCtx, paseoRoots: resolvePaseoSelfRoots(env, "/home/u") },
});

describe("p2a path/normalization hardening", () => {
  it("collects agy's capitalised Path key", () => {
    expect(collectPathsFromObject({ Path: "/repo/a.ts" })).toContain("/repo/a.ts");
  });
  it("treats a read with no recognised path as opaque (L1), not L0", async () => {
    const r = await decideAction(readAction({ paths: [] }), opts);
    expect(r.decision.level).toBe("L1");
    expect(r.decision.reasons).toContain("opaque:read_without_path");
  });
  it.each(["~/.paseo/config.json", "$PASEO_HOME/plugins/x.json", "/custom/data/gate-state.json"])(
    "writes to Paseo/plugin-self location %s are L3 pluginSelf",
    async (p) => {
      const r = await decideAction(
        editAction(p),
        optsWithEnv({ PASEO_HOME: "/ph", PASEO_GUARDIAN_DATA_DIR: "/custom/data" }),
      );
      expect(r.decision.level).toBe("L3");
    },
  );
  it("reading ~/.paseo/config.json is a secret read", async () => {
    const r = await decideAction(readAction({ paths: ["~/.paseo/config.json"] }), opts);
    expect(r.touchedSecret).toBe(true);
  });
  it.each(["PASEO_HOME", "PASEO_PLUGIN_DIR", "PASEO_GUARDIAN_DATA_DIR"])(
    "assigning %s is an exec-hijack env write",
    (v) => {
      expect(isExecHijackEnvVar(v, "/tmp/x")).toBe(true);
    },
  );
  it.each([
    "build.rs", "conftest.py", "setup.py", "setup.cfg", "noxfile.py", "tox.ini", "Taskfile.yml",
    "Taskfile.yaml", "justfile", "build.gradle", "build.gradle.kts", "settings.gradle",
    "settings.gradle.kts", "pom.xml", "CMakeLists.txt", "meson.build", "Rakefile", "Gemfile",
    "composer.json", "deno.json", "deno.jsonc", "bunfig.toml", "Directory.Build.props", "App.csproj",
  ])("%s is a build/script entrypoint", (f) =>
    expect(isBuildOrScriptEntrypoint(`/repo/${f}`, "/repo")).toBe(true),
  );
  it("`.cargo/config.toml` is an entrypoint", () =>
    expect(isBuildOrScriptEntrypoint("/repo/.cargo/config.toml", "/repo")).toBe(true));

  it.each([
    "$PASEO_PLUGIN_DIR/x.json", "${PASEO_PLUGIN_DIR}/x.json", "$PASEO_GUARDIAN_DATA_DIR/x",
    "${PASEO_GUARDIAN_DATA_DIR}/x", "${PASEO_HOME}/x", "$PASEO_HOME",
  ])("writes to %s are L3 when the variable is set", async (p) => {
    const r = await decideAction(
      editAction(p),
      optsWithEnv({ PASEO_HOME: "/ph", PASEO_PLUGIN_DIR: "/pd", PASEO_GUARDIAN_DATA_DIR: "/gd" }),
    );
    expect(r.decision.level).toBe("L3");
  });
  it("PASEO_PLUGIN_DIR is a plugin-self root", async () => {
    const r = await decideAction(editAction("/pd/a.json"), optsWithEnv({ PASEO_PLUGIN_DIR: "/pd" }));
    expect(r.decision.level).toBe("L3");
  });
  it("$PASEO_HOME with PASEO_HOME unset does not crash or become plugin-self", async () => {
    const r = await decideAction(editAction("$PASEO_HOME/x.ts"), optsWithEnv({}));
    expect(r.decision.level).not.toBe("L3");
  });
  describe("PASEO_* root assignments are L2 in any shell", () => {
    const names = ["PASEO_HOME", "PASEO_PLUGIN_DIR", "PASEO_GUARDIAN_DATA_DIR"];
    const exec = (shell: "bash" | "pwsh7" | "cmd", source: string, os: "darwin" | "windows"): Action => ({
      ...base(),
      cwd: os === "windows" ? "C:\\repo" : "/repo",
      worktreeRoot: os === "windows" ? "C:\\repo" : "/repo",
      host: { os },
      kind: "exec",
      toolName: "Bash",
      exec: { shell, source },
    });
    const winOpts: DecideOptions = {
      denyAsAsk: false,
      allowPosixPwshHost: true,
      pathCtx: { os: "windows", cwd: "C:\\repo", worktreeRoot: "C:\\repo", home: "C:\\Users\\alice" },
    };
    const forms: Array<[string, (v: string) => Action]> = [
      ["bash inline prefix", (v) => exec("bash", `${v}=/x ls`, "darwin")],
      ["bash export", (v) => exec("bash", `export ${v}=/x`, "darwin")],
      ["pwsh $env:", (v) => exec("pwsh7", `$env:${v} = 'C:\\x'`, "windows")],
      ["pwsh SetEnvironmentVariable", (v) =>
        exec("pwsh7", `[Environment]::SetEnvironmentVariable('${v}', 'C:\\x')`, "windows")],
      ["cmd set", (v) => exec("cmd", `set ${v}=C:\\x`, "windows")],
    ];
    for (const [label, mk] of forms) {
      const t = label.startsWith("pwsh") && !hasPwsh7 ? it.skip : it;
      t.each(names)(`${label}: %s reaches L2`, async (v) => {
        const a = mk(v);
        const r = await decideAction(a, a.host.os === "windows" ? winOpts : opts);
        expect(r.decision.level, JSON.stringify(r.decision.reasons)).toBe("L2");
      });
    }
    it("unrelated var is unaffected", async () => {
      const r = await decideAction(exec("bash", "FOO=1 ls", "darwin"), opts);
      expect(r.decision.level).not.toBe("L2");
    });
  });
});
