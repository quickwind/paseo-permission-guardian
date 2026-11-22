import { describe, expect, it } from "vitest";
import { decideAction, type DecideOptions } from "../server/decide.js";
import { collectPathsFromObject } from "../server/normalize/types.js";
import { isBuildOrScriptEntrypoint, resolvePaseoSelfRoots } from "../server/paths/index.js";
import { isExecHijackEnvVar } from "../server/secrets/patterns.js";
import type { Action } from "../shared/types.js";

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
});
