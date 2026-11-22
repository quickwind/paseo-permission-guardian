import { describe, expect, it } from "vitest";
import { decideAction, type DecideOptions } from "../server/decide.js";
import { classifyWindowsPath } from "../server/paths/index.js";
import type { Action } from "../shared/types.js";

// N1 — Windows Paseo roots are realpath-resolved (junction/symlink targets are protected).
const winEnv = { USERPROFILE: "C:\\Users\\alice" };
const JUNCTIONS: Array<[string, string]> = [
  ["c:\\users\\alice\\.paseo", "D:\\PaseoData"],
  ["d:\\ph", "E:\\PhReal"],
  ["d:\\gd", "F:\\GdReal"],
];
function fakeRealpath(p: string): string {
  const lower = p.toLowerCase();
  for (const [link, target] of JUNCTIONS) {
    if (lower === link || lower.startsWith(`${link}\\`)) return target + p.slice(link.length);
  }
  return p;
}
const junctionCtx = {
  os: "windows" as const,
  cwd: "C:\\repo",
  worktreeRoot: "C:\\repo",
  home: "C:\\Users\\alice",
  envSnapshot: winEnv,
  windowsRealpath: fakeRealpath,
};

describe("N1 Windows Paseo roots resolve junction targets", () => {
  it("target of a junctioned ~\\.paseo: config.json is protected plugin-self and sensitive", () => {
    const c = classifyWindowsPath("D:\\PaseoData\\config.json", junctionCtx);
    expect(c.isProtected).toBe(true);
    expect(c.isPluginSelf).toBe(true);
    expect(c.isSensitive).toBe(true);
  });
  it("target of a junctioned default plugin data dir is plugin-self", () => {
    const c = classifyWindowsPath("D:\\PaseoData\\permission-guardian\\audit.jsonl", junctionCtx);
    expect(c.isPluginSelf).toBe(true);
  });
  it("target of a junctioned PASEO_HOME is a home root (R11 subpaths)", () => {
    const ctx = { ...junctionCtx, envSnapshot: { ...winEnv, PASEO_HOME: "D:\\ph" } };
    expect(classifyWindowsPath("E:\\PhReal\\settings.json", ctx).isProtected).toBe(true);
    expect(classifyWindowsPath("E:\\PhReal\\worktrees\\a\\b.ts", ctx).isProtected).toBe(false);
  });
  it("target of a junctioned PASEO_GUARDIAN_DATA_DIR is a whole plugin-self root", () => {
    const ctx = { ...junctionCtx, envSnapshot: { ...winEnv, PASEO_GUARDIAN_DATA_DIR: "D:\\gd" } };
    expect(classifyWindowsPath("F:\\GdReal\\anything.txt", ctx).isPluginSelf).toBe(true);
  });
  it("target of a junctioned paseoRoots entry is a whole plugin-self root", () => {
    const ctx = { ...junctionCtx, paseoRoots: ["D:\\gd"] };
    expect(classifyWindowsPath("F:\\GdReal\\x.json", ctx).isPluginSelf).toBe(true);
  });
  it("skipHostRealpath disables root resolution", () => {
    const c = classifyWindowsPath("D:\\PaseoData\\config.json", { ...junctionCtx, skipHostRealpath: true });
    expect(c.isProtected).toBe(false);
  });
  it("decide: write to junction target is L3, read of config.json is read_secret", async () => {
    const base: Omit<Action, "kind"> = {
      provider: "claude",
      agentId: "a",
      requestId: "r",
      toolName: "Tool",
      host: { os: "windows" },
      cwd: "C:\\repo",
      worktreeRoot: "C:\\repo",
    };
    const opts: DecideOptions = { pathCtx: junctionCtx, denyAsAsk: false, envSnapshot: winEnv };
    const w = await decideAction({ ...base, kind: "edit", paths: ["D:\\PaseoData\\config.json"] }, opts);
    expect(w.decision.level).toBe("L3");
    const r = await decideAction({ ...base, kind: "read", paths: ["D:\\PaseoData\\config.json"] }, opts);
    expect(r.touchedSecret).toBe(true);
  });
});

// N3 — cmd copy/move/ren judge sensitive and protected independently; %PASEO_*% macros expand.
function cmdExec(source: string, env: Record<string, string> = {}): [Action, DecideOptions] {
  const envSnapshot = { USERPROFILE: "C:\\Users\\u", ...env };
  return [
    {
      provider: "claude",
      agentId: "a",
      requestId: "r",
      toolName: "Bash",
      host: { os: "windows" },
      cwd: "C:\\repo",
      worktreeRoot: "C:\\repo",
      kind: "exec",
      exec: { shell: "cmd", source },
    },
    {
      denyAsAsk: false,
      envSnapshot,
      pathCtx: { os: "windows", cwd: "C:\\repo", worktreeRoot: "C:\\repo", home: "C:\\Users\\u", envSnapshot },
    },
  ];
}

describe("N3 cmd plugin-self writes and %PASEO_*% macros", () => {
  it.each(["copy", "move", "ren"])("%s x C:\\Users\\u\\.paseo\\config.json is L3", async (verb) => {
    const r = await decideAction(...cmdExec(`${verb} x C:\\Users\\u\\.paseo\\config.json`));
    expect(r.decision.level, JSON.stringify(r.decision.reasons)).toBe("L3");
  });
  it("copy onto a plugin-self non-secret path is L3", async () => {
    const r = await decideAction(...cmdExec("copy x C:\\Users\\u\\.paseo\\plugins\\p\\index.js"));
    expect(r.decision.level, JSON.stringify(r.decision.reasons)).toBe("L3");
  });
  it("del %PASEO_HOME%\\config.json with PASEO_HOME set is L3", async () => {
    const r = await decideAction(...cmdExec("del %PASEO_HOME%\\config.json", { PASEO_HOME: "D:\\ph" }));
    expect(r.decision.level, JSON.stringify(r.decision.reasons)).toBe("L3");
  });
  it("copy x %PASEO_GUARDIAN_DATA_DIR%\\a.json with the var set is L3", async () => {
    const r = await decideAction(
      ...cmdExec("copy x %PASEO_GUARDIAN_DATA_DIR%\\a.json", { PASEO_GUARDIAN_DATA_DIR: "D:\\gd" }),
    );
    expect(r.decision.level, JSON.stringify(r.decision.reasons)).toBe("L3");
  });
  it("del %PASEO_HOME%\\config.json with PASEO_HOME unset stays opaque (not L0)", async () => {
    const r = await decideAction(...cmdExec("del %PASEO_HOME%\\config.json"));
    expect(r.decision.level).not.toBe("L0");
    expect(JSON.stringify(r.decision)).toMatch(/dynamic_or_unexpanded_path/);
  });
  it("copy within the worktree stays L0-able (no regression)", async () => {
    const r = await decideAction(...cmdExec("copy a.txt b.txt"));
    expect(r.decision.level).not.toBe("L3");
  });
});
