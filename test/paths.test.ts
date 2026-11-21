import { mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  classifyPosixPath,
  isBuildOrScriptEntrypoint,
  resolveAncestorRealPath,
} from "../server/paths/index.js";

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "paseo-paths-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

describe("POSIX Path Model", () => {
  it("prevents symlinked parent directories from escaping worktree via ancestor realpath", async () => {
    const root = await makeTempDir();
    const worktree = join(root, "repo");
    const outside = join(root, "outside");
    await mkdir(worktree, { recursive: true });
    await mkdir(outside, { recursive: true });

    // Create a symlink inside worktree pointing outside (junction on Windows requires no elevation)
    const escapeLink = join(worktree, "escape");
    await symlink(outside, escapeLink, process.platform === "win32" ? "junction" : undefined);

    // Non-existent nested file under the symlinked directory
    const target = join(escapeLink, "nested", "new-file.txt");
    const resolved = resolveAncestorRealPath(target);
    expect(resolved).toContain("outside");

    const classified = classifyPosixPath(target, {
      cwd: worktree,
      worktreeRoot: worktree,
    });
    expect(classified.inWorktree).toBe(false);
  });

  it("identifies sensitive paths across home and project files", () => {
    const ctx = { cwd: "/repo", worktreeRoot: "/repo", home: "/Users/alice" };

    expect(classifyPosixPath("~/.ssh/id_rsa", ctx).isSensitive).toBe(true);
    expect(classifyPosixPath("$HOME/.aws/credentials", ctx).isSensitive).toBe(true);
    expect(classifyPosixPath(".env.production", ctx).isSensitive).toBe(true);
    expect(classifyPosixPath("certs/server.pem", ctx).isSensitive).toBe(true);
    expect(classifyPosixPath("/etc/shadow", ctx).isSensitive).toBe(true);
    expect(classifyPosixPath("src/index.ts", ctx).isSensitive).toBe(false);
  });

  it("protects entire .git/ directory, agent configs, and plugin self files", () => {
    const ctx = {
      cwd: "/repo",
      worktreeRoot: "/repo",
      home: "/Users/alice",
      pluginDataDir: "/Users/alice/.paseo/permission-guardian",
    };

    const gitAttr = classifyPosixPath(".git/info/attributes", ctx);
    expect(gitAttr.isProtected).toBe(true);
    expect(gitAttr.isPluginSelf).toBe(false);

    const claudeCfg = classifyPosixPath(".claude/settings.json", ctx);
    expect(claudeCfg.isProtected).toBe(true);

    const pluginFile = classifyPosixPath("~/.paseo/permission-guardian/policy.yaml", ctx);
    expect(pluginFile.isProtected).toBe(true);
    expect(pluginFile.isPluginSelf).toBe(true);
  });

  it("distinguishes build/script entrypoints from ordinary source files", () => {
    expect(isBuildOrScriptEntrypoint("/repo/package.json", "/repo")).toBe(true);
    expect(isBuildOrScriptEntrypoint("/repo/scripts/release.sh", "/repo")).toBe(true);
    expect(isBuildOrScriptEntrypoint("/repo/vitest.config.ts", "/repo")).toBe(true);
    expect(isBuildOrScriptEntrypoint("/repo/src/utils/math.ts", "/repo")).toBe(false);
  });
});
