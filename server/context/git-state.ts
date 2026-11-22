import { execFile } from "node:child_process";
import { realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";

/**
 * Git working-tree state for delete targets (ADR-0009). A target is "clean" only when it is a
 * regular tracked index entry (`git ls-files -v` tag `H`, so assume-unchanged / skip-worktree
 * entries are not clean) AND `git status` reports nothing for it (worktree and index equal HEAD).
 * Every other outcome — untracked, ignored, modified, staged, outside the worktree, a directory,
 * not a repository, git missing, timeout, abort or any error — is `false` (fail to human).
 *
 * Pure Node: spawns the `git` binary via `execFile` (no shell) with `GIT_OPTIONAL_LOCKS=0` and
 * literal pathspecs. Results are never cached: each call reflects the state at decision time and
 * the live path records it in the audit snapshot so replay never calls git.
 */
export interface GitStateRequest {
  worktreeRoot: string;
  /** Absolute target paths (the delete effect targets). */
  targets: string[];
  signal?: AbortSignal;
}

/** Returns a record with one boolean per requested target (`true` ⇔ tracked and clean). */
export type GitStateProvider = (req: GitStateRequest) => Promise<Record<string, boolean>>;

export interface GitStateProviderOptions {
  /** Total budget for all git invocations of one request (default 1500 ms). */
  timeoutMs?: number;
  gitBinary?: string;
}

export const DEFAULT_GIT_STATE_TIMEOUT_MS = 1500;
const MAX_BUFFER = 4 * 1024 * 1024;

function allFalse(targets: string[]): Record<string, boolean> {
  return Object.fromEntries(targets.map((t) => [t, false]));
}

function toGitRel(top: string, target: string): string | null {
  const rel = relative(top, target);
  if (rel === "" || isAbsolute(rel) || rel === ".." || rel.startsWith(`..${sep}`)) return null;
  return sep === "\\" ? rel.split("\\").join("/") : rel;
}

function isUnder(root: string, target: string): boolean {
  const rel = relative(root, target);
  return rel !== "" && !isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${sep}`);
}

export function createGitStateProvider(options: GitStateProviderOptions = {}): GitStateProvider {
  const timeoutMs = options.timeoutMs ?? DEFAULT_GIT_STATE_TIMEOUT_MS;
  const gitBinary = options.gitBinary ?? "git";

  return async (req) => {
    const targets = Array.from(new Set(req.targets));
    const result = allFalse(targets);
    if (targets.length === 0) return result;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.max(0, timeoutMs));
    const onAbort = () => controller.abort();
    if (req.signal) {
      if (req.signal.aborted) controller.abort();
      else req.signal.addEventListener("abort", onAbort, { once: true });
    }

    const run = (cwd: string, args: string[]): Promise<string> =>
      new Promise((resolvePromise, reject) => {
        if (controller.signal.aborted) {
          reject(new Error("git_state_aborted"));
          return;
        }
        execFile(
          gitBinary,
          args,
          {
            cwd,
            signal: controller.signal,
            windowsHide: true,
            maxBuffer: MAX_BUFFER,
            encoding: "utf8",
            env: {
              ...process.env,
              GIT_OPTIONAL_LOCKS: "0",
              GIT_LITERAL_PATHSPECS: "1",
              GIT_TERMINAL_PROMPT: "0",
              LC_ALL: "C",
            },
          },
          (error, stdout) => {
            if (error) reject(error);
            else resolvePromise(String(stdout));
          },
        );
      });

    try {
      const root = await realpath(req.worktreeRoot);
      const topRaw = (await run(root, ["rev-parse", "--show-toplevel"])).trim();
      if (!topRaw) return result;
      const top = await realpath(resolve(topRaw));

      // Only targets inside BOTH the worktree root and the repository are candidates.
      const relByTarget = new Map<string, string>();
      for (const target of targets) {
        if (!isAbsolute(target)) continue;
        const abs = resolve(target);
        if (!isUnder(root, abs)) continue;
        const rel = toGitRel(top, abs);
        if (rel !== null) relByTarget.set(target, rel);
      }
      if (relByTarget.size === 0) return result;
      const rels = Array.from(new Set(relByTarget.values()));

      const lsOut = await run(top, ["ls-files", "-z", "-v", "--full-name", "--", ...rels]);
      const tracked = new Set<string>();
      for (const entry of lsOut.split("\0")) {
        if (entry.startsWith("H ")) tracked.add(entry.slice(2));
      }

      const statusOut = await run(top, [
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignored=matching",
        "--",
        ...rels,
      ]);
      const dirty = new Set<string>();
      const fields = statusOut.split("\0");
      for (let i = 0; i < fields.length; i++) {
        const field = fields[i];
        if (field.length < 4) continue;
        const xy = field.slice(0, 2);
        dirty.add(field.slice(3));
        if (xy[0] === "R" || xy[0] === "C") {
          const orig = fields[i + 1];
          if (orig) dirty.add(orig);
          i += 1;
        }
      }

      for (const [target, rel] of relByTarget) {
        result[target] = tracked.has(rel) && !dirty.has(rel);
      }
      return result;
    } catch {
      return allFalse(targets);
    } finally {
      clearTimeout(timer);
      req.signal?.removeEventListener("abort", onAbort);
    }
  };
}
