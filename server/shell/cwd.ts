import { isAbsolute, posix, resolve } from "node:path";

export interface CwdState {
  cwd: string;
  uncertain: boolean;
  stack: string[];
}

function isPosixStylePath(p: string): boolean {
  return p.startsWith("/") && !p.startsWith("//") && !/^[A-Za-z]:/.test(p);
}

/**
 * Resolve a static literal `cd` / `pushd` / wrapper target against `currentCwd`.
 * Supports `~`, `$HOME`, `${HOME}`, `$PWD`, and `${PWD}` prefixes.
 * Returns `null` for dynamic variables, `cd -`, or unresolvable expressions.
 */
export function resolveStaticPosixCwd(
  currentCwd: string,
  target: string,
  home?: string,
): string | null {
  if (target === "") {
    return currentCwd;
  }
  if (target === "-" || target.includes("\0")) {
    return null;
  }

  let expanded = target;
  if (target === "~" || target === "$HOME" || target === "${HOME}") {
    if (!home) return null;
    expanded = home;
  } else if (target.startsWith("~/")) {
    if (!home) return null;
    expanded = isPosixStylePath(home)
      ? posix.join(home, target.slice(2))
      : `${home.replace(/[\\/]+$/, "")}/${target.slice(2)}`;
  } else if (target.startsWith("~")) {
    // Reject `~user`, `~-` ($OLDPWD), `~+` ($PWD), `~N` directory stack — target cannot be statically resolved
    return null;
  } else if (target.startsWith("$HOME/")) {
    if (!home) return null;
    expanded = isPosixStylePath(home)
      ? posix.join(home, target.slice("$HOME/".length))
      : `${home.replace(/[\\/]+$/, "")}/${target.slice("$HOME/".length)}`;
  } else if (target.startsWith("${HOME}/")) {
    if (!home) return null;
    expanded = isPosixStylePath(home)
      ? posix.join(home, target.slice("${HOME}/".length))
      : `${home.replace(/[\\/]+$/, "")}/${target.slice("${HOME}/".length)}`;
  } else if (target === "$PWD" || target === "${PWD}") {
    expanded = currentCwd;
  } else if (target.startsWith("$PWD/")) {
    expanded = isPosixStylePath(currentCwd)
      ? posix.join(currentCwd, target.slice("$PWD/".length))
      : `${currentCwd.replace(/[\\/]+$/, "")}/${target.slice("$PWD/".length)}`;
  } else if (target.startsWith("${PWD}/")) {
    expanded = isPosixStylePath(currentCwd)
      ? posix.join(currentCwd, target.slice("${PWD}/".length))
      : `${currentCwd.replace(/[\\/]+$/, "")}/${target.slice("${PWD}/".length)}`;
  }

  if (/[$`%!]/.test(expanded)) {
    return null;
  }

  if (isPosixStylePath(currentCwd) && !/^[A-Za-z]:[\\/]/.test(expanded)) {
    return posix.isAbsolute(expanded)
      ? posix.resolve(expanded)
      : posix.resolve(currentCwd, expanded);
  }
  return isAbsolute(expanded) ? resolve(expanded) : resolve(currentCwd, expanded);
}

/**
 * Tracks deterministic linear static literal `cwd` across sequential commands
 * (`;`, `&&`, `{ ... }`) while isolating subshells and falling back to
 * `uncertain` on conditional branches (`||`, `if`, `case`, loops) or dynamic targets.
 */
export class LinearCwdTracker {
  private cwd: string;
  private uncertain: boolean;
  private stack: string[];
  private readonly home?: string;

  constructor(options: { cwd: string; home?: string; uncertain?: boolean; stack?: string[] }) {
    this.cwd = options.cwd;
    this.home = options.home;
    this.uncertain = Boolean(options.uncertain);
    this.stack = options.stack ? [...options.stack] : [];
  }

  getCwd(): string {
    return this.cwd;
  }

  isUncertain(): boolean {
    return this.uncertain;
  }

  snapshot(): CwdState {
    return {
      cwd: this.cwd,
      uncertain: this.uncertain,
      stack: [...this.stack],
    };
  }

  clone(): LinearCwdTracker {
    return new LinearCwdTracker({
      cwd: this.cwd,
      home: this.home,
      uncertain: this.uncertain,
      stack: this.stack,
    });
  }

  markUncertain(): void {
    this.uncertain = true;
  }

  applyCd(target: string | undefined, isDynamic: boolean): void {
    if (this.uncertain || isDynamic) {
      this.uncertain = true;
      return;
    }
    if (target === undefined) {
      if (!this.home) {
        this.uncertain = true;
        return;
      }
      this.cwd = this.home;
      return;
    }
    const next = resolveStaticPosixCwd(this.cwd, target, this.home);
    if (!next) {
      this.uncertain = true;
      return;
    }
    this.cwd = next;
  }

  applyPushd(target: string | undefined, isDynamic: boolean): void {
    if (this.uncertain || isDynamic || target === undefined) {
      this.uncertain = true;
      return;
    }
    const next = resolveStaticPosixCwd(this.cwd, target, this.home);
    if (!next) {
      this.uncertain = true;
      return;
    }
    this.stack.push(this.cwd);
    this.cwd = next;
  }

  applyPopd(): void {
    if (this.uncertain || this.stack.length === 0) {
      this.uncertain = true;
      return;
    }
    const popped = this.stack.pop();
    if (!popped) {
      this.uncertain = true;
      return;
    }
    this.cwd = popped;
  }

  mergeBranch(before: CwdState, branch: CwdState): void {
    if (before.uncertain || branch.uncertain || branch.cwd !== before.cwd) {
      this.uncertain = true;
    }
  }
}
