/**
 * Ruling R11: Paseo home roots (`~/.paseo`, `$PASEO_HOME`) are NOT protected wholesale — Paseo's
 * default worktree location is `~/.paseo/worktrees/...`. Only these control/state subpaths are
 * plugin-self protected. Whole-root plugin-self roots (`PASEO_PLUGIN_DIR`,
 * `PASEO_GUARDIAN_DATA_DIR`, plugin data dir) are handled separately.
 */
export interface PaseoHomeRelMatch {
  protected: boolean;
  /** Reading the file is a secret read (Paseo config/settings, plugin settings JSON). */
  secret: boolean;
}

const NO_MATCH: PaseoHomeRelMatch = { protected: false, secret: false };

/**
 * Classify a path relative to a Paseo home root. `rel` uses forward slashes with no leading
 * slash; `""` is the root itself. Comparison is case-insensitive (Windows parity; on POSIX this
 * errs towards protecting).
 */
export function matchPaseoHomeRel(relRaw: string): PaseoHomeRelMatch {
  const rel = relRaw.replace(/^\/+|\/+$/g, "").toLowerCase();
  // The root itself contains the protected subpaths (e.g. `rm -rf ~/.paseo`).
  if (rel === "") return { protected: true, secret: false };
  const parts = rel.split("/");
  const head = parts[0];
  if (parts.length === 1) {
    if (head === "config.json" || head === "settings.json") return { protected: true, secret: true };
    if (head === "plugin-settings" || head === "plugins" || head === "permission-guardian" || head === "state") {
      return { protected: true, secret: false };
    }
    if (/\.(?:key|pem)$/.test(head) || /^daemon.*\.json$/.test(head)) {
      return { protected: true, secret: false };
    }
    return NO_MATCH;
  }
  if (head === "plugin-settings") {
    return { protected: true, secret: rel.endsWith(".json") };
  }
  if (head === "plugins" || head === "permission-guardian" || head === "state") {
    return { protected: true, secret: false };
  }
  return NO_MATCH;
}

/** Relative path of `candidate` under `root` (forward slashes), or null when not under it. */
export function relUnder(candidate: string, root: string, caseInsensitive: boolean): string | null {
  let c = candidate.replaceAll("\\", "/").replace(/\/+$/, "");
  let r = root.replaceAll("\\", "/").replace(/\/+$/, "");
  if (!r) return null;
  if (caseInsensitive) {
    c = c.toLowerCase();
    r = r.toLowerCase();
  }
  if (c === r) return "";
  if (c.startsWith(`${r}/`)) return c.slice(r.length + 1);
  return null;
}
