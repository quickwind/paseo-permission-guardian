import { createHash } from "node:crypto";
import { resolvePaseoHomeRoots, resolvePaseoSelfRoots } from "../paths/index.js";

/**
 * Engine data version, part of the fingerprint. Bump it on ANY decision-affecting change — rules,
 * command registry, path/secret classification, normalization or other classification code — as
 * well as on any change to the shape of stored gate data, so a latch never outlives the engine
 * that earned it.
 */
/** 2: non-recursive worktree deletes require a tracked, clean git file (ADR-0009). */
export const ENGINE_DATA_VERSION = 2;

export interface FingerprintInput {
  pluginVersion: string;
  policyHash?: string | null;
  denyAsAsk: boolean;
  windowsDefaultShell: string;
  /** Digest of decision-relevant environment inputs; see `computeEnvDigest`. */
  envDigest?: string;
}

/**
 * sha256 hex over the environment-derived inputs that can change a live decision (paseo self roots
 * and whether CDPATH is set). Deliberately NOT the whole environment, which would change every
 * restart.
 */
export function computeEnvDigest(
  env: Record<string, string | undefined>,
  home: string,
  dataDir: string,
): string {
  const canonical = JSON.stringify({
    paseoRoots: resolvePaseoSelfRoots(env, home, dataDir),
    paseoHomeRoots: resolvePaseoHomeRoots(env, home),
    cdpathSet: Boolean(env.CDPATH),
  });
  return createHash("sha256").update(canonical).digest("hex");
}

/**
 * sha256 hex over a canonical JSON with a fixed key order. Any change to the
 * engine identity (plugin version, policy, deny-as-ask, default shell, env digest) changes it.
 */
export function computeFingerprint(input: FingerprintInput): string {
  const canonical = JSON.stringify({
    engineDataVersion: ENGINE_DATA_VERSION,
    pluginVersion: input.pluginVersion,
    policyHash: input.policyHash ?? "builtin",
    denyAsAsk: input.denyAsAsk,
    windowsDefaultShell: input.windowsDefaultShell,
    envDigest: input.envDigest ?? "none",
  });
  return createHash("sha256").update(canonical).digest("hex");
}
