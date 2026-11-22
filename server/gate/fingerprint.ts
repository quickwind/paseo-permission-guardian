import { createHash } from "node:crypto";
import { resolvePaseoSelfRoots } from "../paths/index.js";

/** Version of the persisted engine data layout. Bump when stored gate data changes shape. */
export const ENGINE_DATA_VERSION = 1;

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
