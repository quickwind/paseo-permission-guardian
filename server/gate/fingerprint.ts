import { createHash } from "node:crypto";

/** Version of the persisted engine data layout. Bump when stored gate data changes shape. */
export const ENGINE_DATA_VERSION = 1;

export interface FingerprintInput {
  pluginVersion: string;
  policyHash?: string | null;
  denyAsAsk: boolean;
  windowsDefaultShell: string;
}

/**
 * sha256 hex over a canonical JSON with a fixed key order. Any change to the
 * engine identity (plugin version, policy, deny-as-ask, default shell) changes it.
 */
export function computeFingerprint(input: FingerprintInput): string {
  const canonical = JSON.stringify({
    engineDataVersion: ENGINE_DATA_VERSION,
    pluginVersion: input.pluginVersion,
    policyHash: input.policyHash ?? "builtin",
    denyAsAsk: input.denyAsAsk,
    windowsDefaultShell: input.windowsDefaultShell,
  });
  return createHash("sha256").update(canonical).digest("hex");
}
