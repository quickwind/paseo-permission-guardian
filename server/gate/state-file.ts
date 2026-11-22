import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

export const GATE_STATE_FILE = "gate-state.json";

export interface GateStateFile {
  version: 1;
  latched: boolean;
  fingerprint: string;
  minSamplesAtLatch: number;
  latchedAt: string | null;
  suspendedBy: string[];
  lastReplay: string | null;
}

function isGateStateFile(v: unknown): v is GateStateFile {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    o.version === 1 &&
    typeof o.latched === "boolean" &&
    typeof o.fingerprint === "string" &&
    typeof o.minSamplesAtLatch === "number" &&
    (o.latchedAt === null || typeof o.latchedAt === "string") &&
    Array.isArray(o.suspendedBy) &&
    o.suspendedBy.every((s) => typeof s === "string") &&
    (o.lastReplay === null || typeof o.lastReplay === "string")
  );
}

/** Returns null when the file is missing, unreadable, non-JSON, or fails schema validation. Never throws. */
export async function readGateState(dataDir: string): Promise<GateStateFile | null> {
  try {
    const parsed: unknown = JSON.parse(await readFile(join(dataDir, GATE_STATE_FILE), "utf8"));
    return isGateStateFile(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/** Writes via a pid-suffixed tmp file then renames over the target. */
export async function writeGateState(dataDir: string, s: GateStateFile): Promise<void> {
  await mkdir(dataDir, { recursive: true });
  const target = join(dataDir, GATE_STATE_FILE);
  const tmp = `${target}.tmp.${process.pid}`;
  await writeFile(tmp, `${JSON.stringify(s, null, 2)}\n`, "utf8");
  await rename(tmp, target);
}
