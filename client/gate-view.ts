import type { GateEntry, GateStatus, GuardianStatusSnapshot } from "../shared/types.js";

/** Pure view helpers for the settings screen (no React Native imports; unit-tested). */

export function effectiveModeLabelKey(
  mode: GuardianStatusSnapshot["effectiveMode"],
): "mode.effectiveValues.act" | "mode.effectiveValues.off" | "mode.effectiveValues.shadow" {
  if (mode === "act") return "mode.effectiveValues.act";
  if (mode === "off") return "mode.effectiveValues.off";
  return "mode.effectiveValues.shadow";
}

/** Integrity is bad when the gate is unavailable or any entry is not a plain false allow. */
export function hasIntegrityProblem(gate: Pick<GateStatus, "state" | "entries">): boolean {
  return gate.state === "unavailable" || gate.entries.some((e) => e.kind !== "false_allow");
}

export function entryActionLabelKey(
  entry: Pick<GateEntry, "kind">,
): "act.entries.acknowledge" | "act.entries.annotate" {
  return entry.kind === "corrupt_line" ? "act.entries.acknowledge" : "act.entries.annotate";
}
