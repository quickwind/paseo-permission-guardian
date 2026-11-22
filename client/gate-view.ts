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

/** Agent title, or the first 8 characters of the agent id. */
export function entryAgentLabel(entry: Pick<GateEntry, "agentTitle" | "agentId">): string | undefined {
  if (entry.agentTitle) return entry.agentTitle;
  return entry.agentId ? entry.agentId.slice(0, 8) : undefined;
}

/** Local time of the resolution (fallback: request time); unparsable values are shown verbatim. */
export function entryTime(entry: Pick<GateEntry, "resolvedAt" | "requestedAt">): string | undefined {
  const iso = entry.resolvedAt ?? entry.requestedAt;
  if (!iso) return undefined;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export type EntryContentView =
  | { source: "request" | "recovered"; summary?: string; toolName?: string }
  | { source: "missing" }
  | { source: "none" };

/** What the entry was about: the recorded request, a timeline recovery (orphans), or nothing. */
export function entryContentView(entry: GateEntry): EntryContentView {
  const summary = entry.summary ?? entry.command;
  if (summary || entry.toolName) {
    return {
      source: "request",
      ...(summary ? { summary } : {}),
      ...(entry.toolName ? { toolName: entry.toolName } : {}),
    };
  }
  if (entry.kind === "orphan_deny") {
    const oc = entry.orphanContext;
    if (oc && !oc.unavailable && (oc.summary || oc.toolName)) {
      return {
        source: "recovered",
        ...(oc.summary ? { summary: oc.summary } : {}),
        ...(oc.toolName ? { toolName: oc.toolName } : {}),
      };
    }
    return { source: "missing" };
  }
  if (entry.kind === "false_allow" || entry.kind === "unevaluable_deny") return { source: "missing" };
  return { source: "none" };
}

export type ChoiceLabelKey =
  | "act.entries.choice.allow"
  | "act.entries.choice.allowOnce"
  | "act.entries.choice.allowAlways"
  | "act.entries.choice.deny"
  | "act.entries.choice.denyOnce"
  | "act.entries.choice.denyAlways";

export function choiceLabelKey(resolution: NonNullable<GateEntry["resolution"]>): ChoiceLabelKey {
  const id = resolution.selectedActionId ?? "";
  const scope = /once/i.test(id) ? "Once" : /always|session|forever/i.test(id) ? "Always" : "";
  return `act.entries.choice.${resolution.behavior}${scope}` as ChoiceLabelKey;
}
