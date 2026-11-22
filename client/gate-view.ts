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

export type CountedKind = "orphan_deny" | "unevaluable_deny" | "corrupt_line";
export const COUNTED_KINDS: readonly CountedKind[] = ["orphan_deny", "unevaluable_deny", "corrupt_line"];

/** Per-kind entry counts for the summary rows (false_allow is shown from the gate's own counter). */
export function entryKindCounts(entries: readonly Pick<GateEntry, "kind">[]): Record<CountedKind, number> {
  const out: Record<CountedKind, number> = { orphan_deny: 0, unevaluable_deny: 0, corrupt_line: 0 };
  for (const e of entries) if (e.kind !== "false_allow") out[e.kind] += 1;
  return out;
}

/** Summary rows to show: only kinds with at least one entry, with their label key. */
export function entryCountRows(
  entries: readonly Pick<GateEntry, "kind">[],
): { kind: CountedKind; count: number; labelKey: `act.counts.${CountedKind}` }[] {
  const counts = entryKindCounts(entries);
  return COUNTED_KINDS.filter((k) => counts[k] > 0).map((kind) => ({
    kind,
    count: counts[kind],
    labelKey: `act.counts.${kind}` as const,
  }));
}

export type IntegrityKey =
  | "act.integrityNormal"
  | "act.integritySep"
  | "act.integrityUnavailable"
  | `act.integrityDetail.${CountedKind}.${"one" | "other"}`;

/**
 * Words describing what is wrong, e.g. "1 unmatched denial needs review" / "1 条未匹配的拒绝待处理";
 * kinds are joined; "Normal" when nothing is wrong. Takes a translator so it stays locale-agnostic.
 */
export function integrityText(
  gate: Pick<GateStatus, "state" | "entries">,
  t: (key: IntegrityKey) => string,
): string {
  const counts = entryKindCounts(gate.entries);
  const parts = COUNTED_KINDS.filter((k) => counts[k] > 0).map((k) => {
    const n = counts[k];
    const word = t(`act.integrityDetail.${k}.${n === 1 ? "one" : "other"}`);
    return `${n} ${word}`;
  });
  if (gate.state === "unavailable" && parts.length === 0) return t("act.integrityUnavailable");
  if (parts.length === 0) return t("act.integrityNormal");
  return parts.join(t("act.integritySep"));
}

/** Navigation subset used by the settings screen (undefined on older hosts). */
export interface OpenAgentNavigation {
  readonly openAgent: (input: { readonly agentId: string; readonly serverId?: string }) => void;
}

/** The open-chat action is available only with navigation and an agent id. */
export function canOpenChat(
  entry: Pick<GateEntry, "agentId">,
  navigation: Partial<OpenAgentNavigation> | undefined,
): boolean {
  return Boolean(entry.agentId) && typeof navigation?.openAgent === "function";
}

/** Opens the entry's agent chat; returns whether it was opened. */
export function openEntryChat(
  entry: Pick<GateEntry, "agentId">,
  navigation: Partial<OpenAgentNavigation> | undefined,
): boolean {
  if (!canOpenChat(entry, navigation) || !entry.agentId) return false;
  navigation!.openAgent!({ agentId: entry.agentId });
  return true;
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
