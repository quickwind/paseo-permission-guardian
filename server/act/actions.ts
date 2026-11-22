import type { AgentPermissionRequest } from "@getpaseo/protocol/agent-types";

export const AUTO_ANSWER_PROVIDERS: ReadonlySet<string> = new Set(["agy"]);

// The spec pattern's bare `all` would match the legitimate ids/labels "allow"/"Allow", so `all`
// only counts as a standalone token (not surrounded by letters): "allow_all", "Allow all" match.
const PERSISTENT = /always|session|remember|forever|(?<![a-z])all(?![a-z])|persist/i;

type Action = NonNullable<AgentPermissionRequest["actions"]>[number];

interface Mapping {
  allowId: string;
  denyId: string;
}

const MAPPINGS: Readonly<Record<string, Mapping>> = {
  agy: { allowId: "allow", denyId: "deny" },
};

export function resolveAnswer(
  provider: string,
  request: AgentPermissionRequest,
  verdict: "allow" | "deny",
): { selectedActionId: string } | null {
  if (!AUTO_ANSWER_PROVIDERS.has(provider)) return null;
  const mapping = Object.hasOwn(MAPPINGS, provider) ? MAPPINGS[provider] : undefined;
  if (!mapping) return null;
  const actions = request.actions;
  if (!Array.isArray(actions)) return null;

  const behavior = verdict;
  const wantedId = verdict === "allow" ? mapping.allowId : mapping.denyId;
  const sameBehavior = actions.filter((a: Action) => a?.behavior === behavior);
  if (sameBehavior.length !== 1) return null;
  const action = sameBehavior[0]!;
  if (action.id !== wantedId) return null;
  if (typeof action.id !== "string" || action.id.length === 0) return null;
  if (PERSISTENT.test(action.id) || PERSISTENT.test(String(action.label ?? ""))) return null;
  return { selectedActionId: action.id };
}
