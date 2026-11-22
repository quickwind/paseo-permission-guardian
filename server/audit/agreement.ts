import type { AgreementOutcome, AuditResolution, GuardianDecision } from "../../shared/types.js";

export function computeAgreement(
  decision: GuardianDecision | undefined,
  resolution: AuditResolution | undefined,
): AgreementOutcome {
  if (!decision || !resolution) {
    return "pending";
  }

  if (resolution.actor === "plugin") {
    return "agree";
  }

  if (decision.verdict === "allow") {
    return resolution.behavior === "allow" ? "agree" : "false_allow";
  }

  if (decision.verdict === "deny") {
    return resolution.behavior === "deny" ? "agree" : "false_deny";
  }

  if (decision.verdict === "ask") {
    return resolution.behavior === "allow"
      ? "plugin_ask_human_allow"
      : "plugin_ask_human_deny";
  }

  return "unknown";
}
