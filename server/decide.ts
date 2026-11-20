import type {
  Action,
  EffectTag,
  GuardianDecision,
  GuardianVerdict,
  RiskLevel,
} from "../shared/types.js";
import type { SessionState } from "./context/session.js";
import {
  analyzeActionEffects,
  hasNetReadPipedToInterpreter,
  type EffectAnalysisOptions,
} from "./effects.js";

const LEVEL_ORDER: Record<RiskLevel, number> = {
  L0: 0,
  L1: 1,
  L2: 2,
  L3: 3,
};

const NEVER_AUTO_ANSWER_KINDS = new Set<Action["kind"]>(["question", "plan", "mode"]);

export interface DecideOptions extends EffectAnalysisOptions {
  denyAsAsk?: boolean;
}

export interface DecideResult {
  decision: GuardianDecision;
  touchedSecret: boolean;
  touchedUntrusted: boolean;
}

function elevateLevel(current: RiskLevel, candidate: RiskLevel): RiskLevel {
  return LEVEL_ORDER[candidate] > LEVEL_ORDER[current] ? candidate : current;
}

function bumpOneLevel(level: RiskLevel): RiskLevel {
  if (level === "L0") return "L1";
  if (level === "L1") return "L2";
  return level;
}

function levelToVerdict(level: RiskLevel, denyAsAsk: boolean): GuardianVerdict {
  if (level === "L0") return "allow";
  if (level === "L3") return denyAsAsk ? "ask" : "deny";
  return "ask";
}

function baseLevelForEffect(effect: EffectTag): { level: RiskLevel; reason?: string } {
  switch (effect.tag) {
    case "read":
    case "write_worktree":
    case "exec_project":
    case "infra_read":
      return { level: "L0" };

    case "net_read":
      return effect.detail === "trusted_domain"
        ? { level: "L0" }
        : { level: "L1", reason: `untrusted_net_read:${effect.target ?? ""}` };

    case "delete_worktree":
      return effect.recursive
        ? { level: "L1", reason: `recursive_delete_worktree:${effect.target ?? ""}` }
        : { level: "L0" };

    case "opaque":
      return { level: "L1", reason: `opaque:${effect.detail ?? effect.target ?? "unknown"}` };

    case "exec_inline":
      return { level: "L1", reason: `exec_inline:${effect.detail ?? effect.target ?? ""}` };

    case "exec_network_sourced":
      return { level: "L1", reason: `exec_network_sourced:${effect.target ?? ""}` };

    case "pkg_install":
      return { level: "L1", reason: "pkg_install" };

    case "write_outside":
      return effect.detail === "temp_dir"
        ? { level: "L1", reason: "write_temp_dir" }
        : { level: "L2", reason: `write_outside:${effect.target ?? ""}` };

    case "read_secret":
      return { level: "L2", reason: `read_secret:${effect.target ?? ""}` };

    case "net_egress":
      return { level: "L2", reason: `net_egress:${effect.target ?? ""}` };

    case "vcs_remote":
      return { level: "L2", reason: `vcs_remote:${effect.detail ?? ""}` };

    case "infra_mutate":
      return { level: "L2", reason: `infra_mutate:${effect.target ?? ""}` };

    case "privilege":
      return { level: "L2", reason: `privilege:${effect.detail ?? effect.target ?? ""}` };

    case "write_protected":
      return effect.pluginSelf
        ? { level: "L3", reason: "write_protected:plugin_self" }
        : { level: "L2", reason: `write_protected:${effect.target ?? ""}` };

    case "delete_outside":
      return effect.recursive
        ? { level: "L3", reason: `recursive_delete_outside:${effect.target ?? ""}` }
        : { level: "L2", reason: `delete_outside:${effect.target ?? ""}` };

    case "system_destructive":
      return { level: "L3", reason: `system_destructive:${effect.target ?? ""}` };
  }
}

/**
 * Deterministic risk classifier (ADR-0001 & ADR-0002).
 * Runs fresh on every request with zero cross-state caching.
 */
export async function decideAction(
  action: Action,
  options: DecideOptions,
): Promise<DecideResult> {
  if (NEVER_AUTO_ANSWER_KINDS.has(action.kind)) {
    return {
      decision: {
        level: "L2",
        verdict: "ask",
        reasons: [`never_auto_answer:${action.kind}`],
        neverAutoAnswer: true,
      },
      touchedSecret: false,
      touchedUntrusted: false,
    };
  }

  const analysis = await analyzeActionEffects(action, options);
  const { effects, opaqueReasons, pipelines } = analysis;
  const session: SessionState | undefined = options.session;

  let maxLevel: RiskLevel = "L0";
  const reasons: string[] = [];

  if (effects.length === 0) {
    maxLevel = "L1";
    reasons.push("no_effects_extracted");
  }

  for (const effect of effects) {
    const base = baseLevelForEffect(effect);
    let effectLevel = base.level;

    // Untrusted taint raises net_egress, exec_*, and vcs_remote by one level (ADR-0002)
    if (
      session?.untrustedTaint &&
      (effect.tag === "net_egress" ||
        effect.tag === "exec_project" ||
        effect.tag === "exec_inline" ||
        effect.tag === "exec_network_sourced" ||
        effect.tag === "vcs_remote")
    ) {
      effectLevel = bumpOneLevel(effectLevel);
      reasons.push(`untrusted_taint_elevated:${effect.tag}`);
    }

    maxLevel = elevateLevel(maxLevel, effectLevel);
    if (base.reason) {
      reasons.push(base.reason);
    }
  }

  // Cross-layer combination rules (DESIGN.md §10.3)
  const hasReadSecret = effects.some((e) => e.tag === "read_secret");
  const hasNetEgress = effects.some((e) => e.tag === "net_egress");

  // Rule 1: read_secret + net_egress anywhere in the call (any layer) -> L3 deny
  if (hasReadSecret && hasNetEgress) {
    maxLevel = elevateLevel(maxLevel, "L3");
    reasons.push("combo:read_secret_and_net_egress");
  }

  // Rule 2: secretTaint active + net_egress in a later call -> at least L2 ask
  if (session?.secretTaint && hasNetEgress) {
    maxLevel = elevateLevel(maxLevel, "L2");
    reasons.push("combo:secret_taint_and_net_egress");
  }

  // Rule 3: net_read piped into an interpreter (curl | sh, wget | bash) -> L3 deny
  if (hasNetReadPipedToInterpreter(pipelines)) {
    maxLevel = elevateLevel(maxLevel, "L3");
    reasons.push("combo:net_read_piped_to_interpreter");
  }

  const denyAsAsk = options.denyAsAsk ?? false;
  const verdict = levelToVerdict(maxLevel, denyAsAsk);

  if (reasons.length === 0) {
    reasons.push("deterministic_l0_safe");
  }

  return {
    decision: {
      level: maxLevel,
      verdict,
      reasons: Array.from(new Set(reasons)),
      effects,
      ...(opaqueReasons.length > 0 ? { opaqueReasons } : {}),
    },
    touchedSecret: analysis.touchedSecret,
    touchedUntrusted: analysis.touchedUntrusted,
  };
}
