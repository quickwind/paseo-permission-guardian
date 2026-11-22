import type {
  Action,
  EffectTag,
  GuardianDecision,
  GuardianVerdict,
  RiskLevel,
} from "../shared/types.js";
import type { SessionState } from "./context/session.js";
import type { GitStateProvider } from "./context/git-state.js";
import { redactString } from "./audit/redact.js";
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
  /**
   * Live only (ADR-0009): looks up whether non-recursive worktree delete targets are tracked and
   * clean in git. Absent ⇒ every such target is treated as not clean (L1).
   */
  gitStateProvider?: GitStateProvider;
  /**
   * Replay only (ADR-0009): per-target results recorded by the live decision, keyed by the
   * redacted effect target. When set, the provider is never called; a missing key ⇒ not clean.
   */
  recordedDeleteTargetsClean?: Record<string, boolean>;
  /** Propagated to the git lookup. */
  signal?: AbortSignal;
}

export interface DecideResult {
  decision: GuardianDecision;
  touchedSecret: boolean;
  touchedUntrusted: boolean;
  /**
   * Per non-recursive worktree delete target (raw effect target ⇒ tracked and clean). Absent when
   * the action has no such target. The live path records it in the audit context snapshot.
   */
  deleteTargetsClean?: Record<string, boolean>;
}

/** Non-recursive `delete_worktree` targets that need the git-clean check (ADR-0009). */
function deleteTargetsNeedingGitCheck(effects: EffectTag[]): string[] {
  const targets = new Set<string>();
  for (const e of effects) {
    if (e.tag === "delete_worktree" && !e.recursive && typeof e.target === "string") {
      targets.add(e.target);
    }
  }
  return [...targets];
}

async function resolveDeleteTargetsClean(
  targets: string[],
  options: DecideOptions,
): Promise<Record<string, boolean>> {
  const out: Record<string, boolean> = {};
  if (options.recordedDeleteTargetsClean) {
    const recorded = options.recordedDeleteTargetsClean;
    for (const t of targets) {
      const key = redactString(t);
      out[t] = Object.prototype.hasOwnProperty.call(recorded, key) && recorded[key] === true;
    }
    return out;
  }
  let looked: Record<string, boolean> = {};
  if (options.gitStateProvider) {
    try {
      const worktreeRoot = options.pathCtx.worktreeRoot ?? options.pathCtx.cwd;
      looked = await options.gitStateProvider({
        worktreeRoot,
        targets,
        ...(options.signal ? { signal: options.signal } : {}),
      });
    } catch {
      looked = {};
    }
  }
  for (const t of targets) {
    out[t] = looked !== null && typeof looked === "object" && looked[t] === true;
  }
  return out;
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
      // Non-recursive: L0 here; the git-clean check in decideAction raises it (ADR-0009).
      return effect.recursive
        ? { level: "L1", reason: `recursive_delete_worktree:${effect.target ?? ""}` }
        : { level: "L0" };

    case "opaque":
      return { level: "L1", reason: `opaque:${effect.detail ?? effect.target ?? "unknown"}` };

    case "exec_inline":
      return effect.detail === "execution_policy_bypass"
        ? { level: "L2", reason: "execution_policy_bypass" }
        : { level: "L1", reason: `exec_inline:${effect.detail ?? effect.target ?? ""}` };

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

  const deleteTargets = deleteTargetsNeedingGitCheck(effects);
  const deleteTargetsClean =
    deleteTargets.length > 0 ? await resolveDeleteTargetsClean(deleteTargets, options) : undefined;

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

  // ADR-0009: a non-recursive worktree delete is L0 only for tracked files without uncommitted changes.
  if (deleteTargetsClean) {
    for (const [target, clean] of Object.entries(deleteTargetsClean)) {
      if (clean) continue;
      maxLevel = elevateLevel(maxLevel, "L1");
      reasons.push(`delete_uncommitted:${target}`);
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

  // Rule 3: net_read piped into an interpreter, network read + dynamic eval, or downloaded-and-executed file -> L3 deny
  if (hasNetReadPipedToInterpreter(pipelines)) {
    maxLevel = elevateLevel(maxLevel, "L3");
    reasons.push("combo:net_read_piped_to_interpreter");
  }

  const hasAnyNetRead = effects.some((e) => e.tag === "net_read");
  const hasDynamicPwshEval = effects.some(
    (e) =>
      e.tag === "exec_inline" &&
      ((e.target === "Invoke-Expression" && e.detail !== "iex_static") ||
        e.target === "[scriptblock]::Create"),
  );
  const hasAnyPwshEval = effects.some(
    (e) =>
      e.tag === "exec_inline" &&
      (e.target === "Invoke-Expression" || e.target === "[scriptblock]::Create"),
  );
  if (hasAnyNetRead && hasDynamicPwshEval) {
    maxLevel = elevateLevel(maxLevel, "L3");
    reasons.push("combo:net_read_and_dynamic_eval");
  } else if (hasAnyNetRead && hasAnyPwshEval) {
    maxLevel = elevateLevel(maxLevel, "L2");
    reasons.push("combo:net_read_and_static_eval");
  }

  if (effects.some((e) => e.tag === "exec_network_sourced" && e.detail === "downloaded_and_executed")) {
    maxLevel = elevateLevel(maxLevel, "L3");
    reasons.push("combo:download_and_execute_file");
  }

  const denyAsAsk = options.denyAsAsk ?? false;
  const verdict = levelToVerdict(maxLevel, denyAsAsk);

  if (reasons.length === 0) {
    reasons.push("deterministic_l0_safe");
  }

  const redactedReasons = Array.from(new Set(reasons.map((r) => redactString(r))));
  const redactedOpaqueReasons = Array.from(new Set(opaqueReasons.map((r) => redactString(r))));
  const redactedEffects = effects.map((e) => ({
    ...e,
    ...(e.target !== undefined ? { target: redactString(e.target) } : {}),
    ...(e.detail !== undefined ? { detail: redactString(e.detail) } : {}),
  }));

  return {
    decision: {
      level: maxLevel,
      verdict,
      reasons: redactedReasons,
      effects: redactedEffects,
      ...(redactedOpaqueReasons.length > 0 ? { opaqueReasons: redactedOpaqueReasons } : {}),
    },
    touchedSecret: analysis.touchedSecret,
    touchedUntrusted: analysis.touchedUntrusted,
    ...(deleteTargetsClean ? { deleteTargetsClean } : {}),
  };
}
