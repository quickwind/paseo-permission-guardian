import type { PluginHookEvents } from "@getpaseo/plugin/server";
import { DEFAULT_GUARDIAN_SETTINGS, type GuardianSettings } from "../shared/settings.js";
import type {
  Action,
  GuardianDecision,
  GuardianStatusSnapshot,
  GuardianVerdict,
  ResolutionActor,
} from "../shared/types.js";
import { AuditStore } from "./audit/store.js";
import { detectHostOs, normalizePermissionRequest } from "./normalize/index.js";

export interface PluginAnsweredEntry {
  decision: GuardianVerdict;
  answeredAt: number;
}

export interface GuardianServiceOptions {
  auditStore: AuditStore;
  pluginVersion: string;
  initialSettings?: GuardianSettings;
  answeredTtlMs?: number;
  now?: () => number;
}

const DEFAULT_ANSWERED_TTL_MS = 10 * 60 * 1000; // 10 minutes
const NEVER_AUTO_ANSWER_KINDS = new Set<Action["kind"]>(["question", "plan", "mode"]);

export class PermissionGuardianService {
  private readonly auditStore: AuditStore;
  private readonly pluginVersion: string;
  private readonly answeredTtlMs: number;
  private readonly now: () => number;
  private readonly answeredByPlugin = new Map<string, PluginAnsweredEntry>();

  private settings: GuardianSettings;

  constructor(options: GuardianServiceOptions) {
    this.auditStore = options.auditStore;
    this.pluginVersion = options.pluginVersion;
    this.answeredTtlMs = options.answeredTtlMs ?? DEFAULT_ANSWERED_TTL_MS;
    this.now = options.now ?? (() => Date.now());
    this.settings = options.initialSettings ?? DEFAULT_GUARDIAN_SETTINGS;
  }

  updateSettings(next: GuardianSettings): void {
    this.settings = next;
  }

  getSettings(): GuardianSettings {
    return this.settings;
  }

  getStatus(): GuardianStatusSnapshot {
    return {
      pluginVersion: this.pluginVersion,
      mode: this.settings.mode,
      effectiveMode: this.settings.mode === "off" ? "off" : "shadow",
      dataDir: this.auditStore.getDataDir(),
      metrics: this.auditStore.getMetrics(),
    };
  }

  /**
   * Record that this plugin submitted a response for requestId (used in P2+ act mode).
   */
  markAnsweredByPlugin(requestId: string, decision: GuardianVerdict): void {
    this.evictExpiredAnswers();
    this.answeredByPlugin.set(requestId, {
      decision,
      answeredAt: this.now(),
    });
  }

  unmarkAnsweredByPlugin(requestId: string): void {
    this.answeredByPlugin.delete(requestId);
  }

  async handlePermissionBefore(
    payload: PluginHookEvents["agent.permission.before"],
  ): Promise<void> {
    if (this.settings.mode === "off") {
      return;
    }

    const startedAt = this.now();
    try {
      const normalized = normalizePermissionRequest(payload.request, {
        agentId: payload.agent.id,
        provider: payload.request.provider || payload.agent.provider,
        cwd: payload.agent.cwd,
        hostOs: detectHostOs(),
        windowsDefaultShell: this.settings.windowsDefaultShell,
        includeRaw: this.settings.includeRawInAudit,
      });

      const decision = this.evaluateP0ShadowDecision(normalized.action, normalized.warnings);
      const latencyMs = Math.max(0, this.now() - startedAt);

      await this.auditStore.recordBefore({
        requestId: payload.request.id,
        agentId: payload.agent.id,
        provider: normalized.action.provider,
        mode: this.settings.mode,
        requestedAt: new Date(startedAt).toISOString(),
        latencyMs,
        normalizedBy: normalized.normalizedBy,
        warnings: normalized.warnings,
        action: normalized.action,
        decision,
      });
    } catch (error) {
      // Fail-to-human invariant: never auto-allow, never auto-deny, never break Paseo hook delivery.
      console.error(
        `[paseo-permission-guardian] Error handling agent.permission.before for ${payload.request.id}:`,
        error,
      );
    }
  }

  async handlePermissionAfter(
    payload: PluginHookEvents["agent.permission.after"],
  ): Promise<void> {
    if (this.settings.mode === "off") {
      return;
    }

    try {
      const actor = this.resolveActor(payload.requestId);
      await this.auditStore.recordAfter({
        requestId: payload.requestId,
        agentId: payload.agent.id,
        provider: payload.agent.provider,
        mode: this.settings.mode,
        resolution: {
          behavior: payload.resolution.behavior,
          selectedActionId: payload.resolution.selectedActionId,
          message:
            payload.resolution.behavior === "deny" ? payload.resolution.message : undefined,
          resolvedAt: new Date(this.now()).toISOString(),
          actor,
        },
      });
    } catch (error) {
      console.error(
        `[paseo-permission-guardian] Error handling agent.permission.after for ${payload.requestId}:`,
        error,
      );
    }
  }

  async flush(): Promise<void> {
    await this.auditStore.flush();
  }

  private evaluateP0ShadowDecision(action: Action, warnings: string[]): GuardianDecision {
    if (NEVER_AUTO_ANSWER_KINDS.has(action.kind)) {
      return {
        level: "L2",
        verdict: "ask",
        reasons: [`never_auto_answer:${action.kind}`],
        neverAutoAnswer: true,
      };
    }

    const reasons = ["p0_shadow_only"];
    if (action.kind === "other") {
      reasons.push("unclassified_action");
    }
    if (warnings.length > 0) {
      reasons.push(...warnings);
    }

    return {
      level: "L1",
      verdict: "ask",
      reasons,
    };
  }

  private resolveActor(requestId: string): ResolutionActor {
    this.evictExpiredAnswers();
    const entry = this.answeredByPlugin.get(requestId);
    if (entry) {
      this.answeredByPlugin.delete(requestId);
      return "plugin";
    }
    return "human";
  }

  private evictExpiredAnswers(): void {
    const cutoff = this.now() - this.answeredTtlMs;
    for (const [key, value] of this.answeredByPlugin.entries()) {
      if (value.answeredAt < cutoff) {
        this.answeredByPlugin.delete(key);
      }
    }
  }
}
