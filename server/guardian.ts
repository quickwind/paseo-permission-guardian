import { homedir } from "node:os";
import { emptyGateStatus } from "../shared/types.js";
import type { PluginHookEvents } from "@getpaseo/plugin/server";
import { DEFAULT_GUARDIAN_SETTINGS, type GuardianSettings } from "../shared/settings.js";
import type {
  GuardianStatusSnapshot,
  GuardianVerdict,
  ResolutionActor,
} from "../shared/types.js";
import { AuditStore } from "./audit/store.js";
import { SessionContextStore, type SessionState, type TimelineFetcher } from "./context/session.js";
import { decideAction } from "./decide.js";
import { resolvePaseoSelfRoots } from "./paths/index.js";
import { detectHostOs, normalizePermissionRequest } from "./normalize/index.js";

export interface PluginAnsweredEntry {
  decision: GuardianVerdict;
  answeredAt: number;
}

export interface GuardianServiceOptions {
  auditStore: AuditStore;
  pluginVersion: string;
  initialSettings?: GuardianSettings;
  sessionStore?: SessionContextStore;
  answeredTtlMs?: number;
  now?: () => number;
}

const DEFAULT_ANSWERED_TTL_MS = 10 * 60 * 1000; // 10 minutes
const CONTEXT_SENSITIVE_KINDS = new Set(["exec", "fetch", "other"]);

export class PermissionGuardianService {
  private readonly auditStore: AuditStore;
  private readonly sessionStore: SessionContextStore;
  private readonly pluginVersion: string;
  private readonly answeredTtlMs: number;
  private readonly now: () => number;
  private readonly answeredByPlugin = new Map<string, PluginAnsweredEntry>();

  private settings: GuardianSettings;
  private settingsInvalid = false;
  private settingsInvalidReason: string | null = null;

  constructor(options: GuardianServiceOptions) {
    this.auditStore = options.auditStore;
    this.sessionStore = options.sessionStore ?? new SessionContextStore();
    this.pluginVersion = options.pluginVersion;
    this.answeredTtlMs = options.answeredTtlMs ?? DEFAULT_ANSWERED_TTL_MS;
    this.now = options.now ?? (() => Date.now());
    this.settings = options.initialSettings ?? DEFAULT_GUARDIAN_SETTINGS;
  }

  updateSettings(next: GuardianSettings): void {
    this.settings = next;
    this.settingsInvalid = false;
    this.settingsInvalidReason = null;
  }

  getSettings(): GuardianSettings {
    return this.settings;
  }

  getSessionStore(): SessionContextStore {
    return this.sessionStore;
  }

  markSettingsInvalid(reason: string): void {
    this.settingsInvalid = true;
    this.settingsInvalidReason = reason;
  }

  getSettingsInvalidReason(): string | null {
    return this.settingsInvalid ? this.settingsInvalidReason : null;
  }

  getEffectiveBaseMode(): "off" | "shadow" | "act" {
    return this.settingsInvalid ? "shadow" : this.settings.mode;
  }

  getStatus(): GuardianStatusSnapshot {
    return {
      pluginVersion: this.pluginVersion,
      mode: this.settings.mode,
      effectiveMode: this.getEffectiveBaseMode() === "off" ? "off" : "shadow",
      dataDir: this.auditStore.getDataDir(),
      metrics: this.auditStore.getMetrics(),
      gate: emptyGateStatus(),
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
    fetchTimeline?: TimelineFetcher,
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

      const pathCtx = {
        cwd: normalized.action.cwd,
        worktreeRoot: normalized.action.worktreeRoot ?? payload.agent.cwd,
        pluginDataDir: this.auditStore.getDataDir(),
        paseoRoots: resolvePaseoSelfRoots(process.env, homedir(), this.auditStore.getDataDir()),
      };

      // Incremental same-turn timeline sync for context-sensitive calls (ADR-0002)
      let contextUnavailable = false;
      let session: SessionState;
      if (CONTEXT_SENSITIVE_KINDS.has(normalized.action.kind)) {
        const synced = await this.sessionStore.syncFromTimeline(
          payload.agent.id,
          pathCtx,
          fetchTimeline,
        );
        session = synced.state;
        contextUnavailable = !synced.contextAvailable;
      } else {
        session = this.sessionStore.getOrCreate(payload.agent.id);
      }

      const evaluated = await decideAction(normalized.action, {
        pathCtx,
        session,
        contextUnavailable,
        denyAsAsk: this.settings.denyAsAsk,
        envSnapshot: process.env,
      });

      // Update live session context from this request's effects
      if (evaluated.touchedSecret) {
        this.sessionStore.markSecretTaint(payload.agent.id);
      }
      if (evaluated.touchedUntrusted) {
        this.sessionStore.markUntrustedTaint(payload.agent.id);
      }
      if (normalized.action.kind === "edit" && normalized.action.paths) {
        for (const p of normalized.action.paths) {
          this.sessionStore.recordFileModification(payload.agent.id, p, pathCtx);
        }
      }

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
        decision: evaluated.decision,
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

  handleTurnAfter(agentId: string): void {
    this.sessionStore.onTurnEnd(agentId);
  }

  handleAgentClosed(agentId: string): void {
    this.sessionStore.deleteSession(agentId);
  }

  async flush(): Promise<void> {
    await this.auditStore.flush();
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
