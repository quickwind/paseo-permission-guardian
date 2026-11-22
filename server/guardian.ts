import { homedir } from "node:os";
import { emptyGateStatus } from "../shared/types.js";
import type { PluginHookEvents } from "@getpaseo/plugin/server";
import { DEFAULT_GUARDIAN_SETTINGS, type GuardianSettings } from "../shared/settings.js";
import type { AgentPermissionResponse } from "@getpaseo/protocol/agent-types";
import type {
  ContextSnapshot,
  GuardianStatusSnapshot,
  GuardianVerdict,
  OfferedAction,
  ResolutionActor,
} from "../shared/types.js";
import type { ActResponder, PermissionAnswerer } from "./act/responder.js";
import { AuditStore } from "./audit/store.js";
import { createGitStateProvider, type GitStateProvider } from "./context/git-state.js";
import { SessionContextStore, type SessionState, type TimelineFetcher } from "./context/session.js";
import { decideAction } from "./decide.js";
import { buildDecideContext, buildDecidePathCtx } from "./decide-context.js";
import { computeEnvDigest, computeFingerprint } from "./gate/fingerprint.js";
import type { GateController } from "./gate/gate.js";
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
  /** Evidence gate (act mode). Absent ⇒ shadow-only behaviour. */
  gate?: GateController;
  /** Act responder. Absent ⇒ never answers; legacy plugin-mark attribution. */
  responder?: ActResponder;
  /**
   * When true the gate is NOT configured at construction (it stays unconfigured ⇒ shadow, no
   * replay, no latch side effects) until `activateGate()` is called once the audit store and the
   * first real settings read have completed (F7). Default false (configure immediately).
   */
  deferGateConfigure?: boolean;
  /** Git-clean lookup for non-recursive worktree deletes (ADR-0009). Default: the `git` binary. */
  gitStateProvider?: GitStateProvider;
}

export interface PermissionBeforeContext {
  answerer?: PermissionAnswerer;
  signal?: AbortSignal;
}

const SNAPSHOT_MAX_MODIFIED_FILES = 200;

/** Spec §3.7: session state as seen by the decision (taken before this request's own updates). */
export function buildContextSnapshot(session: SessionState, contextUnavailable = false): ContextSnapshot {
  const files = [...session.modifiedFiles];
  return {
    contextUnavailable,
    secretTaint: session.secretTaint,
    untrustedTaint: session.untrustedTaint,
    modifiedEntrypoints: [...session.modifiedEntrypoints],
    modifiedFiles: files.slice(0, SNAPSHOT_MAX_MODIFIED_FILES),
    modifiedFilesTruncated: files.length > SNAPSHOT_MAX_MODIFIED_FILES,
  };
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
  private readonly gate: GateController | undefined;
  private readonly responder: ActResponder | undefined;
  private readonly gitStateProvider: GitStateProvider;

  private settings: GuardianSettings;
  private settingsInvalid = false;
  private settingsInvalidReason: string | null = null;
  private gateActive: boolean;

  constructor(options: GuardianServiceOptions) {
    this.auditStore = options.auditStore;
    this.sessionStore = options.sessionStore ?? new SessionContextStore();
    this.pluginVersion = options.pluginVersion;
    this.answeredTtlMs = options.answeredTtlMs ?? DEFAULT_ANSWERED_TTL_MS;
    this.now = options.now ?? (() => Date.now());
    this.settings = options.initialSettings ?? DEFAULT_GUARDIAN_SETTINGS;
    this.gate = options.gate;
    this.responder = options.responder;
    this.gitStateProvider = options.gitStateProvider ?? createGitStateProvider();
    this.gateActive = options.deferGateConfigure !== true;
    this.configureGate();
  }

  /** Configures the gate for the first time (see `deferGateConfigure`). Idempotent. */
  activateGate(): void {
    if (this.gateActive) return;
    this.gateActive = true;
    this.configureGate();
  }

  updateSettings(next: GuardianSettings): void {
    this.settings = next;
    this.settingsInvalid = false;
    this.settingsInvalidReason = null;
    this.configureGate();
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
    this.configureGate();
  }

  private configureGate(): void {
    if (!this.gate || !this.gateActive) return;
    try {
      const dataDir = this.auditStore.getDataDir();
      const fingerprint = computeFingerprint({
        pluginVersion: this.pluginVersion,
        policyHash: null,
        denyAsAsk: this.settings.denyAsAsk,
        windowsDefaultShell: this.settings.windowsDefaultShell,
        envDigest: computeEnvDigest(process.env, homedir(), dataDir),
      });
      this.gate.configure({
        settings: this.settings,
        settingsValid: !this.settingsInvalid,
        settingsInvalidReason: this.settingsInvalidReason,
        fingerprint,
      });
    } catch (error) {
      // The gate stays in its previous (or unconfigured ⇒ shadow) state.
      console.error("[paseo-permission-guardian] gate configure failed:", error);
    }
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
      effectiveMode: this.gate
        ? this.gate.effectiveMode()
        : this.getEffectiveBaseMode() === "off"
          ? "off"
          : "shadow",
      dataDir: this.auditStore.getDataDir(),
      metrics: this.auditStore.getMetrics(),
      gate: this.gate ? this.gate.status() : emptyGateStatus(),
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
    ctx?: PermissionBeforeContext,
  ): Promise<void> {
    // N4: invalid settings fall back to effective shadow, which still records.
    if (this.getEffectiveBaseMode() === "off") {
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

      const ctxInput = {
        action: normalized.action,
        agentCwd: payload.agent.cwd,
        dataDir: this.auditStore.getDataDir(),
        home: homedir(),
        env: process.env,
        denyAsAsk: this.settings.denyAsAsk,
      };
      const pathCtx = buildDecidePathCtx(ctxInput);

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

      // Spec §3.7: snapshot before decideAction and before this request's own taint updates.
      const contextSnapshot = buildContextSnapshot(session, contextUnavailable);

      const evaluated = await decideAction(
        normalized.action,
        buildDecideContext({
          ...ctxInput,
          session,
          contextUnavailable,
          gitStateProvider: this.gitStateProvider,
          ...(ctx?.signal ? { signal: ctx.signal } : {}),
        }),
      );
      if (evaluated.deleteTargetsClean) {
        contextSnapshot.deleteTargetsClean = { ...evaluated.deleteTargetsClean };
      }

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
      const offeredActions: OfferedAction[] =
        payload.request.actions?.map((a) => ({ id: a.id, behavior: a.behavior })) ?? [];

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
        offeredActions,
        contextSnapshot,
      });

      // Spec §3.5: act path (recordBefore above is memory-first; disk append is queued).
      if (this.responder && ctx?.answerer) {
        await this.responder.maybeAnswer({
          agentId: payload.agent.id,
          request: payload.request,
          decision: evaluated.decision,
          kind: normalized.action.kind,
          answerer: ctx.answerer,
          ...(ctx.signal ? { signal: ctx.signal } : {}),
        });
      }
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
    // N4: invalid settings fall back to effective shadow, which still records.
    if (this.getEffectiveBaseMode() === "off") {
      return;
    }

    try {
      const actor = this.resolveActor(payload.requestId, payload.resolution);
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

  private resolveActor(requestId: string, resolution: AgentPermissionResponse): ResolutionActor {
    if (this.responder) return this.responder.attribute(requestId, resolution);
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
