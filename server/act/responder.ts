import type { AgentPermissionRequest, AgentPermissionResponse } from "@getpaseo/protocol/agent-types";
import type { ActOutcome, ActionKind, GuardianDecision } from "../../shared/types.js";
import { redactString } from "../audit/redact.js";
import type { AuditStore } from "../audit/store.js";
import type { GateController } from "../gate/gate.js";
import { resolveAnswer } from "./actions.js";

/**
 * Act-mode responder (spec §3.5, §3.6). Answers a permission request on the user's behalf only
 * when every check passes; every error or doubt leaves the request to the human.
 */

/** Sends a permission response. Production wraps `context.paseo.agents.ref(id).respondToPermission`. */
export interface PermissionAnswerer {
  respond(agentId: string, requestId: string, response: AgentPermissionResponse): Promise<void>;
}

export interface MaybeAnswerInput {
  agentId: string;
  request: AgentPermissionRequest;
  decision: GuardianDecision;
  kind: ActionKind;
  signal?: AbortSignal;
  answerer: PermissionAnswerer;
}

interface Mark {
  behavior: "allow" | "deny";
  selectedActionId: string;
  sentAt: number;
  /** Set once the attribution window elapsed without a matching `after`. */
  unconfirmed: boolean;
  timer: ReturnType<typeof setTimeout> | null;
}

const DEFAULT_WINDOW_MS = 15_000;
/** Marks are kept this long only to recognise late `after` events (spec §3.6). */
const DEFAULT_MARK_TTL_MS = 10 * 60 * 1000;
const NEVER_ANSWER_KINDS: ReadonlySet<ActionKind> = new Set<ActionKind>(["question", "plan", "mode"]);
const DENY_PREFIX = "Blocked by Permission Guardian: ";
const DENY_MESSAGE_MAX = 500;

export function buildDenyMessage(reasons: readonly string[]): string {
  const body = redactString(reasons.join("; "));
  return `${DENY_PREFIX}${body}`.slice(0, DENY_MESSAGE_MAX);
}

export class ActResponder {
  private readonly gate: GateController;
  private readonly store: AuditStore;
  private readonly now: () => number;
  private readonly windowMs: number;
  private readonly markTtlMs: number;
  private readonly marks = new Map<string, Mark>();
  private disposed = false;

  constructor(opts: {
    gate: GateController;
    store: AuditStore;
    now: () => number;
    windowMs?: number;
    markTtlMs?: number;
  }) {
    this.gate = opts.gate;
    this.store = opts.store;
    this.now = opts.now;
    this.windowMs = opts.windowMs ?? DEFAULT_WINDOW_MS;
    this.markTtlMs = opts.markTtlMs ?? DEFAULT_MARK_TTL_MS;
  }

  /**
   * Returns `"skipped"` when no answer was sent, `"error"` when sending threw, and `"answered"` when
   * a response frame was sent. Sending is fire-and-forget: whether it was applied is decided only by
   * the matching `after` event (`attribute`), which records the final `actOutcome`.
   */
  async maybeAnswer(input: MaybeAnswerInput): Promise<ActOutcome> {
    const { agentId, request, decision, kind, signal, answerer } = input;
    const requestId = request.id;
    let marked: Mark | null = null;
    try {
      if (this.disposed) return "skipped";
      // 1. Effective mode must be act.
      if (this.gate.effectiveMode() !== "act") return "skipped";
      // 2. The `after` event already arrived (in-memory record has a resolution).
      if (this.alreadyResolved(requestId)) return "skipped";
      // 3. Never-auto-answer decisions and kinds.
      if (decision.neverAutoAnswer || NEVER_ANSWER_KINDS.has(kind)) return "skipped";
      if (this.marks.has(requestId)) return "skipped";

      // 4. Map verdict to a provider action.
      let response: AgentPermissionResponse;
      if (decision.verdict === "allow" && decision.level === "L0") {
        const resolved = resolveAnswer(request.provider, request, "allow");
        if (!resolved) return "skipped";
        response = { behavior: "allow", selectedActionId: resolved.selectedActionId };
      } else if (decision.verdict === "deny" && decision.level === "L3") {
        if (!this.gate.canAutoDeny()) return "skipped";
        const resolved = resolveAnswer(request.provider, request, "deny");
        if (!resolved) return "skipped";
        response = {
          behavior: "deny",
          selectedActionId: resolved.selectedActionId,
          message: buildDenyMessage(decision.reasons ?? []),
        };
      } else {
        return "skipped";
      }

      // 5. Re-check immediately before sending.
      if (this.disposed || signal?.aborted) return "skipped";
      if (this.gate.effectiveMode() !== "act") return "skipped";
      if (response.behavior === "deny" && !this.gate.canAutoDeny()) return "skipped";
      if (this.alreadyResolved(requestId)) return "skipped";

      // 6. Mark before sending so an `after` racing the send is attributed correctly.
      this.evictExpired();
      marked = {
        behavior: response.behavior,
        selectedActionId: response.selectedActionId!,
        sentAt: this.now(),
        unconfirmed: false,
        timer: null,
      };
      const mark = marked;
      mark.timer = setTimeout(() => this.onWindowElapsed(requestId, mark), this.windowMs);
      mark.timer.unref?.();
      this.marks.set(requestId, mark);

      // 7. Fire-and-forget send.
      await answerer.respond(agentId, requestId, response);
      return "answered";
    } catch (error) {
      console.error(`[paseo-permission-guardian] act responder failed for ${requestId}:`, error);
      if (marked && this.marks.get(requestId) === marked) {
        this.clearMark(requestId, marked);
        this.store.setActOutcome(requestId, "error");
      }
      return marked ? "error" : "skipped";
    }
  }

  /**
   * Attribution (spec §3.6): `plugin` only if this request is marked, the resolution matches what
   * was sent (behavior and selectedActionId) and it arrived within the window. One-shot: the mark is
   * consumed. Records `actOutcome` on the in-memory record (preserved by the following
   * `recordAfter`) and informs the gate.
   */
  attribute(requestId: string, resolution: AgentPermissionResponse): "plugin" | "human" {
    try {
      this.evictExpired();
      const mark = this.marks.get(requestId);
      if (!mark) return "human";
      this.clearMark(requestId, mark);

      const matches =
        resolution.behavior === mark.behavior && resolution.selectedActionId === mark.selectedActionId;
      if (!matches) {
        this.store.setActOutcome(requestId, "lost_race");
        // Same behavior but a different/missing selectedActionId: the plugin's frame may have been
        // the one applied without an echo, so it counts toward the unconfirmed streak (F4).
        if (resolution.behavior === mark.behavior && !mark.unconfirmed) this.gate.noteActOutcome("lost_race");
        return "human";
      }
      const inWindow = this.now() - mark.sentAt <= this.windowMs;
      if (inWindow && !mark.unconfirmed) {
        this.store.setActOutcome(requestId, "answered");
        this.gate.noteActOutcome("answered");
        return "plugin";
      }
      // Matching but late: the plugin's frame was evidently not applied.
      if (!mark.unconfirmed) this.recordUnconfirmed(requestId);
      return "human";
    } catch (error) {
      console.error(`[paseo-permission-guardian] attribution failed for ${requestId}:`, error);
      return "human";
    }
  }

  dispose(): void {
    this.disposed = true;
    for (const mark of this.marks.values()) {
      if (mark.timer) clearTimeout(mark.timer);
      mark.timer = null;
    }
    this.marks.clear();
  }

  private alreadyResolved(requestId: string): boolean {
    return Boolean(this.store.getRecord(requestId)?.resolution);
  }

  private onWindowElapsed(requestId: string, mark: Mark): void {
    try {
      mark.timer = null;
      if (this.disposed || this.marks.get(requestId) !== mark || mark.unconfirmed) return;
      // Keep the mark (until TTL) only to recognise a late `after`.
      mark.unconfirmed = true;
      this.recordUnconfirmed(requestId);
    } catch (error) {
      console.error(`[paseo-permission-guardian] unconfirmed handling failed for ${requestId}:`, error);
    }
  }

  private recordUnconfirmed(requestId: string): void {
    this.store.setActOutcome(requestId, "unconfirmed");
    this.gate.noteActOutcome("unconfirmed");
  }

  private clearMark(requestId: string, mark: Mark): void {
    if (mark.timer) clearTimeout(mark.timer);
    mark.timer = null;
    this.marks.delete(requestId);
  }

  private evictExpired(): void {
    const cutoff = this.now() - this.markTtlMs;
    for (const [id, mark] of this.marks) {
      if (mark.sentAt >= cutoff) continue;
      this.clearMark(id, mark);
      if (!mark.unconfirmed) this.recordUnconfirmed(id);
    }
  }
}
