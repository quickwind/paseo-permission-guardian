import type { ActOutcome, AuditRecord, GateEntry, GateState, GateStatus } from "../../shared/types.js";
import type { GuardianSettings } from "../../shared/settings.js";
import { readAuditWindow } from "../audit/reader.js";
import type { AuditStore } from "../audit/store.js";
import {
  CONFIRMED_CANCELLATION_SIGNATURES,
  replayWindow,
  type ReplayDecideHandle,
  type ReplayResult,
} from "./replay.js";
import { readGateState, writeGateState, type GateStateFile } from "./state-file.js";

/**
 * Evidence gate (spec §3.2). Decides the effective mode (`off` | `shadow` | `act`).
 *
 * Fail to human: every error path yields `shadow`. Effective mode is `act` only when settings are
 * valid, mode is `act`, a replay for the current fingerprint and window has completed and is
 * available, no audit persist failure is outstanding, the responder is not paused, and the §3.2
 * pseudo-code says `act`.
 */

const DAY_MS = 86_400_000;
const REPLAY_MAX_RECORDS = 20_000;
const UNCONFIRMED_PAUSE_THRESHOLD = 3;
const MIN_SAMPLES_FLOOR = 20;
const MAX_FALSE_ALLOW_ENTRIES = 5;
const MAX_INTEGRITY_ENTRIES = 20;
const DEFAULT_DEBOUNCE_MS = 2_000;

type EffectiveMode = "off" | "shadow" | "act";

interface CompletedReplay {
  fingerprint: string;
  windowDays: number;
  result: ReplayResult;
  /** Non-null ⇒ unavailable (replay's own reason or a controller error). */
  unavailableReason: string | null;
  inWindow: Set<string>;
  annotations: Map<string, "not_safety">;
  at: number;
}

interface Candidate {
  seq: number;
  entry: GateEntry;
}

interface Computed {
  state: GateState;
  reason: string;
  mode: EffectiveMode;
  writeLatch: boolean;
  falseAllowIds: string[];
  overrideValid: boolean;
  latchBase: boolean;
  suspended: boolean;
}

export interface GateConfigureInput {
  settings: GuardianSettings;
  settingsValid: boolean;
  /** Full engine fingerprint, already including the env digest. */
  fingerprint: string;
  /** Reason surfaced as `settings_invalid:<reason>` when `settingsValid` is false. */
  settingsInvalidReason?: string | null;
}

function validMinSamplesAtLatch(n: unknown): n is number {
  return typeof n === "number" && Number.isInteger(n) && n >= MIN_SAMPLES_FLOOR;
}

function sameActGate(a: GuardianSettings["actGate"], b: GuardianSettings["actGate"]): boolean {
  return (
    a.minSamples === b.minSamples &&
    a.windowDays === b.windowDays &&
    a.autoFallbackOnFalseAllow === b.autoFallbackOnFalseAllow &&
    a.allowOverride === b.allowOverride
  );
}

function emptyFile(fingerprint: string): GateStateFile {
  return {
    version: 1,
    latched: false,
    fingerprint,
    minSamplesAtLatch: 0,
    latchedAt: null,
    suspendedBy: [],
    lastReplay: null,
  };
}

export class GateController {
  private readonly store: AuditStore;
  private readonly dataDir: string;
  private readonly replayDecide: ReplayDecideHandle;
  private readonly now: () => number;
  private readonly debounceMs: number;
  private readonly unsubscribe: () => void;

  private settings: GuardianSettings | null = null;
  private settingsValid = false;
  private settingsInvalidReason: string | null = null;
  private fingerprint: string | null = null;

  /** In-memory source of truth for gate-state.json once loaded; null ⇒ not latched. */
  private file: GateStateFile | null = null;
  private fileLoaded = false;
  private writeChain: Promise<void> = Promise.resolve();

  private completed: CompletedReplay | null = null;
  private candidates = new Map<string, Candidate>();
  private seq = 0;
  /** Human allows of recorded-L3 requests seen since the last replay (incremental false-deny). */
  private falseDenyCandidates = new Map<string, number>();
  /** Bumped on every annotate(); replays that started under an older generation are discarded. */
  private annotationGen = 0;
  /** Set when a gate-state.json write fails; cleared by the next successful write. */
  private stateWriteFailed = false;
  private readonly writeState: typeof writeGateState;

  private replayChain: Promise<unknown> = Promise.resolve();
  private queuedReplay: Promise<GateStatus> | null = null;
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private disposed = false;

  private consecutiveUnconfirmed = 0;
  private paused = false;
  /** A manual replay was requested and has not yet been consumed by a run. */
  private pendingManual = false;
  private observedOverrideKey = "none";

  constructor(opts: {
    store: AuditStore;
    dataDir: string;
    replayDecide: ReplayDecideHandle;
    now?: () => number;
    /** Debounce for reconciliation-triggered replays. */
    debounceMs?: number;
    /** Injectable gate-state writer (tests simulate write failures). */
    writeState?: typeof writeGateState;
  }) {
    this.writeState = opts.writeState ?? writeGateState;
    this.store = opts.store;
    this.dataDir = opts.dataDir;
    this.replayDecide = opts.replayDecide;
    this.now = opts.now ?? (() => Date.now());
    this.debounceMs = opts.debounceMs ?? DEFAULT_DEBOUNCE_MS;
    this.unsubscribe = this.store.onMerged((record, previous) => this.onReconciled(record, previous));
  }

  // ---------------------------------------------------------------- configuration

  configure(input: GateConfigureInput): void {
    try {
      const prevSettings = this.settings;
      const prevFingerprint = this.fingerprint;
      this.settings = input.settings;
      this.settingsValid = input.settingsValid;
      this.settingsInvalidReason = input.settingsValid ? null : (input.settingsInvalidReason ?? "unknown");
      this.fingerprint = input.fingerprint;

      this.observeOverride();

      const fingerprintChanged = prevFingerprint !== input.fingerprint;
      const gateChanged = !prevSettings || !sameActGate(prevSettings.actGate, input.settings.actGate);
      this.applyTransitions(false);
      if (fingerprintChanged || gateChanged) void this.replay().catch(() => undefined);
    } catch (error) {
      console.error("[paseo-permission-guardian] gate configure failed:", error);
    }
  }

  // ---------------------------------------------------------------- queries

  effectiveMode(): EffectiveMode {
    try {
      return this.compute().mode;
    } catch (error) {
      console.error("[paseo-permission-guardian] gate effectiveMode failed:", error);
      return this.settings?.mode === "off" && this.settingsValid ? "off" : "shadow";
    }
  }

  canAutoDeny(): boolean {
    try {
      if (this.effectiveMode() !== "act") return false;
      const replay = this.currentReplay();
      return (
        replay !== null &&
        replay.unavailableReason === null &&
        replay.result.falseDenyCount === 0 &&
        this.falseDenyCandidates.size === 0
      );
    } catch {
      return false;
    }
  }

  status(): GateStatus {
    const c = this.safeCompute();
    const s = this.settings;
    const result = this.currentReplay()?.result ?? null;
    const entries: GateEntry[] = [];
    const pf = this.store.getPersistFailure();
    if (pf) entries.push({ kind: "corrupt_line", key: `persist_failure#${pf.firstAt}`, requestId: "", effects: [] });
    const faEntries = this.falseAllowEntries();
    const listed = new Set(faEntries.map((e) => e.requestId));
    if (c.suspended && this.file) {
      // Suspending ids stay annotatable even when the latest replay no longer reports them (R6).
      for (const id of this.file.suspendedBy) {
        if (!listed.has(id)) faEntries.push({ requestId: id, effects: [], kind: "false_allow", key: id });
      }
    }
    entries.push(...faEntries.slice(0, MAX_FALSE_ALLOW_ENTRIES));
    if (result) entries.push(...result.integrity.slice(0, MAX_INTEGRITY_ENTRIES));
    return {
      state: c.state,
      reason: c.reason,
      samples: result?.samples ?? 0,
      minSamples: s?.actGate.minSamples ?? 200,
      falseAllowCount: c.falseAllowIds.length,
      falseDenyCount: (result?.falseDenyCount ?? 0) + this.falseDenyCandidates.size,
      entries,
      unconfirmedCount: this.consecutiveUnconfirmed,
      lastReplayAt: this.completed ? new Date(this.completed.at).toISOString() : null,
      fingerprint: this.fingerprint ?? "",
      override: {
        valid: c.overrideValid,
        accepted: s?.actOverride.accepted ?? false,
        acceptedAt: s?.actOverride.acceptedAt ?? null,
      },
      latched: c.latchBase,
      suspended: c.suspended,
    };
  }

  // ---------------------------------------------------------------- inputs

  noteActOutcome(outcome: ActOutcome): void {
    if (outcome === "answered") {
      this.consecutiveUnconfirmed = 0;
      return;
    }
    // `lost_race` is only reported by the responder when the human's behavior matched what the
    // plugin sent (e.g. a missing selectedActionId echo): the plugin's frame may not have landed.
    if (outcome === "unconfirmed" || outcome === "lost_race") {
      this.consecutiveUnconfirmed += 1;
      if (this.consecutiveUnconfirmed >= UNCONFIRMED_PAUSE_THRESHOLD && !this.paused) {
        this.paused = true;
        this.emit("paused", { reason: "responder_unconfirmed" });
      }
    }
  }

  /**
   * Incremental update on a merged audit record. Never runs the engine itself: a human denial whose
   * live (current-engine) verdict was `allow`, or a human denial with no decision (orphan), is
   * treated as a false-allow candidate immediately (fallback/suspension); every human-resolved
   * record schedules a debounced, coalesced replay which is authoritative for all counters.
   */
  onReconciled(record: AuditRecord, previous?: AuditRecord): void {
    try {
      if (this.disposed) return;
      const res = record.resolution;
      if (!res || res.actor === "plugin") return;
      const changed =
        !previous ||
        !previous.resolution ||
        Boolean(record.decision) !== Boolean(previous.decision) ||
        previous.resolution.behavior !== res.behavior;
      if (!changed) return;

      if (
        res.behavior === "deny" &&
        !CONFIRMED_CANCELLATION_SIGNATURES.some((sig) => sig(res, record)) &&
        (!record.decision || record.decision.verdict === "allow")
      ) {
        const entry: GateEntry = {
          requestId: record.requestId,
          effects: [],
          kind: record.decision ? "false_allow" : "orphan_deny",
          key: record.requestId,
        };
        if (record.requestedAt) entry.requestedAt = record.requestedAt;
        const src = record.action?.exec?.source;
        if (typeof src === "string") entry.command = src.slice(0, 200);
        const modeBefore = this.safeCompute().mode;
        this.seq += 1;
        this.candidates.set(record.requestId, { seq: this.seq, entry });
        this.applyTransitions(false, modeBefore);
      } else {
        // The merged record no longer qualifies (e.g. the `before` of an orphan deny arrived with a
        // verdict other than allow): drop its in-memory candidate.
        if (this.candidates.has(record.requestId)) {
          const modeBefore = this.safeCompute().mode;
          this.candidates.delete(record.requestId);
          this.applyTransitions(false, modeBefore);
        }
        this.seq += 1;
        if (res.behavior === "allow" && record.decision?.level === "L3") {
          this.falseDenyCandidates.set(record.requestId, this.seq);
        }
      }
      this.scheduleReplay();
    } catch (error) {
      console.error("[paseo-permission-guardian] gate onReconciled failed:", error);
    }
  }

  async annotate(key: string, annotation: "not_safety" | null): Promise<GateStatus> {
    this.annotationGen += 1;
    const pf = this.store.getPersistFailure();
    if (annotation === "not_safety" && pf && key === `persist_failure#${pf.firstAt}`) {
      // History may be incomplete: drop the result BEFORE clearing (the store nulls the failure
      // synchronously, then awaits the marker removal) so shadow holds until a fresh replay
      // completes. The generation bump above discards any in-flight replay. If clearing rejects,
      // `completed` stays null (shadow) and the error propagates.
      this.completed = null;
      await this.store.clearPersistFailure();
    }
    if (annotation === null) {
      // Un-annotating can re-introduce a false-allow: no result counts until the next replay.
      this.completed = null;
    }
    await this.store.appendEvent({ event: "annotation", key, annotation, at: this.iso() });
    return this.replay();
  }

  /**
   * Runs a replay (≤1 concurrent; concurrent callers coalesce onto one queued run). Only a
   * `manual` replay (the `guardian.gate.replay` RPC) that completes available clears a responder
   * pause (ruling R12); automatic replays never do.
   */
  replay(opts: { manual?: boolean } = {}): Promise<GateStatus> {
    if (opts.manual) this.pendingManual = true;
    if (this.queuedReplay) return this.queuedReplay;
    const run = this.replayChain.then(async () => {
      this.queuedReplay = null;
      await this.doReplay();
      return this.status();
    });
    this.queuedReplay = run;
    this.replayChain = run.catch(() => undefined);
    return run;
  }

  async dispose(): Promise<void> {
    this.disposed = true;
    if (this.debounceTimer) clearTimeout(this.debounceTimer);
    this.debounceTimer = null;
    this.unsubscribe();
    await this.replayChain.catch(() => undefined);
    await this.writeChain.catch(() => undefined);
    await this.replayDecide.dispose().catch(() => undefined);
  }

  // ---------------------------------------------------------------- replay

  private scheduleReplay(): void {
    if (this.disposed || this.debounceTimer) return;
    this.debounceTimer = setTimeout(() => {
      this.debounceTimer = null;
      if (!this.disposed) void this.replay().catch(() => undefined);
    }, this.debounceMs);
    this.debounceTimer.unref?.();
  }

  private async doReplay(): Promise<void> {
    const fingerprint = this.fingerprint;
    const settings = this.settings;
    if (!fingerprint || !settings || this.disposed) return;
    const windowDays = settings.actGate.windowDays;
    const startSeq = this.seq;
    const startGen = this.annotationGen;
    const at = this.now();
    const manual = this.pendingManual;
    this.pendingManual = false;

    let completed: CompletedReplay;
    try {
      await this.loadFile();
      await this.store.flush();
      const window = await readAuditWindow(this.dataDir, at - windowDays * DAY_MS, {
        maxRecords: REPLAY_MAX_RECORDS,
      });
      const result = await replayWindow(window, this.replayDecide, {
        cancellationSignatures: CONFIRMED_CANCELLATION_SIGNATURES,
      });
      completed = {
        fingerprint,
        windowDays,
        result,
        unavailableReason: result.unavailableReason,
        inWindow: new Set(window.records.map((r) => r.requestId)),
        annotations: window.annotations,
        at,
      };
    } catch (error) {
      console.error("[paseo-permission-guardian] gate replay failed:", error);
      completed = {
        fingerprint,
        windowDays,
        result: { samples: 0, falseAllows: [], falseDenyCount: 0, integrity: [], skippedAllow: 0, unavailableReason: null },
        unavailableReason: "replay_error",
        inWindow: new Set(),
        annotations: new Map(),
        at,
      };
    }

    // Stale: engine identity or window changed while replaying; a newer replay is queued.
    // Stale: an annotation changed after this replay read the window; annotate() queues a new one.
    // A stale manual request carries over to that newer run.
    if (
      this.fingerprint !== fingerprint ||
      this.settings?.actGate.windowDays !== windowDays ||
      this.annotationGen !== startGen
    ) {
      if (manual) this.pendingManual = true;
      return;
    }

    const modeBefore = this.safeCompute().mode;
    this.completed = completed;
    for (const [id, c] of this.candidates) if (c.seq <= startSeq) this.candidates.delete(id);
    for (const [id, seq] of this.falseDenyCandidates) if (seq <= startSeq) this.falseDenyCandidates.delete(id);
    if (
      manual &&
      completed.unavailableReason === null &&
      !this.store.getPersistFailure() &&
      !this.stateWriteFailed
    ) {
      // R12: the pause clears only on daemon start (new controller) or a manual replay that
      // completed available.
      if (this.paused) this.emit("unpaused", { reason: "manual_replay" });
      this.consecutiveUnconfirmed = 0;
      this.paused = false;
    }

    this.applyTransitions(true, modeBefore);
    if (this.file) {
      this.file = { ...this.file, lastReplay: new Date(at).toISOString() };
    } else {
      this.file = { ...emptyFile(fingerprint), lastReplay: new Date(at).toISOString() };
    }
    this.persistFile();
    const r = completed.result;
    this.emit("replay", {
      fingerprint: fingerprint.slice(0, 12),
      samples: r.samples,
      falseAllowCount: r.falseAllows.length,
      falseDenyCount: r.falseDenyCount,
      integrityCount: r.integrity.length,
      skippedAllow: r.skippedAllow,
      unavailableReason: completed.unavailableReason,
    });
  }

  private async loadFile(): Promise<void> {
    if (this.fileLoaded) return;
    await this.writeChain.catch(() => undefined);
    const loaded = await readGateState(this.dataDir);
    if (this.fileLoaded) return;
    this.fileLoaded = true;
    this.file = loaded;
  }

  // ---------------------------------------------------------------- state machine

  private currentReplay(): CompletedReplay | null {
    const c = this.completed;
    if (!c || !this.settings || c.fingerprint !== this.fingerprint) return null;
    if (c.windowDays !== this.settings.actGate.windowDays) return null;
    return c;
  }

  private falseAllowEntries(): GateEntry[] {
    const out = new Map<string, GateEntry>();
    const r = this.currentReplay();
    if (r) for (const e of r.result.falseAllows) out.set(e.requestId, e);
    for (const [id, c] of this.candidates) if (!out.has(id)) out.set(id, c.entry);
    return [...out.values()];
  }

  private safeCompute(): Computed {
    try {
      return this.compute();
    } catch (error) {
      console.error("[paseo-permission-guardian] gate compute failed:", error);
      return {
        state: "unavailable",
        reason: "internal_error",
        mode: "shadow",
        writeLatch: false,
        falseAllowIds: [],
        overrideValid: false,
        latchBase: false,
        suspended: false,
      };
    }
  }

  /** Pure: derives state, reason and effective mode from current inputs (spec §3.2 pseudo-code). */
  private compute(): Computed {
    const s = this.settings;
    const fp = this.fingerprint;
    const base: Computed = {
      state: "replaying",
      reason: "not_configured",
      mode: "shadow",
      writeLatch: false,
      falseAllowIds: [],
      overrideValid: false,
      latchBase: false,
      suspended: false,
    };
    if (!s || !fp) return base;
    const gate = s.actGate;

    const f = this.file;
    const latchBase =
      f !== null &&
      f.latched === true &&
      f.fingerprint === fp &&
      validMinSamplesAtLatch(f.minSamplesAtLatch) &&
      gate.minSamples <= f.minSamplesAtLatch;
    const suspended = latchBase && f!.suspendedBy.length > 0;
    const latchValid = latchBase && !suspended;
    const overrideValid =
      gate.allowOverride && s.actOverride.accepted === true && s.actOverride.fingerprint === fp;

    const replay = this.currentReplay();
    const falseAllowIds = this.falseAllowEntries().map((e) => e.requestId);
    // R6: an unannotated suspending id is still a disagreement even if the latest replay no longer
    // reports it, so it counts as a false-allow (no re-latching or override while suspended).
    if (suspended) for (const id of f!.suspendedBy) if (!falseAllowIds.includes(id)) falseAllowIds.push(id);
    const falseAllow = falseAllowIds.length;
    const samples = replay?.result.samples ?? 0;
    const pf = this.store.getPersistFailure();

    // --- state (independent of mode)
    let state: GateState;
    let stateReason: string;
    if (pf) {
      state = "unavailable";
      stateReason = "audit_persist_failure";
    } else if (this.stateWriteFailed) {
      state = "unavailable";
      stateReason = "gate_state_write_failure";
    } else if (!replay) {
      state = "replaying";
      stateReason = "replaying";
    } else if (replay.unavailableReason) {
      state = "unavailable";
      stateReason = replay.unavailableReason;
    } else if (suspended) {
      state = "suspended";
      stateReason = "suspended_false_allow";
    } else if (falseAllow > 0) {
      state = latchValid ? "latched" : "failed_false_allow";
      stateReason = "false_allow";
    } else if (latchValid) {
      state = "latched";
      stateReason = "latched";
    } else if (samples >= gate.minSamples) {
      state = "passed";
      stateReason = "passed";
    } else {
      state = "collecting";
      stateReason = "collecting";
    }

    const out: Computed = { ...base, state, reason: stateReason, falseAllowIds, overrideValid, latchBase, suspended };

    // --- effective mode
    if (!this.settingsValid) {
      out.reason = `settings_invalid:${this.settingsInvalidReason ?? "unknown"}`;
      return out;
    }
    if (s.mode === "off") {
      out.mode = "off";
      out.reason = "mode_off";
      return out;
    }
    if (s.mode !== "act") {
      out.reason = s.mode === "shadow" ? "mode_shadow" : "mode_unknown";
      return out;
    }
    if (state === "replaying" || state === "unavailable") return out;
    if (this.paused) {
      out.reason = "responder_unconfirmed";
      return out;
    }
    if (falseAllow > 0 && gate.autoFallbackOnFalseAllow) {
      out.reason = suspended ? "suspended_false_allow" : "false_allow_fallback";
      return out;
    }
    if (falseAllow > 0) {
      if (latchValid || overrideValid) {
        out.mode = "act";
        out.reason = `false_allow_reported:${latchValid ? "latched" : "override"}`;
      } else {
        out.reason = "false_allow_reported";
      }
      return out;
    }
    if (latchValid) {
      out.mode = "act";
      out.reason = "latched";
      return out;
    }
    if (samples >= gate.minSamples) {
      out.mode = "act";
      out.reason = "passed";
      out.writeLatch = true;
      return out;
    }
    if (overrideValid) {
      out.mode = "act";
      out.reason = "override";
      return out;
    }
    out.reason = suspended ? "suspended_false_allow" : "collecting";
    return out;
  }

  /**
   * Applies latch side effects: clear (fingerprint change, raised minSamples, invalid file, aged-out
   * suspending entry), suspend/resume, and latch writing. Removals from `suspendedBy` and aged-out
   * clears happen only after a completed, available replay (`fromReplay`).
   */
  private applyTransitions(fromReplay: boolean, modeBeforeInput?: EffectiveMode): void {
    const s = this.settings;
    const fp = this.fingerprint;
    if (!s || !fp) return;
    // Invalid settings: the real engine identity is unknown (the fingerprint was derived from
    // fallback settings), so no latch side effects at all; the mode is shadow regardless. They are
    // applied on the next configure with valid settings / the next replay (F7 ruling).
    if (!this.settingsValid) return;
    const modeBefore = modeBeforeInput ?? this.safeCompute().mode;

    const f = this.file;
    if (f && f.latched) {
      let clearReason: string | null = null;
      if (f.fingerprint !== fp) clearReason = "fingerprint_changed";
      else if (!validMinSamplesAtLatch(f.minSamplesAtLatch)) clearReason = "invalid_latch";
      else if (s.actGate.minSamples > f.minSamplesAtLatch) clearReason = "min_samples_raised";
      if (clearReason) this.clearLatch(clearReason);
    }

    const replay = this.currentReplay();
    const available =
      replay !== null &&
      replay.unavailableReason === null &&
      !this.store.getPersistFailure() &&
      !this.stateWriteFailed;
    const faEntries = this.falseAllowEntries();
    const falseIds = new Set(faEntries.map((e) => e.requestId));
    const orphanIds = new Set(faEntries.filter((e) => e.kind === "orphan_deny").map((e) => e.requestId));

    if (this.file && this.file.latched) {
      const before = this.file.suspendedBy;
      let next = [...before];
      let agedOut = false;
      if (fromReplay && available) {
        // R6: a suspension is lifted ONLY by a `not_safety` annotation; an unannotated id that is
        // still in the window (or still a live candidate) keeps suspending even if the replay no
        // longer reports it; one that left the window unannotated clears the latch.
        next = next.filter((id) => {
          if (replay!.annotations.get(id) === "not_safety") return false;
          if (falseIds.has(id) || replay!.inWindow.has(id)) return true;
          agedOut = true;
          return false;
        });
      }
      if (agedOut) {
        this.clearLatch("suspending_entry_aged_out");
      } else {
        if (s.actGate.autoFallbackOnFalseAllow) {
          // Orphan candidates (no decision yet) only force shadow in memory; they are never
          // persisted into suspendedBy (F5). The replay decides once the `before` is known.
          for (const id of falseIds) if (!orphanIds.has(id) && !next.includes(id)) next.push(id);
        }
        const added = next.filter((id) => !before.includes(id));
        const changed = added.length > 0 || next.length !== before.length;
        if (changed) {
          this.file = { ...this.file, suspendedBy: next };
          this.persistFile();
          if (added.length > 0) this.emit("suspended", { requestIds: added.slice(0, MAX_FALSE_ALLOW_ENTRIES) });
          if (before.length > 0 && next.length === 0) this.emit("resumed", {});
        }
      }
    }

    const c = this.safeCompute();
    if (c.writeLatch && available) {
      this.file = {
        version: 1,
        latched: true,
        fingerprint: fp,
        minSamplesAtLatch: s.actGate.minSamples,
        latchedAt: this.iso(),
        suspendedBy: [],
        lastReplay: this.file?.lastReplay ?? null,
      };
      this.persistFile();
      this.emit("latch_written", { fingerprint: fp.slice(0, 12), minSamplesAtLatch: s.actGate.minSamples });
    }

    const modeAfter = this.safeCompute().mode;
    if (modeBefore === "act" && modeAfter !== "act" && falseIds.size > 0) {
      this.emit("fallback_false_allow", { requestIds: [...falseIds].slice(0, MAX_FALSE_ALLOW_ENTRIES) });
    }
  }

  private clearLatch(reason: string): void {
    const prev = this.file;
    this.file = {
      ...(prev ?? emptyFile(this.fingerprint ?? "")),
      latched: false,
      fingerprint: this.fingerprint ?? prev?.fingerprint ?? "",
      minSamplesAtLatch: 0,
      latchedAt: null,
      suspendedBy: [],
    };
    this.persistFile();
    this.emit("latch_cleared", { reason });
  }

  private observeOverride(): void {
    const o = this.settings?.actOverride;
    const key = o?.accepted ? `accepted:${o.fingerprint ?? ""}` : "none";
    if (key === this.observedOverrideKey) return;
    const wasAccepted = this.observedOverrideKey !== "none";
    this.observedOverrideKey = key;
    if (key !== "none") {
      this.emit("override_accepted", {
        fingerprint: (o?.fingerprint ?? "").slice(0, 12),
        acceptedAt: o?.acceptedAt ?? null,
      });
    } else if (wasAccepted) {
      this.emit("override_revoked", {});
    }
  }

  // ---------------------------------------------------------------- persistence helpers

  /** Serializes all gate-state.json writes through one chain; each write persists the latest state. */
  private persistFile(): void {
    if (!this.fileLoaded) return;
    this.writeChain = this.writeChain
      .then(async () => {
        const snapshot = this.file;
        if (!snapshot) return;
        await this.writeState(this.dataDir, { ...snapshot, suspendedBy: [...snapshot.suspendedBy] });
        if (this.stateWriteFailed) {
          this.stateWriteFailed = false;
          this.emit("state_write_recovered", {});
        }
      })
      .catch((error) => {
        console.error("[paseo-permission-guardian] gate-state write failed:", error);
        // Fail to human: the in-memory latch/suspension may differ from disk (a restart could
        // resurrect a latch), so the gate is unavailable until a later write succeeds.
        if (!this.stateWriteFailed) {
          this.stateWriteFailed = true;
          this.emit("state_write_failure", { error: error instanceof Error ? error.message : String(error) });
        }
      });
  }

  private emit(type: string, payload: Record<string, unknown>): void {
    void this.store.appendEvent({ event: "gate", type, at: this.iso(), ...payload }).catch(() => undefined);
  }

  private iso(): string {
    return new Date(this.now()).toISOString();
  }
}
