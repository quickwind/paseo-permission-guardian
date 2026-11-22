import { describe, expect, it } from "vitest";
import {
  choiceLabelKey,
  effectiveModeLabelKey,
  entryActionLabelKey,
  entryAgentLabel,
  entryContentView,
  entryTime,
  hasIntegrityProblem,
} from "../client/gate-view.js";
import { emptyGateStatus, type GateEntry } from "../shared/types.js";

const e = (kind: GateEntry["kind"]): GateEntry => ({ requestId: "r", effects: [], kind, key: "k" });

describe("F8 client gate view helpers", () => {
  it("maps every effective mode to a label key, including act", () => {
    expect(effectiveModeLabelKey("act")).toBe("mode.effectiveValues.act");
    expect(effectiveModeLabelKey("off")).toBe("mode.effectiveValues.off");
    expect(effectiveModeLabelKey("shadow")).toBe("mode.effectiveValues.shadow");
  });
  it("integrity reflects unavailable state and any non-false_allow entry", () => {
    const ok = emptyGateStatus();
    expect(hasIntegrityProblem({ ...ok, entries: [e("false_allow")] })).toBe(false);
    expect(hasIntegrityProblem({ ...ok, state: "unavailable" })).toBe(true);
    for (const k of ["corrupt_line", "orphan_deny", "unevaluable_deny"] as const) {
      expect(hasIntegrityProblem({ ...ok, entries: [e(k)] })).toBe(true);
    }
  });
  it("corrupt lines are acknowledged; denials are annotated", () => {
    expect(entryActionLabelKey(e("corrupt_line"))).toBe("act.entries.acknowledge");
    expect(entryActionLabelKey(e("unevaluable_deny"))).toBe("act.entries.annotate");
    expect(entryActionLabelKey(e("false_allow"))).toBe("act.entries.annotate");
  });
});

describe("B: entry display helpers", () => {
  const base: GateEntry = { requestId: "r", effects: ["delete_worktree"], kind: "false_allow", key: "r" };
  it("agent label falls back to a short id; time prefers resolvedAt", () => {
    expect(entryAgentLabel({ ...base, agentTitle: "Fix build", agentId: "abcdef1234567" })).toBe("Fix build");
    expect(entryAgentLabel({ ...base, agentId: "abcdef1234567" })).toBe("abcdef12");
    expect(entryAgentLabel(base)).toBeUndefined();
    expect(entryTime({ ...base, requestedAt: "2026-11-23T01:00:00.000Z", resolvedAt: "2026-11-23T01:00:05.000Z" })).toBe(
      new Date("2026-11-23T01:00:05.000Z").toLocaleString(),
    );
    expect(entryTime({ ...base, requestedAt: "garbage" })).toBe("garbage");
    expect(entryTime(base)).toBeUndefined();
  });
  it("content view: request summary, recovered orphan, or missing", () => {
    expect(entryContentView({ ...base, summary: "rm a", toolName: "Bash" })).toEqual({ source: "request", summary: "rm a", toolName: "Bash" });
    const orphan: GateEntry = { ...base, kind: "orphan_deny", effects: [] };
    expect(entryContentView({ ...orphan, orphanContext: { summary: "rm b", toolName: "Bash", callId: "c" } })).toEqual({
      source: "recovered",
      summary: "rm b",
      toolName: "Bash",
    });
    expect(entryContentView({ ...orphan, orphanContext: { unavailable: true } })).toEqual({ source: "missing" });
    expect(entryContentView(orphan)).toEqual({ source: "missing" });
    expect(entryContentView({ ...base, kind: "corrupt_line" })).toEqual({ source: "none" });
  });
  it("choice label keys", () => {
    expect(choiceLabelKey({ behavior: "deny", selectedActionId: "reject_once" })).toBe("act.entries.choice.denyOnce");
    expect(choiceLabelKey({ behavior: "deny" })).toBe("act.entries.choice.deny");
    expect(choiceLabelKey({ behavior: "deny", selectedActionId: "reject_always" })).toBe("act.entries.choice.denyAlways");
    expect(choiceLabelKey({ behavior: "allow", selectedActionId: "allow_once" })).toBe("act.entries.choice.allowOnce");
    expect(choiceLabelKey({ behavior: "allow", selectedActionId: "allow_always" })).toBe("act.entries.choice.allowAlways");
    expect(choiceLabelKey({ behavior: "allow" })).toBe("act.entries.choice.allow");
  });
  it("every entry display key exists in en and zh", async () => {
    const { messages } = await import("../client/i18n.js");
    const keys = [
      "time",
      "provider",
      "agent",
      "tool",
      "yourChoice",
      "message",
      "effects",
      "recovered",
      "missing",
      "choice.allow",
      "choice.allowOnce",
      "choice.allowAlways",
      "choice.deny",
      "choice.denyOnce",
      "choice.denyAlways",
    ];
    for (const lang of ["en", "zh"] as const) {
      const entries = (messages.resources[lang] as any).act.entries;
      for (const k of keys) {
        const v = k.split(".").reduce((o: any, p) => o?.[p], entries);
        expect(typeof v, `${lang}:${k}`).toBe("string");
      }
    }
    expect((messages.resources.zh as any).act.entries.missing).toBe("插件当时未收到请求内容");
    expect((messages.resources.zh as any).act.entries.choice.denyOnce).toBe("拒绝一次");
  });
});
