import { describe, expect, it } from "vitest";
import { effectiveModeLabelKey, entryActionLabelKey, hasIntegrityProblem } from "../client/gate-view.js";
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
