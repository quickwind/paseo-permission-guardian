import { describe, expect, it } from "vitest";
import { messages } from "../client/i18n.js";

function collectLeafKeys(obj: Record<string, unknown>, prefix = ""): string[] {
  const keys: string[] = [];
  for (const [k, v] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${k}` : k;
    if (typeof v === "string") {
      keys.push(path);
    } else if (v && typeof v === "object") {
      keys.push(...collectLeafKeys(v as Record<string, unknown>, path));
    }
  }
  return keys.sort();
}

describe("client i18n translations", () => {
  it("provides complete zh translations matching every en key", () => {
    const enKeys = collectLeafKeys(
      messages.resources.en as Record<string, unknown>,
    );
    const zhKeys = collectLeafKeys(
      messages.resources.zh as Record<string, unknown>,
    );

    expect(enKeys.length).toBeGreaterThan(0);
    expect(zhKeys).toEqual(enKeys);
  });

  it("builds a valid PluginMessage for the settings screen title", () => {
    const msg = messages.message("settings.title");
    expect(msg).toBeDefined();
    expect(typeof msg).toBe("object");
  });

  it("defines every act-mode key in en and zh", () => {
    const required = [
      "act.section.title",
      "act.minSamples",
      "act.windowDays",
      "act.autoFallback",
      "act.allowOverride",
      "act.override.accept",
      "act.override.confirm",
      ...[
        "replaying",
        "unavailable",
        "failed_false_allow",
        "collecting",
        "passed",
        "latched",
        "suspended",
      ].map((s) => `act.state.${s}`),
      "act.entries.annotate",
      "act.entries.acknowledge",
      "act.entries.kind.false_allow",
      "act.entries.kind.orphan_deny",
      "act.entries.kind.corrupt_line",
      "act.override.changed",
      "act.validation.range",
      "act.help.pwshUnavailable",
      "act.unconfirmed",
      "act.integrity",
      "mode.effectiveValues.act",
      "act.autoFallbackOffWarning",
      "act.entries.kind.unevaluable_deny",
    ];
    const enKeys = collectLeafKeys(
      messages.resources.en as Record<string, unknown>,
    );
    const zhKeys = collectLeafKeys(
      messages.resources.zh as Record<string, unknown>,
    );
    for (const key of required) {
      expect(enKeys, key).toContain(key);
      expect(zhKeys, key).toContain(key);
    }
  });
});

describe("F8 act-mode labels", () => {
  const en = messages.resources.en as any;
  const zh = messages.resources.zh as any;
  it("effective act mode has an Act label in en and zh", () => {
    expect(en.mode.effectiveValues.act).toBe("Act");
    expect(zh.mode.effectiveValues.act).toBe("自动应答中");
  });
  it("the act option no longer claims to be unavailable / currently shadow", () => {
    expect(en.mode.options.act).not.toMatch(/P2|currently shadow/i);
    expect(zh.mode.options.act).not.toMatch(/P2|当前按影子模式运行/);
  });
  it("has a warning for auto-fallback off", () => {
    expect(en.act.autoFallbackOffWarning.length).toBeGreaterThan(20);
    expect(zh.act.autoFallbackOffWarning.length).toBeGreaterThan(5);
  });
});
