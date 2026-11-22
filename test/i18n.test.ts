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
