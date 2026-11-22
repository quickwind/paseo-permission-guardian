import { describe, expect, it, vi } from "vitest";

vi.mock("react-native", () => ({ Text: "Text", TextInput: "TextInput", View: "View" }));
vi.mock("@getpaseo/plugin/client/ui", () => {
  const C = () => null;
  return { Loading: C, ScrollView: C, SettingsAction: C, SettingsCard: C, SettingsInput: C, SettingsRow: C, SettingsSection: C, SettingsSelect: C, SettingsSwitch: C, SidebarRow: C };
});
vi.mock("@getpaseo/plugin/client", async (orig) => ({
  ...(await orig<Record<string, unknown>>()),
  useRpc: () => async () => ({}),
  useSettings: () => ({ status: "loading" }),
  useTranslation: () => ({ t: (k: string) => k }),
}));
import {
  entryViewModel,
  openReviewScreen,
  REVIEW_SCREEN_ID,
  reviewBadgeCount,
} from "../client/gate-view.js";
import { messages } from "../client/i18n.js";
import contribute from "../index.client.js";
import { emptyGateStatus, type GateEntry } from "../shared/types.js";

function translator(locale: "en" | "zh") {
  const res = messages.resources[locale] as Record<string, unknown>;
  return (key: string): string => {
    let cur: unknown = res;
    for (const part of key.split(".")) cur = (cur as Record<string, unknown>)?.[part];
    if (typeof cur !== "string") throw new Error(`missing i18n key ${key}`);
    return cur;
  };
}

function entry(kind: GateEntry["kind"], extra: Partial<GateEntry> = {}): GateEntry {
  return {
    key: `${kind}-1`,
    kind,
    requestId: "req-1",
    effects: [],
    ...extra,
  } as GateEntry;
}

describe("review badge count", () => {
  it("counts all entry kinds, zero when none or unknown", () => {
    const g = emptyGateStatus();
    expect(reviewBadgeCount(null)).toBe(0);
    expect(reviewBadgeCount({ gate: g })).toBe(0);
    expect(
      reviewBadgeCount({
        gate: { ...g, entries: [entry("orphan_deny"), entry("false_allow"), entry("corrupt_line")] },
      }),
    ).toBe(3);
  });
});

describe("entryViewModel", () => {
  const nav = { openAgent: () => {} };
  it("offers open chat only with navigation and agentId", () => {
    const e = entry("orphan_deny", { agentId: "agent-12345678" });
    expect(entryViewModel(e, translator("en"), nav).canOpenChat).toBe(true);
    expect(entryViewModel(e, translator("en"), undefined).canOpenChat).toBe(false);
    expect(entryViewModel(entry("orphan_deny"), translator("en"), nav).canOpenChat).toBe(false);
  });
  it("uses acknowledge for corrupt_line and annotate otherwise", () => {
    expect(entryViewModel(entry("corrupt_line"), translator("en"), nav).actionLabel).toBe("Acknowledge");
    expect(entryViewModel(entry("orphan_deny"), translator("en"), nav).actionLabel).toBe("Not a safety issue");
    expect(entryViewModel(entry("orphan_deny"), translator("zh"), nav).actionLabel).toBe("不是安全问题");
  });
  it("labels the agent field and recovered note per spec", () => {
    const e = entry("orphan_deny", {
      agentTitle: "Fix bug",
      orphanContext: { summary: "rm -rf x" },
    } as Partial<GateEntry>);
    const zh = entryViewModel(e, translator("zh"), nav);
    expect(zh.details).toContain("Agent 名称: Fix bug");
    expect(zh.details).toContain("命令内容由插件从对话记录中找回（插件当时没有收到这条请求）");
    const en = entryViewModel(e, translator("en"), nav);
    expect(en.details).toContain("Agent: Fix bug");
    expect(en.title).toContain("rm -rf x");
  });
  it("rewords the unavailable orphan note", () => {
    expect(translator("zh")("act.entries.missing")).toBe("插件当时没有收到这条请求，也未能从对话记录中找回内容");
    expect(translator("en")("act.entries.missing")).toBe(
      "The plugin did not receive this request and could not recover it from the chat history",
    );
  });
});

describe("new i18n keys", () => {
  it("exist in both locales", () => {
    for (const l of ["en", "zh"] as const) {
      const t = translator(l);
      for (const k of [
        "review.title",
        "review.sidebarTitle",
        "review.settingsHint",
        "review.empty",
        "act.entries.recovered",
        "act.entries.missing",
      ]) {
        expect(t(k).length).toBeGreaterThan(0);
      }
    }
    expect(translator("zh")("review.settingsHint")).toBe("要打开对应对话，请在侧边栏“权限守卫”中查看。");
    expect(translator("en")("review.settingsHint")).toBe(
      "To open the related chat, use “Permission Guardian” in the sidebar.",
    );
  });
});

describe("index.client registration", () => {
  it("registers settings screen, review screen and sidebar footer item", () => {
    const calls: Record<string, any[]> = { settings: [], screen: [], footer: [] };
    const removed: string[] = [];
    const client = {
      addSettingsScreen: (c: any) => (calls.settings.push(c), () => removed.push("settings")),
      addScreen: (c: any) => (calls.screen.push(c), () => removed.push("screen")),
      addSidebarFooterItem: (c: any) => (calls.footer.push(c), () => removed.push("footer")),
    } as any;
    const cleanup = contribute(client);
    expect(calls.settings).toHaveLength(1);
    expect(calls.screen.map((c) => c.id)).toEqual(["guardian-review"]);
    expect(calls.footer.map((c) => c.id)).toEqual(["guardian-review"]);
    expect(typeof calls.screen[0].Component).toBe("function");
    expect(typeof calls.footer[0].Component).toBe("function");
    cleanup();
    expect(removed.sort()).toEqual(["footer", "screen", "settings"]);
  });
  it("press handler opens the review screen", () => {
    const opened: unknown[] = [];
    openReviewScreen((i) => void opened.push(i));
    expect(opened).toEqual([{ screenId: REVIEW_SCREEN_ID }]);
    expect(REVIEW_SCREEN_ID).toBe("guardian-review");
  });
});
