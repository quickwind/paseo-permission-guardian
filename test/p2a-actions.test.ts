import { readFileSync } from "node:fs";
import type { AgentPermissionRequest } from "@getpaseo/protocol/agent-types";
import { describe, expect, it } from "vitest";
import { AUTO_ANSWER_PROVIDERS, resolveAnswer } from "../server/act/actions.js";

const fixtures = JSON.parse(
  readFileSync(new URL("./fixtures/agy/read-allow-deny.json", import.meta.url), "utf8"),
) as AgentPermissionRequest[];

type Action = NonNullable<AgentPermissionRequest["actions"]>[number];
const withActions = (actions: Action[] | undefined, provider = "agy"): AgentPermissionRequest => ({
  ...fixtures[0]!,
  provider,
  ...(actions ? { actions } : { actions: undefined }),
});
const allow: Action = { id: "allow", label: "Allow", behavior: "allow" };
const deny: Action = { id: "deny", label: "Deny", behavior: "deny" };

describe("resolveAnswer", () => {
  it("only enables agy", () => {
    expect([...AUTO_ANSWER_PROVIDERS]).toEqual(["agy"]);
  });
  it("resolves real agy fixtures", () => {
    for (const f of fixtures) {
      expect(resolveAnswer("agy", f, "allow")).toEqual({ selectedActionId: "allow" });
      expect(resolveAnswer("agy", f, "deny")).toEqual({ selectedActionId: "deny" });
    }
  });
  it("refuses extra persistent allow", () => {
    const r = withActions([allow, deny, { id: "allow_always", label: "Always", behavior: "allow" }]);
    expect(resolveAnswer("agy", r, "allow")).toBeNull();
  });
  it("refuses two allow actions", () => {
    const r = withActions([allow, { id: "allow2", label: "Allow", behavior: "allow" }, deny]);
    expect(resolveAnswer("agy", r, "allow")).toBeNull();
  });
  it("refuses two deny actions", () => {
    const r = withActions([allow, deny, { id: "deny2", label: "Deny", behavior: "deny" }]);
    expect(resolveAnswer("agy", r, "deny")).toBeNull();
  });
  it("refuses missing actions", () => {
    expect(resolveAnswer("agy", withActions(undefined), "allow")).toBeNull();
    expect(resolveAnswer("agy", withActions([]), "deny")).toBeNull();
  });
  it("refuses persistent-looking label", () => {
    const r = withActions([{ ...allow, label: "Allow for session" }, deny]);
    expect(resolveAnswer("agy", r, "allow")).toBeNull();
  });
  it("refuses wrong behavior on matching id", () => {
    expect(resolveAnswer("agy", withActions([{ ...allow, behavior: "deny" }, deny]), "allow")).toBeNull();
  });
  it("refuses providers not enabled", () => {
    const devin = withActions(
      [
        { id: "allow_once", label: "Allow once", behavior: "allow" },
        { id: "reject_once", label: "Reject", behavior: "deny" },
      ],
      "devin",
    );
    expect(resolveAnswer("devin", devin, "allow")).toBeNull();
    expect(resolveAnswer("claude", withActions([{ ...allow, id: "accept" }], "claude"), "allow")).toBeNull();
    expect(resolveAnswer("other", withActions([allow, deny], "other"), "allow")).toBeNull();
  });
});

describe("persistent token guard", () => {
  it.each(["allow_all", "Allow all", "always", "remember", "persist"])("refuses %s", (id) => {
    const r = withActions([{ id: "allow", label: id, behavior: "allow" }, deny]);
    expect(resolveAnswer("agy", r, "allow")).toBeNull();
  });
});
