import { afterAll, describe, expect, it } from "vitest";
import { disposeSharedPwshHost } from "../server/shell/pwsh-host.js";
import { decideAction, type DecideOptions } from "../server/decide.js";
import { parseMcpToolName } from "../server/normalize/types.js";
import { hasSandboxBypassFlag } from "../server/normalize/sandbox.js";
import { PASEO_READONLY_MCP_TOOLS } from "../server/effects.js";
import type { Action } from "../shared/types.js";

afterAll(async () => {
  await disposeSharedPwshHost();
});

function base(): Omit<Action, "kind"> {
  return {
    provider: "claude",
    agentId: "agent-1",
    requestId: "req-1",
    toolName: "Tool",
    host: { os: "darwin" },
    cwd: "/repo",
    worktreeRoot: "/repo",
  };
}
const opts: DecideOptions = {
  pathCtx: { cwd: "/repo", worktreeRoot: "/repo", home: "/home/u" },
  denyAsAsk: false,
};
const bashExec = (source: string): Action => ({
  ...base(),
  kind: "exec",
  exec: { shell: "bash", source },
});
const mcpAction = (server: string, tool: string): Action => ({
  ...base(),
  kind: "mcp",
  mcp: { server, tool, args: {} },
});

describe("p2a control surface hardening", () => {
  it("parses single-underscore MCP names", () =>
    expect(parseMcpToolName("mcp_paseo_respond_to_permission")).toEqual({
      server: "paseo",
      tool: "respond_to_permission",
    }));
  it("keeps double-underscore parsing", () =>
    expect(parseMcpToolName("mcp__github__get_issue")).toEqual({
      server: "github",
      tool: "get_issue",
    }));
  it.each([
    "respond_to_permission",
    "send_agent_prompt",
    "create_agent",
    "kill_agent",
    "update_agent",
    "set_agent_mode",
  ])("paseo MCP tool %s is L2", async (t) => {
    expect((await decideAction(mcpAction("paseo", t), opts)).decision.level).toBe("L2");
  });
  it("paseo read-only MCP tool stays L1 (unlisted MCP)", async () =>
    expect((await decideAction(mcpAction("paseo", "list_agents"), opts)).decision.level).toBe("L1"));
  it("exports the read-only set", () => expect(PASEO_READONLY_MCP_TOOLS.size).toBe(22));
  it.each([
    "paseo plugin reload x",
    "paseo --host h:1 plugin disable x",
    "paseo --home /h permit allow a r",
    "paseo agent send a hi",
    "paseo settings set k v",
    "paseo --json agent send a hi",
  ])("paseo CLI control `%s` is L2", async (src) =>
    expect((await decideAction(bashExec(src), opts)).decision.level).toBe("L2"));
  it("sandbox bypass flag raises a benign command to L2", async () => {
    const r = await decideAction({ ...bashExec("ls"), sandboxBypass: true }, opts);
    expect(r.decision.level).toBe("L2");
  });
  it.each([
    { BypassSandbox: true },
    { bypass_sandbox: "true" },
    { dangerouslyDisableSandbox: true },
    { unsandboxed: 1 },
  ])("detects %o", (input) => expect(hasSandboxBypassFlag(input)).toBe(true));
  it("ignores false flags", () =>
    expect(hasSandboxBypassFlag({ BypassSandbox: false })).toBe(false));
});
