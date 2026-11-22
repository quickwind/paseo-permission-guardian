import type { AgentPermissionRequest } from "@getpaseo/protocol/agent-types";
import { describe, expect, it } from "vitest";
import { normalizePermissionRequest, type NormalizeContext } from "../server/normalize/index.js";

const baseCtx: NormalizeContext = {
  agentId: "agent-1",
  provider: "claude",
  cwd: "/repo/app",
  worktreeRoot: "/repo",
  hostOs: "darwin",
  includeRaw: true,
};

describe("normalizePermissionRequest", () => {
  it("normalizes Claude Bash command on POSIX", () => {
    const req: AgentPermissionRequest = {
      id: "req-1",
      provider: "claude",
      name: "Bash",
      kind: "tool",
      input: { command: "git status" },
    };

    const res = normalizePermissionRequest(req, baseCtx);
    expect(res.normalizedBy).toBe("claude");
    expect(res.warnings).toEqual([]);
    expect(res.action.kind).toBe("exec");
    expect(res.action.exec).toEqual({ shell: "bash", source: "git status" });
  });

  it("normalizes Claude PowerShell command on Windows with configured default", () => {
    const req: AgentPermissionRequest = {
      id: "req-2",
      provider: "claude-code",
      name: "PowerShell",
      kind: "tool",
      input: { command: "Get-ChildItem" },
    };

    const res = normalizePermissionRequest(req, {
      ...baseCtx,
      hostOs: "windows",
      windowsDefaultShell: "pwsh5",
    });
    expect(res.action.kind).toBe("exec");
    expect(res.action.exec).toEqual({ shell: "pwsh5", source: "Get-ChildItem" });
  });

  it("normalizes Claude Read, Edit, WebFetch, and MCP tools", () => {
    const readRes = normalizePermissionRequest(
      {
        id: "r1",
        provider: "claude",
        name: "Read",
        kind: "tool",
        input: { file_path: "/repo/app/src/index.ts" },
      },
      baseCtx,
    );
    expect(readRes.action.kind).toBe("read");
    expect(readRes.action.paths).toEqual(["/repo/app/src/index.ts"]);

    const editRes = normalizePermissionRequest(
      {
        id: "r2",
        provider: "claude",
        name: "Write",
        kind: "tool",
        input: { file_path: "/repo/app/new.ts" },
      },
      baseCtx,
    );
    expect(editRes.action.kind).toBe("edit");
    expect(editRes.action.paths).toEqual(["/repo/app/new.ts"]);

    const fetchRes = normalizePermissionRequest(
      {
        id: "r3",
        provider: "claude",
        name: "WebFetch",
        kind: "tool",
        input: { url: "https://example.com/docs" },
      },
      baseCtx,
    );
    expect(fetchRes.action.kind).toBe("fetch");
    expect(fetchRes.action.url?.href).toBe("https://example.com/docs");

    const mcpRes = normalizePermissionRequest(
      {
        id: "r4",
        provider: "claude",
        name: "mcp__github__list_issues",
        kind: "tool",
        input: { repo: "getpaseo/paseo" },
      },
      baseCtx,
    );
    expect(mcpRes.action.kind).toBe("mcp");
    expect(mcpRes.action.mcp).toEqual({
      server: "github",
      tool: "list_issues",
      args: { repo: "getpaseo/paseo" },
    });
  });

  it("normalizes Antigravity and Devin CLI ACP permission requests", () => {
    const devinExec: AgentPermissionRequest = {
      id: "acp-1",
      provider: "devin",
      name: "execute",
      kind: "tool",
      metadata: {
        rawRequest: {
          toolCall: {
            kind: "execute",
            title: "Run tests",
            rawInput: { command: "npm test", cwd: "/repo/app" },
          },
        },
      },
    };

    const devinRes = normalizePermissionRequest(devinExec, {
      ...baseCtx,
      provider: "devin",
    });
    expect(devinRes.normalizedBy).toBe("acp");
    expect(devinRes.action.kind).toBe("exec");
    expect(devinRes.action.exec).toEqual({ shell: "bash", source: "npm test" });

    const agyEdit: AgentPermissionRequest = {
      id: "acp-2",
      provider: "antigravity",
      name: "edit",
      kind: "tool",
      metadata: {
        rawRequest: {
          toolCall: {
            kind: "edit",
            title: "Edit file",
            locations: [{ path: "/repo/app/README.md" }],
            rawInput: { TargetFile: "/repo/app/README.md" },
          },
        },
      },
    };

    const agyRes = normalizePermissionRequest(agyEdit, {
      ...baseCtx,
      provider: "antigravity",
    });
    expect(agyRes.normalizedBy).toBe("acp");
    expect(agyRes.action.kind).toBe("edit");
    expect(agyRes.action.paths).toEqual(["/repo/app/README.md"]);
  });

  it("passes through question, plan, and mode kinds unchanged", () => {
    for (const kind of ["question", "plan", "mode"] as const) {
      const res = normalizePermissionRequest(
        {
          id: `k-${kind}`,
          provider: "claude",
          name: "Prompt",
          kind,
        },
        baseCtx,
      );
      expect(res.normalizedBy).toBe("kind-passthrough");
      expect(res.action.kind).toBe(kind);
    }
  });

  it("fails safely to kind=other on unsupported providers without detail", () => {
    const res = normalizePermissionRequest(
      {
        id: "u-1",
        provider: "custom-agent",
        name: "mystery_tool",
        kind: "tool",
        input: { foo: "bar" },
      },
      { ...baseCtx, provider: "custom-agent" },
    );
    expect(res.normalizedBy).toBe("generic-fallback");
    expect(res.action.kind).toBe("other");
    expect(res.warnings).toContain("unsupported_provider:custom-agent");
  });

  it("M2: generic fallback carries sandboxBypass from the request input", () => {
    const res = normalizePermissionRequest(
      {
        id: "u-2",
        provider: "custom-agent",
        name: "run",
        kind: "tool",
        input: { dangerouslyDisableSandbox: true },
        detail: { type: "shell", command: "ls" },
      } as AgentPermissionRequest,
      { ...baseCtx, provider: "custom-agent" },
    );
    expect(res.normalizedBy).toBe("generic-detail");
    expect(res.action.sandboxBypass).toBe(true);
    const plain = normalizePermissionRequest(
      { id: "u-3", provider: "custom-agent", name: "x", kind: "tool", input: { foo: 1 } },
      { ...baseCtx, provider: "custom-agent" },
    );
    expect(plain.action.sandboxBypass).toBeUndefined();
  });
});
