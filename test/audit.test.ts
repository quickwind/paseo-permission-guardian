import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { redactString, redactValue } from "../server/audit/redact.js";
import { AuditStore, computeAgreement } from "../server/audit/store.js";
import { detectCredentialLiterals } from "../server/secrets/patterns.js";
import type { Action } from "../shared/types.js";

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "paseo-guardian-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

function sampleAction(requestId: string, command = "git status"): Action {
  return {
    provider: "claude",
    agentId: "agent-1",
    requestId,
    kind: "exec",
    toolName: "Bash",
    host: { os: "darwin" },
    cwd: "/repo",
    exec: { shell: "bash", source: command },
  };
}

describe("redaction", () => {
  it("redacts tokens, auth headers, env secrets, and PEM keys", () => {
    const input = [
      "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456",
      "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz123456",
      "ghp_1234567890abcdefghijklmnopqrstuv",
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
    ].join("\n");

    const output = redactString(input);
    expect(output).not.toContain("eyJhbGci");
    expect(output).not.toContain("sk-proj-");
    expect(output).not.toContain("ghp_123456");
    expect(output).not.toContain("MIIEpAIBAAKCAQEA");
    expect(output).toContain("[REDACTED]");
    expect(output).toContain("[REDACTED_PEM_KEY]");
  });

  it("redacts sensitive object keys and handles circular references", () => {
    const obj: Record<string, unknown> = {
      apiKey: "super-secret",
      nested: { Authorization: "Bearer secret-token-value-123456", safe: "ok" },
    };
    obj.self = obj;

    const redacted = redactValue(obj);
    expect(redacted.apiKey).toBe("[REDACTED]");
    expect((redacted.nested as Record<string, unknown>).Authorization).toBe("[REDACTED]");
    expect((redacted.nested as Record<string, unknown>).safe).toBe("ok");
    expect(redacted.self).toBe("[CIRCULAR]");
  });

  it("redacts PGPASSWORD, sk_live, pypi-, and URL credentials consistently without regex state drift", () => {
    const sample =
      "PGPASSWORD=my-pg-pass FOO=sk_live_1234567890abcdef1234 BAR=pypi-AgEI1234567890abcdef1234 postgres://admin:s3cr3t@db.internal/app";

    // Guard against /g lastIndex bugs on repeated calls
    expect(detectCredentialLiterals(sample)).toEqual(["stripe_key", "pypi_token", "url_credentials"]);
    expect(detectCredentialLiterals(sample)).toEqual(["stripe_key", "pypi_token", "url_credentials"]);

    const output = redactString(sample);
    expect(output).not.toContain("my-pg-pass");
    expect(output).not.toContain("sk_live_");
    expect(output).not.toContain("pypi-AgEI");
    expect(output).not.toContain("s3cr3t");
    expect(output).toContain("postgres://admin:[REDACTED]@db.internal/app");
  });
});

describe("AuditStore", () => {
  it("reconciles out-of-order after-before events and tracks metrics accurately", async () => {
    const dataDir = await makeTempDir();
    const fixedDate = new Date("2026-11-20T12:00:00.000Z");
    const store = new AuditStore({
      dataDir,
      pluginVersion: "0.1.0",
      now: () => fixedDate,
    });

    // After arrives BEFORE before (human raced plugin analysis)
    await store.recordAfter({
      requestId: "req-oo-1",
      agentId: "agent-1",
      provider: "claude",
      mode: "shadow",
      resolution: {
        behavior: "deny",
        message: "Not safe",
        resolvedAt: fixedDate.toISOString(),
        actor: "human",
      },
    });

    expect(store.getMetrics().pendingCount).toBe(1);
    expect(store.getMetrics().reconciledCount).toBe(0);

    const merged = await store.recordBefore({
      requestId: "req-oo-1",
      agentId: "agent-1",
      provider: "claude",
      mode: "shadow",
      requestedAt: fixedDate.toISOString(),
      latencyMs: 5,
      normalizedBy: "claude",
      warnings: [],
      action: sampleAction("req-oo-1", "API_TOKEN=secret123 curl https://example.com"),
      decision: { level: "L0", verdict: "allow", reasons: ["test"] },
    });

    await store.flush();

    expect(merged.outOfOrder).toBe(true);
    expect(merged.agreement).toBe("false_allow");
    expect(merged.action?.exec?.source).not.toContain("secret123");

    const metrics = store.getMetrics();
    expect(metrics.totalRequests).toBe(1);
    expect(metrics.reconciledCount).toBe(1);
    expect(metrics.pendingCount).toBe(0);
    expect(metrics.falseAllowCount).toBe(1);
    expect(metrics.outOfOrderCount).toBe(1);

    const summaryRaw = await readFile(join(dataDir, "summary.json"), "utf8");
    expect(JSON.parse(summaryRaw).falseAllowCount).toBe(1);
  });

  it("rotates JSONL files by size and handles concurrent bursts cleanly", async () => {
    const dataDir = await makeTempDir();
    const fixedDate = new Date("2026-11-20T12:00:00.000Z");
    const store = new AuditStore({
      dataDir,
      pluginVersion: "0.1.0",
      maxFileBytes: 600,
      now: () => fixedDate,
    });

    await Promise.all(
      Array.from({ length: 12 }, (_, idx) =>
        store.recordBefore({
          requestId: `burst-${idx}`,
          agentId: "agent-1",
          provider: "claude",
          mode: "shadow",
          requestedAt: fixedDate.toISOString(),
          latencyMs: 2,
          normalizedBy: "claude",
          warnings: [],
          action: sampleAction(`burst-${idx}`, `echo message-${idx}`),
          decision: { level: "L1", verdict: "ask", reasons: ["p0_shadow_only"] },
        }),
      ),
    );
    await store.flush();

    const files = (await readdir(dataDir)).filter((f) => f.endsWith(".jsonl")).sort();
    expect(files.length).toBeGreaterThan(1);

    let lineCount = 0;
    for (const file of files) {
      const content = await readFile(join(dataDir, file), "utf8");
      const lines = content.trim().split("\n").filter(Boolean);
      for (const line of lines) {
        expect(() => JSON.parse(line)).not.toThrow();
        lineCount += 1;
      }
    }
    expect(lineCount).toBe(12);
    expect(store.getMetrics().totalRequests).toBe(12);
  });

  it("redacts secrets inside decision effects, reasons, and warnings", async () => {
    const dataDir = await makeTempDir();
    const store = new AuditStore({ dataDir, pluginVersion: "0.1.0" });

    const record = await store.recordBefore({
      requestId: "req-redact-decision",
      agentId: "agent-1",
      provider: "claude",
      mode: "shadow",
      requestedAt: "2026-11-21T00:00:00.000Z",
      latencyMs: 1,
      normalizedBy: "claude",
      warnings: ["warning with sk-proj-abcdefghijklmnopqrstuvwxyz123456"],
      action: sampleAction("req-redact-decision", "PGPASSWORD=secret123 git push"),
      decision: {
        level: "L2",
        verdict: "ask",
        reasons: ["vcs_remote:PGPASSWORD=secret123 git push"],
        effects: [
          {
            tag: "vcs_remote",
            layer: 0,
            target: "PGPASSWORD=secret123 curl https://admin:topsecret@api.example.com",
          },
        ],
      },
    });
    await store.flush();

    const serialized = JSON.stringify(record);
    expect(serialized).not.toContain("sk-proj-abcdefghijklmnopqrstuvwxyz123456");
    expect(serialized).not.toContain("secret123");
    expect(serialized).not.toContain("topsecret");
  });

  it("computes agreement outcomes correctly", () => {
    expect(
      computeAgreement(
        { level: "L0", verdict: "allow", reasons: [] },
        { behavior: "allow", resolvedAt: "t", actor: "human" },
      ),
    ).toBe("agree");
    expect(
      computeAgreement(
        { level: "L0", verdict: "allow", reasons: [] },
        { behavior: "deny", resolvedAt: "t", actor: "human" },
      ),
    ).toBe("false_allow");
    expect(
      computeAgreement(
        { level: "L3", verdict: "deny", reasons: [] },
        { behavior: "allow", resolvedAt: "t", actor: "human" },
      ),
    ).toBe("false_deny");
    expect(
      computeAgreement(
        { level: "L1", verdict: "ask", reasons: [] },
        { behavior: "allow", resolvedAt: "t", actor: "human" },
      ),
    ).toBe("plugin_ask_human_allow");
  });
});
