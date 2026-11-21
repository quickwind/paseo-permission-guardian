import { defineRpc } from "@getpaseo/plugin";
import { z } from "zod";

export const AuditMetricsSummarySchema = z.object({
  totalRequests: z.number().int().nonnegative(),
  reconciledCount: z.number().int().nonnegative(),
  pendingCount: z.number().int().nonnegative(),
  wouldAllowCount: z.number().int().nonnegative(),
  wouldAskCount: z.number().int().nonnegative(),
  wouldDenyCount: z.number().int().nonnegative(),
  humanAllowCount: z.number().int().nonnegative(),
  humanDenyCount: z.number().int().nonnegative(),
  falseAllowCount: z.number().int().nonnegative(),
  falseDenyCount: z.number().int().nonnegative(),
  agreementCount: z.number().int().nonnegative(),
  outOfOrderCount: z.number().int().nonnegative(),
  lastUpdatedAt: z.string().nullable(),
});

export const getGuardianStatus = defineRpc({
  name: "guardian.status",
  input: z.object({}),
  output: z.object({
    pluginVersion: z.string(),
    mode: z.enum(["off", "shadow", "act"]),
    effectiveMode: z.enum(["off", "shadow"]),
    dataDir: z.string(),
    metrics: AuditMetricsSummarySchema,
  }),
});

export const evaluateGuardianDryRun = defineRpc({
  name: "guardian.dry_run",
  input: z.object({
    shell: z.enum(["bash", "cmd", "pwsh5", "pwsh7", "argv"]),
    source: z.string().max(32_768),
    hostOs: z.enum(["darwin", "linux", "windows"]).default("linux"),
    cwd: z.string().default("/tmp"),
    worktreeRoot: z.string().optional(),
    home: z.string().optional(),
  }),
  output: z.object({
    level: z.enum(["L0", "L1", "L2", "L3"]),
    verdict: z.enum(["allow", "ask", "deny"]),
    reasons: z.array(z.string()),
    touchedSecret: z.boolean(),
  }),
});
