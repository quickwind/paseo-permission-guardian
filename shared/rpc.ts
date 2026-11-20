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
