import { defineRpc } from "@getpaseo/plugin";
import { z } from "zod";
import type { GateStatus } from "./types.js";

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

export const GateEntrySchema = z.object({
  requestId: z.string(),
  requestedAt: z.string().optional(),
  command: z.string().optional(),
  effects: z.array(z.string()),
  kind: z.enum(["false_allow", "orphan_deny", "corrupt_line"]),
  key: z.string(),
});

export const GateStatusSchema = z.object({
  state: z.enum([
    "replaying",
    "unavailable",
    "failed_false_allow",
    "collecting",
    "passed",
    "latched",
    "suspended",
  ]),
  reason: z.string(),
  samples: z.number().int().nonnegative(),
  minSamples: z.number().int().nonnegative(),
  falseAllowCount: z.number().int().nonnegative(),
  falseDenyCount: z.number().int().nonnegative(),
  entries: z.array(GateEntrySchema),
  unconfirmedCount: z.number().int().nonnegative(),
  lastReplayAt: z.string().nullable(),
  fingerprint: z.string(),
  override: z.object({
    valid: z.boolean(),
    accepted: z.boolean(),
    acceptedAt: z.string().nullable(),
  }),
  latched: z.boolean(),
  suspended: z.boolean(),
});

// Compile-time check: the Zod schema and the GateStatus interface stay mutually assignable.
type _SchemaToType = z.infer<typeof GateStatusSchema> extends GateStatus ? true : never;
type _TypeToSchema = GateStatus extends z.infer<typeof GateStatusSchema> ? true : never;
export const _gateStatusConsistent: [_SchemaToType, _TypeToSchema] = [true, true];

export const getGuardianStatus = defineRpc({
  name: "guardian.status",
  input: z.object({}),
  output: z.object({
    pluginVersion: z.string(),
    mode: z.enum(["off", "shadow", "act"]),
    effectiveMode: z.enum(["off", "shadow", "act"]),
    dataDir: z.string(),
    metrics: AuditMetricsSummarySchema,
    gate: GateStatusSchema,
  }),
});

export const gateReplay = defineRpc({
  name: "guardian.gate.replay",
  input: z.object({}),
  output: GateStatusSchema,
});

export const gateAnnotate = defineRpc({
  name: "guardian.gate.annotate",
  input: z.object({ key: z.string(), annotation: z.enum(["not_safety"]).nullable() }),
  output: GateStatusSchema,
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
