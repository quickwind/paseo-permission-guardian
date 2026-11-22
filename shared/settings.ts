import { defineSettings } from "@getpaseo/plugin";
import { z } from "zod";

const ActGateSchema = z.object({
  minSamples: z.number().int().min(20).max(5000).default(200),
  windowDays: z.number().int().min(1).max(365).default(30),
  autoFallbackOnFalseAllow: z.boolean().default(true),
  allowOverride: z.boolean().default(true),
});

const ActOverrideSchema = z.object({
  accepted: z.boolean().default(false),
  acceptedAt: z.string().nullable().default(null),
  fingerprint: z.string().nullable().default(null),
});

export const GuardianSettingsSchema = z.object({
  mode: z.enum(["off", "shadow", "act"]).default("shadow"),
  denyAsAsk: z.boolean().default(true),
  timelineVerbosity: z.enum(["off", "notable", "all"]).default("notable"),
  includeRawInAudit: z.boolean().default(true),
  userPolicyPath: z.string().default("~/.paseo/permission-guardian/policy.yaml"),
  teamPolicyPath: z.string().default(""),
  windowsDefaultShell: z.enum(["pwsh7", "pwsh5", "cmd"]).default("pwsh7"),
  pinnedProjects: z.record(z.string(), z.string()).default({}),
  actGate: ActGateSchema.default(() => ActGateSchema.parse({})),
  actOverride: ActOverrideSchema.default(() => ActOverrideSchema.parse({})),
});

export type GuardianSettings = z.infer<typeof GuardianSettingsSchema>;

export const DEFAULT_GUARDIAN_SETTINGS: GuardianSettings = GuardianSettingsSchema.parse({});

export const guardianSettings = defineSettings({
  id: "guardian",
  scope: "host",
  version: 1,
  schema: GuardianSettingsSchema,
});
