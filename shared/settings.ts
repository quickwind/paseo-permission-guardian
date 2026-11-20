import { defineSettings } from "@getpaseo/plugin";
import { z } from "zod";

export const GuardianSettingsSchema = z.object({
  mode: z.enum(["off", "shadow", "act"]).default("shadow"),
  denyAsAsk: z.boolean().default(true),
  timelineVerbosity: z.enum(["off", "notable", "all"]).default("notable"),
  includeRawInAudit: z.boolean().default(true),
  userPolicyPath: z.string().default("~/.paseo/permission-guardian/policy.yaml"),
  teamPolicyPath: z.string().default(""),
  windowsDefaultShell: z.enum(["pwsh7", "pwsh5", "cmd"]).default("pwsh7"),
  pinnedProjects: z.record(z.string(), z.string()).default({}),
});

export type GuardianSettings = z.infer<typeof GuardianSettingsSchema>;

export const DEFAULT_GUARDIAN_SETTINGS: GuardianSettings = GuardianSettingsSchema.parse({});

export const guardianSettings = defineSettings({
  id: "guardian",
  scope: "host",
  version: 1,
  schema: GuardianSettingsSchema,
});
