import { homedir } from "node:os";
import { join } from "node:path";
import type { PluginServerContext } from "@getpaseo/plugin/server";
import { getGuardianStatus } from "./shared/rpc.js";
import { DEFAULT_GUARDIAN_SETTINGS, guardianSettings } from "./shared/settings.js";
import { AuditStore } from "./server/audit/store.js";
import { PermissionGuardianService } from "./server/guardian.js";

const PLUGIN_VERSION = "0.1.0";

function resolveAuditDataDir(): string {
  const override = process.env.PASEO_GUARDIAN_DATA_DIR?.trim();
  if (override) {
    return override;
  }
  return join(homedir(), ".paseo", "permission-guardian", "audit");
}

export default function contribute(server: PluginServerContext) {
  const settingsHandle = server.registerSettings(guardianSettings);
  const auditStore = new AuditStore({
    dataDir: resolveAuditDataDir(),
    pluginVersion: PLUGIN_VERSION,
  });
  const guardian = new PermissionGuardianService({
    auditStore,
    pluginVersion: PLUGIN_VERSION,
    initialSettings: DEFAULT_GUARDIAN_SETTINGS,
  });

  // Load initial persisted settings asynchronously; keep safe shadow defaults until ready.
  void settingsHandle
    .read()
    .then((state) => {
      if (state.status === "ready") {
        guardian.updateSettings(state.values);
      } else {
        console.error(
          `[paseo-permission-guardian] Stored settings invalid (${state.error}); using defaults.`,
        );
      }
    })
    .catch((error) => {
      console.error("[paseo-permission-guardian] Failed to read initial settings:", error);
    });

  const unsubscribeSettings = settingsHandle.subscribe((state) => {
    if (state.status === "ready") {
      guardian.updateSettings(state.values);
    }
  });

  const removeBeforeHook = server.addHook("agent.permission.before", async (payload) => {
    await guardian.handlePermissionBefore(payload);
  });

  const removeAfterHook = server.addHook("agent.permission.after", async (payload) => {
    await guardian.handlePermissionAfter(payload);
  });

  server.handle(getGuardianStatus, async () => guardian.getStatus());

  return async () => {
    removeBeforeHook();
    removeAfterHook();
    await unsubscribeSettings();
    await guardian.flush();
  };
}
