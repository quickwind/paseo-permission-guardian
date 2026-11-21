import { homedir } from "node:os";
import { join } from "node:path";
import type { PluginServerContext } from "@getpaseo/plugin/server";
import { evaluateGuardianDryRun, getGuardianStatus } from "./shared/rpc.js";
import { DEFAULT_GUARDIAN_SETTINGS, guardianSettings } from "./shared/settings.js";
import { AuditStore } from "./server/audit/store.js";
import type { TimelineFetcher } from "./server/context/session.js";
import { decideAction } from "./server/decide.js";
import { PermissionGuardianService } from "./server/guardian.js";
import { disposeSharedPwshHost } from "./server/shell/pwsh-host.js";

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

  const removeBeforeHook = server.addHook(
    "agent.permission.before",
    async (payload, context) => {
      const fetchTimeline: TimelineFetcher = async (agentId) => {
        const res = await context.paseo.agents.ref(agentId).timeline.refetch({
          direction: "tail",
          limit: 1,
          wholeTurns: true,
        });
        return res.entries.map((entry) => entry.item);
      };
      await guardian.handlePermissionBefore(payload, fetchTimeline);
    },
  );

  const removeAfterHook = server.addHook("agent.permission.after", async (payload) => {
    await guardian.handlePermissionAfter(payload);
  });

  const removeTurnAfterHook = server.addHook("agent.turn.after", async (payload) => {
    guardian.handleTurnAfter(payload.agent.id);
  });

  const removeCloseAfterHook = server.addHook("agent.close.after", async (payload) => {
    guardian.handleAgentClosed(payload.agent.id);
  });

  const removeArchiveAfterHook = server.addHook("agent.archive.after", async (payload) => {
    guardian.handleAgentClosed(payload.agent.id);
  });

  server.handle(getGuardianStatus, async () => guardian.getStatus());

  server.handle(evaluateGuardianDryRun, async (input) => {
    const res = await decideAction(
      {
        provider: "paseo",
        agentId: "dry-run",
        requestId: "dry-run",
        kind: "exec",
        toolName: input.shell,
        host: { os: input.hostOs },
        cwd: input.cwd,
        worktreeRoot: input.worktreeRoot ?? input.cwd,
        exec: { shell: input.shell, source: input.source },
      },
      {
        pathCtx: {
          os: input.hostOs,
          cwd: input.cwd,
          worktreeRoot: input.worktreeRoot ?? input.cwd,
          home: input.home ?? (input.hostOs === "windows" ? "C:\\Users\\user" : homedir()),
        },
        denyAsAsk: guardian.getSettings().denyAsAsk,
      },
    );
    return {
      level: res.decision.level,
      verdict: res.decision.verdict,
      reasons: res.decision.reasons,
      touchedSecret: res.touchedSecret,
    };
  });

  return async () => {
    removeBeforeHook();
    removeAfterHook();
    removeTurnAfterHook();
    removeCloseAfterHook();
    removeArchiveAfterHook();
    await unsubscribeSettings();
    await guardian.flush();
    await disposeSharedPwshHost();
  };
}
