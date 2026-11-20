import {
  type PluginSurfaceProps,
  useRpc,
  useSettings,
} from "@getpaseo/plugin/client";
import {
  Loading,
  ScrollView,
  SettingsAction,
  SettingsCard,
  SettingsInput,
  SettingsRow,
  SettingsSection,
  SettingsSelect,
  SettingsSwitch,
} from "@getpaseo/plugin/client/ui";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Text, View } from "react-native";
import { getGuardianStatus } from "../shared/rpc.js";
import { guardianSettings, type GuardianSettings } from "../shared/settings.js";
import type { GuardianStatusSnapshot } from "../shared/types.js";

const MODE_OPTIONS = [
  { label: "Shadow (observe & audit only)", value: "shadow" as const },
  { label: "Off (disabled)", value: "off" as const },
  { label: "Act (available in P2, currently shadow)", value: "act" as const },
];

const TIMELINE_OPTIONS = [
  { label: "Notable events only", value: "notable" as const },
  { label: "All events", value: "all" as const },
  { label: "Off", value: "off" as const },
];

const WINDOWS_SHELL_OPTIONS = [
  { label: "PowerShell 7 (pwsh)", value: "pwsh7" as const },
  { label: "Windows PowerShell 5.1", value: "pwsh5" as const },
  { label: "Command Prompt (cmd.exe)", value: "cmd" as const },
];

export function GuardianSettingsScreen({ theme, layout }: PluginSurfaceProps) {
  const settings = useSettings(guardianSettings);
  const fetchStatus = useRpc(getGuardianStatus);
  const [status, setStatus] = useState<GuardianStatusSnapshot | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);

  const refreshStatus = useCallback(() => {
    setStatusError(null);
    void fetchStatus({})
      .then((snapshot) => setStatus(snapshot))
      .catch((error) => {
        setStatusError(error instanceof Error ? error.message : "Failed to load status");
      });
  }, [fetchStatus]);

  useEffect(() => {
    refreshStatus();
  }, [refreshStatus]);

  const styles = useMemo(
    () => ({
      container: {
        flex: 1,
        backgroundColor: theme.colors.surface0,
      },
      content: {
        padding: layout.compact ? 16 : 24,
        gap: layout.compact ? 16 : 20,
      },
      notice: {
        color: theme.colors.foregroundMuted,
        fontSize: 13,
        lineHeight: 18,
      },
      errorText: {
        color: theme.colors.statusDanger,
        fontSize: 13,
      },
      metricValue: {
        color: theme.colors.foreground,
        fontSize: 14,
      },
    }),
    [theme, layout.compact],
  );

  if (settings.status === "loading") {
    return <Loading />;
  }

  if (settings.status === "error" || settings.status === "invalid") {
    return (
      <View style={[styles.container, styles.content]}>
        <Text style={styles.errorText}>{settings.error}</Text>
        <SettingsCard>
          <SettingsAction
            label="Reset settings"
            hint="Restore default Permission Guardian settings."
            actionLabel="Reset"
            onPress={() => {
              void settings.reset();
            }}
          />
        </SettingsCard>
      </View>
    );
  }

  const { values, revision } = settings;

  const update = (patch: Partial<GuardianSettings>) => {
    void settings.save({ ...values, ...patch }, revision).then(() => {
      refreshStatus();
    });
  };

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <SettingsSection title="Runtime mode">
        <SettingsCard>
          <SettingsSelect
            label="Guardian mode"
            hint="Shadow mode records and reconciles every permission request without answering prompts."
            value={values.mode}
            options={MODE_OPTIONS}
            disabled={settings.saving}
            onValueChange={(mode) => update({ mode })}
          />
          <SettingsSwitch
            label="Treat deny as ask"
            hint="Convert deny verdicts into human prompts instead of automatically denying."
            value={values.denyAsAsk}
            disabled={settings.saving}
            onValueChange={(denyAsAsk) => update({ denyAsAsk })}
          />
          <SettingsSelect
            label="Timeline verbosity"
            hint="Controls which events are appended to agent timelines."
            value={values.timelineVerbosity}
            options={TIMELINE_OPTIONS}
            disabled={settings.saving}
            onValueChange={(timelineVerbosity) => update({ timelineVerbosity })}
          />
        </SettingsCard>
      </SettingsSection>

      <SettingsSection title="Audit & policy">
        <SettingsCard>
          <SettingsSwitch
            label="Include raw payloads in audit log"
            hint="Raw provider payloads are redacted for known secrets before writing to JSONL."
            value={values.includeRawInAudit}
            disabled={settings.saving}
            onValueChange={(includeRawInAudit) => update({ includeRawInAudit })}
          />
          <SettingsSelect
            label="Default Windows shell"
            hint="Used when a Windows exec request does not specify a shell."
            value={values.windowsDefaultShell}
            options={WINDOWS_SHELL_OPTIONS}
            disabled={settings.saving}
            onValueChange={(windowsDefaultShell) => update({ windowsDefaultShell })}
          />
          <SettingsInput
            label="User policy path"
            hint="Local YAML policy file path (read-only from UI)."
            initialValue={values.userPolicyPath}
            placeholder="~/.paseo/permission-guardian/policy.yaml"
            disabled={settings.saving}
            onChangeText={(userPolicyPath) => update({ userPolicyPath })}
          />
          <SettingsInput
            label="Team policy path"
            hint="Optional local file path distributed via Git, dotfiles, or MDM."
            initialValue={values.teamPolicyPath}
            placeholder="/path/to/team-policy.yaml"
            disabled={settings.saving}
            onChangeText={(teamPolicyPath) => update({ teamPolicyPath })}
          />
        </SettingsCard>
      </SettingsSection>

      <SettingsSection title="Shadow audit status">
        <SettingsCard>
          {statusError ? (
            <SettingsRow label="Status error">
              <Text style={styles.errorText}>{statusError}</Text>
            </SettingsRow>
          ) : null}
          <SettingsRow label="Effective mode">
            <Text style={styles.metricValue}>{status?.effectiveMode ?? "..."}</Text>
          </SettingsRow>
          <SettingsRow label="Total requests">
            <Text style={styles.metricValue}>{String(status?.metrics.totalRequests ?? 0)}</Text>
          </SettingsRow>
          <SettingsRow label="Reconciled / Pending">
            <Text style={styles.metricValue}>
              {`${status?.metrics.reconciledCount ?? 0} / ${status?.metrics.pendingCount ?? 0}`}
            </Text>
          </SettingsRow>
          <SettingsRow label="False allows">
            <Text style={styles.metricValue}>{String(status?.metrics.falseAllowCount ?? 0)}</Text>
          </SettingsRow>
          <SettingsRow label="Audit directory" hint={status?.dataDir ?? "Loading..."} />
          <SettingsAction
            label="Refresh metrics"
            actionLabel="Refresh"
            onPress={refreshStatus}
          />
        </SettingsCard>
      </SettingsSection>

      {settings.saveError ? (
        <Text style={styles.errorText}>{settings.saveError}</Text>
      ) : (
        <Text style={styles.notice}>
          P0 runs in shadow-only mode. Deterministic AST rules and act mode arrive in P1a/P2.
        </Text>
      )}
    </ScrollView>
  );
}
