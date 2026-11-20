import {
  type PluginSurfaceProps,
  useRpc,
  useSettings,
  useTranslation,
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
import { messages } from "./i18n.js";

export function GuardianSettingsScreen({ theme, layout }: PluginSurfaceProps) {
  const { t } = useTranslation(messages);
  const settings = useSettings(guardianSettings);
  const fetchStatus = useRpc(getGuardianStatus);
  const [status, setStatus] = useState<GuardianStatusSnapshot | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);

  const modeOptions = useMemo(
    () => [
      { label: t("mode.options.shadow"), value: "shadow" as const },
      { label: t("mode.options.off"), value: "off" as const },
      { label: t("mode.options.act"), value: "act" as const },
    ],
    [t],
  );

  const timelineOptions = useMemo(
    () => [
      { label: t("timeline.options.notable"), value: "notable" as const },
      { label: t("timeline.options.all"), value: "all" as const },
      { label: t("timeline.options.off"), value: "off" as const },
    ],
    [t],
  );

  const windowsShellOptions = useMemo(
    () => [
      { label: t("windowsShell.options.pwsh7"), value: "pwsh7" as const },
      { label: t("windowsShell.options.pwsh5"), value: "pwsh5" as const },
      { label: t("windowsShell.options.cmd"), value: "cmd" as const },
    ],
    [t],
  );

  const refreshStatus = useCallback(() => {
    setStatusError(null);
    void fetchStatus({})
      .then((snapshot) => setStatus(snapshot))
      .catch((error) => {
        setStatusError(error instanceof Error ? error.message : t("settings.loadStatusError"));
      });
  }, [fetchStatus, t]);

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
            label={t("settings.resetLabel")}
            hint={t("settings.resetHint")}
            actionLabel={t("settings.resetAction")}
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

  const effectiveModeLabel = status
    ? status.effectiveMode === "off"
      ? t("mode.effectiveValues.off")
      : t("mode.effectiveValues.shadow")
    : "...";

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <SettingsSection title={t("sections.runtimeMode")}>
        <SettingsCard>
          <SettingsSelect
            label={t("mode.label")}
            hint={t("mode.hint")}
            value={values.mode}
            options={modeOptions}
            disabled={settings.saving}
            onValueChange={(mode) => update({ mode })}
          />
          <SettingsSwitch
            label={t("denyAsAsk.label")}
            hint={t("denyAsAsk.hint")}
            value={values.denyAsAsk}
            disabled={settings.saving}
            onValueChange={(denyAsAsk) => update({ denyAsAsk })}
          />
          <SettingsSelect
            label={t("timeline.label")}
            hint={t("timeline.hint")}
            value={values.timelineVerbosity}
            options={timelineOptions}
            disabled={settings.saving}
            onValueChange={(timelineVerbosity) => update({ timelineVerbosity })}
          />
        </SettingsCard>
      </SettingsSection>

      <SettingsSection title={t("sections.auditAndPolicy")}>
        <SettingsCard>
          <SettingsSwitch
            label={t("audit.includeRawLabel")}
            hint={t("audit.includeRawHint")}
            value={values.includeRawInAudit}
            disabled={settings.saving}
            onValueChange={(includeRawInAudit) => update({ includeRawInAudit })}
          />
          <SettingsSelect
            label={t("windowsShell.label")}
            hint={t("windowsShell.hint")}
            value={values.windowsDefaultShell}
            options={windowsShellOptions}
            disabled={settings.saving}
            onValueChange={(windowsDefaultShell) => update({ windowsDefaultShell })}
          />
          <SettingsInput
            label={t("policy.userPathLabel")}
            hint={t("policy.userPathHint")}
            initialValue={values.userPolicyPath}
            placeholder="~/.paseo/permission-guardian/policy.yaml"
            disabled={settings.saving}
            onChangeText={(userPolicyPath) => update({ userPolicyPath })}
          />
          <SettingsInput
            label={t("policy.teamPathLabel")}
            hint={t("policy.teamPathHint")}
            initialValue={values.teamPolicyPath}
            placeholder={t("policy.teamPathPlaceholder")}
            disabled={settings.saving}
            onChangeText={(teamPolicyPath) => update({ teamPolicyPath })}
          />
        </SettingsCard>
      </SettingsSection>

      <SettingsSection title={t("sections.shadowAuditStatus")}>
        <SettingsCard>
          {statusError ? (
            <SettingsRow label={t("status.errorLabel")}>
              <Text style={styles.errorText}>{statusError}</Text>
            </SettingsRow>
          ) : null}
          <SettingsRow label={t("status.effectiveModeLabel")}>
            <Text style={styles.metricValue}>{effectiveModeLabel}</Text>
          </SettingsRow>
          <SettingsRow label={t("status.totalRequestsLabel")}>
            <Text style={styles.metricValue}>{String(status?.metrics.totalRequests ?? 0)}</Text>
          </SettingsRow>
          <SettingsRow label={t("status.reconciledPendingLabel")}>
            <Text style={styles.metricValue}>
              {`${status?.metrics.reconciledCount ?? 0} / ${status?.metrics.pendingCount ?? 0}`}
            </Text>
          </SettingsRow>
          <SettingsRow label={t("status.falseAllowsLabel")}>
            <Text style={styles.metricValue}>{String(status?.metrics.falseAllowCount ?? 0)}</Text>
          </SettingsRow>
          <SettingsRow
            label={t("status.auditDirLabel")}
            hint={status?.dataDir ?? t("status.loading")}
          />
          <SettingsAction
            label={t("status.refreshLabel")}
            actionLabel={t("status.refreshAction")}
            onPress={refreshStatus}
          />
        </SettingsCard>
      </SettingsSection>

      {settings.saveError ? (
        <Text style={styles.errorText}>{settings.saveError}</Text>
      ) : (
        <Text style={styles.notice}>{t("settings.p0Notice")}</Text>
      )}
    </ScrollView>
  );
}
