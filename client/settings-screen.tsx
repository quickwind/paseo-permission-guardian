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
import { gateAnnotate, gateReplay, getGuardianStatus } from "../shared/rpc.js";
import { guardianSettings, type GuardianSettings } from "../shared/settings.js";
import type {
  GateEntry,
  GateStatus,
  GuardianStatusSnapshot,
} from "../shared/types.js";
import { messages } from "./i18n.js";

export function GuardianSettingsScreen({ theme, layout }: PluginSurfaceProps) {
  const { t } = useTranslation(messages);
  const settings = useSettings(guardianSettings);
  const fetchStatus = useRpc(getGuardianStatus);
  const [status, setStatus] = useState<GuardianStatusSnapshot | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [confirmingOverride, setConfirmingOverride] = useState(false);
  const [gateBusy, setGateBusy] = useState(false);
  const replayGate = useRpc(gateReplay);
  const annotateGate = useRpc(gateAnnotate);

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
        setStatusError(
          error instanceof Error
            ? error.message
            : t("settings.loadStatusError"),
        );
      });
  }, [fetchStatus, t]);

  useEffect(() => {
    refreshStatus();
    const timer = setInterval(refreshStatus, 5000);
    return () => clearInterval(timer);
  }, [refreshStatus]);

  const runGateAction = (action: () => Promise<GateStatus>) => {
    setGateBusy(true);
    void action()
      .then((gate) => setStatus((prev) => (prev ? { ...prev, gate } : prev)))
      .catch((error) => {
        setStatusError(
          error instanceof Error
            ? error.message
            : t("settings.loadStatusError"),
        );
      })
      .finally(() => {
        setGateBusy(false);
        refreshStatus();
      });
  };

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

  const gate = status?.gate ?? null;
  const updateActGate = (patch: Partial<GuardianSettings["actGate"]>) =>
    update({ actGate: { ...values.actGate, ...patch } });
  const numberField = (
    text: string,
    min: number,
    max: number,
    apply: (n: number) => void,
  ): void => {
    const n = Number(text.trim());
    if (text.trim() !== "" && Number.isInteger(n) && n >= min && n <= max)
      apply(n);
  };
  const entryKindLabel = (entry: GateEntry) =>
    t(`act.entries.kind.${entry.kind}`);
  const overrideStatusLabel = !values.actOverride.accepted
    ? t("act.override.inactive")
    : gate && !gate.override.valid
      ? t("act.override.expired")
      : t("act.override.active");

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
            onValueChange={(windowsDefaultShell) =>
              update({ windowsDefaultShell })
            }
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
            <Text style={styles.metricValue}>
              {String(status?.metrics.totalRequests ?? 0)}
            </Text>
          </SettingsRow>
          <SettingsRow label={t("status.reconciledPendingLabel")}>
            <Text style={styles.metricValue}>
              {`${status?.metrics.reconciledCount ?? 0} / ${status?.metrics.pendingCount ?? 0}`}
            </Text>
          </SettingsRow>
          <SettingsRow label={t("status.falseAllowsLabel")}>
            <Text style={styles.metricValue}>
              {String(status?.metrics.falseAllowCount ?? 0)}
            </Text>
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

      <SettingsSection title={t("act.section.title")}>
        <SettingsCard>
          <SettingsInput
            label={t("act.minSamples")}
            hint={t("act.minSamplesHint")}
            initialValue={String(values.actGate.minSamples)}
            disabled={settings.saving}
            onChangeText={(text) =>
              numberField(text, 20, 5000, (minSamples) =>
                updateActGate({ minSamples }),
              )
            }
          />
          <SettingsInput
            label={t("act.windowDays")}
            hint={t("act.windowDaysHint")}
            initialValue={String(values.actGate.windowDays)}
            disabled={settings.saving}
            onChangeText={(text) =>
              numberField(text, 1, 365, (windowDays) =>
                updateActGate({ windowDays }),
              )
            }
          />
          <SettingsSwitch
            label={t("act.autoFallback")}
            hint={t("act.autoFallbackHint")}
            value={values.actGate.autoFallbackOnFalseAllow}
            disabled={settings.saving}
            onValueChange={(autoFallbackOnFalseAllow) =>
              updateActGate({ autoFallbackOnFalseAllow })
            }
          />
          <SettingsSwitch
            label={t("act.allowOverride")}
            hint={t("act.allowOverrideHint")}
            value={values.actGate.allowOverride}
            disabled={settings.saving}
            onValueChange={(allowOverride) => updateActGate({ allowOverride })}
          />
          {values.actGate.allowOverride ? (
            <>
              <SettingsRow label={t("act.override.status")}>
                <Text style={styles.metricValue}>{overrideStatusLabel}</Text>
              </SettingsRow>
              {values.actOverride.accepted ? (
                <SettingsAction
                  label={t("act.override.revoke")}
                  actionLabel={t("act.override.revoke")}
                  disabled={settings.saving}
                  onPress={() => {
                    setConfirmingOverride(false);
                    update({
                      actOverride: {
                        accepted: false,
                        acceptedAt: null,
                        fingerprint: null,
                      },
                    });
                  }}
                />
              ) : confirmingOverride ? (
                <>
                  <Text style={styles.notice}>{t("act.override.confirm")}</Text>
                  <SettingsAction
                    label={t("act.override.accept")}
                    actionLabel={t("act.override.confirmAction")}
                    disabled={settings.saving || !gate}
                    onPress={() => {
                      if (!gate) return;
                      setConfirmingOverride(false);
                      update({
                        actOverride: {
                          accepted: true,
                          acceptedAt: new Date().toISOString(),
                          fingerprint: gate.fingerprint,
                        },
                      });
                    }}
                  />
                  <SettingsAction
                    label={t("act.override.cancel")}
                    actionLabel={t("act.override.cancel")}
                    onPress={() => setConfirmingOverride(false)}
                  />
                </>
              ) : (
                <SettingsAction
                  label={t("act.override.accept")}
                  hint={t("act.override.acceptHint")}
                  actionLabel={t("act.override.accept")}
                  disabled={settings.saving || !gate}
                  onPress={() => setConfirmingOverride(true)}
                />
              )}
            </>
          ) : null}
        </SettingsCard>
        <SettingsCard>
          {gate ? (
            <>
              <SettingsRow label={t("act.status.state")}>
                <Text style={styles.metricValue}>
                  {t(`act.state.${gate.state}`)}
                </Text>
              </SettingsRow>
              {gate.reason ? (
                <SettingsRow label={t("act.status.reason")}>
                  <Text style={styles.notice}>{gate.reason}</Text>
                </SettingsRow>
              ) : null}
              <SettingsRow label={t("act.status.samples")}>
                <Text
                  style={styles.metricValue}
                >{`${gate.samples} / ${gate.minSamples}`}</Text>
              </SettingsRow>
              <SettingsRow label={t("act.status.falseAllows")}>
                <Text style={styles.metricValue}>
                  {String(gate.falseAllowCount)}
                </Text>
              </SettingsRow>
              <SettingsRow label={t("act.status.falseDenies")}>
                <Text style={styles.metricValue}>
                  {String(gate.falseDenyCount)}
                </Text>
              </SettingsRow>
              <SettingsRow label={t("act.unconfirmed")}>
                <Text style={styles.metricValue}>
                  {String(gate.unconfirmedCount)}
                </Text>
              </SettingsRow>
              <SettingsRow label={t("act.integrity")}>
                <Text style={styles.metricValue}>
                  {gate.entries.some((e) => e.kind === "corrupt_line")
                    ? t("act.integrityBad")
                    : t("act.integrityOk")}
                </Text>
              </SettingsRow>
              <SettingsRow label={t("act.status.lastReplay")}>
                <Text style={styles.metricValue}>
                  {gate.lastReplayAt ?? t("act.status.never")}
                </Text>
              </SettingsRow>
              <SettingsRow label={t("act.status.fingerprint")}>
                <Text style={styles.metricValue}>
                  {gate.fingerprint.slice(0, 8)}
                </Text>
              </SettingsRow>
              {gate.entries.map((entry) => (
                <SettingsAction
                  key={entry.key}
                  label={`${entryKindLabel(entry)}: ${entry.command ?? entry.requestId}`}
                  hint={
                    entry.effects.length > 0
                      ? entry.effects.join(", ")
                      : undefined
                  }
                  actionLabel={
                    entry.kind === "corrupt_line"
                      ? t("act.entries.acknowledge")
                      : t("act.entries.annotate")
                  }
                  disabled={gateBusy}
                  onPress={() =>
                    runGateAction(() =>
                      annotateGate({
                        key: entry.key,
                        annotation: "not_safety",
                      }),
                    )
                  }
                />
              ))}
            </>
          ) : (
            <SettingsRow label={t("act.status.title")}>
              <Text style={styles.metricValue}>{t("status.loading")}</Text>
            </SettingsRow>
          )}
          <SettingsAction
            label={t("act.replay")}
            hint={t("act.replayHint")}
            actionLabel={t("act.replayAction")}
            disabled={gateBusy}
            onPress={() => runGateAction(() => replayGate({}))}
          />
          <Text style={styles.notice}>{t("act.help.pwshUnavailable")}</Text>
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
