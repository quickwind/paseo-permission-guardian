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
import { Text, TextInput, View } from "react-native";
import { gateAnnotate, gateReplay, getGuardianStatus } from "../shared/rpc.js";
import { guardianSettings, type GuardianSettings } from "../shared/settings.js";
import type {
  GateEntry,
  GateStatus,
  GuardianStatusSnapshot,
} from "../shared/types.js";
import {
  choiceLabelKey,
  effectiveModeLabelKey,
  entryActionLabelKey,
  entryAgentLabel,
  entryContentView,
  entryTime,
  hasIntegrityProblem,
} from "./gate-view.js";
import { messages } from "./i18n.js";

function NumberField(props: {
  label: string;
  hint: string;
  value: number;
  min: number;
  max: number;
  disabled: boolean;
  errorText: string;
  textStyle: object;
  onCommit: (n: number) => void;
}) {
  const { value, min, max, onCommit } = props;
  const [text, setText] = useState(String(value));
  const [invalid, setInvalid] = useState(false);
  useEffect(() => {
    setText(String(value));
    setInvalid(false);
  }, [value]);
  const commit = () => {
    const trimmed = text.trim();
    const n = Number(trimmed);
    if (trimmed !== "" && Number.isInteger(n) && n >= min && n <= max) {
      setInvalid(false);
      if (n !== value) onCommit(n);
    } else {
      setInvalid(true);
    }
  };
  return (
    <SettingsRow
      label={props.label}
      hint={props.hint}
      error={invalid ? props.errorText : null}
    >
      <TextInput
        style={props.textStyle}
        value={text}
        editable={!props.disabled}
        keyboardType="numeric"
        onChangeText={setText}
        onBlur={commit}
        onSubmitEditing={commit}
      />
    </SettingsRow>
  );
}

export function GuardianSettingsScreen({ theme, layout }: PluginSurfaceProps) {
  const { t } = useTranslation(messages);
  const settings = useSettings(guardianSettings);
  const fetchStatus = useRpc(getGuardianStatus);
  const [status, setStatus] = useState<GuardianStatusSnapshot | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [pendingFingerprint, setPendingFingerprint] = useState<string | null>(
    null,
  );
  const [overrideChanged, setOverrideChanged] = useState(false);
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
      input: {
        color: theme.colors.foreground,
        fontSize: 14,
        minWidth: 80,
        padding: 4,
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
  const entryKindLabel = (entry: GateEntry) =>
    t(`act.entries.kind.${entry.kind}`);
  /** Headline: what the entry was about (request summary, recovered summary, or a notice). */
  const entryHeadline = (entry: GateEntry): string => {
    const view = entryContentView(entry);
    if (view.source === "request" || view.source === "recovered") {
      return view.summary ?? view.toolName ?? entry.requestId;
    }
    if (view.source === "missing") return t("act.entries.missing");
    return entry.key;
  };
  /** Detail lines: time, provider, agent, tool, effects, the human's choice and message. */
  const entryDetails = (entry: GateEntry): string => {
    const lines: string[] = [];
    const view = entryContentView(entry);
    const time = entryTime(entry);
    if (time) lines.push(`${t("act.entries.time")}: ${time}`);
    if (entry.provider) lines.push(`${t("act.entries.provider")}: ${entry.provider}`);
    const agent = entryAgentLabel(entry);
    if (agent) lines.push(`${t("act.entries.agent")}: ${agent}`);
    if ((view.source === "request" || view.source === "recovered") && view.toolName) {
      lines.push(`${t("act.entries.tool")}: ${view.toolName}`);
    }
    if (view.source === "recovered") lines.push(t("act.entries.recovered"));
    if (entry.effects.length > 0) {
      lines.push(`${t("act.entries.effects")}: ${entry.effects.join(", ")}`);
    }
    if (entry.resolution) {
      lines.push(`${t("act.entries.yourChoice")}: ${t(choiceLabelKey(entry.resolution))}`);
      if (entry.resolution.message) {
        lines.push(`${t("act.entries.message")}: ${entry.resolution.message}`);
      }
    }
    return lines.join("\n");
  };
  const overrideStatusLabel = !values.actOverride.accepted
    ? t("act.override.inactive")
    : gate && !gate.override.valid
      ? t("act.override.expired")
      : t("act.override.active");

  const effectiveModeLabel = status
    ? t(effectiveModeLabelKey(status.effectiveMode))
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
          <NumberField
            label={t("act.minSamples")}
            hint={t("act.minSamplesHint")}
            value={values.actGate.minSamples}
            min={20}
            max={5000}
            disabled={settings.saving}
            errorText={t("act.validation.range")}
            textStyle={styles.input}
            onCommit={(minSamples) => updateActGate({ minSamples })}
          />
          <NumberField
            label={t("act.windowDays")}
            hint={t("act.windowDaysHint")}
            value={values.actGate.windowDays}
            min={1}
            max={365}
            disabled={settings.saving}
            errorText={t("act.validation.range")}
            textStyle={styles.input}
            onCommit={(windowDays) => updateActGate({ windowDays })}
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
          {!values.actGate.autoFallbackOnFalseAllow ? (
            <Text style={styles.errorText}>
              {t("act.autoFallbackOffWarning")}
            </Text>
          ) : null}
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
                    setPendingFingerprint(null);
                    update({
                      actOverride: {
                        accepted: false,
                        acceptedAt: null,
                        fingerprint: null,
                      },
                    });
                  }}
                />
              ) : pendingFingerprint !== null ? (
                <>
                  <Text style={styles.notice}>{t("act.override.confirm")}</Text>
                  <SettingsAction
                    label={t("act.override.accept")}
                    actionLabel={t("act.override.confirmAction")}
                    disabled={settings.saving || !gate?.fingerprint}
                    onPress={() => {
                      const current = gate?.fingerprint;
                      setPendingFingerprint(null);
                      if (!current) return;
                      if (current !== pendingFingerprint) {
                        setOverrideChanged(true);
                        return;
                      }
                      update({
                        actOverride: {
                          accepted: true,
                          acceptedAt: new Date().toISOString(),
                          fingerprint: current,
                        },
                      });
                    }}
                  />
                  <SettingsAction
                    label={t("act.override.cancel")}
                    actionLabel={t("act.override.cancel")}
                    onPress={() => setPendingFingerprint(null)}
                  />
                </>
              ) : (
                <>
                  {overrideChanged ? (
                    <Text style={styles.errorText}>
                      {t("act.override.changed")}
                    </Text>
                  ) : null}
                  <SettingsAction
                    label={t("act.override.accept")}
                    hint={t("act.override.acceptHint")}
                    actionLabel={t("act.override.accept")}
                    disabled={settings.saving || !gate?.fingerprint}
                    onPress={() => {
                      if (!gate?.fingerprint) return;
                      setOverrideChanged(false);
                      setPendingFingerprint(gate.fingerprint);
                    }}
                  />
                </>
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
                  {hasIntegrityProblem(gate)
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
              {gate.entries.map((entry) => {
                const details = entryDetails(entry);
                return (
                  <SettingsAction
                    key={entry.key}
                    label={`${entryKindLabel(entry)}: ${entryHeadline(entry)}`}
                    hint={details.length > 0 ? details : undefined}
                    actionLabel={t(entryActionLabelKey(entry))}
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
                );
              })}
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
