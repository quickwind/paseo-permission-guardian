import { type PluginScreenProps, useRpc, useSettings, useTranslation } from "@getpaseo/plugin/client";
import {
  Loading,
  ScrollView,
  SettingsAction,
  SettingsCard,
  SettingsRow,
  SettingsSection,
} from "@getpaseo/plugin/client/ui";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Text } from "react-native";
import { gateAnnotate, gateReplay, getGuardianStatus } from "../shared/rpc.js";
import { guardianSettings } from "../shared/settings.js";
import type { GateStatus, GuardianStatusSnapshot } from "../shared/types.js";
import { GateEntryList } from "./entry-list.js";
import { effectiveModeLabelKey, integrityText } from "./gate-view.js";
import { messages } from "./i18n.js";

/** Plugin screen listing gate entries that need review, with open-chat and annotate actions. */
export function GuardianReviewScreen({ theme, layout, navigation }: PluginScreenProps) {
  const { t } = useTranslation(messages);
  const settings = useSettings(guardianSettings);
  const fetchStatus = useRpc(getGuardianStatus);
  const replayGate = useRpc(gateReplay);
  const annotateGate = useRpc(gateAnnotate);
  const [status, setStatus] = useState<GuardianStatusSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(() => {
    void fetchStatus({})
      .then((snapshot) => {
        setError(null);
        setStatus(snapshot);
      })
      .catch((e) => setError(e instanceof Error ? e.message : t("settings.loadStatusError")));
  }, [fetchStatus, t]);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 5000);
    return () => clearInterval(timer);
  }, [refresh]);

  const run = (action: () => Promise<GateStatus>) => {
    setBusy(true);
    void action()
      .then((gate) => setStatus((prev) => (prev ? { ...prev, gate } : prev)))
      .catch((e) => setError(e instanceof Error ? e.message : t("settings.loadStatusError")))
      .finally(() => {
        setBusy(false);
        refresh();
      });
  };

  const styles = useMemo(
    () => ({
      container: { flex: 1, backgroundColor: theme.colors.surface0 },
      content: { padding: layout.compact ? 16 : 24, gap: layout.compact ? 16 : 20 },
      notice: { color: theme.colors.foregroundMuted, fontSize: 13, lineHeight: 18 },
      errorText: { color: theme.colors.statusDanger, fontSize: 13 },
      value: { color: theme.colors.foreground, fontSize: 14 },
    }),
    [theme, layout.compact],
  );

  if (!status && !error) return <Loading />;
  const gate = status?.gate ?? null;

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {error ? <Text style={styles.errorText}>{error}</Text> : null}
      {gate && status ? (
        <>
          <SettingsSection title={t("review.summary")}>
            <SettingsCard>
              <SettingsRow label={t("status.effectiveModeLabel")}>
                <Text style={styles.value}>{t(effectiveModeLabelKey(status.effectiveMode))}</Text>
              </SettingsRow>
              <SettingsRow label={t("act.status.state")}>
                <Text style={styles.value}>{t(`act.state.${gate.state}`)}</Text>
              </SettingsRow>
              <SettingsRow label={t("act.integrity")}>
                <Text style={styles.value}>{integrityText(gate, (key) => t(key))}</Text>
              </SettingsRow>
              <SettingsRow label={t("act.status.samples")}>
                <Text style={styles.value}>{`${gate.samples} / ${gate.minSamples}`}</Text>
              </SettingsRow>
              <SettingsAction
                label={t("act.replay")}
                hint={t("act.replayHint")}
                actionLabel={t("act.replayAction")}
                disabled={busy}
                onPress={() => run(() => replayGate({}))}
              />
            </SettingsCard>
          </SettingsSection>
          {settings.status === "ready" && settings.values.showSidebarItem ? (
            <SettingsSection title={t("review.hide")}>
              <SettingsCard>
                <SettingsAction
                  label={t("review.hide")}
                  hint={t("review.hideHint")}
                  actionLabel={t("review.hideAction")}
                  disabled={settings.saving}
                  onPress={() =>
                    void settings.save({ ...settings.values, showSidebarItem: false }, settings.revision)
                  }
                />
              </SettingsCard>
            </SettingsSection>
          ) : null}
          <SettingsSection title={t("review.entries")}>
            <SettingsCard>
              {gate.entries.length === 0 ? (
                <Text style={styles.notice}>{t("review.empty")}</Text>
              ) : (
                <>
                  <Text style={styles.notice}>{t("act.entries.gateHint")}</Text>
                  <GateEntryList
                    entries={gate.entries}
                    busy={busy}
                    navigation={navigation}
                    onAnnotate={(entry) =>
                      run(() => annotateGate({ key: entry.key, annotation: "not_safety" }))
                    }
                  />
                </>
              )}
            </SettingsCard>
          </SettingsSection>
        </>
      ) : null}
    </ScrollView>
  );
}
