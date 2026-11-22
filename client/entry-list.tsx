import { useTranslation } from "@getpaseo/plugin/client";
import { SettingsAction } from "@getpaseo/plugin/client/ui";
import { View } from "react-native";
import type { GateEntry } from "../shared/types.js";
import { entryAgentLabel, entryViewModel, openEntryChat, type OpenAgentNavigation } from "./gate-view.js";
import { messages } from "./i18n.js";

/**
 * Shared list of gate entries (settings screen and review screen).
 * The open-chat action appears only when `navigation` is given and the entry has an agent id.
 */
export function GateEntryList(props: {
  entries: readonly GateEntry[];
  busy: boolean;
  navigation?: Partial<OpenAgentNavigation>;
  onAnnotate: (entry: GateEntry) => void;
}) {
  const { t } = useTranslation(messages);
  return (
    <>
      {props.entries.map((entry) => {
        const vm = entryViewModel(entry, (key) => t(key as never), props.navigation);
        return (
          <View key={entry.key}>
            <SettingsAction
              label={vm.title}
              hint={vm.details.length > 0 ? vm.details : undefined}
              actionLabel={vm.actionLabel}
              disabled={props.busy}
              onPress={() => props.onAnnotate(entry)}
            />
            {vm.canOpenChat ? (
              <SettingsAction
                label={entryAgentLabel(entry) ?? ""}
                actionLabel={t("act.entries.openChat")}
                onPress={() => {
                  openEntryChat(entry, props.navigation);
                }}
              />
            ) : null}
          </View>
        );
      })}
    </>
  );
}
