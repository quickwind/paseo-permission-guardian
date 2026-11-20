import type { PluginClientContext } from "@getpaseo/plugin/client";
import { messages } from "./client/i18n.js";
import { GuardianSettingsScreen } from "./client/settings-screen.js";

export default function contribute(client: PluginClientContext) {
  const removeSettings = client.addSettingsScreen({
    id: "guardian-settings",
    title: messages.message("settings.title"),
    icon: "ShieldCheck",
    Component: GuardianSettingsScreen,
  });

  return () => {
    removeSettings();
  };
}
