import type { PluginClientContext } from "@getpaseo/plugin/client";
import { GuardianSettingsScreen } from "./client/settings-screen.js";

export default function contribute(client: PluginClientContext) {
  const removeSettings = client.addSettingsScreen({
    id: "guardian-settings",
    title: "Permission Guardian",
    icon: "ShieldCheck",
    Component: GuardianSettingsScreen,
  });

  return () => {
    removeSettings();
  };
}
