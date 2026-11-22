import type { PluginClientContext } from "@getpaseo/plugin/client";
import { messages } from "./client/i18n.js";
import { GuardianReviewScreen } from "./client/review-screen.js";
import { GuardianSettingsScreen } from "./client/settings-screen.js";
import { GuardianSidebarItem } from "./client/sidebar-item.js";
import { REVIEW_SCREEN_ID } from "./client/gate-view.js";

export default function contribute(client: PluginClientContext) {
  const removeSettings = client.addSettingsScreen({
    id: "guardian-settings",
    title: messages.message("settings.title"),
    icon: "ShieldCheck",
    Component: GuardianSettingsScreen,
  });
  const removeScreen = client.addScreen({
    id: REVIEW_SCREEN_ID,
    title: messages.message("review.title"),
    Component: GuardianReviewScreen,
  });
  const removeSidebar = client.addSidebarFooterItem({
    id: REVIEW_SCREEN_ID,
    title: messages.message("review.sidebarTitle"),
    Component: GuardianSidebarItem,
  });

  return () => {
    removeSettings();
    removeScreen();
    removeSidebar();
  };
}
