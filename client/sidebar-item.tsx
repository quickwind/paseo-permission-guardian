import { type PluginSidebarItemProps, useRpc, useSettings, useTranslation } from "@getpaseo/plugin/client";
import { SidebarRow } from "@getpaseo/plugin/client/ui";
import { useEffect, useState } from "react";
import { Text, View } from "react-native";
import { getGuardianStatus } from "../shared/rpc.js";
import { guardianSettings } from "../shared/settings.js";
import { openReviewScreen, REVIEW_SCREEN_ID, reviewBadgeCount, shouldShowSidebarItem } from "./gate-view.js";
import { messages } from "./i18n.js";

const POLL_MS = 30_000;

/** Sidebar row opening the review screen, with a count of entries needing review. */
export function GuardianSidebarItem({ theme, currentScreen, openScreen }: PluginSidebarItemProps) {
  const { t } = useTranslation(messages);
  const fetchStatus = useRpc(getGuardianStatus);
  const settings = useSettings(guardianSettings);
  const [count, setCount] = useState(0);

  useEffect(() => {
    let alive = true;
    const poll = () => {
      void fetchStatus({})
        .then((s) => alive && setCount(reviewBadgeCount(s)))
        .catch(() => alive && setCount(0));
    };
    poll();
    const timer = setInterval(poll, POLL_MS);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [fetchStatus]);

  if (!shouldShowSidebarItem(settings)) return null;

  return (
    <SidebarRow
      icon="ShieldCheck"
      label={t("review.sidebarTitle")}
      active={currentScreen?.screenId === REVIEW_SCREEN_ID}
      onPress={() => openReviewScreen(openScreen)}
      trailing={
        count > 0 ? (
          <View style={{ paddingHorizontal: 6, borderRadius: 8, backgroundColor: theme.colors.statusDanger }}>
            <Text style={{ color: theme.colors.surface0, fontSize: 11 }}>{String(count)}</Text>
          </View>
        ) : undefined
      }
    />
  );
}
