import { Badge, Tooltip } from "@chakra-ui/react";
import { FC, MouseEvent } from "react";
import { useTranslation } from "react-i18next";
import { useDashboard } from "contexts/DashboardContext";
import { User } from "types/User";

export type OnlineIpsCellProps = {
  user: User;
};

/**
 * Shows how many public IPs the user is currently online from, and flags the
 * row when that exceeds the user's limit. Purely presentational: the table
 * owns the single bulk fetch, so this never issues a request of its own.
 */
export const OnlineIpsCell: FC<OnlineIpsCellProps> = ({ user }) => {
  const { t } = useTranslation();
  const sessions = useDashboard((state) => state.onlineIps[user.username]);
  const resetOnlineIps = useDashboard((state) => state.resetOnlineIps);

  if (!sessions || sessions.length === 0) {
    return <span>-</span>;
  }

  // The limit counts public IPs: devices behind one address share it.
  const ips = new Set(sessions.map((session) => session.ip));
  const limit = user.ip_limit ?? 0;
  const overLimit = limit > 0 && ips.size > limit;

  const label = sessions
    .map(
      (session) =>
        `${session.device_name || session.device || "?"} (${session.ip})`
    )
    .join("\n");

  const onReset = (e: MouseEvent) => {
    // The row opens the user modal; a reset click must stay a reset.
    e.stopPropagation();
    resetOnlineIps(user.username);
  };

  return (
    <Tooltip
      hasArrow
      label={`${label}\n\nClick to restart counting`}
      textAlign="center"
      placement="top"
      background="#353645"
      color="white"
      borderRadius={5}
      padding={2}
      maxW={"300px"}
    >
      <Badge
        as="button"
        onClick={onReset}
        colorScheme={overLimit ? "red" : "green"}
        fontSize="11px"
        cursor="pointer"
      >
        {overLimit ? t("usersTable.overIpLimit") : `${ips.size}/${limit || "∞"}`}
      </Badge>
    </Tooltip>
  );
};