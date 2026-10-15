import { Badge, Tooltip } from "@chakra-ui/react";
import { FC } from "react";
import { useTranslation } from "react-i18next";
import { useDashboard } from "contexts/DashboardContext";
import { User } from "types/User";

export type OnlineIpsCellProps = {
  user: User;
};

/**
 * Shows how many devices the user is currently online from, and flags the row
 * when that exceeds the user's limit. Purely presentational: the table owns the
 * single bulk fetch, so this never issues a request of its own.
 */
export const OnlineIpsCell: FC<OnlineIpsCellProps> = ({ user }) => {
  const { t } = useTranslation();
  const sessions = useDashboard((state) => state.onlineIps[user.username]);

  if (!sessions || sessions.length === 0) {
    return <span>-</span>;
  }

  // Several devices may share one address, so the limit is spent per device.
  const devices = new Set(sessions.map((session) => session.device));
  const limit = user.ip_limit ?? 0;
  const overLimit = limit > 0 && devices.size > limit;

  const label = sessions
    .map(
      (session) =>
        `${session.device_name || session.device || "?"} (${session.ip})`
    )
    .join("\n");

  return (
    <Tooltip
      hasArrow
      label={label}
      textAlign="center"
      placement="top"
      background="#353645"
      color="white"
      borderRadius={5}
      padding={2}
      maxW={"300px"}
    >
      <Badge
        colorScheme={overLimit ? "red" : "green"}
        fontSize="11px"
        cursor="default"
      >
        {overLimit ? t("usersTable.overIpLimit") : `${devices.size}/${limit || "∞"}`}
      </Badge>
    </Tooltip>
  );
};