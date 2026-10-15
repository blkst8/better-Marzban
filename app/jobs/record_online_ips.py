from app import logger, scheduler, xray
from app.db import GetDB, crud
from app.db.models import User
from app.utils import report
from config import (
    DISABLE_RECORDING_ONLINE_IPS,
    ENFORCE_IP_LIMIT,
    JOB_RECORD_ONLINE_IPS_INTERVAL,
    ONLINE_IP_STALE_INTERVAL,
)


reported_breaches = {}


def enforce_ip_limits() -> None:
    """
    Disconnects the excess devices of any user over their limit.

    The limit counts distinct devices, so several devices behind one IP are
    counted separately. Nodes are expected to enforce the limit themselves at
    connect time; this is the backstop for nodes that report sessions but do
    not block. The most recently seen devices are dropped first, so the
    longest-lived sessions survive.
    """
    with GetDB() as db:
        users = db.query(User).filter(
            User.ip_limit.isnot(None), User.ip_limit > 0
        ).all()

        # Users that dropped back under their limit stop being reported, so the
        # next breach is announced again.
        for username in list(reported_breaches.keys()):
            if username not in {u.username for u in users}:
                del reported_breaches[username]

        for user in users:
            records = crud.get_user_online_ips(db, user)
            # Records are newest first, so the first sighting of each device is
            # that device's most recent session. dict.fromkeys keeps that order
            # while collapsing the repeated sessions of one device.
            devices = list(dict.fromkeys(r.device for r in records))
            if len(devices) <= user.ip_limit:
                continue


            # Records are newest first, so the allowance goes to the tail: the
            # longest-lived devices keep their sessions and the devices that
            # arrived most recently are the ones rejected.
            allowed = set(devices[-user.ip_limit:])
            excess = [r for r in records if r.device not in allowed]


            for record in excess:
                node = xray.nodes.get(record.node_id)
                if node is None:
                    continue
                try:
                    node.kick_online_ip(
                        f"{user.id}.{user.username}", record.ip, record.device
                    )
                except Exception:
                    logger.exception(
                        f"Failed to kick online ip {record.ip} of user \"{user.username}\""
                    )

            logger.info(
                f"User \"{user.username}\" is online from {len(devices)} devices "
                f"but is limited to {user.ip_limit}; kicked {len(excess)}"
            )

            # Reporting the same episode on every poll would spam the admins, so
            # repeat only when the set of excess devices actually changes.
            excess_devices = tuple(sorted({r.device for r in excess}))
            if reported_breaches.get(user.username) != excess_devices:
                reported_breaches[user.username] = excess_devices
                report.ip_limit_breach(
                    username=user.username,
                    limit=user.ip_limit,
                    devices=devices,
                    admin=user.admin,
                )


def record_online_ips() -> None:
    if DISABLE_RECORDING_ONLINE_IPS:
        return

    with GetDB() as db:
        for node_id, node in list(xray.nodes.items()):
            if not (node.connected and node.started):
                continue

            try:
                reported = node.get_online_ips()
            except Exception:
                logger.exception(f"Failed to get online ips from node {node_id}")
                continue

            crud.sync_node_online_ips(db, node_id, reported)

        # A node that goes unreachable never reports again, so its sessions
        # would otherwise stay listed forever.
        stale = crud.delete_stale_online_ips(db, ONLINE_IP_STALE_INTERVAL)
        if stale:
            logger.info(f"Removed {stale} online session(s) that went stale")

    if ENFORCE_IP_LIMIT:
        enforce_ip_limits()


scheduler.add_job(record_online_ips, 'interval',
                  seconds=JOB_RECORD_ONLINE_IPS_INTERVAL,
                  coalesce=True, max_instances=1)