import os
import ipaddress
import re
import time

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
    Disconnects the excess sessions of any user over their limit.

    The limit counts distinct public IPs: every device behind one NAT address
    shares that address's single allowance. Nodes are expected to enforce the
    limit themselves at connect time; this is the backstop for nodes that
    report sessions but do not block. Within one address, the most recently
    seen sessions are dropped first, so the longest-lived sessions survive.
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
            # Records are newest first, so dict.fromkeys keeps the IPs in the
            # order of their most recent session.
            ips = list(dict.fromkeys(r.ip for r in records))
            if len(ips) <= user.ip_limit:
                continue

            # The allowance goes to the tail: the longest-lived IPs keep their
            # sessions and the addresses that arrived most recently are the
            # ones rejected.
            allowed = set(ips[-user.ip_limit:])
            excess = [r for r in records if r.ip not in allowed]

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
                f"User \"{user.username}\" is online from {len(ips)} IPs "
                f"but is limited to {user.ip_limit}; kicked {len(excess)} sessions"
            )

            # Reporting the same episode on every poll would spam the admins, so
            # repeat only when the set of excess addresses actually changes.
            excess_ips = tuple(sorted({r.ip for r in excess}))
            if reported_breaches.get(user.username) != excess_ips:
                reported_breaches[user.username] = excess_ips
                report.ip_limit_breach(
                    username=user.username,
                    limit=user.ip_limit,
                    ips=ips,
                    admin=user.admin,
                )


# Main-host recording ---------------------------------------------------------
#
# Remote nodes report their live sessions over the node API. The main host has
# no such channel, so its sessions are derived from the core's access log:
# every accepted connection names the client IP and the user's email. A
# (user, ip) pair counts as online while a connection from it was accepted
# within ONLINE_IP_STALE_INTERVAL seconds.

_ACCESS_LINE_RE = re.compile(
    r"(?:from\s+)?"
    r"(?P<ip>[0-9]{1,3}(?:\.[0-9]{1,3}){3}|\[[0-9a-fA-F:]+\]):\d+\s+"
    r"accepted\s+.*?email:\s*(?P<email>\S+)"
)

_main_sightings: dict[tuple[int, str], float] = {}
_access_log_state: dict = {"path": None, "inode": None, "offset": 0}
_access_log_warned = False


def _access_log_path():
    try:
        path = (xray.config or {}).get("log", {}).get("access")
    except Exception:
        return None
    if not path or path == "none":
        return None
    return path


def _read_new_access_lines(path: str) -> list:
    """Returns the access-log lines appended since the last poll.

    Follows the file across rotation and truncation. The first look at a file
    considers only its last megabyte, so an old log does not turn one poll
    into a full replay of history.
    """
    state = _access_log_state
    stat = os.stat(path)
    if (
        state["path"] != path
        or state["inode"] != stat.st_ino
        or stat.st_size < state["offset"]
    ):
        offset = 0
        if state["path"] != path:
            offset = max(0, stat.st_size - 1_000_000)
        state.update(path=path, inode=stat.st_ino, offset=offset)

    with open(path, "r", errors="replace") as f:
        f.seek(state["offset"])
        data = f.read()
        state["offset"] = f.tell()
    return data.splitlines()


def parse_access_email(email: str):
    """Extracts the user id from a core email ("{id}.{username}[.{inbound}]")."""
    try:
        return int(email.split(".")[0])
    except (ValueError, AttributeError):
        return None


def _record_main_host(db) -> None:
    global _access_log_warned

    path = _access_log_path()
    if not path:
        if not _access_log_warned:
            logger.warning(
                'No "access" log configured in the xray config; '
                "main-host online devices cannot be recorded"
            )
            _access_log_warned = True
        return

    try:
        lines = _read_new_access_lines(path)
    except FileNotFoundError:
        return
    except OSError:
        logger.exception(f"Failed to read access log {path}")
        return

    now = time.time()
    for line in lines:
        if "accepted" not in line:
            continue
        match = _ACCESS_LINE_RE.search(line)
        if not match:
            continue
        user_id = parse_access_email(match.group("email"))
        if user_id is None:
            continue
        ip = match.group("ip").strip("[]")
        # Traffic dialed from the VPS itself (loopback) is never a remote
        # device; keepalives would otherwise pin a phantom session forever.
        try:
            if ipaddress.ip_address(ip).is_loopback:
                continue
        except ValueError:
            continue
        _main_sightings[(user_id, ip)] = now

    # A long-lived connection does not re-log its acceptance, so the sighting
    # window is what turns the append-only log into a "live" snapshot.
    for key, seen_at in list(_main_sightings.items()):
        if now - seen_at > ONLINE_IP_STALE_INTERVAL:
            del _main_sightings[key]

    reported: dict[str, list] = {}
    for user_id, ip in _main_sightings:
        # The access log carries no device fingerprint, so each address
        # counts as its own device.
        reported.setdefault(str(user_id), []).append(
            {"ip": ip, "device": ip, "device_name": ""}
        )
    crud.sync_node_online_ips(db, None, reported)


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

        _record_main_host(db)

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