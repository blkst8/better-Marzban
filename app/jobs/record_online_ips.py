import os
import ipaddress
import re
import subprocess
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
    XRAY_EXCLUDE_INBOUND_TAGS,
)


reported_breaches = {}


def _inbound_ports_by_proto() -> tuple[list, list]:
    """(tcp, udp) port lists of the main host's managed xray inbounds."""
    tcp_ports, udp_ports = set(), set()
    for inbound in xray.config.get("inbounds", []):
        if inbound.get("tag") in XRAY_EXCLUDE_INBOUND_TAGS:
            continue
        if inbound.get("protocol") == "dokodemo-door":
            continue  # the local API inbound, nothing external connects there
        port = inbound.get("port")
        if not isinstance(port, int):
            continue
        network = inbound.get("streamSettings", {}).get("network", "tcp")
        (udp_ports if network in ("kcp", "quic") else tcp_ports).add(port)
    return sorted(tcp_ports), sorted(udp_ports)


_IPTABLES_CHAIN = "MARZBAN_IPLIMIT"
_chain_ready = False
_blocked_ips: dict[str, str] = {}


def _iptables(args: list) -> str:
    result = subprocess.run(
        ["iptables", *args], capture_output=True, text=True, timeout=15
    )
    if result.returncode != 0:
        raise RuntimeError(f"iptables {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


def _ensure_chain() -> None:
    """Creates the chain once per process and clears leftover rules."""
    global _chain_ready
    if _chain_ready:
        return
    try:
        try:
            _iptables(["-N", _IPTABLES_CHAIN])
        except RuntimeError:
            pass  # chain already exists
        # The jump from INPUT is idempotent: -C succeeds when already present.
        if subprocess.run(
            ["iptables", "-C", "INPUT", "-j", _IPTABLES_CHAIN],
            capture_output=True, timeout=15,
        ).returncode != 0:
            _iptables(["-I", "INPUT", "1", "-j", _IPTABLES_CHAIN])
        # A previous run's blocks must not outlive this process' state.
        _iptables(["-F", _IPTABLES_CHAIN])
        _blocked_ips.clear()
        _chain_ready = True
    except Exception:
        logger.exception("Failed to prepare the ip-limit firewall chain")
        return
    tcp_ports, udp_ports = _inbound_ports_by_proto()
    logger.info(
        f"ip-limit firewall chain {_IPTABLES_CHAIN} ready; "
        f"enforcing tcp:{tcp_ports} udp:{udp_ports}"
    )


def _reconcile_blocked_ips(desired: dict[str, str]) -> None:
    """
    Makes the firewall match the current breach set exactly.

    desired: {ip: username} — every excess main-host address. Rules are
    rebuilt only when the set changes, so a steady breach costs nothing.
    """
    if desired == _blocked_ips:
        return

    try:
        tcp_ports, udp_ports = _inbound_ports_by_proto()
        _iptables(["-F", _IPTABLES_CHAIN])
        for ip, username in desired.items():
            try:
                if tcp_ports:
                    _iptables([
                        "-A", _IPTABLES_CHAIN, "-s", ip, "-p", "tcp",
                        "-m", "multiport", "--dports", ",".join(map(str, tcp_ports)),
                        "-j", "DROP",
                    ])
                if udp_ports:
                    _iptables([
                        "-A", _IPTABLES_CHAIN, "-s", ip, "-p", "udp",
                        "-m", "multiport", "--dports", ",".join(map(str, udp_ports)),
                        "-j", "DROP",
                    ])
                logger.info(f"Blocked {ip} (over ip limit, user \"{username}\")")
            except Exception:
                logger.exception(f"Failed to block {ip} of user \"{username}\"")
        _blocked_ips.clear()
        _blocked_ips.update(desired)
    except Exception:
        logger.exception("Reconciling the ip-limit firewall failed; "
                         "continuing monitor-only")


def enforce_ip_limits() -> None:
    """
    Firewalls the excess addresses of any user over their limit.

    The limit counts distinct public IPs: every device behind one NAT address
    shares that address's single allowance. Nodes are expected to enforce the
    limit themselves at connect time; on the main host the panel drops the
    excess addresses into a firewall chain, so the newest addresses are the
    ones blocked and the longest-lived ones keep working.
    """
    with GetDB() as db:
        users = db.query(User).filter(
            User.ip_limit.isnot(None), User.ip_limit > 0
        ).all()

        _ensure_chain()

        # Users that dropped back under their limit stop being reported, so the
        # next breach is announced again.
        for username in list(reported_breaches.keys()):
            if username not in {u.username for u in users}:
                del reported_breaches[username]

        desired_blocks: dict[str, str] = {}

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

            # Main-host rows have no node channel; the excess addresses are
            # firewalled off instead.
            for ip in {r.ip for r in excess if r.node_id is None}:
                desired_blocks[ip] = user.username

            logger.info(
                f"User \"{user.username}\" is online from {len(ips)} IPs "
                f"but is limited to {user.ip_limit}; blocking {len(desired_blocks)} excess"
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

        # Users that fell back under their limit must also release their block.
        _reconcile_blocked_ips(desired_blocks)


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