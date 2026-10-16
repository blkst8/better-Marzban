import os
import ipaddress
import re
import subprocess
import threading
import time
from datetime import datetime, timezone

from app import logger, scheduler, xray
from app.db import GetDB, crud
from app.db.models import User
from app.utils import report
from config import (
    DISABLE_RECORDING_ONLINE_IPS,
    ENFORCE_IP_LIMIT,
    IPLIMIT_EXTRA_BLOCK_PORTS,
    JOB_RECORD_ONLINE_IPS_INTERVAL,
    ONLINE_IP_MAIN_STALE_INTERVAL,
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

# The follower thread tails the access log so a fresh breach is firewalled
# within ~a second instead of waiting for the next poll. The scheduler job and
# the follower share one pipeline lock: both run the same record + sweep +
# enforce pass, and only one may touch the firewall at a time.
_pipeline_lock = threading.Lock()
_follower_started = False


def _log_line_ts(line: str) -> float:
    """Parses the xray access-log timestamp ("2026/10/16 16:20:41 ...")."""
    try:
        return datetime.strptime(line[:19], "%Y/%m/%d %H:%M:%S").timestamp()
    except (ValueError, TypeError):
        return time.time()


def _register_sighting(line: str, now: float) -> bool:
    """Records one access-log line; True when the (user, ip) pair is new."""
    if "accepted" not in line:
        return False
    match = _ACCESS_LINE_RE.search(line)
    if not match:
        return False
    user_id = parse_access_email(match.group("email"))
    if user_id is None:
        return False
    ip = match.group("ip").strip("[]")
    # Traffic dialed from the VPS itself (loopback) is never a remote
    # device; keepalives would otherwise pin a phantom session forever.
    try:
        if ipaddress.ip_address(ip).is_loopback:
            return False
    except ValueError:
        return False

    key = (user_id, ip)
    if key in _main_sightings:
        _main_sightings[key] = max(now, _main_sightings[key])
        return False
    # The log's own timestamp anchors first_seen: replaying history at boot
    # must not make old addresses look freshly arrived.
    _main_sightings[key] = _log_line_ts(line)
    return True


def _follow_loop() -> None:
    """Tails the access log and re-runs the pipeline on new sightings."""
    while True:
        try:
            path = _access_log_path()
            if not path:
                return  # access log disabled: the periodic job covers it
            _follow_once(path)
        except Exception:
            # A dead follower would silently degrade blocking to the 30 s
            # poll; make any such death loud.
            logger.exception("access-log follower crashed; restarting in 5s")
            time.sleep(5)


def _follow_once(path: str) -> None:
    new_sightings = False
    with open(path, errors="replace") as f:
        f.seek(0, os.SEEK_END)  # the periodic job covers history
        ino = os.fstat(f.fileno()).st_ino
        while True:
            line = f.readline()
            if line:
                if not line.endswith("\n"):
                    break  # partial write; the next pass re-reads it
                if _register_sighting(line, time.time()):
                    new_sightings = True
                continue
            # EOF: copytruncate shrinks the file, rotation replaces it
            try:
                stat = os.stat(path)
                if stat.st_ino == ino and stat.st_size >= f.tell():
                    time.sleep(0.3)
                    continue
            except OSError:
                pass
            break
    if new_sightings:
        _trigger_pipeline()


def _trigger_pipeline() -> None:
    """Runs a pipeline pass now, unless one is already running."""
    if _pipeline_lock.acquire(blocking=False):
        try:
            record_online_ips()
        finally:
            _pipeline_lock.release()


def _ensure_follower() -> None:
    global _follower_started
    if _follower_started:
        return
    _follower_started = True
    threading.Thread(
        target=_follow_loop, daemon=True, name="access-log-follow"
    ).start()


def _iptables(args: list) -> str:
    result = subprocess.run(
        ["iptables", *args], capture_output=True, text=True, timeout=15
    )
    if result.returncode != 0:
        raise RuntimeError(f"iptables {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


def _ip6tables(args: list) -> str:
    result = subprocess.run(
        ["ip6tables", *args], capture_output=True, text=True, timeout=15
    )
    if result.returncode != 0:
        raise RuntimeError(f"ip6tables {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


def _firewall(ip: str):
    """Routes a rule to iptables or ip6tables by the address family."""
    return _ip6tables if ipaddress.ip_address(ip).version == 6 else _iptables


def _block_ports() -> tuple[list, list]:
    """(tcp, udp) port lists firewalled for excess addresses: the xray
    inbounds plus the nginx front ports that proxy into them."""
    tcp_ports, udp_ports = _inbound_ports_by_proto()
    extra = {
        int(p) for p in IPLIMIT_EXTRA_BLOCK_PORTS.split(",") if p.strip().isdigit()
    }
    return sorted(set(tcp_ports) | extra), udp_ports


def _ensure_family_chain(binary: str, runner) -> None:
    try:
        try:
            runner(["-N", _IPTABLES_CHAIN])
        except RuntimeError:
            pass  # chain already exists
        # The jump from INPUT is idempotent: -C succeeds when already present.
        if subprocess.run(
            [binary, "-C", "INPUT", "-j", _IPTABLES_CHAIN],
            capture_output=True, timeout=15,
        ).returncode != 0:
            runner(["-I", "INPUT", "1", "-j", _IPTABLES_CHAIN])
        # A previous run's blocks must not outlive this process' state.
        runner(["-F", _IPTABLES_CHAIN])
    except RuntimeError as e:
        if binary == "ip6tables":
            # v6 unusable on this host: degrade to v4-only blocking.
            logger.warning(f"ip6tables unavailable, IPv6 stays unblocked: {e}")
            return
        raise


def _ensure_chain() -> None:
    """Creates the chains once per process and clears leftover rules."""
    global _chain_ready
    if _chain_ready:
        return
    try:
        _ensure_family_chain("iptables", _iptables)
        try:
            _ensure_family_chain("ip6tables", _ip6tables)
        except Exception:
            logger.warning("IPv6 blocking disabled: ip6tables unusable")
        _blocked_ips.clear()
        _chain_ready = True
    except Exception:
        logger.exception("Failed to prepare the ip-limit firewall chain")
        return
    tcp_ports, udp_ports = _block_ports()
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
        tcp_ports, udp_ports = _block_ports()
        dports = ",".join(map(str, tcp_ports))
        udports = ",".join(map(str, udp_ports))
        _iptables(["-F", _IPTABLES_CHAIN])
        try:
            _ip6tables(["-F", _IPTABLES_CHAIN])
        except Exception:
            pass  # v6 blocking unavailable on this host
        for ip, username in desired.items():
            try:
                fw = _firewall(ip)
                if tcp_ports:
                    fw([
                        "-A", _IPTABLES_CHAIN, "-s", ip, "-p", "tcp",
                        "-m", "multiport", "--dports", dports,
                        "-j", "DROP",
                    ])
                if udp_ports:
                    fw([
                        "-A", _IPTABLES_CHAIN, "-s", ip, "-p", "udp",
                        "-m", "multiport", "--dports", udports,
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
        _register_sighting(line, now)

    # A long-lived connection does not re-log its acceptance, so the sighting
    # window is what keeps last_seen fresh while the connection is in use.
    for key, seen_at in list(_main_sightings.items()):
        if now - seen_at > ONLINE_IP_STALE_INTERVAL:
            del _main_sightings[key]

    reported: dict[str, list] = {}
    for (user_id, ip), seen_at in _main_sightings.items():
        # The access log carries no device fingerprint, so each address
        # counts as its own device. seen_at rides along: it anchors
        # first_seen at the address's real arrival, not at boot time.
        reported.setdefault(str(user_id), []).append(
            {"ip": ip, "device": ip, "device_name": "", "seen_at": seen_at}
        )
    # Upsert, never snapshot: rows keep their first_seen (the enforcement
    # allowance anchor) across idle gaps and are swept on their own window.
    crud.upsert_main_online_ips(db, reported)


def record_online_ips() -> None:
    if DISABLE_RECORDING_ONLINE_IPS:
        return

    _ensure_follower()

    # The follower thread triggers this same pipeline on fresh breaches; both
    # entry points serialize here so the firewall is touched by one at a time.
    with _pipeline_lock:
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
            # would otherwise stay listed forever. Main-host rows idle longer by
            # design and sweep on their own window.
            stale = crud.delete_stale_online_ips(
                db, ONLINE_IP_STALE_INTERVAL,
                main_max_age_seconds=ONLINE_IP_MAIN_STALE_INTERVAL,
            )
            if stale:
                logger.info(f"Removed {stale} online session(s) that went stale")

        if ENFORCE_IP_LIMIT:
            enforce_ip_limits()


# Fire once immediately so the follower starts and the firewall reconciles
# right after boot instead of one interval later. The scheduler runs in UTC, so
# the naive local now() could land hours in its future — pass aware UTC.
scheduler.add_job(record_online_ips, 'interval',
                  seconds=JOB_RECORD_ONLINE_IPS_INTERVAL,
                  next_run_time=datetime.now(timezone.utc),
                  misfire_grace_time=None,
                  coalesce=True, max_instances=1)