"""
Prometheus instrumentation for the Marzban panel.

Exposes HTTP request metrics plus panel domain gauges that are read from the
database at scrape time, because the source of truth for those numbers is the
database rather than an in-process counter.
"""

import time
from datetime import datetime, timedelta

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram
from sqlalchemy import func

REGISTRY = CollectorRegistry(auto_describe=True)

http_requests_total = Counter(
    "marzban_http_requests_total",
    "Total HTTP requests handled by the panel.",
    ["method", "path", "status"],
    registry=REGISTRY,
)

http_request_duration_seconds = Histogram(
    "marzban_http_request_duration_seconds",
    "Time spent handling an HTTP request.",
    ["method", "path"],
    registry=REGISTRY,
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

users_total = Gauge(
    "marzban_users",
    "Number of users per status.",
    ["status"],
    registry=REGISTRY,
)

users_online = Gauge(
    "marzban_users_online",
    "Users seen online within the configured online window.",
    registry=REGISTRY,
)

users_with_ip_limit = Gauge(
    "marzban_users_with_ip_limit",
    "Users that have an IP limit configured.",
    registry=REGISTRY,
)

users_over_ip_limit = Gauge(
    "marzban_users_over_ip_limit",
    "Users currently online from more distinct IPs than their limit allows.",
    registry=REGISTRY,
)

online_ips = Gauge(
    "marzban_online_ips",
    "Distinct IPs users are currently online from.",
    registry=REGISTRY,
)

nodes_total = Gauge(
    "marzban_nodes",
    "Number of nodes per status.",
    ["status"],
    registry=REGISTRY,
)

node_traffic_bytes = Gauge(
    "marzban_node_traffic_bytes",
    "Cumulative traffic recorded per node.",
    ["node", "direction"],
    registry=REGISTRY,
)

users_used_traffic_bytes = Gauge(
    "marzban_users_used_traffic_bytes",
    "Cumulative traffic consumed by all users.",
    registry=REGISTRY,
)

system_traffic_bytes = Gauge(
    "marzban_system_traffic_bytes",
    "Cumulative uplink and downlink recorded across all nodes.",
    ["direction"],
    registry=REGISTRY,
)

online_devices = Gauge(
    "marzban_online_devices",
    "Distinct devices users are currently online from.",
    registry=REGISTRY,
)


def _path_template(scope) -> str:
    """
    Returns the route pattern of the matched route so label cardinality stays
    bounded no matter how many usernames appear in the URL.
    """
    route = scope.get("route")
    return getattr(route, "path", None) or "unmatched"


class MetricsMiddleware:
    """
    Records request count and latency for every request.

    Uses the raw ASGI interface rather than BaseHTTPMiddleware so the matched
    route is already on the scope by the time the response start message
    arrives, which is what keeps the path label bounded.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        status_code = 500

        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            self._observe(scope, status_code, time.perf_counter() - started)

    @staticmethod
    def _observe(scope, status_code: int, elapsed: float) -> None:
        method = scope.get("method", "")
        path = _path_template(scope)
        try:
            http_requests_total.labels(method, path, str(status_code)).inc()
            http_request_duration_seconds.labels(method, path).observe(elapsed)
        except Exception:
            # Instrumentation must never break a request.
            pass


def collect_domain_metrics(db, online_hours: int = 24) -> None:
    """
    Reads panel domain gauges out of the database.

    Args:
        db (Session): Database session.
        online_hours (int): Window used to decide whether a user counts as online.
    """
    from app.db.models import Node, System, User, UserOnlineIp

    cutoff = datetime.utcnow() - timedelta(hours=online_hours)

    for status, count in db.query(User.status, func.count(User.id)) \
            .group_by(User.status).all():
        users_total.labels(status=_status_value(status)).set(count)

    users_online.set(
        db.query(func.count(User.id))
        .filter(User.online_at.isnot(None), User.online_at >= cutoff)
        .scalar() or 0
    )

    users_with_ip_limit.set(
        db.query(func.count(User.id))
        .filter(User.ip_limit.isnot(None), User.ip_limit > 0)
        .scalar() or 0
    )

    online_ips.set(db.query(func.count(UserOnlineIp.ip)).scalar() or 0)
    online_devices.set(
        db.query(func.count(func.distinct(UserOnlineIp.device))).scalar() or 0
    )

    # The limit is expressed in devices, so the breach check counts devices.
    over_limit = 0
    for limit, seen in db.query(
        User.ip_limit,
        func.count(func.distinct(UserOnlineIp.device)),
    ).join(UserOnlineIp, UserOnlineIp.user_id == User.id) \
            .filter(User.ip_limit.isnot(None), User.ip_limit > 0) \
            .group_by(User.id, User.ip_limit).all():
        if seen > limit:
            over_limit += 1
    users_over_ip_limit.set(over_limit)

    for status, count in db.query(Node.status, func.count(Node.id)) \
            .group_by(Node.status).all():
        nodes_total.labels(status=_status_value(status)).set(count)

    for name, uplink, downlink in db.query(Node.name, Node.uplink, Node.downlink).all():
        node_traffic_bytes.labels(node=name, direction="uplink").set(uplink or 0)
        node_traffic_bytes.labels(node=name, direction="downlink").set(downlink or 0)

    users_used_traffic_bytes.set(db.query(func.sum(User.used_traffic)).scalar() or 0)

    system = db.query(System).first()
    if system:
        system_traffic_bytes.labels(direction="uplink").set(system.uplink or 0)
        system_traffic_bytes.labels(direction="downlink").set(system.downlink or 0)


def _status_value(status) -> str:
    return getattr(status, "value", None) or str(status)