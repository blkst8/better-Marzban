"""
Behavioural tests for the Prometheus endpoint.

These assert the wire format a scraper actually consumes, plus the auth and
label-cardinality properties that make the endpoint usable in production.
"""

import re

from app.db import crud
from app.db.models import UserOnlineIp
from app.metrics import REGISTRY
from app.models.user import UserCreate


def make_user(db, username: str, ip_limit=None):
    return crud.create_user(
        db,
        UserCreate(username=username, proxies={"vless": {}}, ip_limit=ip_limit),
    )


def scrape(client):
    res = client.get("/api/metrics")
    assert res.status_code == 200
    return res.text


def value_of(text: str, name: str, labels: str = "") -> float:
    """Returns the value of a single sample line from Prometheus text format."""
    pattern = re.compile(
        rf"^{re.escape(name)}(\{{{re.escape(labels)}\}})? ([0-9.e+-]+)$", re.MULTILINE
    )
    match = pattern.search(text)
    assert match, f"metric {name}{{{labels}}} not found in:\n{text}"
    return float(match.group(2))


def test_metrics_endpoint_requires_authentication(anonymous_client):
    assert anonymous_client.get("/api/metrics").status_code == 401


def test_metrics_endpoint_returns_prometheus_content_type(client):
    res = client.get("/api/metrics")
    assert res.headers["content-type"].startswith("text/plain")


def test_http_requests_are_counted(client):
    before = value_of(scrape(client), "marzban_http_requests_total",
                      'method="GET",path="/api/metrics",status="200"')

    client.get("/api/metrics")

    after = value_of(scrape(client), "marzban_http_requests_total",
                     'method="GET",path="/api/metrics",status="200"')
    assert after > before


def test_request_latency_histogram_is_exposed(client):
    client.get("/api/metrics")
    text = scrape(client)

    assert "marzban_http_request_duration_seconds_bucket" in text
    assert "marzban_http_request_duration_seconds_count" in text


def test_users_are_counted_per_status(client, db):
    make_user(db, "metric_user_active")
    text = scrape(client)

    assert value_of(text, "marzban_users", 'status="active"') >= 1


def session(ip, device=""):
    return {"ip": ip, "device": device, "device_name": ""}


def test_online_ips_gauge_reflects_stored_records(client, db):
    user = make_user(db, "metric_user_ips")
    crud.sync_node_online_ips(db, 1, {
        user.id: [session("10.1.1.1", "a"), session("10.1.1.2", "b")],
    })

    text = scrape(client)
    assert value_of(text, "marzban_online_ips") == 2
    assert value_of(text, "marzban_online_devices") == 2


def test_online_devices_gauge_dedupes_one_device_across_ips(client, db):
    user = make_user(db, "metric_same_device")
    crud.sync_node_online_ips(db, 1, {
        user.id: [session("10.1.2.1", "phone"), session("10.1.2.2", "phone")],
    })

    text = scrape(client)
    assert value_of(text, "marzban_online_ips") == 2
    assert value_of(text, "marzban_online_devices") == 1


def test_users_over_ip_limit_is_counted(client, db):
    over = make_user(db, "metric_over_limit", ip_limit=1)
    within = make_user(db, "metric_within_limit", ip_limit=5)

    crud.sync_node_online_ips(db, 1, {
        over.id: [session("10.2.2.1", "a"), session("10.2.2.2", "b")],
        within.id: [session("10.2.2.3", "c")],
    })

    text = scrape(client)
    assert value_of(text, "marzban_users_over_ip_limit") == 1
    assert value_of(text, "marzban_users_with_ip_limit") >= 2


def test_users_with_zero_ip_limit_are_not_counted_as_limited(client, db):
    make_user(db, "metric_unlimited_zero", ip_limit=0)

    assert value_of(scrape(client), "marzban_users_with_ip_limit") == 0


def test_path_label_uses_the_route_pattern_not_the_raw_url(client, db):
    user = make_user(db, "metric_path_label")

    client.get(f"/api/user/{user.username}/online-ips")
    text = scrape(client)

    # The username must not leak into the label, or cardinality explodes.
    assert user.username not in text
    assert 'path="/api/user/{username}/online-ips"' in text


def test_node_traffic_gauges_are_exposed(client, db):
    from app.db.models import Node
    from app.models.node import NodeStatus

    db.add(Node(
        name="metric-node",
        address="127.0.0.1",
        port=1,
        api_port=2,
        status=NodeStatus.connected,
        uplink=111,
        downlink=222,
    ))
    db.commit()

    text = scrape(client)
    assert value_of(text, "marzban_node_traffic_bytes",
                    'direction="uplink",node="metric-node"') == 111
    assert value_of(text, "marzban_node_traffic_bytes",
                    'direction="downlink",node="metric-node"') == 222


def test_scraping_does_not_duplicate_series(client, db):
    user = make_user(db, "metric_no_dupes")
    crud.sync_node_online_ips(db, 1, {user.id: [session("10.3.3.1", "a")]})

    first = scrape(client)
    second = scrape(client)

    def count_series(text, name):
        return len([l for l in text.splitlines() if l.startswith(name)])

    assert count_series(first, "marzban_online_ips") == 1
    assert count_series(second, "marzban_online_ips") == 1


def test_stale_online_ips_are_not_counted(client, db):
    user = make_user(db, "metric_stale")
    crud.sync_node_online_ips(db, 1, {
        user.id: [session("10.4.4.1", "a"), session("10.4.4.2", "b")],
    })
    crud.sync_node_online_ips(db, 1, {user.id: [session("10.4.4.1", "a")]})

    assert value_of(scrape(client), "marzban_online_ips") == 1
    assert db.query(UserOnlineIp).filter(UserOnlineIp.user_id == user.id).count() == 1


def test_registry_is_scoped_to_the_app():
    names = {metric.name for metric in REGISTRY.collect()}

    assert "marzban_http_requests" in names
    assert "marzban_users" in names
    assert "marzban_online_ips" in names