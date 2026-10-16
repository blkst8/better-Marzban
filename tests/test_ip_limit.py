"""
Behavioural tests for the online-session limit.

The limit counts distinct public IPs: every device behind one NAT address
shares that address's single allowance. These cover what the panel stores,
what the API reports, which sessions the enforcement pass drops, and that rows
disappear once a session goes away.
"""

from datetime import datetime, timedelta

import pytest

from app.db import crud
from app.db.models import User, UserOnlineIp
from app.jobs import record_online_ips
from app.models.user import UserCreate, UserModify


def make_user(db, username: str, ip_limit=None) -> User:
    return crud.create_user(
        db,
        UserCreate(
            username=username,
            proxies={"vless": {}},
            ip_limit=ip_limit,
        ),
    )


def session(ip, device="", device_name=""):
    return {"ip": ip, "device": device, "device_name": device_name}


def sessions(*specs):
    """Builds a node report from (ip, device, device_name) tuples."""
    return [session(*spec) for spec in specs]


def report(db, node_id, mapping):
    crud.sync_node_online_ips(db, node_id, mapping)


def _ips_of(db, dbuser):
    return [record.ip for record in crud.get_user_online_ips(db, dbuser)]


def _devices_of(db, dbuser):
    return [record.device for record in crud.get_user_online_ips(db, dbuser)]


def test_create_user_with_ip_limit(db):
    assert make_user(db, "ipuser1", ip_limit=3).ip_limit == 3


def test_create_user_without_ip_limit_is_unlimited(db):
    assert make_user(db, "ipuser2").ip_limit is None


def test_update_user_changes_ip_limit(db):
    dbuser = make_user(db, "ipuser3", ip_limit=1)
    updated = crud.update_user(db, dbuser, UserModify(proxies={"vless": {}}, ip_limit=5))
    assert updated.ip_limit == 5


def test_update_user_with_zero_ip_limit_means_unlimited(db):
    dbuser = make_user(db, "ipuser4", ip_limit=4)
    updated = crud.update_user(db, dbuser, UserModify(proxies={"vless": {}}, ip_limit=0))
    assert updated.ip_limit is None


def test_ip_limit_rejects_negative(db):
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        UserCreate(username="ipuser5", proxies={"vless": {}}, ip_limit=-1)


def test_ip_limit_rejects_string(db):
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        UserCreate(username="ipuser6", proxies={"vless": {}}, ip_limit="two")


def test_ip_limit_accepts_float_and_truncates(db):
    assert make_user(db, "ipuser7", ip_limit=2.9).ip_limit == 2


# --- session storage -------------------------------------------------------

def test_two_devices_behind_one_ip_are_separate_sessions(db):
    dbuser = make_user(db, "ipuser8", ip_limit=2)
    report(db, 1, {dbuser.id: sessions(
        ("10.0.0.5", "phone", "iPhone"),
        ("10.0.0.5", "laptop", "Windows"),
    )})

    assert len(crud.get_user_online_ips(db, dbuser)) == 2
    assert sorted(_devices_of(db, dbuser)) == ["laptop", "phone"]


def test_same_device_on_two_ips_is_two_sessions(db):
    dbuser = make_user(db, "ipuser9", ip_limit=2)
    report(db, 1, {dbuser.id: sessions(
        ("10.0.0.5", "phone", "iPhone"),
        ("10.0.0.9", "phone", "iPhone"),
    )})

    assert len(crud.get_user_online_ips(db, dbuser)) == 2


def test_device_name_is_stored_and_refreshed(db):
    dbuser = make_user(db, "ipuser10", ip_limit=2)
    report(db, 1, {dbuser.id: sessions(("10.0.0.5", "phone", "iPhone · iOS 17"))})
    assert crud.get_user_online_ips(db, dbuser)[0].device_name == "iPhone · iOS 17"

    report(db, 1, {dbuser.id: sessions(("10.0.0.5", "phone", "iPhone · iOS 18"))})
    assert crud.get_user_online_ips(db, dbuser)[0].device_name == "iPhone · iOS 18"


def test_sync_replaces_previous_sessions(db):
    dbuser = make_user(db, "ipuser11")

    report(db, 1, {dbuser.id: sessions(("10.0.0.1", "a"), ("10.0.0.2", "b"))})
    assert sorted(_ips_of(db, dbuser)) == ["10.0.0.1", "10.0.0.2"]

    # A later poll reports fewer sessions; the vanished one must disappear.
    report(db, 1, {dbuser.id: sessions(("10.0.0.1", "a"))})
    assert _ips_of(db, dbuser) == ["10.0.0.1"]


def test_disconnected_device_is_removed_from_the_table(db):
    dbuser = make_user(db, "ipuser12")
    report(db, 1, {dbuser.id: sessions(("10.0.0.1", "a"), ("10.0.0.2", "b"))})

    # Device "b" disconnects and is no longer reported.
    report(db, 1, {dbuser.id: sessions(("10.0.0.1", "a"))})

    rows = crud.get_user_online_ips(db, dbuser)
    assert [r.device for r in rows] == ["a"]
    assert db.query(UserOnlineIp).filter(UserOnlineIp.user_id == dbuser.id).count() == 1


def test_sync_only_removes_rows_of_the_polled_node(db):
    dbuser = make_user(db, "ipuser13")

    report(db, 1, {dbuser.id: sessions(("10.0.0.1", "a"))})
    report(db, 2, {dbuser.id: sessions(("10.0.0.2", "b"))})

    # Polling node 1 with an empty report must not touch node 2's row.
    report(db, 1, {})
    assert _ips_of(db, dbuser) == ["10.0.0.2"]


def test_sync_ignores_reported_user_that_does_not_exist(db):
    report(db, 1, {999999: sessions(("10.0.0.9", "a"))})
    assert db.query(UserOnlineIp).filter(UserOnlineIp.user_id == 999999).count() == 0


def test_stale_sessions_are_swept(db):
    dbuser = make_user(db, "ipuser14")
    report(db, 1, {dbuser.id: sessions(("10.0.0.1", "a"), ("10.0.0.2", "b"))})

    old = datetime.utcnow() - timedelta(hours=2)
    db.query(UserOnlineIp).filter(UserOnlineIp.ip == "10.0.0.1") \
        .update({"last_seen_at": old})

    assert crud.delete_stale_online_ips(db, 60) == 1
    assert _ips_of(db, dbuser) == ["10.0.0.2"]


def test_fresh_sessions_survive_the_sweep(db):
    dbuser = make_user(db, "ipuser15")
    report(db, 1, {dbuser.id: sessions(("10.0.0.1", "a"))})

    assert crud.delete_stale_online_ips(db, 3600) == 0
    assert _ips_of(db, dbuser) == ["10.0.0.1"]


# --- API -------------------------------------------------------------------

def test_online_ips_endpoint_reports_sessions_with_detail(client, db):
    dbuser = make_user(db, "ipuser16", ip_limit=1)
    report(db, 1, {dbuser.id: sessions(
        ("10.0.0.5", "phone", "iPhone"),
        ("10.0.0.5", "laptop", "Windows"),
    )})

    body = client.get(f"/api/user/{dbuser.username}/online-ips").json()

    assert body["ip_limit"] == 1
    # One address: both devices share its single allowance.
    assert body["online_devices"] == 1
    assert {e["device"] for e in body["online_ips"]} == {"phone", "laptop"}
    assert {e["device_name"] for e in body["online_ips"]} == {"iPhone", "Windows"}
    assert body["over_limit"] is False


def test_one_ip_hosting_two_devices_stays_within_limit(client, db):
    """Devices behind one address share it; only distinct IPs count."""
    dbuser = make_user(db, "ipuser17", ip_limit=1)
    report(db, 1, {dbuser.id: sessions(
        ("10.0.0.5", "phone"),
        ("10.0.0.5", "laptop"),
    )})

    body = client.get(f"/api/user/{dbuser.username}/online-ips").json()
    assert body["online_devices"] == 1
    assert body["over_limit"] is False


def test_online_ips_endpoint_is_not_over_limit_at_exactly_the_limit(client, db):
    dbuser = make_user(db, "ipuser18", ip_limit=2)
    report(db, 1, {dbuser.id: sessions(("10.0.0.1", "a"), ("10.0.0.2", "b"))})

    body = client.get(f"/api/user/{dbuser.username}/online-ips").json()
    assert body["online_devices"] == 2
    assert body["over_limit"] is False


def test_online_ips_endpoint_is_over_limit_at_one_past_the_limit(client, db):
    dbuser = make_user(db, "ipuser19", ip_limit=2)
    report(db, 1, {dbuser.id: sessions(
        ("10.0.0.1", "a"), ("10.0.0.2", "b"), ("10.0.0.3", "c")
    )})

    body = client.get(f"/api/user/{dbuser.username}/online-ips").json()
    assert body["online_devices"] == 3
    assert body["over_limit"] is True


def test_one_device_on_many_ips_is_over_limit(client, db):
    """The same device dialing from several addresses burns the limit per IP."""
    dbuser = make_user(db, "ipuser20", ip_limit=1)
    report(db, 1, {dbuser.id: sessions(
        ("10.0.0.1", "phone"), ("10.0.0.2", "phone"), ("10.0.0.3", "phone")
    )})

    body = client.get(f"/api/user/{dbuser.username}/online-ips").json()
    assert body["online_devices"] == 3
    assert body["over_limit"] is True


def test_online_ips_endpoint_never_marks_unlimited_user_over_limit(client, db):
    dbuser = make_user(db, "ipuser21")
    report(db, 1, {dbuser.id: sessions(
        ("10.0.0.1", "a"), ("10.0.0.2", "b"), ("10.0.0.3", "c")
    )})

    body = client.get(f"/api/user/{dbuser.username}/online-ips").json()
    assert body["ip_limit"] is None
    assert body["over_limit"] is False


def test_online_ips_endpoint_reports_node_and_timestamps(client, db):
    dbuser = make_user(db, "ipuser22", ip_limit=1)
    report(db, 1, {dbuser.id: sessions(("10.0.0.1", "a"))})

    entry = client.get(f"/api/user/{dbuser.username}/online-ips").json()["online_ips"][0]
    assert entry["node_id"] == 1
    assert entry["first_seen_at"] is not None
    assert entry["last_seen_at"] is not None


def test_bulk_online_ips_endpoint_returns_sessions(client, db):
    first = make_user(db, "ipuser23")
    second = make_user(db, "ipuser24")
    report(db, 1, {
        first.id: sessions(("10.0.0.1", "a", "iPhone")),
        second.id: sessions(("10.0.0.2", "b"), ("10.0.0.3", "c")),
    })

    body = client.get("/api/users/online-ips").json()
    assert body["ipuser23"] == [{"ip": "10.0.0.1", "device": "a", "device_name": "iPhone"}]
    assert len(body["ipuser24"]) == 2


def test_online_ips_endpoint_requires_authentication(anonymous_client):
    assert anonymous_client.get("/api/users/online-ips").status_code == 401


# --- enforcement -----------------------------------------------------------

def test_enforcement_kicks_only_the_excess_devices(db, monkeypatch):
    dbuser = make_user(db, "ipuser25", ip_limit=2)
    report(db, 1, {dbuser.id: sessions(
        ("10.0.0.1", "a"), ("10.0.0.2", "b"),
        ("10.0.0.3", "c"), ("10.0.0.4", "d"),
    )})

    node = FakeNode()
    monkeypatch.setattr(record_online_ips.xray, "nodes", {1: node})
    record_online_ips.enforce_ip_limits()

    kicked_ips = [ip for _, ip, _ in node.kicked]
    assert sorted(kicked_ips) == ["10.0.0.3", "10.0.0.4"]


def test_enforcement_does_not_kick_devices_behind_one_ip(db, monkeypatch):
    """Two devices share an address: one IP, one allowance — nobody is dropped."""
    dbuser = make_user(db, "ipuser26", ip_limit=1)
    report(db, 1, {dbuser.id: sessions(
        ("10.0.0.5", "phone"), ("10.0.0.5", "laptop"),
    )})

    node = FakeNode()
    monkeypatch.setattr(record_online_ips.xray, "nodes", {1: node})
    record_online_ips.enforce_ip_limits()

    assert node.kicked == []


def test_enforcement_leaves_within_limit_users_alone(db, monkeypatch):
    dbuser = make_user(db, "ipuser27", ip_limit=4)
    report(db, 1, {dbuser.id: sessions(("10.0.0.1", "a"), ("10.0.0.2", "b"))})

    node = FakeNode()
    monkeypatch.setattr(record_online_ips.xray, "nodes", {1: node})
    record_online_ips.enforce_ip_limits()

    assert node.kicked == []


def test_enforcement_leaves_unlimited_users_alone(db, monkeypatch):
    dbuser = make_user(db, "ipuser28")
    report(db, 1, {dbuser.id: sessions(("10.0.0.1", "a"), ("10.0.0.2", "b"))})

    node = FakeNode()
    monkeypatch.setattr(record_online_ips.xray, "nodes", {1: node})
    record_online_ips.enforce_ip_limits()

    assert node.kicked == []


def test_enforcement_preserves_the_longest_lived_device(db, monkeypatch):
    dbuser = make_user(db, "ipuser29", ip_limit=1)

    report(db, 1, {dbuser.id: sessions(("10.0.0.1", "phone"))})
    report(db, 1, {dbuser.id: sessions(("10.0.0.1", "phone"), ("10.0.0.9", "laptop"))})

    node = FakeNode()
    monkeypatch.setattr(record_online_ips.xray, "nodes", {1: node})
    record_online_ips.enforce_ip_limits()

    assert node.kicked == [(f"{dbuser.id}.ipuser29", "10.0.0.9", "laptop")]


def test_enforcement_counts_ips_across_nodes(db, monkeypatch):
    """One address per node, but the user is over the limit overall."""
    dbuser = make_user(db, "ipuser30", ip_limit=1)
    report(db, 1, {dbuser.id: sessions(("10.0.0.1", "phone"))})
    report(db, 2, {dbuser.id: sessions(("10.0.0.9", "laptop"))})

    node = FakeNode()
    monkeypatch.setattr(record_online_ips.xray, "nodes", {1: node, 2: node})
    record_online_ips.enforce_ip_limits()

    assert len(node.kicked) == 1


def test_enforcement_skips_sessions_on_a_missing_node(db, monkeypatch):
    dbuser = make_user(db, "ipuser31", ip_limit=1)
    report(db, 77, {dbuser.id: sessions(("10.0.0.1", "a"), ("10.0.0.2", "b"))})

    monkeypatch.setattr(record_online_ips.xray, "nodes", {})
    record_online_ips.enforce_ip_limits()  # must not raise


def test_enforcement_kicks_main_host_sessions_by_ip(db, monkeypatch):
    """node_id=None rows have no node channel; the excess address is dropped."""
    dbuser = make_user(db, "ipuser35", ip_limit=1)
    report(db, None, {dbuser.id: sessions(
        ("10.0.0.1", "a"), ("10.0.0.2", "b"),
    )})

    kicked = []
    monkeypatch.setattr(record_online_ips, "_kick_main_host_ip",
                        lambda ip, ports: kicked.append(ip) or 1)
    monkeypatch.setattr(record_online_ips.xray, "nodes", {})
    record_online_ips.enforce_ip_limits()

    # Newest address is dropped, the longest-lived one survives.
    assert kicked == ["10.0.0.2"]


def test_enforcement_survives_a_failing_main_host_kick(db, monkeypatch):
    dbuser = make_user(db, "ipuser36", ip_limit=1)
    report(db, None, {dbuser.id: sessions(
        ("10.0.0.1", "a"), ("10.0.0.2", "b"),
    )})

    def broken_kick(ip, ports):
        raise RuntimeError("ss is not available")

    monkeypatch.setattr(record_online_ips, "_kick_main_host_ip", broken_kick)
    monkeypatch.setattr(record_online_ips.xray, "nodes", {})
    record_online_ips.enforce_ip_limits()  # must not raise


# --- lifecycle -------------------------------------------------------------

def test_deleting_a_user_cascades_to_sessions(db):
    dbuser = make_user(db, "ipuser32")
    report(db, 1, {dbuser.id: sessions(("10.0.0.1", "a"))})

    crud.remove_user(db, dbuser)

    assert db.query(UserOnlineIp).filter(UserOnlineIp.user_id == dbuser.id).count() == 0


def test_poll_job_syncs_from_a_fake_node(db, monkeypatch):
    dbuser = make_user(db, "ipuser33", ip_limit=1)
    node = FakeNode(online_ips={
        str(dbuser.id): [session("10.0.0.1", "phone", "iPhone")],
    })

    monkeypatch.setattr(record_online_ips.xray, "nodes", {1: node})
    record_online_ips.record_online_ips()

    assert _ips_of(db, dbuser) == ["10.0.0.1"]
    assert _devices_of(db, dbuser) == ["phone"]


def test_poll_job_survives_a_failing_node(db, monkeypatch):
    dbuser = make_user(db, "ipuser34")
    monkeypatch.setattr(
        record_online_ips.xray, "nodes", {1: FakeNode(raise_on_read=True)}
    )

    record_online_ips.record_online_ips()  # must not raise

    assert _ips_of(db, dbuser) == []


class FakeNode:
    """Stand-in for a connected Marzban-node."""

    def __init__(self, online_ips=None, raise_on_read=False):
        self.online_ips = online_ips or {}
        self.raise_on_read = raise_on_read
        self.kicked = []

    @property
    def connected(self):
        return True

    @property
    def started(self):
        return True

    def get_online_ips(self):
        if self.raise_on_read:
            raise ConnectionError("node is unreachable")
        return self.online_ips

    def kick_online_ip(self, email, ip, device=""):
        self.kicked.append((email, ip, device))