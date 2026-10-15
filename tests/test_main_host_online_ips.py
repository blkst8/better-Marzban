"""
Tests for main-host online-device recording.

Remote nodes report their sessions over the node API, but the main host has no
such channel: its sessions come from the core's access log. These cover the
line parser, the incremental file reader, the sighting window, and that the
main-host rows (node_id = None) reach the same API the dashboard reads.
"""

import pytest

from app.db import crud
from app.db.models import UserOnlineIp
from app.jobs import record_online_ips as job
from app.models.user import UserCreate


def make_user(db, username: str, ip_limit=None):
    return crud.create_user(
        db,
        UserCreate(
            username=username,
            proxies={"vless": {}},
            ip_limit=ip_limit,
        ),
    )

# xray 24.x format:  "2026/10/16 12:00:00 from 1.2.3.4:5678 accepted tcp:x.com:443 [in -> out] email: 3.usr.in"
# legacy format:     "2026/10/16 12:00:00 1.2.3.4:5678 accepted tcp:x.com:443 [in -> out] email: 3.usr.in"
LINE_WITH_FROM = (
    "2026/10/16 12:00:00 from 198.51.100.7:5678 accepted tcp:example.com:443 "
    "[VLESS-in -> direct] email: 3.someuser.VLESS-in"
)
LINE_LEGACY = (
    "2026/10/16 12:00:01 198.51.100.7:5678 accepted tcp:example.com:443 "
    "[VLESS-in -> direct] email: 3.someuser.VLESS-in"
)
LINE_IPV6 = (
    "2026/10/16 12:00:02 from [2001:db8::1]:443 accepted tcp:example.com:443 "
    "[VLESS-in -> direct] email: 4.v6user.VLESS-in"
)


@pytest.fixture(autouse=True)
def _reset_recorder_state():
    job._main_sightings.clear()
    job._access_log_state.update(path=None, inode=None, offset=0)
    job._access_log_warned = False
    yield
    job._main_sightings.clear()
    job._access_log_state.update(path=None, inode=None, offset=0)


def test_parse_access_email_extracts_leading_id():
    assert job.parse_access_email("3.someuser.VLESS-in") == 3
    assert job.parse_access_email("12.usr") == 12


def test_parse_access_email_rejects_non_user_emails():
    assert job.parse_access_email("not-a-user-email") is None
    assert job.parse_access_email("") is None


def test_line_parser_handles_from_prefix_and_legacy():
    for line in (LINE_WITH_FROM, LINE_LEGACY):
        match = job._ACCESS_LINE_RE.search(line)
        assert match, line
        assert match.group("ip") == "198.51.100.7"
        assert job.parse_access_email(match.group("email")) == 3


def test_line_parser_handles_ipv6():
    match = job._ACCESS_LINE_RE.search(LINE_IPV6)
    assert match
    assert match.group("ip") == "[2001:db8::1]"


def test_line_parser_ignores_non_accepted_lines():
    rejected = (
        "2026/10/16 12:00:03 from 198.51.100.7:5678 rejected tcp:example.com:443 "
        "[VLESS-in -> direct] email: 3.someuser.VLESS-in"
    )
    assert "accepted" not in rejected
    assert job._ACCESS_LINE_RE.search(rejected) is None


def test_reader_returns_only_new_lines(tmp_path):
    log = tmp_path / "access.log"
    log.write_text(LINE_WITH_FROM + "\n")

    first = job._read_new_access_lines(str(log))
    assert first == [LINE_WITH_FROM]
    # Second poll with no growth must not replay old lines.
    assert job._read_new_access_lines(str(log)) == []

    log.write_text(LINE_WITH_FROM + "\n" + LINE_IPV6 + "\n")
    second = job._read_new_access_lines(str(log))
    assert second == [LINE_IPV6]


def test_reader_resets_on_truncation(tmp_path):
    log = tmp_path / "access.log"
    log.write_text((LINE_WITH_FROM + "\n") * 10)
    job._read_new_access_lines(str(log))

    # copytruncate-style rotation: same file, size shrinks.
    log.write_text(LINE_IPV6 + "\n")
    lines = job._read_new_access_lines(str(log))
    assert lines == [LINE_IPV6]


def test_main_host_rows_are_synced_with_node_id_none(db, tmp_path, monkeypatch):
    user = make_user(db, "mainhost1")
    log = tmp_path / "access.log"
    log.write_text(LINE_WITH_FROM.replace("3.someuser", f"{user.id}.someuser") + "\n")
    monkeypatch.setattr(job, "_access_log_path", lambda: str(log))

    job._record_main_host(db)

    rows = db.query(UserOnlineIp).filter(UserOnlineIp.user_id == user.id).all()
    assert len(rows) == 1
    assert rows[0].node_id is None
    # No fingerprint exists in the log, so each address is its own device.
    assert rows[0].device == "198.51.100.7"


def test_disappeared_sessions_are_removed_on_next_poll(db, tmp_path, monkeypatch):
    user = make_user(db, "mainhost2")
    log = tmp_path / "access.log"
    log.write_text(LINE_WITH_FROM.replace("3.someuser", f"{user.id}.someuser") + "\n")
    monkeypatch.setattr(job, "_access_log_path", lambda: str(log))

    job._record_main_host(db)
    assert db.query(UserOnlineIp).filter(UserOnlineIp.user_id == user.id).count() == 1

    # No new connections and an expired window: the snapshot must empty out.
    job._main_sightings.clear()
    job._record_main_host(db)
    assert db.query(UserOnlineIp).filter(UserOnlineIp.user_id == user.id).count() == 0


def test_missing_access_log_only_warns(db, monkeypatch):
    monkeypatch.setattr(job, "_access_log_path", lambda: None)
    job._record_main_host(db)
    assert job._access_log_warned is True
    assert db.query(UserOnlineIp).count() == 0


def test_endpoint_reports_main_host_sessions(db, client):
    user = make_user(db, "mainhost3")
    crud.sync_node_online_ips(db, None, {
        str(user.id): [{"ip": "203.0.113.9", "device": "203.0.113.9", "device_name": ""}],
    })

    response = client.get("/api/users/online-ips")
    assert response.status_code == 200
    payload = response.json()
    assert user.username in payload
    assert payload[user.username][0]["ip"] == "203.0.113.9"
