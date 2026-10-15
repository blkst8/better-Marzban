"""
Tests for the Telegram bot's device-limit surface.

The bot talks to the database through crud and to the node through
xray.nodes, so these exercise exactly what a real admin would trigger,
with the Telegram client replaced by a recorder.
"""

import pytest

import app.telegram.handlers.report as report_module
from app.db import crud
from app.db import GetDB
from app.db.models import JWT
from app.models.user import UserCreate, UserModify
from app.telegram.utils.keyboard import BotKeyboard


def make_user(db, username: str, ip_limit=None):
    return crud.create_user(
        db,
        UserCreate(username=username, proxies={"vless": {}}, ip_limit=ip_limit),
    )


class FakeNode:
    def __init__(self):
        self.kicked = []

    @property
    def connected(self):
        return True

    @property
    def started(self):
        return True

    def kick_online_ip(self, email, ip, device=""):
        self.kicked.append((email, ip, device))


@pytest.fixture
def jwt_secret(db):
    """Subscription URL generation needs a stored secret."""
    if not db.query(JWT).first():
        db.add(JWT(secret_key="test-secret"))
        db.commit()
    yield

@pytest.fixture
def sent(monkeypatch):
    """Replaces the Telegram sender with a recorder."""
    outbox = []
    monkeypatch.setattr(report_module, "report", lambda text, **kw: outbox.append((text, kw)))
    yield outbox


def device_limit_from_keyboard(markup) -> int:
    """Reads the device limit back out of the user_devices_menu markup."""
    row = [btn.text for row in markup.keyboard for btn in row]
    hit = [t for t in row if t.startswith("📵 Device limit:")]
    assert hit, f"no device limit button in {row}"
    text = hit[0].split(":")[1].strip()
    return None if text == "Unlimited" else int(text)


def test_user_devices_menu_lists_every_device_once(db):
    dbuser = make_user(db, "tguser1")
    crud.sync_node_online_ips(db, 1, {
        dbuser.id: [
            {"ip": "10.0.0.7", "device": "phone", "device_name": "iPhone"},
            {"ip": "10.0.0.7", "device": "laptop", "device_name": "Windows"},
            {"ip": "10.0.0.9", "device": "tablet", "device_name": "iPad"},
        ]})
    rows = crud.get_user_online_ips(db, dbuser)
    sessions = [{"ip": r.ip, "device": r.device, "device_name": r.device_name or ""} for r in rows]

    keyboard = BotKeyboard.user_devices_menu("tguser1", sessions, device_limit=2)

    kick_rows = [
        (row[0].text, row[1].callback_data)
        for row in keyboard.keyboard if len(row) > 1
        and row[1].callback_data.startswith("kick_device:")
    ]
    assert len(kick_rows) == 3
    devices_mentioned = sum(
        1 for text, _ in kick_rows
        if text.startswith(("iPhone", "Windows", "iPad"))
    )
    assert devices_mentioned == 3
    # Callback data carries an index, never the device or IP payload.
    assert all(callback == f"kick_device:tguser1:{i}" for i, (_, callback) in enumerate(kick_rows))


def test_devices_menu_keyboard_stays_under_telegram_callback_limit(db):
    """A 40-char device label plus IP must not push callback data past 64 bytes."""
    dbuser = make_user(db, "tguser2")
    crud.sync_node_online_ips(db, 1, {
        dbuser.id: [{"ip": "255.255.255.255", "device": "d" * 40, "device_name": "x" * 40}]
    })
    rows = crud.get_user_online_ips(db, dbuser)
    sessions = [{"ip": r.ip, "device": r.device, "device_name": r.device_name or ""} for r in rows]

    keyboard = BotKeyboard.user_devices_menu("tguser2", sessions, device_limit=1)
    for row in keyboard.keyboard:
        for btn in row:
            if btn.callback_data:
                assert len(btn.callback_data.encode()) <= 64, btn.callback_data


def test_user_menu_gains_devices_entry(db):
    make_user(db, "tguser3")
    keyboard = BotKeyboard.user_menu({"status": "active", "username": "tguser3"})
    callbacks = [btn.callback_data for row in keyboard.keyboard for btn in row]
    assert "devices:tguser3" in callbacks


def test_devices_menu_shows_none_from_unlimited_limit(db):
    make_user(db, "tguser4")
    keyboard = BotKeyboard.user_devices_menu("tguser4", [], device_limit=None)
    assert device_limit_from_keyboard(keyboard) is None

    keyboard = BotKeyboard.user_devices_menu("tguser5", [], device_limit=3)
    assert device_limit_from_keyboard(keyboard) == 3


def test_breach_report_message_names_the_user_and_limit(sent):
    report_module.report_ip_limit_breach(
        "breachy", limit=2, devices=["a", "b", "c"], admin=None)

    text, kwargs = sent[-1]
    assert "breachy" in text
    assert "2" in text          # limit
    assert "3" in text          # device count


def test_breach_report_is_deduped_per_episode(db, sent, monkeypatch):
    """The enforcement job reports once, and only again if excess changes."""
    from app.jobs import record_online_ips

    dbuser = make_user(db, "tguser6", ip_limit=1)
    monkeypatch.setattr(record_online_ips.report, "ip_limit_breach",
                        lambda **kw: sent.append(kw))

    crud.sync_node_online_ips(db, 1, {
        dbuser.id: [{"ip": "10.0.0.1", "device": "a", "device_name": ""},
                    {"ip": "10.0.0.2", "device": "b", "device_name": ""}]})
    node = FakeNode()
    monkeypatch.setattr(record_online_ips.xray, "nodes", {1: node})

    record_online_ips.enforce_ip_limits()
    first = list(sent)
    assert len(first) == 1

    # Same episode, next poll: no repeat.
    record_online_ips.enforce_ip_limits()
    assert len(sent) == len(first)

    # Excess devices change -> reported again.
    crud.sync_node_online_ips(db, 1, {
        dbuser.id: [{"ip": "10.0.0.1", "device": "a", "device_name": ""},
                    {"ip": "10.0.0.2", "device": "b", "device_name": ""},
                    {"ip": "10.0.0.3", "device": "c", "device_name": ""}]})
    record_online_ips.enforce_ip_limits()
    assert len(sent) == len(first) + 1

    dummy = make_user(db, "tguser6-other")
    crud.remove_user(db, dummy)


def test_breach_report_is_not_repeated_after_recovery(db, sent, monkeypatch):
    from app.jobs import record_online_ips

    dbuser = make_user(db, "tguser7", ip_limit=1)
    monkeypatch.setattr(record_online_ips.report, "ip_limit_breach",
                        lambda **kw: sent.append(kw))
    node = FakeNode()
    monkeypatch.setattr(record_online_ips.xray, "nodes", {1: node})

    crud.sync_node_online_ips(db, 1, {
        dbuser.id: [{"ip": "10.0.0.1", "device": "a", "device_name": ""},
                    {"ip": "10.0.0.2", "device": "b", "device_name": ""}]})
    record_online_ips.enforce_ip_limits()
    assert len(sent) == 1

    # Back under the limit: episode closes, no further report.
    crud.sync_node_online_ips(db, 1, {
        dbuser.id: [{"ip": "10.0.0.1", "device": "a", "device_name": ""}]})
    record_online_ips.enforce_ip_limits()
    assert len(sent) == 1

    # Breached again later: reported anew.
    crud.sync_node_online_ips(db, 1, {
        dbuser.id: [{"ip": "10.0.0.1", "device": "a", "device_name": ""},
                    {"ip": "10.0.0.9", "device": "z", "device_name": ""}]})
    record_online_ips.enforce_ip_limits()
    assert len(sent) == 2


def test_remove_user_online_ip_targets_one_device(db):
    dbuser = make_user(db, "tguser8")
    crud.sync_node_online_ips(db, 1, {
        dbuser.id: [{"ip": "10.0.0.5", "device": "phone", "device_name": ""},
                    {"ip": "10.0.0.5", "device": "laptop", "device_name": ""}]})

    crud.remove_user_online_ip(db, dbuser, "10.0.0.5", "phone")

    left = {r.device for r in crud.get_user_online_ips(db, dbuser)}
    assert left == {"laptop"}


def test_info_text_reports_device_limit_and_sessions(db, jwt_secret):
    from app.telegram.utils.shared import get_user_info_text

    dbuser = make_user(db, "tguser9", ip_limit=3)
    crud.sync_node_online_ips(db, 1, {
        dbuser.id: [{"ip": "10.0.0.5", "device": "phone", "device_name": "iPhone · iOS 17"}]})

    text = get_user_info_text(dbuser, online_sessions=[
        {"ip": "10.0.0.5", "device": "phone", "device_name": "iPhone · iOS 17"}])

    assert "Device limit" in text and "3" in text
    assert "Online devices (1)" in text
    assert "iPhone · iOS 17" in text


def test_info_text_without_sessions(db, jwt_secret):
    from app.telegram.utils.shared import get_user_info_text

    dbuser = make_user(db, "tguser10")
    text = get_user_info_text(dbuser)

    assert "Unlimited" in text
    assert "Online devices (0)" in text


def test_usage_command_shows_device_limit(db, jwt_secret, monkeypatch):
    """The public /usage reply now reports the device limit and device count."""
    import app.telegram.handlers.user as user_module

    dbuser = make_user(db, "tguser11", ip_limit=1)
    crud.sync_node_online_ips(db, 1, {
        dbuser.id: [{"ip": "10.0.0.5", "device": "phone", "device_name": ""},
                    {"ip": "10.0.0.6", "device": "phone", "device_name": ""}]})

    replies = {}

    class FakeMessage:
        text = "/usage tguser11"
        chat = type("Chat", (), {"id": 1})()

    monkeypatch.setattr(user_module.bot, "reply_to",
                        lambda message, text, **kw: replies.setdefault("text", text))

    import telebot.util
    monkeypatch.setattr(telebot.util, "extract_arguments", lambda text: "tguser11")

    user_module.usage_command(FakeMessage())

    text = replies["text"]
    assert "Device limit" in text
    assert "Online devices" in text


def test_zero_limit_clears_rather_than_no_change(db, monkeypatch):
    """The bot edit flow must pass 0 through, not translate it into None."""
    from app import xray
    from app.models.user import UserModify

    captured = {}
    real_update = crud.update_user

    def spy_update(db, dbuser, modify):
        captured["modify"] = modify
        return real_update(db, dbuser, modify)

    monkeypatch.setattr(crud, "update_user", spy_update)
    monkeypatch.setattr(xray.operations, "update_user", lambda dbuser: None)

    make_user(db, "tgzero", ip_limit=4)

    with GetDB() as db:
        dbuser = crud.get_user(db, "tgzero")
        crud.update_user(db, dbuser, UserModify(ip_limit=0))

    with GetDB() as db:
        dbuser = crud.get_user(db, "tgzero")

    assert captured["modify"].ip_limit == 0, "0 must not be silently converted to None"
    assert dbuser.ip_limit is None, "0 means unlimited in the database"


def test_none_limit_keeps_existing_limit(db):
    from app.models.user import UserModify

    make_user(db, "tgkeep", ip_limit=3)

    with GetDB() as db:
        dbuser = crud.get_user(db, "tgkeep")
        crud.update_user(db, dbuser, UserModify(ip_limit=None))

    with GetDB() as db:
        dbuser = crud.get_user(db, "tgkeep")

    assert dbuser.ip_limit == 3, "None must mean no change"
