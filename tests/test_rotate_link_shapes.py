"""
Rotation of link TLS shapes across decoy inbounds.

Deterministic via a stubbed random.choice (always the last pool item), so the
assertions check the real code paths without relying on luck.
"""

import random

from app.db import crud
from app.jobs import rotate_link_shapes as job
from app.models.proxy import ProxyHost


def _host(**overrides):
    data = dict(
        remark="test",
        address="1.2.3.4",
        port=443,
        sni="www.google.com",
        host=None,
        path=None,
        security="tls",
        alpn="",
        fingerprint="chrome",
        allowinsecure=None,
        is_disabled=False,
        mux_enable=False,
        fragment_setting=None,
        noise_setting=None,
        random_user_agent=False,
        use_sni_as_host=False,
    )
    data.update(overrides)
    return ProxyHost(**data)


def _decoy(sni, port):
    return {"sni": sni, "tls": "reality", "port": port, "protocol": "vless"}


def test_rotate_points_links_at_a_decoy(db, monkeypatch):
    crud.update_hosts(db, "VLESS Reality", [_host()])
    monkeypatch.setitem(job.xray.config.inbounds_by_tag, "VLESS Reality", _decoy(["www.google.com"], 443))
    # unrelated decoy on its own port: the last pool entry wins
    monkeypatch.setitem(job.xray.config.inbounds_by_tag, "VLESS Reality 2096", _decoy(["claude.ai"], 2096))
    monkeypatch.setattr(random, "choice", lambda seq: seq[-1])

    job.rotate_link_shapes()

    hosts = crud.get_hosts(db, "VLESS Reality")
    assert hosts[0].port == 2096
    assert hosts[0].sni == "claude.ai"
    assert getattr(hosts[0].fingerprint, "value", hosts[0].fingerprint) == job.FINGERPRINTS[-1]
    assert hosts[0].fragment_setting == job.FRAGMENTS[-1]


def test_rotate_leaves_disabled_hosts_alone(db, monkeypatch):
    crud.update_hosts(db, "VLESS Reality", [_host(is_disabled=True)])
    monkeypatch.setitem(job.xray.config.inbounds_by_tag, "VLESS Reality", _decoy(["www.google.com"], 443))
    monkeypatch.setitem(job.xray.config.inbounds_by_tag, "VLESS Reality 2096", _decoy(["claude.ai"], 2096))
    monkeypatch.setattr(random, "choice", lambda seq: seq[-1])

    job.rotate_link_shapes()

    hosts = crud.get_hosts(db, "VLESS Reality")
    assert getattr(hosts[0].fingerprint, "value", hosts[0].fingerprint) == "chrome"
    assert hosts[0].sni == "www.google.com"
    assert hosts[0].fragment_setting is None


def test_non_reality_hosts_keep_their_port(db, monkeypatch):
    crud.update_hosts(db, "VLESS WS", [_host(port=10082, sni="", security="none")])
    monkeypatch.setitem(job.xray.config.inbounds_by_tag, "VLESS WS", {"sni": [], "tls": "none", "port": 10082})
    monkeypatch.setitem(job.xray.config.inbounds_by_tag, "VLESS Reality 2096", _decoy(["claude.ai"], 2096))
    monkeypatch.setattr(random, "choice", lambda seq: seq[-1])

    job.rotate_link_shapes()

    hosts = crud.get_hosts(db, "VLESS WS")
    assert hosts[0].port == 10082
    assert hosts[0].sni == ""
