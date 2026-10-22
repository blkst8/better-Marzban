"""
Rotation of link TLS shapes: uTLS fingerprint, fragment setting, decoy SNI.

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
        sni="www.bing.com",
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


def test_rotate_rewrites_fingerprint_fragment_and_sni(db, monkeypatch):
    crud.update_hosts(db, "VLESS Reality", [_host()])
    monkeypatch.setitem(
        job.xray.config.inbounds_by_tag, "VLESS Reality",
        {"sni": ["www.microsoft.com", "www.bing.com"]},
    )
    monkeypatch.setattr(random, "choice", lambda seq: seq[-1])

    job.rotate_link_shapes()

    hosts = crud.get_hosts(db, "VLESS Reality")
    assert hosts[0].fingerprint == job.FINGERPRINTS[-1]
    assert hosts[0].fragment_setting == job.FRAGMENTS[-1]
    # pool minus the current SNI -> only microsoft left
    assert hosts[0].sni == "www.microsoft.com"


def test_rotate_leaves_disabled_hosts_alone(db, monkeypatch):
    crud.update_hosts(db, "VLESS Reality", [_host(is_disabled=True)])
    monkeypatch.setitem(
        job.xray.config.inbounds_by_tag, "VLESS Reality",
        {"sni": ["www.microsoft.com", "www.bing.com"]},
    )
    monkeypatch.setattr(random, "choice", lambda seq: seq[-1])

    job.rotate_link_shapes()

    hosts = crud.get_hosts(db, "VLESS Reality")
    assert hosts[0].fingerprint == "chrome"
    assert hosts[0].sni == "www.bing.com"
    assert hosts[0].fragment_setting is None
