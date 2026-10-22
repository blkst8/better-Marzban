"""
Rotates the TLS shape of every generated link on a random cadence.

Each pass rewrites the hosts table with a new uTLS fingerprint, a new TLS
fragment shape and a new Reality decoy SNI (from the inbound's own serverNames
pool). Clients pick the changes up on their next subscription refresh, so no
stable ClientHello signature exists for a middlebox to key on.
"""

import random
from datetime import datetime, timezone

from app import logger, scheduler, xray
from app.db import GetDB, crud
from app.models.proxy import ProxyHost, ProxyHostSecurity
from config import (
    JOB_ROTATE_LINKS_INTERVAL_MIN,
    JOB_ROTATE_LINKS_JITTER_S,
    ROTATE_LINKS_ENABLED,
)

# uTLS profiles xray supports; "random"/"randomized" let the client library
# pick its own shape per handshake.
FINGERPRINTS = [
    "chrome", "firefox", "safari", "ios", "android",
    "edge", "360", "qq", "random", "randomized",
]

# v2rayNG/Hiddify fragment format, as validated by ProxyHost:
# "<length-range>,<interval-range>,<packet>" (packet: tlshello).
FRAGMENTS = [
    "1-3,5-10,tlshello",
    "2-5,8-16,tlshello",
    "3-6,10-25,tlshello",
    "5-10,15-30,tlshello",
    "10-20,20-40,tlshello",
    "20-30,40-60,tlshello",
]


def _copy_host(host) -> ProxyHost:
    """get_hosts returns SQLAlchemy rows; rebuild them as pydantic hosts."""
    return ProxyHost(
        remark=host.remark,
        address=host.address,
        port=host.port,
        sni=host.sni,
        host=host.host,
        path=host.path,
        security=host.security,
        alpn=host.alpn,
        fingerprint=host.fingerprint,
        allowinsecure=host.allowinsecure,
        is_disabled=host.is_disabled,
        mux_enable=host.mux_enable,
        fragment_setting=host.fragment_setting,
        noise_setting=host.noise_setting,
        random_user_agent=host.random_user_agent,
        use_sni_as_host=host.use_sni_as_host,
    )


def rotate_link_shapes() -> None:
    if not ROTATE_LINKS_ENABLED:
        return

    with GetDB() as db:
        rotated = 0
        for tag in list(xray.config.inbounds_by_tag):
            hosts = crud.get_hosts(db, tag)
            if not hosts:
                continue
            inbound = xray.config.inbounds_by_tag.get(tag, {})
            # The Reality decoy pool is the inbound's own serverNames: a client
            # SNI outside that list would fail the handshake.
            sni_pool = [s for s in (inbound.get("sni") or []) if s]

            modified = []
            for host in hosts:
                new = _copy_host(host)
                if new.is_disabled:
                    modified.append(new)
                    continue

                new.fingerprint = random.choice(FINGERPRINTS)

                if new.security in (
                    ProxyHostSecurity.tls,
                    ProxyHostSecurity.inbound_default,
                ):
                    new.fragment_setting = random.choice(FRAGMENTS)

                if sni_pool and new.sni:
                    choices = [s for s in sni_pool if s != new.sni] or list(sni_pool)
                    new.sni = random.choice(choices)

                modified.append(new)
                rotated += 1

            crud.update_hosts(db, tag, modified)

    xray.hosts.update()
    logger.info(f"Rotated link TLS shapes for {rotated} host entries")


# Random cadence: base interval plus jitter, so the shape never changes on a
# clockwork schedule a middlebox could learn.
scheduler.add_job(
    rotate_link_shapes, 'interval',
    minutes=JOB_ROTATE_LINKS_INTERVAL_MIN,
    jitter=JOB_ROTATE_LINKS_JITTER_S,
    next_run_time=datetime.now(timezone.utc),
    misfire_grace_time=None,
    coalesce=True, max_instances=1,
)
