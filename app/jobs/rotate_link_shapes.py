"""
Rotates the TLS shape of every generated link on a random cadence.

Every Reality inbound is a decoy fronting a real site (deepseek, opencode,
claude, z.ai, moonshot, google...). Each pass picks one of those live decoys
for every Reality host entry and rewrites the link to point at it: the port
and the SNI both come from that decoy's own serverNames, so an active prober
always receives that site's genuine certificate.

All decoy inbounds share one keypair and one shortId list, so any link stays
valid against any decoy — switching decoys never breaks a client, it only
changes what the ClientHello looks like to DPI.

uTLS fingerprint and TLS fragment shape rotate on the same pass.
"""

import random
import re
from datetime import datetime, timedelta, timezone

from app import logger, scheduler, xray
from app.db import GetDB, crud
from app.models.proxy import ProxyHost, ProxyHostSecurity
from config import (
    JOB_ROTATE_LINKS_MAX_MINUTES,
    JOB_ROTATE_LINKS_MIN_MINUTES,
    ROTATE_LINKS_ENABLED,
)

# uTLS profiles xray supports, verified live against a decoy (a fingerprint
# this core cannot build fails the handshake *silently*, so only keep ones
# proven to connect). "random"/"randomized" let the client library pick its
# own shape per handshake.
FINGERPRINTS = [
    "chrome", "firefox", "safari", "ios",
    "edge", "qq", "random", "randomized",
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

# The model validates the fragment shape; stale rows may hold values written
# before that validation existed, and copying them would abort the rotation.
_FRAGMENT_RE = re.compile(r"^\d+-\d+,\d+-\d+,[a-z]+$")


def _copy_host(host) -> ProxyHost:
    """get_hosts returns SQLAlchemy rows; rebuild them as pydantic hosts."""
    fragment = host.fragment_setting
    if fragment and not _FRAGMENT_RE.match(fragment):
        fragment = None
    return ProxyHost(
        fragment_setting=fragment,
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
        noise_setting=host.noise_setting,
        random_user_agent=host.random_user_agent,
        use_sni_as_host=host.use_sni_as_host,
    )


def _reality_decoys():
    """Live Reality inbounds, each one a decoy fronting a real site.

    Derived from the running config, so adding a decoy is a config change,
    not a code change — no hardcoded list to drift out of sync.
    """
    decoys = []
    for tag, inbound in xray.config.inbounds_by_tag.items():
        if inbound.get("tls") != "reality":
            continue
        names = [n for n in (inbound.get("sni") or []) if n]
        port = inbound.get("port")
        if names and port:
            decoys.append({"tag": tag, "port": port, "names": names})
    return decoys


def rotate_link_shapes() -> None:
    if not ROTATE_LINKS_ENABLED:
        return

    decoys = _reality_decoys()

    with GetDB() as db:
        rows_by_tag = {}
        for tag in list(xray.config.inbounds_by_tag):
            hosts = crud.get_hosts(db, tag)
            if hosts:
                rows_by_tag[tag] = hosts

        # Deal decoys round-robin from a shuffled deck instead of picking one
        # at random per link: with N links and N decoys every link lands on a
        # different site, so your devices show different SNIs at the same time.
        reality_rows = sum(
            len(hosts) for tag, hosts in rows_by_tag.items()
            if xray.config.inbounds_by_tag.get(tag, {}).get("tls") == "reality"
        )
        deal = []
        while decoys and len(deal) < reality_rows:
            cycle = list(decoys)
            random.shuffle(cycle)
            deal.extend(cycle)

        rotated = 0
        for tag, hosts in rows_by_tag.items():
            inbound = xray.config.inbounds_by_tag.get(tag, {})
            is_reality = inbound.get("tls") == "reality"

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

                if is_reality and deal:
                    # Port and SNI travel together: the SNI only returns a
                    # genuine certificate from the frontend serving that name.
                    decoy = deal.pop(0)
                    new.port = decoy["port"]
                    new.sni = random.choice(decoy["names"])

                modified.append(new)
                rotated += 1

            crud.update_hosts(db, tag, modified)

    xray.hosts.update()
    logger.info(
        f"Rotated link TLS shapes for {rotated} host entries "
        f"across {len(decoys)} decoys"
    )


def _schedule_next() -> None:
    """Random cadence, self-rescheduled: never a clockwork pattern."""
    delay = random.uniform(JOB_ROTATE_LINKS_MIN_MINUTES, JOB_ROTATE_LINKS_MAX_MINUTES)
    scheduler.add_job(
        rotate_link_shapes, 'date',
        run_date=datetime.now(timezone.utc) + timedelta(minutes=delay),
        id="rotate-link-shapes", replace_existing=True,
        misfire_grace_time=None,
    )
    logger.info(f"Next link-shape rotation in {delay:.0f} min")


def rotate_and_reschedule() -> None:
    try:
        rotate_link_shapes()
    finally:
        _schedule_next()


# First run immediately at boot; the job reschedules itself afterwards.
scheduler.add_job(
    rotate_and_reschedule, 'date',
    run_date=datetime.now(timezone.utc),
    id="rotate-link-shapes", replace_existing=True,
    misfire_grace_time=None,
)
