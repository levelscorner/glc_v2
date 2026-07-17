"""SSRF guard for outbound URL fetches (Session 12 hardening, finding C1).

`/v1/vision` resolves image URLs by fetching them server-side. Without a
guard, an attacker points it at an internal address — cloud metadata
(``169.254.169.254``), the gateway's own loopback (``127.0.0.1:8111``), or
any RFC-1918 host — and the gateway becomes a proxy into the private
network. `follow_redirects=True` made it worse: a public URL could 302 to
an internal one.

Mitigations here:
- scheme must be http/https;
- the host must resolve to a *global* address only — every A/AAAA record is
  rejected if private, loopback, link-local, multicast, reserved, or
  unspecified (v4 and v6);
- an optional allowlist (``GLC_IMAGE_URL_ALLOWLIST``, comma-separated hosts
  or parent domains) restricts fetches to named hosts;
- the caller must re-run :func:`check_url_allowed` on every redirect hop.

Residual: this validates the *hostname's* current DNS answer, so a
determined attacker could still attempt DNS rebinding (resolve public at
check time, private at connect time). Closing that fully requires pinning
the validated IP and connecting to it with the original Host header; noted
as a follow-up.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse


def _host_is_global(host: str) -> bool:
    """True only if every address ``host`` resolves to is globally routable."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    if not infos:
        return False
    for info in infos:
        ip = info[4][0]
        # Strip any IPv6 zone id (e.g. "fe80::1%eth0").
        ip = ip.split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        ):
            return False
    return True


def _allowlist() -> set[str]:
    raw = os.getenv("GLC_IMAGE_URL_ALLOWLIST", "").strip()
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def _host_in_allowlist(host: str, allow: set[str]) -> bool:
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in allow)


def check_url_allowed(url: str) -> tuple[bool, str]:
    """Return ``(ok, reason)``. Call on the initial URL and every redirect."""
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return False, f"scheme not allowed: {p.scheme!r}"
    host = p.hostname or ""
    if not host:
        return False, "url has no host"
    allow = _allowlist()
    if allow and not _host_in_allowlist(host, allow):
        return False, f"host not in GLC_IMAGE_URL_ALLOWLIST: {host}"
    if not _host_is_global(host):
        return False, f"host resolves to a private/link-local address: {host}"
    return True, "ok"
