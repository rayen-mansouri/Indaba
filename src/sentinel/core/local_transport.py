"""Validation for the deliberately local-only HTTP integration surfaces."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


class LocalTransportError(ValueError):
    """Raised before a configured integration can address a non-local endpoint."""


def require_loopback_url(url: str, *, label: str) -> str:
    """Accept an HTTP(S) endpoint only when its literal host is loopback.

    The benchmark has no external service dependency.  Avoiding DNS resolution is
    intentional: it keeps validation deterministic and prevents a hostname from
    being resolved as part of a configuration check.
    """

    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise LocalTransportError(f"{label} must be an absolute loopback HTTP(S) URL")
    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return url.rstrip("/")
    try:
        if ipaddress.ip_address(host).is_loopback:
            return url.rstrip("/")
    except ValueError:
        pass
    raise LocalTransportError(f"{label} must use localhost or a loopback IP address")
