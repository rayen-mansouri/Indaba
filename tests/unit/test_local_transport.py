from __future__ import annotations

import pytest

from sentinel.core.local_transport import LocalTransportError, require_loopback_url
from sentinel.defenses.client import HttpDefense


@pytest.mark.parametrize("url", ["http://127.0.0.1:8080/", "http://[::1]:8080", "https://localhost/api"])
def test_loopback_urls_are_accepted(url: str) -> None:
    assert require_loopback_url(url, label="test") == url.rstrip("/")


@pytest.mark.parametrize("url", ["https://example.invalid", "http://10.0.0.1", "http://user@127.0.0.1"])
def test_non_loopback_urls_are_rejected(url: str) -> None:
    with pytest.raises(LocalTransportError):
        require_loopback_url(url, label="test")


def test_http_defense_rejects_non_local_endpoint() -> None:
    with pytest.raises(LocalTransportError):
        HttpDefense("https://example.invalid")
