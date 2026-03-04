import socket
from unittest.mock import patch

import pytest

from libtea._http import TeaHttpClient
from libtea.client import TeaClient

BASE_URL = "https://api.example.com/tea/v1"

# Public IP used by getaddrinfo mock so SSRF validation passes for test hostnames.
_FAKE_PUBLIC_ADDR = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]


def _mock_getaddrinfo(host, port, *args, **kwargs):
    """Return a fake public IP for example.com test hostnames; fail for all others."""
    if isinstance(host, str) and (host == "example.com" or host.endswith(".example.com")):
        return _FAKE_PUBLIC_ADDR
    raise socket.gaierror(f"DNS resolution disabled for host {host!r} in tests")


@pytest.fixture(autouse=True)
def _fake_dns():
    """Auto-mock DNS for test hostnames so fail-closed SSRF checks pass."""
    with patch("libtea._security.socket.getaddrinfo", side_effect=_mock_getaddrinfo):
        yield


@pytest.fixture
def base_url():
    return BASE_URL


@pytest.fixture
def client():
    c = TeaClient(base_url=BASE_URL)
    yield c
    c.close()


@pytest.fixture
def http_client():
    c = TeaHttpClient(base_url=BASE_URL)
    yield c
    c.close()
