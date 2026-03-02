import socket
from unittest.mock import patch

import pytest

from libtea._http import TeaHttpClient
from libtea.client import TeaClient

BASE_URL = "https://api.example.com/tea/v1"

# Public IP used by getaddrinfo mock so SSRF validation passes for test hostnames.
_FAKE_PUBLIC_ADDR = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

_real_getaddrinfo = socket.getaddrinfo


def _mock_getaddrinfo(host, port, *args, **kwargs):
    """Return a fake public IP for *.example.com test hostnames, delegate otherwise."""
    if isinstance(host, str) and host.endswith(".example.com"):
        return _FAKE_PUBLIC_ADDR
    return _real_getaddrinfo(host, port, *args, **kwargs)


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
