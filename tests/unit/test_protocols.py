"""Tests for TeaClientProtocol."""

from libtea.client import TeaClient
from libtea.protocols import TeaClientProtocol

BASE_URL = "https://api.example.com/tea/v1"


class TestProtocol:
    def test_tea_client_satisfies_protocol(self):
        """TeaClient is a structural subtype of TeaClientProtocol (runtime_checkable)."""
        client = TeaClient(BASE_URL)
        assert isinstance(client, TeaClientProtocol)
        client.close()
