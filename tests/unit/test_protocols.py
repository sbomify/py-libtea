"""Tests for TeaClientProtocol."""

from unittest.mock import Mock, create_autospec

from libtea.client import TeaClient
from libtea.protocols import TeaClientProtocol

BASE_URL = "https://api.example.com/tea/v0.4.0"


class TestProtocol:
    def test_tea_client_satisfies_protocol(self):
        """TeaClient is a structural subtype of TeaClientProtocol (runtime_checkable)."""
        client = TeaClient(BASE_URL)
        assert isinstance(client, TeaClientProtocol)
        client.close()

    def test_issubclass_and_spec_mocks(self):
        """The protocol is method-only, so issubclass() works and spec-derived doubles satisfy it."""
        assert issubclass(TeaClient, TeaClientProtocol)
        assert isinstance(Mock(spec=TeaClient), TeaClientProtocol)
        assert isinstance(create_autospec(TeaClient, instance=True), TeaClientProtocol)
