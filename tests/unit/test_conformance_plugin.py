"""Test the conformance pytest plugin registration and fixtures."""

from libtea.conformance.plugin import pytest_addoption, pytest_configure


class TestPluginRegistration:
    def test_addoption_callable(self) -> None:
        assert callable(pytest_addoption)

    def test_configure_callable(self) -> None:
        assert callable(pytest_configure)

    def test_plugin_discoverable(self) -> None:
        from libtea.conformance import plugin

        assert hasattr(plugin, "pytest_addoption")
        assert hasattr(plugin, "tea_client")
        assert hasattr(plugin, "test_tea_conformance")
