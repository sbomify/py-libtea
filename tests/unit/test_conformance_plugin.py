"""Test the conformance pytest plugin registration and fixtures."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from libtea.conformance._checks import ALL_CHECKS, CheckContext
from libtea.conformance._types import CheckResult, CheckStatus
from libtea.conformance.plugin import (
    pytest_addoption,
    pytest_collection_modifyitems,
    pytest_configure,
    pytest_generate_tests,
)


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


class TestPytestAddoption:
    def test_registers_all_options(self) -> None:
        mock_parser = MagicMock(spec=pytest.Parser)
        mock_group = MagicMock()
        mock_parser.getgroup.return_value = mock_group
        pytest_addoption(mock_parser)
        mock_parser.getgroup.assert_called_once_with("tea-conformance", "TEA server conformance testing")
        option_names = [call.args[0] for call in mock_group.addoption.call_args_list]
        assert "--tea-base-url" in option_names
        assert "--tea-tei" in option_names
        assert "--tea-token" in option_names
        assert "--tea-product-uuid" in option_names
        assert "--tea-release-uuid" in option_names
        assert "--tea-component-uuid" in option_names
        assert "--tea-component-release-uuid" in option_names
        assert "--tea-artifact-uuid" in option_names
        assert "--tea-timeout" in option_names


class TestPytestConfigure:
    def test_registers_marker(self) -> None:
        mock_config = MagicMock(spec=pytest.Config)
        pytest_configure(mock_config)
        mock_config.addinivalue_line.assert_called_once_with("markers", "tea_conformance: TEA server conformance check")


class TestPytestCollectionModifyitems:
    def test_skips_tea_items_when_no_base_url(self) -> None:
        mock_config = MagicMock(spec=pytest.Config)
        mock_config.getoption.return_value = None
        item = MagicMock(spec=pytest.Item)
        item.keywords = {"tea_conformance": True}
        pytest_collection_modifyitems(mock_config, [item])
        item.add_marker.assert_called_once()
        marker = item.add_marker.call_args[0][0]
        assert marker.kwargs.get("reason") == "--tea-base-url not provided"

    def test_does_not_skip_when_base_url_provided(self) -> None:
        mock_config = MagicMock(spec=pytest.Config)
        mock_config.getoption.return_value = "https://tea.example.com"
        item = MagicMock(spec=pytest.Item)
        item.keywords = {"tea_conformance": True}
        pytest_collection_modifyitems(mock_config, [item])
        item.add_marker.assert_not_called()

    def test_skips_only_tea_items(self) -> None:
        mock_config = MagicMock(spec=pytest.Config)
        mock_config.getoption.return_value = None
        tea_item = MagicMock(spec=pytest.Item)
        tea_item.keywords = {"tea_conformance": True}
        other_item = MagicMock(spec=pytest.Item)
        other_item.keywords = {}
        pytest_collection_modifyitems(mock_config, [tea_item, other_item])
        tea_item.add_marker.assert_called_once()
        other_item.add_marker.assert_not_called()


class TestPytestGenerateTests:
    def test_parametrizes_when_fixture_requested(self) -> None:
        mock_metafunc = MagicMock(spec=pytest.Metafunc)
        mock_metafunc.fixturenames = ["tea_check_fn"]
        pytest_generate_tests(mock_metafunc)
        mock_metafunc.parametrize.assert_called_once_with(
            "tea_check_fn",
            ALL_CHECKS,
            ids=[fn.__name__ for fn in ALL_CHECKS],
        )

    def test_does_nothing_without_fixture(self) -> None:
        mock_metafunc = MagicMock(spec=pytest.Metafunc)
        mock_metafunc.fixturenames = ["other_fixture"]
        pytest_generate_tests(mock_metafunc)
        mock_metafunc.parametrize.assert_not_called()


class TestTeaConformance:
    def _get_test_fn(self):
        """Import the plugin's test function without exposing it as a pytest test."""
        from libtea.conformance import plugin

        return plugin.test_tea_conformance

    def test_pass_result(self) -> None:
        fn = self._get_test_fn()
        mock_client = MagicMock()
        ctx = CheckContext()
        check_fn = MagicMock(return_value=CheckResult(name="test", status=CheckStatus.PASS, message="OK"))
        fn(mock_client, ctx, check_fn)

    def test_skip_result(self) -> None:
        fn = self._get_test_fn()
        mock_client = MagicMock()
        ctx = CheckContext()
        check_fn = MagicMock(return_value=CheckResult(name="test", status=CheckStatus.SKIP, message="no data"))
        with pytest.raises(pytest.skip.Exception):
            fn(mock_client, ctx, check_fn)

    def test_fail_result(self) -> None:
        fn = self._get_test_fn()
        mock_client = MagicMock()
        ctx = CheckContext()
        check_fn = MagicMock(return_value=CheckResult(name="test", status=CheckStatus.FAIL, message="bad"))
        with pytest.raises(pytest.fail.Exception):
            fn(mock_client, ctx, check_fn)


class TestTeaClientFixtureLogic:
    def test_client_created_with_correct_params(self) -> None:
        """Verify the fixture logic creates TeaClient with the right params."""
        from libtea.client import TeaClient

        # The fixture extracts base_url, token, and timeout from config.
        # We test the same logic directly.
        client = TeaClient(base_url="https://tea.example.com/v1", token="secret", timeout=15.0)
        assert client._http._base_url == "https://tea.example.com/v1"
        client.close()


class TestTeaCheckContextFixtureLogic:
    def test_context_fields_from_options(self) -> None:
        """Verify CheckContext is constructed with the right fields."""
        ctx = CheckContext(
            tei="urn:tei:uuid:example.com:abc",
            product_uuid="p-uuid",
            product_release_uuid="r-uuid",
            component_uuid="c-uuid",
            artifact_uuid="a-uuid",
        )
        assert ctx.tei == "urn:tei:uuid:example.com:abc"
        assert ctx.product_uuid == "p-uuid"
        assert ctx.product_release_uuid == "r-uuid"
        assert ctx.component_uuid == "c-uuid"
        assert ctx.artifact_uuid == "a-uuid"
