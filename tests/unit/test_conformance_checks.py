import responses

from libtea.client import TeaClient
from libtea.conformance._checks import (
    _ZERO_UUID,
    ALL_CHECKS,
    CheckContext,
    check_discovery,
    check_discovery_404,
    check_get_product,
    check_get_product_404,
    check_list_products,
    check_uuid_format,
)
from libtea.conformance._types import CheckStatus

BASE_URL = "https://api.example.com/tea/v1"

# Reusable response payloads ---------------------------------------------------

_PRODUCT_UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
_RELEASE_UUID = "b2c3d4e5-f6a7-8901-bcde-f12345678901"

_PRODUCT_JSON = {
    "uuid": _PRODUCT_UUID,
    "name": "Test Product",
    "identifiers": [{"idType": "PURL", "idValue": "pkg:pypi/foo"}],
}

_PAGINATED_PRODUCTS = {
    "timestamp": "2024-03-20T15:30:00Z",
    "pageStartIndex": 0,
    "pageSize": 10,
    "totalResults": 1,
    "results": [_PRODUCT_JSON],
}

_PAGINATED_PRODUCTS_EMPTY = {
    "timestamp": "2024-03-20T15:30:00Z",
    "pageStartIndex": 0,
    "pageSize": 10,
    "totalResults": 0,
    "results": [],
}

_DISCOVERY_RESULT = [
    {
        "productReleaseUuid": _RELEASE_UUID,
        "servers": [{"rootUrl": "https://api.example.com", "versions": ["1.0.0"]}],
    }
]


# Helpers ----------------------------------------------------------------------


def _make_client() -> TeaClient:
    return TeaClient(base_url=BASE_URL)


# Tests ------------------------------------------------------------------------


class TestCheckDiscovery:
    @responses.activate
    def test_pass(self):
        responses.get(f"{BASE_URL}/discovery", json=_DISCOVERY_RESULT)
        client = _make_client()
        ctx = CheckContext(tei="urn:tei:uuid:example.com:some-uuid")
        result = check_discovery(client, ctx)
        assert result.status == CheckStatus.PASS
        assert ctx.product_release_uuid == _RELEASE_UUID

    def test_skip_no_tei(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_discovery(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_fail_empty_list(self):
        responses.get(f"{BASE_URL}/discovery", json=[])
        client = _make_client()
        ctx = CheckContext(tei="urn:tei:uuid:example.com:some-uuid")
        result = check_discovery(client, ctx)
        assert result.status == CheckStatus.FAIL

    @responses.activate
    def test_does_not_overwrite_existing_uuid(self):
        responses.get(f"{BASE_URL}/discovery", json=_DISCOVERY_RESULT)
        client = _make_client()
        ctx = CheckContext(tei="urn:tei:uuid:example.com:some-uuid", product_release_uuid="existing-uuid")
        check_discovery(client, ctx)
        assert ctx.product_release_uuid == "existing-uuid"


class TestCheckDiscovery404:
    @responses.activate
    def test_pass_on_404(self):
        responses.get(f"{BASE_URL}/discovery", json={"error": "OBJECT_UNKNOWN"}, status=404)
        client = _make_client()
        ctx = CheckContext()
        result = check_discovery_404(client, ctx)
        assert result.status == CheckStatus.PASS

    @responses.activate
    def test_pass_on_empty_list(self):
        responses.get(f"{BASE_URL}/discovery", json=[])
        client = _make_client()
        ctx = CheckContext()
        result = check_discovery_404(client, ctx)
        assert result.status == CheckStatus.PASS


class TestCheckListProducts:
    @responses.activate
    def test_pass(self):
        responses.get(f"{BASE_URL}/products", json=_PAGINATED_PRODUCTS)
        client = _make_client()
        ctx = CheckContext()
        result = check_list_products(client, ctx)
        assert result.status == CheckStatus.PASS
        assert ctx.product_uuid == _PRODUCT_UUID

    @responses.activate
    def test_skip_no_products(self):
        responses.get(f"{BASE_URL}/products", json=_PAGINATED_PRODUCTS_EMPTY)
        client = _make_client()
        ctx = CheckContext()
        result = check_list_products(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_does_not_overwrite_existing_uuid(self):
        responses.get(f"{BASE_URL}/products", json=_PAGINATED_PRODUCTS)
        client = _make_client()
        ctx = CheckContext(product_uuid="existing-uuid")
        check_list_products(client, ctx)
        assert ctx.product_uuid == "existing-uuid"


class TestCheckGetProduct:
    @responses.activate
    def test_pass(self):
        responses.get(f"{BASE_URL}/product/{_PRODUCT_UUID}", json=_PRODUCT_JSON)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID)
        result = check_get_product(client, ctx)
        assert result.status == CheckStatus.PASS
        assert "Test Product" in result.message

    def test_skip_no_uuid(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_get_product(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_fail_on_server_error(self):
        responses.get(f"{BASE_URL}/product/{_PRODUCT_UUID}", status=500)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID)
        result = check_get_product(client, ctx)
        assert result.status == CheckStatus.FAIL


class TestCheckGetProduct404:
    @responses.activate
    def test_pass(self):
        responses.get(
            f"{BASE_URL}/product/{_ZERO_UUID}",
            json={"error": "OBJECT_UNKNOWN"},
            status=404,
        )
        client = _make_client()
        ctx = CheckContext()
        result = check_get_product_404(client, ctx)
        assert result.status == CheckStatus.PASS

    @responses.activate
    def test_fail_when_product_found(self):
        responses.get(
            f"{BASE_URL}/product/{_ZERO_UUID}",
            json={"uuid": _ZERO_UUID, "name": "Surprise", "identifiers": []},
        )
        client = _make_client()
        ctx = CheckContext()
        result = check_get_product_404(client, ctx)
        assert result.status == CheckStatus.FAIL


class TestCheckUuidFormat:
    def test_pass_valid_uuids(self):
        client = _make_client()
        ctx = CheckContext(
            collected_uuids=[
                "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "b2c3d4e5-f6a7-8901-bcde-f12345678901",
            ]
        )
        result = check_uuid_format(client, ctx)
        assert result.status == CheckStatus.PASS

    def test_fail_invalid_uuid(self):
        client = _make_client()
        ctx = CheckContext(
            collected_uuids=[
                "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "NOT-A-UUID",
            ]
        )
        result = check_uuid_format(client, ctx)
        assert result.status == CheckStatus.FAIL
        assert "NOT-A-UUID" in result.details

    def test_fail_uppercase_uuid(self):
        client = _make_client()
        ctx = CheckContext(collected_uuids=["A1B2C3D4-E5F6-7890-ABCD-EF1234567890"])
        result = check_uuid_format(client, ctx)
        assert result.status == CheckStatus.FAIL

    def test_skip_no_uuids(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_uuid_format(client, ctx)
        assert result.status == CheckStatus.SKIP


class TestAllChecksRegistry:
    def test_all_checks_non_empty(self):
        assert len(ALL_CHECKS) > 0

    def test_all_checks_are_callable(self):
        for check in ALL_CHECKS:
            assert callable(check), f"{check} is not callable"

    def test_all_checks_have_unique_names(self):
        """Each check function should produce a unique check name."""
        client = _make_client()
        ctx = CheckContext()
        names = []
        for check in ALL_CHECKS:
            result = check(client, ctx)
            names.append(result.name)
        assert len(names) == len(set(names)), f"Duplicate names: {[n for n in names if names.count(n) > 1]}"

    def test_discovery_checks_come_first(self):
        assert ALL_CHECKS[0].__name__ == "check_discovery"
        assert ALL_CHECKS[1].__name__ == "check_discovery_404"

    def test_cross_cutting_checks_come_last(self):
        last_three = [c.__name__ for c in ALL_CHECKS[-3:]]
        assert "check_uuid_format" in last_three
        assert "check_pagination_fields" in last_three
        assert "check_camel_case_fields" in last_three
