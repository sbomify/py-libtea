import responses

from libtea.client import TeaClient
from libtea.conformance._checks import (
    _ZERO_UUID,
    ALL_CHECKS,
    CheckContext,
    check_camel_case_fields,
    check_cle_event_ordering,
    check_component_cle,
    check_component_release,
    check_component_release_cle,
    check_component_release_collections,
    check_component_releases,
    check_discovery,
    check_discovery_404,
    check_get_artifact,
    check_get_component,
    check_get_product,
    check_get_product_404,
    check_get_product_release,
    check_list_product_releases,
    check_list_products,
    check_pagination_fields,
    check_product_cle,
    check_product_release_cle,
    check_product_release_collection_latest,
    check_product_release_collection_version,
    check_product_release_collections,
    check_product_releases,
    check_search_product_releases,
    check_search_products,
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

_COMPONENT_UUID = "c3d4e5f6-a7b8-9012-cdef-123456789012"
_COMPONENT_RELEASE_UUID = "d4e5f6a7-b8c9-0123-defa-234567890123"
_ARTIFACT_UUID = "e5f6a7b8-c9d0-1234-efab-345678901234"

_DISCOVERY_RESULT = [
    {
        "productReleaseUuid": _RELEASE_UUID,
        "servers": [{"rootUrl": "https://api.example.com", "versions": ["1.0.0"]}],
    }
]

_PRODUCT_RELEASE_JSON = {
    "uuid": _RELEASE_UUID,
    "name": "Test Release",
    "version": "1.0.0",
    "createdDate": "2024-01-01T00:00:00Z",
    "identifiers": [{"idType": "PURL", "idValue": "pkg:pypi/foo@1.0.0"}],
    "components": [{"uuid": _COMPONENT_UUID, "name": "comp"}],
}

_PRODUCT_RELEASE_NO_COMPONENTS_JSON = {
    "uuid": _RELEASE_UUID,
    "name": "Test Release",
    "version": "1.0.0",
    "createdDate": "2024-01-01T00:00:00Z",
    "identifiers": [{"idType": "PURL", "idValue": "pkg:pypi/foo@1.0.0"}],
    "components": [],
}

_PRODUCT_RELEASE_NO_IDENTIFIERS_JSON = {
    "uuid": _RELEASE_UUID,
    "name": "Test Release",
    "version": "1.0.0",
    "createdDate": "2024-01-01T00:00:00Z",
    "identifiers": [],
    "components": [],
}

_PAGINATED_RELEASES = {
    "timestamp": "2024-01-01T00:00:00Z",
    "pageStartIndex": 0,
    "pageSize": 10,
    "totalResults": 1,
    "results": [_PRODUCT_RELEASE_JSON],
}

_PAGINATED_RELEASES_EMPTY = {
    "timestamp": "2024-01-01T00:00:00Z",
    "pageStartIndex": 0,
    "pageSize": 10,
    "totalResults": 0,
    "results": [],
}

_COLLECTION_JSON = {
    "version": 1,
    "artifacts": [{"uuid": _ARTIFACT_UUID, "name": "sbom.json", "formats": []}],
}

_COLLECTION_NO_ARTIFACTS_JSON = {
    "version": 1,
    "artifacts": [],
}

_COMPONENT_JSON = {
    "uuid": _COMPONENT_UUID,
    "name": "Test Component",
    "identifiers": [],
}

_RELEASE_JSON = {
    "uuid": _COMPONENT_RELEASE_UUID,
    "version": "1.0.0",
    "createdDate": "2024-01-01T00:00:00Z",
    "identifiers": [],
}

_COMPONENT_RELEASE_WITH_COLLECTION_JSON = {
    "release": _RELEASE_JSON,
    "latestCollection": _COLLECTION_JSON,
}

_COMPONENT_RELEASE_NO_ARTIFACTS_JSON = {
    "release": _RELEASE_JSON,
    "latestCollection": _COLLECTION_NO_ARTIFACTS_JSON,
}

_ARTIFACT_JSON = {
    "uuid": _ARTIFACT_UUID,
    "name": "sbom.json",
    "formats": [],
}

_CLE_JSON = {
    "events": [
        {
            "id": 3,
            "type": "released",
            "effective": "2024-03-01T00:00:00Z",
            "published": "2024-03-01T00:00:00Z",
        },
        {
            "id": 2,
            "type": "released",
            "effective": "2024-02-01T00:00:00Z",
            "published": "2024-02-01T00:00:00Z",
        },
        {
            "id": 1,
            "type": "released",
            "effective": "2024-01-01T00:00:00Z",
            "published": "2024-01-01T00:00:00Z",
        },
    ]
}

_CLE_UNORDERED_JSON = {
    "events": [
        {
            "id": 1,
            "type": "released",
            "effective": "2024-01-01T00:00:00Z",
            "published": "2024-01-01T00:00:00Z",
        },
        {
            "id": 3,
            "type": "released",
            "effective": "2024-03-01T00:00:00Z",
            "published": "2024-03-01T00:00:00Z",
        },
    ]
}

_CLE_SINGLE_EVENT_JSON = {
    "events": [
        {
            "id": 1,
            "type": "released",
            "effective": "2024-01-01T00:00:00Z",
            "published": "2024-01-01T00:00:00Z",
        },
    ]
}

_PRODUCT_NO_IDENTIFIERS_JSON = {
    "uuid": _PRODUCT_UUID,
    "name": "Test Product",
    "identifiers": [],
}

_PRODUCT_PARTIAL_IDENTIFIER_JSON = {
    "uuid": _PRODUCT_UUID,
    "name": "Test Product",
    "identifiers": [{"idType": "PURL"}],
}


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

    @responses.activate
    def test_fail_on_server_error(self):
        responses.get(f"{BASE_URL}/discovery", status=500)
        client = _make_client()
        ctx = CheckContext(tei="urn:tei:uuid:example.com:some-uuid")
        result = check_discovery(client, ctx)
        assert result.status == CheckStatus.FAIL
        assert "discover() failed" in result.message


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

    @responses.activate
    def test_fail_when_results_returned(self):
        responses.get(f"{BASE_URL}/discovery", json=_DISCOVERY_RESULT)
        client = _make_client()
        ctx = CheckContext()
        result = check_discovery_404(client, ctx)
        assert result.status == CheckStatus.FAIL
        assert "Expected 404 or empty list" in result.message

    @responses.activate
    def test_fail_on_unexpected_error(self):
        responses.get(f"{BASE_URL}/discovery", status=500)
        client = _make_client()
        ctx = CheckContext()
        result = check_discovery_404(client, ctx)
        assert result.status == CheckStatus.FAIL
        assert "Unexpected error" in result.message


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

    @responses.activate
    def test_fail_on_server_error(self):
        responses.get(f"{BASE_URL}/products", status=500)
        client = _make_client()
        ctx = CheckContext()
        result = check_list_products(client, ctx)
        assert result.status == CheckStatus.FAIL


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


class TestCheckSearchProducts:
    @responses.activate
    def test_pass(self):
        responses.get(f"{BASE_URL}/product/{_PRODUCT_UUID}", json=_PRODUCT_JSON)
        responses.get(f"{BASE_URL}/products", json=_PAGINATED_PRODUCTS)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID)
        result = check_search_products(client, ctx)
        assert result.status == CheckStatus.PASS

    def test_skip_no_uuid(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_search_products(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_skip_no_identifiers(self):
        responses.get(f"{BASE_URL}/product/{_PRODUCT_UUID}", json=_PRODUCT_NO_IDENTIFIERS_JSON)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID)
        result = check_search_products(client, ctx)
        assert result.status == CheckStatus.SKIP
        assert "no identifiers" in result.message

    @responses.activate
    def test_skip_partial_identifier(self):
        responses.get(f"{BASE_URL}/product/{_PRODUCT_UUID}", json=_PRODUCT_PARTIAL_IDENTIFIER_JSON)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID)
        result = check_search_products(client, ctx)
        assert result.status == CheckStatus.SKIP
        assert "missing type or value" in result.message

    @responses.activate
    def test_fail_get_product_error(self):
        responses.get(f"{BASE_URL}/product/{_PRODUCT_UUID}", status=500)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID)
        result = check_search_products(client, ctx)
        assert result.status == CheckStatus.FAIL
        assert "get_product()" in result.message

    @responses.activate
    def test_fail_search_error(self):
        responses.get(f"{BASE_URL}/product/{_PRODUCT_UUID}", json=_PRODUCT_JSON)
        responses.get(f"{BASE_URL}/products", status=500)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID)
        result = check_search_products(client, ctx)
        assert result.status == CheckStatus.FAIL
        assert "search_products()" in result.message

    @responses.activate
    def test_fail_no_results(self):
        responses.get(f"{BASE_URL}/product/{_PRODUCT_UUID}", json=_PRODUCT_JSON)
        responses.get(f"{BASE_URL}/products", json=_PAGINATED_PRODUCTS_EMPTY)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID)
        result = check_search_products(client, ctx)
        assert result.status == CheckStatus.FAIL
        assert "no results" in result.message


class TestCheckProductReleases:
    @responses.activate
    def test_pass(self):
        responses.get(f"{BASE_URL}/product/{_PRODUCT_UUID}/releases", json=_PAGINATED_RELEASES)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID)
        result = check_product_releases(client, ctx)
        assert result.status == CheckStatus.PASS
        assert ctx.product_release_uuid == _RELEASE_UUID

    def test_skip_no_uuid(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_product_releases(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_skip_empty(self):
        responses.get(f"{BASE_URL}/product/{_PRODUCT_UUID}/releases", json=_PAGINATED_RELEASES_EMPTY)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID)
        result = check_product_releases(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_fail_on_server_error(self):
        responses.get(f"{BASE_URL}/product/{_PRODUCT_UUID}/releases", status=500)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID)
        result = check_product_releases(client, ctx)
        assert result.status == CheckStatus.FAIL

    @responses.activate
    def test_does_not_overwrite_existing_uuid(self):
        responses.get(f"{BASE_URL}/product/{_PRODUCT_UUID}/releases", json=_PAGINATED_RELEASES)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID, product_release_uuid="existing-uuid")
        check_product_releases(client, ctx)
        assert ctx.product_release_uuid == "existing-uuid"


class TestCheckListProductReleases:
    @responses.activate
    def test_pass(self):
        responses.get(f"{BASE_URL}/productReleases", json=_PAGINATED_RELEASES)
        client = _make_client()
        ctx = CheckContext()
        result = check_list_product_releases(client, ctx)
        assert result.status == CheckStatus.PASS
        assert ctx.product_release_uuid == _RELEASE_UUID

    @responses.activate
    def test_skip_empty(self):
        responses.get(f"{BASE_URL}/productReleases", json=_PAGINATED_RELEASES_EMPTY)
        client = _make_client()
        ctx = CheckContext()
        result = check_list_product_releases(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_fail_on_server_error(self):
        responses.get(f"{BASE_URL}/productReleases", status=500)
        client = _make_client()
        ctx = CheckContext()
        result = check_list_product_releases(client, ctx)
        assert result.status == CheckStatus.FAIL

    @responses.activate
    def test_does_not_overwrite_existing_uuid(self):
        responses.get(f"{BASE_URL}/productReleases", json=_PAGINATED_RELEASES)
        client = _make_client()
        ctx = CheckContext(product_release_uuid="existing-uuid")
        check_list_product_releases(client, ctx)
        assert ctx.product_release_uuid == "existing-uuid"


class TestCheckSearchProductReleases:
    @responses.activate
    def test_pass(self):
        responses.get(f"{BASE_URL}/productRelease/{_RELEASE_UUID}", json=_PRODUCT_RELEASE_JSON)
        responses.get(f"{BASE_URL}/productReleases", json=_PAGINATED_RELEASES)
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_search_product_releases(client, ctx)
        assert result.status == CheckStatus.PASS

    def test_skip_no_uuid(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_search_product_releases(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_skip_no_identifiers(self):
        responses.get(f"{BASE_URL}/productRelease/{_RELEASE_UUID}", json=_PRODUCT_RELEASE_NO_IDENTIFIERS_JSON)
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_search_product_releases(client, ctx)
        assert result.status == CheckStatus.SKIP
        assert "no identifiers" in result.message

    @responses.activate
    def test_skip_partial_identifier(self):
        release_json = {
            **_PRODUCT_RELEASE_NO_IDENTIFIERS_JSON,
            "identifiers": [{"idType": "PURL"}],
        }
        responses.get(f"{BASE_URL}/productRelease/{_RELEASE_UUID}", json=release_json)
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_search_product_releases(client, ctx)
        assert result.status == CheckStatus.SKIP
        assert "missing type or value" in result.message

    @responses.activate
    def test_fail_get_release_error(self):
        responses.get(f"{BASE_URL}/productRelease/{_RELEASE_UUID}", status=500)
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_search_product_releases(client, ctx)
        assert result.status == CheckStatus.FAIL
        assert "get_product_release()" in result.message

    @responses.activate
    def test_fail_search_error(self):
        responses.get(f"{BASE_URL}/productRelease/{_RELEASE_UUID}", json=_PRODUCT_RELEASE_JSON)
        responses.get(f"{BASE_URL}/productReleases", status=500)
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_search_product_releases(client, ctx)
        assert result.status == CheckStatus.FAIL
        assert "search_product_releases()" in result.message

    @responses.activate
    def test_fail_no_results(self):
        responses.get(f"{BASE_URL}/productRelease/{_RELEASE_UUID}", json=_PRODUCT_RELEASE_JSON)
        responses.get(f"{BASE_URL}/productReleases", json=_PAGINATED_RELEASES_EMPTY)
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_search_product_releases(client, ctx)
        assert result.status == CheckStatus.FAIL
        assert "no results" in result.message


class TestCheckGetProductRelease:
    @responses.activate
    def test_pass_with_components(self):
        responses.get(f"{BASE_URL}/productRelease/{_RELEASE_UUID}", json=_PRODUCT_RELEASE_JSON)
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_get_product_release(client, ctx)
        assert result.status == CheckStatus.PASS
        assert ctx.component_uuid == _COMPONENT_UUID

    @responses.activate
    def test_pass_without_components(self):
        responses.get(f"{BASE_URL}/productRelease/{_RELEASE_UUID}", json=_PRODUCT_RELEASE_NO_COMPONENTS_JSON)
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_get_product_release(client, ctx)
        assert result.status == CheckStatus.PASS
        assert ctx.component_uuid is None

    def test_skip_no_uuid(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_get_product_release(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_fail_on_server_error(self):
        responses.get(f"{BASE_URL}/productRelease/{_RELEASE_UUID}", status=500)
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_get_product_release(client, ctx)
        assert result.status == CheckStatus.FAIL

    @responses.activate
    def test_does_not_overwrite_existing_component_uuid(self):
        responses.get(f"{BASE_URL}/productRelease/{_RELEASE_UUID}", json=_PRODUCT_RELEASE_JSON)
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID, component_uuid="existing-uuid")
        check_get_product_release(client, ctx)
        assert ctx.component_uuid == "existing-uuid"


class TestCheckProductReleaseCollectionLatest:
    @responses.activate
    def test_pass_with_artifacts(self):
        responses.get(
            f"{BASE_URL}/productRelease/{_RELEASE_UUID}/collection/latest",
            json=_COLLECTION_JSON,
        )
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_product_release_collection_latest(client, ctx)
        assert result.status == CheckStatus.PASS
        assert ctx.artifact_uuid == _ARTIFACT_UUID

    @responses.activate
    def test_pass_without_artifacts(self):
        responses.get(
            f"{BASE_URL}/productRelease/{_RELEASE_UUID}/collection/latest",
            json=_COLLECTION_NO_ARTIFACTS_JSON,
        )
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_product_release_collection_latest(client, ctx)
        assert result.status == CheckStatus.PASS
        assert ctx.artifact_uuid is None

    def test_skip_no_uuid(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_product_release_collection_latest(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_fail_on_server_error(self):
        responses.get(
            f"{BASE_URL}/productRelease/{_RELEASE_UUID}/collection/latest",
            status=500,
        )
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_product_release_collection_latest(client, ctx)
        assert result.status == CheckStatus.FAIL

    @responses.activate
    def test_does_not_overwrite_existing_artifact_uuid(self):
        responses.get(
            f"{BASE_URL}/productRelease/{_RELEASE_UUID}/collection/latest",
            json=_COLLECTION_JSON,
        )
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID, artifact_uuid="existing-uuid")
        check_product_release_collection_latest(client, ctx)
        assert ctx.artifact_uuid == "existing-uuid"

    @responses.activate
    def test_skips_artifact_with_no_uuid(self):
        collection_json = {
            "version": 1,
            "artifacts": [
                {"name": "no-uuid.json", "formats": []},
                {"uuid": _ARTIFACT_UUID, "name": "sbom.json", "formats": []},
            ],
        }
        responses.get(
            f"{BASE_URL}/productRelease/{_RELEASE_UUID}/collection/latest",
            json=collection_json,
        )
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        check_product_release_collection_latest(client, ctx)
        assert ctx.artifact_uuid == _ARTIFACT_UUID

    @responses.activate
    def test_all_artifacts_without_uuid(self):
        collection_json = {
            "version": 1,
            "artifacts": [
                {"name": "no-uuid-1.json", "formats": []},
                {"name": "no-uuid-2.json", "formats": []},
            ],
        }
        responses.get(
            f"{BASE_URL}/productRelease/{_RELEASE_UUID}/collection/latest",
            json=collection_json,
        )
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_product_release_collection_latest(client, ctx)
        assert result.status == CheckStatus.PASS
        assert ctx.artifact_uuid is None


class TestCheckProductReleaseCollections:
    @responses.activate
    def test_pass(self):
        responses.get(
            f"{BASE_URL}/productRelease/{_RELEASE_UUID}/collections",
            json=[_COLLECTION_JSON],
        )
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_product_release_collections(client, ctx)
        assert result.status == CheckStatus.PASS

    def test_skip_no_uuid(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_product_release_collections(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_fail_on_server_error(self):
        responses.get(
            f"{BASE_URL}/productRelease/{_RELEASE_UUID}/collections",
            status=500,
        )
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_product_release_collections(client, ctx)
        assert result.status == CheckStatus.FAIL


class TestCheckProductReleaseCollectionVersion:
    @responses.activate
    def test_pass(self):
        responses.get(
            f"{BASE_URL}/productRelease/{_RELEASE_UUID}/collection/1",
            json=_COLLECTION_JSON,
        )
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_product_release_collection_version(client, ctx)
        assert result.status == CheckStatus.PASS

    def test_skip_no_uuid(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_product_release_collection_version(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_skip_on_404(self):
        responses.get(
            f"{BASE_URL}/productRelease/{_RELEASE_UUID}/collection/1",
            json={"error": "OBJECT_UNKNOWN"},
            status=404,
        )
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_product_release_collection_version(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_fail_on_server_error(self):
        responses.get(
            f"{BASE_URL}/productRelease/{_RELEASE_UUID}/collection/1",
            status=500,
        )
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_product_release_collection_version(client, ctx)
        assert result.status == CheckStatus.FAIL


class TestCheckGetComponent:
    @responses.activate
    def test_pass(self):
        responses.get(f"{BASE_URL}/component/{_COMPONENT_UUID}", json=_COMPONENT_JSON)
        client = _make_client()
        ctx = CheckContext(component_uuid=_COMPONENT_UUID)
        result = check_get_component(client, ctx)
        assert result.status == CheckStatus.PASS
        assert "Test Component" in result.message

    def test_skip_no_uuid(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_get_component(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_fail_on_server_error(self):
        responses.get(f"{BASE_URL}/component/{_COMPONENT_UUID}", status=500)
        client = _make_client()
        ctx = CheckContext(component_uuid=_COMPONENT_UUID)
        result = check_get_component(client, ctx)
        assert result.status == CheckStatus.FAIL


class TestCheckComponentReleases:
    @responses.activate
    def test_pass(self):
        responses.get(
            f"{BASE_URL}/component/{_COMPONENT_UUID}/releases",
            json=[_RELEASE_JSON],
        )
        client = _make_client()
        ctx = CheckContext(component_uuid=_COMPONENT_UUID)
        result = check_component_releases(client, ctx)
        assert result.status == CheckStatus.PASS
        assert ctx.component_release_uuid == _COMPONENT_RELEASE_UUID

    def test_skip_no_uuid(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_component_releases(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_skip_empty(self):
        responses.get(f"{BASE_URL}/component/{_COMPONENT_UUID}/releases", json=[])
        client = _make_client()
        ctx = CheckContext(component_uuid=_COMPONENT_UUID)
        result = check_component_releases(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_fail_on_server_error(self):
        responses.get(f"{BASE_URL}/component/{_COMPONENT_UUID}/releases", status=500)
        client = _make_client()
        ctx = CheckContext(component_uuid=_COMPONENT_UUID)
        result = check_component_releases(client, ctx)
        assert result.status == CheckStatus.FAIL

    @responses.activate
    def test_does_not_overwrite_existing_uuid(self):
        responses.get(
            f"{BASE_URL}/component/{_COMPONENT_UUID}/releases",
            json=[_RELEASE_JSON],
        )
        client = _make_client()
        ctx = CheckContext(component_uuid=_COMPONENT_UUID, component_release_uuid="existing-uuid")
        check_component_releases(client, ctx)
        assert ctx.component_release_uuid == "existing-uuid"


class TestCheckComponentRelease:
    @responses.activate
    def test_pass_with_artifacts(self):
        responses.get(
            f"{BASE_URL}/componentRelease/{_COMPONENT_RELEASE_UUID}",
            json=_COMPONENT_RELEASE_WITH_COLLECTION_JSON,
        )
        client = _make_client()
        ctx = CheckContext(component_release_uuid=_COMPONENT_RELEASE_UUID)
        result = check_component_release(client, ctx)
        assert result.status == CheckStatus.PASS
        assert ctx.artifact_uuid == _ARTIFACT_UUID

    @responses.activate
    def test_pass_without_artifacts(self):
        responses.get(
            f"{BASE_URL}/componentRelease/{_COMPONENT_RELEASE_UUID}",
            json=_COMPONENT_RELEASE_NO_ARTIFACTS_JSON,
        )
        client = _make_client()
        ctx = CheckContext(component_release_uuid=_COMPONENT_RELEASE_UUID)
        result = check_component_release(client, ctx)
        assert result.status == CheckStatus.PASS
        assert ctx.artifact_uuid is None

    def test_skip_no_uuid(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_component_release(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_fail_on_server_error(self):
        responses.get(f"{BASE_URL}/componentRelease/{_COMPONENT_RELEASE_UUID}", status=500)
        client = _make_client()
        ctx = CheckContext(component_release_uuid=_COMPONENT_RELEASE_UUID)
        result = check_component_release(client, ctx)
        assert result.status == CheckStatus.FAIL

    @responses.activate
    def test_does_not_overwrite_existing_artifact_uuid(self):
        responses.get(
            f"{BASE_URL}/componentRelease/{_COMPONENT_RELEASE_UUID}",
            json=_COMPONENT_RELEASE_WITH_COLLECTION_JSON,
        )
        client = _make_client()
        ctx = CheckContext(component_release_uuid=_COMPONENT_RELEASE_UUID, artifact_uuid="existing-uuid")
        check_component_release(client, ctx)
        assert ctx.artifact_uuid == "existing-uuid"

    @responses.activate
    def test_skips_artifact_with_no_uuid(self):
        json_data = {
            "release": _RELEASE_JSON,
            "latestCollection": {
                "version": 1,
                "artifacts": [
                    {"name": "no-uuid.json", "formats": []},
                    {"uuid": _ARTIFACT_UUID, "name": "sbom.json", "formats": []},
                ],
            },
        }
        responses.get(
            f"{BASE_URL}/componentRelease/{_COMPONENT_RELEASE_UUID}",
            json=json_data,
        )
        client = _make_client()
        ctx = CheckContext(component_release_uuid=_COMPONENT_RELEASE_UUID)
        check_component_release(client, ctx)
        assert ctx.artifact_uuid == _ARTIFACT_UUID

    @responses.activate
    def test_all_artifacts_without_uuid(self):
        json_data = {
            "release": _RELEASE_JSON,
            "latestCollection": {
                "version": 1,
                "artifacts": [
                    {"name": "no-uuid-1.json", "formats": []},
                    {"name": "no-uuid-2.json", "formats": []},
                ],
            },
        }
        responses.get(
            f"{BASE_URL}/componentRelease/{_COMPONENT_RELEASE_UUID}",
            json=json_data,
        )
        client = _make_client()
        ctx = CheckContext(component_release_uuid=_COMPONENT_RELEASE_UUID)
        result = check_component_release(client, ctx)
        assert result.status == CheckStatus.PASS
        assert ctx.artifact_uuid is None


class TestCheckComponentReleaseCollections:
    @responses.activate
    def test_pass(self):
        responses.get(
            f"{BASE_URL}/componentRelease/{_COMPONENT_RELEASE_UUID}/collections",
            json=[_COLLECTION_JSON],
        )
        client = _make_client()
        ctx = CheckContext(component_release_uuid=_COMPONENT_RELEASE_UUID)
        result = check_component_release_collections(client, ctx)
        assert result.status == CheckStatus.PASS

    def test_skip_no_uuid(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_component_release_collections(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_fail_on_server_error(self):
        responses.get(
            f"{BASE_URL}/componentRelease/{_COMPONENT_RELEASE_UUID}/collections",
            status=500,
        )
        client = _make_client()
        ctx = CheckContext(component_release_uuid=_COMPONENT_RELEASE_UUID)
        result = check_component_release_collections(client, ctx)
        assert result.status == CheckStatus.FAIL


class TestCheckGetArtifact:
    @responses.activate
    def test_pass(self):
        responses.get(f"{BASE_URL}/artifact/{_ARTIFACT_UUID}", json=_ARTIFACT_JSON)
        client = _make_client()
        ctx = CheckContext(artifact_uuid=_ARTIFACT_UUID)
        result = check_get_artifact(client, ctx)
        assert result.status == CheckStatus.PASS
        assert "sbom.json" in result.message

    def test_skip_no_uuid(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_get_artifact(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_fail_on_server_error(self):
        responses.get(f"{BASE_URL}/artifact/{_ARTIFACT_UUID}", status=500)
        client = _make_client()
        ctx = CheckContext(artifact_uuid=_ARTIFACT_UUID)
        result = check_get_artifact(client, ctx)
        assert result.status == CheckStatus.FAIL

    @responses.activate
    def test_pass_artifact_without_name(self):
        artifact_no_name = {"uuid": _ARTIFACT_UUID, "formats": []}
        responses.get(f"{BASE_URL}/artifact/{_ARTIFACT_UUID}", json=artifact_no_name)
        client = _make_client()
        ctx = CheckContext(artifact_uuid=_ARTIFACT_UUID)
        result = check_get_artifact(client, ctx)
        assert result.status == CheckStatus.PASS
        assert _ARTIFACT_UUID in result.message


class TestCheckProductCle:
    @responses.activate
    def test_pass(self):
        responses.get(f"{BASE_URL}/product/{_PRODUCT_UUID}/cle", json=_CLE_JSON)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID)
        result = check_product_cle(client, ctx)
        assert result.status == CheckStatus.PASS
        assert "3 event(s)" in result.message

    def test_skip_no_uuid(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_product_cle(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_skip_on_404(self):
        responses.get(
            f"{BASE_URL}/product/{_PRODUCT_UUID}/cle",
            json={"error": "OBJECT_UNKNOWN"},
            status=404,
        )
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID)
        result = check_product_cle(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_fail_on_server_error(self):
        responses.get(f"{BASE_URL}/product/{_PRODUCT_UUID}/cle", status=500)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID)
        result = check_product_cle(client, ctx)
        assert result.status == CheckStatus.FAIL


class TestCheckProductReleaseCle:
    @responses.activate
    def test_pass(self):
        responses.get(f"{BASE_URL}/productRelease/{_RELEASE_UUID}/cle", json=_CLE_JSON)
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_product_release_cle(client, ctx)
        assert result.status == CheckStatus.PASS

    def test_skip_no_uuid(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_product_release_cle(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_skip_on_404(self):
        responses.get(
            f"{BASE_URL}/productRelease/{_RELEASE_UUID}/cle",
            json={"error": "OBJECT_UNKNOWN"},
            status=404,
        )
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_product_release_cle(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_fail_on_server_error(self):
        responses.get(f"{BASE_URL}/productRelease/{_RELEASE_UUID}/cle", status=500)
        client = _make_client()
        ctx = CheckContext(product_release_uuid=_RELEASE_UUID)
        result = check_product_release_cle(client, ctx)
        assert result.status == CheckStatus.FAIL


class TestCheckComponentCle:
    @responses.activate
    def test_pass(self):
        responses.get(f"{BASE_URL}/component/{_COMPONENT_UUID}/cle", json=_CLE_JSON)
        client = _make_client()
        ctx = CheckContext(component_uuid=_COMPONENT_UUID)
        result = check_component_cle(client, ctx)
        assert result.status == CheckStatus.PASS

    def test_skip_no_uuid(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_component_cle(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_skip_on_404(self):
        responses.get(
            f"{BASE_URL}/component/{_COMPONENT_UUID}/cle",
            json={"error": "OBJECT_UNKNOWN"},
            status=404,
        )
        client = _make_client()
        ctx = CheckContext(component_uuid=_COMPONENT_UUID)
        result = check_component_cle(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_fail_on_server_error(self):
        responses.get(f"{BASE_URL}/component/{_COMPONENT_UUID}/cle", status=500)
        client = _make_client()
        ctx = CheckContext(component_uuid=_COMPONENT_UUID)
        result = check_component_cle(client, ctx)
        assert result.status == CheckStatus.FAIL


class TestCheckComponentReleaseCle:
    @responses.activate
    def test_pass(self):
        responses.get(f"{BASE_URL}/componentRelease/{_COMPONENT_RELEASE_UUID}/cle", json=_CLE_JSON)
        client = _make_client()
        ctx = CheckContext(component_release_uuid=_COMPONENT_RELEASE_UUID)
        result = check_component_release_cle(client, ctx)
        assert result.status == CheckStatus.PASS

    def test_skip_no_uuid(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_component_release_cle(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_skip_on_404(self):
        responses.get(
            f"{BASE_URL}/componentRelease/{_COMPONENT_RELEASE_UUID}/cle",
            json={"error": "OBJECT_UNKNOWN"},
            status=404,
        )
        client = _make_client()
        ctx = CheckContext(component_release_uuid=_COMPONENT_RELEASE_UUID)
        result = check_component_release_cle(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_fail_on_server_error(self):
        responses.get(f"{BASE_URL}/componentRelease/{_COMPONENT_RELEASE_UUID}/cle", status=500)
        client = _make_client()
        ctx = CheckContext(component_release_uuid=_COMPONENT_RELEASE_UUID)
        result = check_component_release_cle(client, ctx)
        assert result.status == CheckStatus.FAIL


class TestCheckCleEventOrdering:
    @responses.activate
    def test_pass_ordered(self):
        responses.get(f"{BASE_URL}/product/{_PRODUCT_UUID}/cle", json=_CLE_JSON)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID)
        result = check_cle_event_ordering(client, ctx)
        assert result.status == CheckStatus.PASS
        assert "descending" in result.message

    @responses.activate
    def test_fail_unordered(self):
        responses.get(f"{BASE_URL}/product/{_PRODUCT_UUID}/cle", json=_CLE_UNORDERED_JSON)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID)
        result = check_cle_event_ordering(client, ctx)
        assert result.status == CheckStatus.FAIL
        assert "not ordered" in result.message

    def test_skip_no_data(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_cle_event_ordering(client, ctx)
        assert result.status == CheckStatus.SKIP
        assert "No CLE source" in result.message

    @responses.activate
    def test_skip_few_events(self):
        responses.get(f"{BASE_URL}/product/{_PRODUCT_UUID}/cle", json=_CLE_SINGLE_EVENT_JSON)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID)
        result = check_cle_event_ordering(client, ctx)
        assert result.status == CheckStatus.SKIP
        assert "2+" in result.message

    @responses.activate
    def test_falls_through_few_events_to_next_source(self):
        responses.get(f"{BASE_URL}/product/{_PRODUCT_UUID}/cle", json=_CLE_SINGLE_EVENT_JSON)
        responses.get(f"{BASE_URL}/productRelease/{_RELEASE_UUID}/cle", json=_CLE_JSON)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID, product_release_uuid=_RELEASE_UUID)
        result = check_cle_event_ordering(client, ctx)
        assert result.status == CheckStatus.PASS

    @responses.activate
    def test_falls_through_to_second_source_on_404(self):
        responses.get(
            f"{BASE_URL}/product/{_PRODUCT_UUID}/cle",
            json={"error": "OBJECT_UNKNOWN"},
            status=404,
        )
        responses.get(f"{BASE_URL}/productRelease/{_RELEASE_UUID}/cle", json=_CLE_JSON)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID, product_release_uuid=_RELEASE_UUID)
        result = check_cle_event_ordering(client, ctx)
        assert result.status == CheckStatus.PASS

    @responses.activate
    def test_falls_through_to_component_on_errors(self):
        responses.get(f"{BASE_URL}/product/{_PRODUCT_UUID}/cle", status=500)
        responses.get(f"{BASE_URL}/component/{_COMPONENT_UUID}/cle", json=_CLE_JSON)
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID, component_uuid=_COMPONENT_UUID)
        result = check_cle_event_ordering(client, ctx)
        assert result.status == CheckStatus.PASS

    @responses.activate
    def test_skip_all_sources_404(self):
        responses.get(
            f"{BASE_URL}/product/{_PRODUCT_UUID}/cle",
            json={"error": "OBJECT_UNKNOWN"},
            status=404,
        )
        responses.get(
            f"{BASE_URL}/productRelease/{_RELEASE_UUID}/cle",
            json={"error": "OBJECT_UNKNOWN"},
            status=404,
        )
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID, product_release_uuid=_RELEASE_UUID)
        result = check_cle_event_ordering(client, ctx)
        assert result.status == CheckStatus.SKIP

    @responses.activate
    def test_uses_component_release_source(self):
        responses.get(f"{BASE_URL}/componentRelease/{_COMPONENT_RELEASE_UUID}/cle", json=_CLE_JSON)
        client = _make_client()
        ctx = CheckContext(component_release_uuid=_COMPONENT_RELEASE_UUID)
        result = check_cle_event_ordering(client, ctx)
        assert result.status == CheckStatus.PASS


class TestCheckPaginationFields:
    @responses.activate
    def test_pass(self):
        responses.get(f"{BASE_URL}/products", json=_PAGINATED_PRODUCTS)
        client = _make_client()
        ctx = CheckContext()
        result = check_pagination_fields(client, ctx)
        assert result.status == CheckStatus.PASS

    @responses.activate
    def test_fail_on_server_error(self):
        responses.get(f"{BASE_URL}/products", status=500)
        client = _make_client()
        ctx = CheckContext()
        result = check_pagination_fields(client, ctx)
        assert result.status == CheckStatus.FAIL


class TestCheckCamelCaseFields:
    def test_pass_with_collected_uuids(self):
        client = _make_client()
        ctx = CheckContext(collected_uuids=[_PRODUCT_UUID])
        result = check_camel_case_fields(client, ctx)
        assert result.status == CheckStatus.PASS

    def test_skip_no_collected_data(self):
        client = _make_client()
        ctx = CheckContext()
        result = check_camel_case_fields(client, ctx)
        assert result.status == CheckStatus.SKIP

    def test_skip_with_only_user_seeded_uuid(self):
        client = _make_client()
        ctx = CheckContext(product_uuid=_PRODUCT_UUID)
        result = check_camel_case_fields(client, ctx)
        assert result.status == CheckStatus.SKIP


class TestAllChecksRegistry:
    def test_all_checks_non_empty(self):
        assert len(ALL_CHECKS) > 0

    def test_all_checks_are_callable(self):
        for check in ALL_CHECKS:
            assert callable(check), f"{check} is not callable"

    @responses.activate
    def test_all_checks_have_unique_names(self):
        """Each check function should produce a unique check name."""
        responses.get(f"{BASE_URL}/products", json=_PAGINATED_PRODUCTS)
        responses.get(f"{BASE_URL}/productReleases", json=_PAGINATED_RELEASES)
        responses.get(
            f"{BASE_URL}/product/00000000-0000-0000-0000-000000000000",
            status=404,
            json={"error": "OBJECT_UNKNOWN"},
        )
        responses.get(f"{BASE_URL}/discovery", status=404, json={"error": "OBJECT_UNKNOWN"})
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
