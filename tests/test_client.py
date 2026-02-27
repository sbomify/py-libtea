from pathlib import Path

import pytest
import requests
import responses

from libtea._http import MtlsConfig, probe_endpoint
from libtea.client import (
    _MAX_PAGE_SIZE,
    TeaClient,
    _validate_collection_version,
    _validate_page_offset,
    _validate_page_size,
    _validate_path_segment,
)
from libtea.exceptions import TeaConnectionError, TeaDiscoveryError, TeaServerError, TeaValidationError
from libtea.models import (
    CLE,
    Artifact,
    Checksum,
    ChecksumAlgorithm,
    Collection,
    Component,
    ComponentReleaseWithCollection,
    PaginatedProductReleaseResponse,
    PaginatedProductResponse,
    Product,
    ProductRelease,
    Release,
)


class TestSearchProducts:
    @responses.activate
    def test_search_products_by_purl(self, client, base_url):
        responses.get(
            f"{base_url}/products",
            json={
                "timestamp": "2024-03-20T15:30:00Z",
                "pageStartIndex": 0,
                "pageSize": 100,
                "totalResults": 1,
                "results": [
                    {
                        "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                        "name": "Test Product",
                        "identifiers": [{"idType": "PURL", "idValue": "pkg:pypi/foo"}],
                    },
                ],
            },
        )
        resp = client.search_products("PURL", "pkg:pypi/foo")
        assert isinstance(resp, PaginatedProductResponse)
        assert resp.total_results == 1
        assert resp.results[0].name == "Test Product"
        request = responses.calls[0].request
        assert "idType=PURL" in str(request.url)
        assert "idValue=pkg" in str(request.url)

    @responses.activate
    def test_search_products_pagination(self, client, base_url):
        responses.get(
            f"{base_url}/products",
            json={
                "timestamp": "2024-03-20T15:30:00Z",
                "pageStartIndex": 10,
                "pageSize": 25,
                "totalResults": 50,
                "results": [],
            },
        )
        resp = client.search_products("CPE", "cpe:2.3:a:vendor:product", page_offset=10, page_size=25)
        request = responses.calls[0].request
        assert "pageOffset=10" in str(request.url)
        assert "pageSize=25" in str(request.url)
        assert resp.page_start_index == 10

    @responses.activate
    def test_search_products_empty(self, client, base_url):
        responses.get(
            f"{base_url}/products",
            json={
                "timestamp": "2024-03-20T15:30:00Z",
                "pageStartIndex": 0,
                "pageSize": 100,
                "totalResults": 0,
                "results": [],
            },
        )
        resp = client.search_products("PURL", "pkg:pypi/nonexistent")
        assert resp.total_results == 0
        assert resp.results == []


class TestSearchProductReleases:
    @responses.activate
    def test_search_product_releases_by_purl(self, client, base_url):
        responses.get(
            f"{base_url}/productReleases",
            json={
                "timestamp": "2024-03-20T15:30:00Z",
                "pageStartIndex": 0,
                "pageSize": 100,
                "totalResults": 1,
                "results": [
                    {
                        "uuid": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
                        "version": "1.0.0",
                        "createdDate": "2024-01-01T00:00:00Z",
                        "components": [{"uuid": "c3d4e5f6-a7b8-9012-cdef-123456789012"}],
                    }
                ],
            },
        )
        resp = client.search_product_releases("PURL", "pkg:pypi/foo@1.0.0")
        assert isinstance(resp, PaginatedProductReleaseResponse)
        assert resp.total_results == 1
        assert resp.results[0].version == "1.0.0"
        request = responses.calls[0].request
        assert "idType=PURL" in str(request.url)


class TestProduct:
    @responses.activate
    def test_get_product(self, client, base_url):
        responses.get(
            f"{base_url}/product/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            json={
                "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "name": "Test Product",
                "identifiers": [{"idType": "PURL", "idValue": "pkg:npm/test"}],
            },
        )
        product = client.get_product("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        assert isinstance(product, Product)
        assert product.name == "Test Product"

    @responses.activate
    def test_get_product_releases(self, client, base_url):
        responses.get(
            f"{base_url}/product/a1b2c3d4-e5f6-7890-abcd-ef1234567890/releases",
            json={
                "timestamp": "2024-03-20T15:30:00Z",
                "pageStartIndex": 0,
                "pageSize": 100,
                "totalResults": 1,
                "results": [
                    {
                        "uuid": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
                        "version": "1.0.0",
                        "createdDate": "2024-01-01T00:00:00Z",
                        "components": [{"uuid": "c3d4e5f6-a7b8-9012-cdef-123456789012"}],
                    }
                ],
            },
        )
        resp = client.get_product_releases("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        assert isinstance(resp, PaginatedProductReleaseResponse)
        assert resp.total_results == 1


class TestProductRelease:
    @responses.activate
    def test_get_product_release(self, client, base_url):
        responses.get(
            f"{base_url}/productRelease/b2c3d4e5-f6a7-8901-bcde-f12345678901",
            json={
                "uuid": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
                "version": "1.0.0",
                "createdDate": "2024-01-01T00:00:00Z",
                "components": [{"uuid": "c3d4e5f6-a7b8-9012-cdef-123456789012"}],
            },
        )
        release = client.get_product_release("b2c3d4e5-f6a7-8901-bcde-f12345678901")
        assert isinstance(release, ProductRelease)
        assert release.version == "1.0.0"

    @responses.activate
    def test_get_product_release_collection_latest(self, client, base_url):
        responses.get(
            f"{base_url}/productRelease/b2c3d4e5-f6a7-8901-bcde-f12345678901/collection/latest",
            json={
                "uuid": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
                "version": 1,
                "artifacts": [],
            },
        )
        collection = client.get_product_release_collection_latest("b2c3d4e5-f6a7-8901-bcde-f12345678901")
        assert isinstance(collection, Collection)


class TestComponent:
    @responses.activate
    def test_get_component(self, client, base_url):
        responses.get(
            f"{base_url}/component/c3d4e5f6-a7b8-9012-cdef-123456789012",
            json={
                "uuid": "c3d4e5f6-a7b8-9012-cdef-123456789012",
                "name": "Test Component",
                "identifiers": [],
            },
        )
        component = client.get_component("c3d4e5f6-a7b8-9012-cdef-123456789012")
        assert isinstance(component, Component)
        assert component.name == "Test Component"

    @responses.activate
    def test_get_component_releases(self, client, base_url):
        responses.get(
            f"{base_url}/component/c3d4e5f6-a7b8-9012-cdef-123456789012/releases",
            json=[
                {
                    "uuid": "d4e5f6a7-b8c9-0123-defa-234567890123",
                    "version": "1.0.0",
                    "createdDate": "2024-01-01T00:00:00Z",
                },
            ],
        )
        releases = client.get_component_releases("c3d4e5f6-a7b8-9012-cdef-123456789012")
        assert len(releases) == 1
        assert isinstance(releases[0], Release)


class TestComponentRelease:
    @responses.activate
    def test_get_component_release(self, client, base_url):
        responses.get(
            f"{base_url}/componentRelease/d4e5f6a7-b8c9-0123-defa-234567890123",
            json={
                "release": {
                    "uuid": "d4e5f6a7-b8c9-0123-defa-234567890123",
                    "version": "1.0.0",
                    "createdDate": "2024-01-01T00:00:00Z",
                },
                "latestCollection": {"uuid": "d4e5f6a7-b8c9-0123-defa-234567890123", "version": 1, "artifacts": []},
            },
        )
        result = client.get_component_release("d4e5f6a7-b8c9-0123-defa-234567890123")
        assert isinstance(result, ComponentReleaseWithCollection)
        assert result.release.version == "1.0.0"
        assert result.latest_collection is not None

    @responses.activate
    def test_get_component_release_missing_collection_raises(self, client, base_url):
        """Per TEA spec, latestCollection is required — missing it should raise."""
        responses.get(
            f"{base_url}/componentRelease/d4e5f6a7-b8c9-0123-defa-234567890124",
            json={
                "release": {
                    "uuid": "d4e5f6a7-b8c9-0123-defa-234567890124",
                    "version": "2.0.0",
                    "createdDate": "2024-01-01T00:00:00Z",
                },
            },
        )
        with pytest.raises(TeaValidationError, match="Invalid ComponentReleaseWithCollection"):
            client.get_component_release("d4e5f6a7-b8c9-0123-defa-234567890124")

    @responses.activate
    def test_get_component_release_collection_latest(self, client, base_url):
        responses.get(
            f"{base_url}/componentRelease/d4e5f6a7-b8c9-0123-defa-234567890123/collection/latest",
            json={"uuid": "d4e5f6a7-b8c9-0123-defa-234567890123", "version": 2, "artifacts": []},
        )
        collection = client.get_component_release_collection_latest("d4e5f6a7-b8c9-0123-defa-234567890123")
        assert isinstance(collection, Collection)
        assert collection.version == 2

    @responses.activate
    def test_get_component_release_collections(self, client, base_url):
        responses.get(
            f"{base_url}/componentRelease/d4e5f6a7-b8c9-0123-defa-234567890123/collections",
            json=[
                {"uuid": "d4e5f6a7-b8c9-0123-defa-234567890123", "version": 1, "artifacts": []},
                {"uuid": "d4e5f6a7-b8c9-0123-defa-234567890123", "version": 2, "artifacts": []},
            ],
        )
        collections = client.get_component_release_collections("d4e5f6a7-b8c9-0123-defa-234567890123")
        assert len(collections) == 2

    @responses.activate
    def test_get_component_release_collection_by_version(self, client, base_url):
        responses.get(
            f"{base_url}/componentRelease/d4e5f6a7-b8c9-0123-defa-234567890123/collection/3",
            json={"uuid": "d4e5f6a7-b8c9-0123-defa-234567890123", "version": 3, "artifacts": []},
        )
        collection = client.get_component_release_collection("d4e5f6a7-b8c9-0123-defa-234567890123", 3)
        assert collection.version == 3


class TestArtifact:
    @responses.activate
    def test_get_artifact(self, client, base_url):
        responses.get(
            f"{base_url}/artifact/e5f6a7b8-c9d0-1234-efab-345678901234",
            json={
                "uuid": "e5f6a7b8-c9d0-1234-efab-345678901234",
                "name": "SBOM",
                "type": "BOM",
                "formats": [
                    {
                        "mediaType": "application/json",
                        "url": "https://example.com/sbom.json",
                        "checksums": [],
                    }
                ],
            },
        )
        artifact = client.get_artifact("e5f6a7b8-c9d0-1234-efab-345678901234")
        assert isinstance(artifact, Artifact)
        assert artifact.name == "SBOM"


class TestDiscovery:
    @responses.activate
    def test_discover(self, client, base_url):
        tei = "urn:tei:uuid:example.com:d4d9f54a-abcf-11ee-ac79-1a52914d44b"
        responses.get(
            f"{base_url}/discovery",
            json=[
                {
                    "productReleaseUuid": "d4d9f54a-abcf-11ee-ac79-1a52914d44b",
                    "servers": [{"rootUrl": "https://api.example.com", "versions": ["1.0.0"]}],
                }
            ],
        )
        results = client.discover(tei)
        assert len(results) == 1
        assert results[0].product_release_uuid == "d4d9f54a-abcf-11ee-ac79-1a52914d44b"
        # Verify TEI is NOT double-encoded (requests auto-encodes params)
        request = responses.calls[0].request
        assert "tei=" in str(request.url)

    @responses.activate
    def test_discover_empty_result(self, client, base_url):
        responses.get(f"{base_url}/discovery", json=[])
        results = client.discover("urn:tei:uuid:example.com:d4d9f54a")
        assert results == []


class TestFromWellKnown:
    @responses.activate
    def test_from_well_known_creates_client(self):
        responses.get(
            "https://example.com/.well-known/tea",
            json={
                "schemaVersion": 1,
                "endpoints": [{"url": "https://api.example.com", "versions": ["0.3.0-beta.2"]}],
            },
        )
        responses.head("https://api.example.com/v0.3.0-beta.2", status=200)
        client = TeaClient.from_well_known("example.com")
        assert client is not None
        client.close()

    @responses.activate
    def test_from_well_known_no_compatible_version_raises(self):
        responses.get(
            "https://example.com/.well-known/tea",
            json={
                "schemaVersion": 1,
                "endpoints": [{"url": "https://api.example.com", "versions": ["99.0.0"]}],
            },
        )
        with pytest.raises(TeaDiscoveryError, match="No compatible endpoint"):
            TeaClient.from_well_known("example.com")

    @responses.activate
    def test_from_well_known_with_scheme_and_port(self):
        responses.get(
            "http://example.com:9080/.well-known/tea",
            json={
                "schemaVersion": 1,
                "endpoints": [{"url": "http://api.example.com", "versions": ["0.3.0-beta.2"]}],
            },
        )
        responses.head("http://api.example.com/v0.3.0-beta.2", status=200)
        import warnings

        from libtea.exceptions import TeaInsecureTransportWarning

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            client = TeaClient.from_well_known("example.com", scheme="http", port=9080)
        assert client is not None
        insecure_warnings = [x for x in w if issubclass(x.category, TeaInsecureTransportWarning)]
        assert len(insecure_warnings) >= 1
        client.close()

    @responses.activate
    def test_from_well_known_passes_token(self, base_url):
        responses.get(
            "https://example.com/.well-known/tea",
            json={
                "schemaVersion": 1,
                "endpoints": [{"url": "https://api.example.com", "versions": ["0.3.0-beta.2"]}],
            },
        )
        responses.head("https://api.example.com/v0.3.0-beta.2", status=200)
        responses.get(
            "https://api.example.com/v0.3.0-beta.2/product/f6a7b8c9-d0e1-2345-fabc-456789012345",
            json={"uuid": "f6a7b8c9-d0e1-2345-fabc-456789012345", "name": "P", "identifiers": []},
        )
        client = TeaClient.from_well_known("example.com", token="secret")
        client.get_product("f6a7b8c9-d0e1-2345-fabc-456789012345")
        assert responses.calls[2].request.headers["authorization"] == "Bearer secret"
        client.close()


class TestProbeEndpoint:
    @responses.activate
    def test_probe_success(self):
        responses.head("https://api.example.com/v1", status=200)
        probe_endpoint("https://api.example.com/v1")  # should not raise

    @responses.activate
    def test_probe_404_is_ok(self):
        """404 means the server is alive — probe should succeed."""
        responses.head("https://api.example.com/v1", status=404)
        probe_endpoint("https://api.example.com/v1")  # should not raise

    @responses.activate
    def test_probe_500_raises_server_error(self):
        responses.head("https://api.example.com/v1", status=500)
        with pytest.raises(TeaServerError):
            probe_endpoint("https://api.example.com/v1")

    @responses.activate
    def test_probe_connection_error_raises(self):
        responses.head("https://api.example.com/v1", body=requests.ConnectionError("refused"))
        with pytest.raises(TeaConnectionError):
            probe_endpoint("https://api.example.com/v1")

    @responses.activate
    def test_probe_timeout_raises(self):
        responses.head("https://api.example.com/v1", body=requests.Timeout("timed out"))
        with pytest.raises(TeaConnectionError):
            probe_endpoint("https://api.example.com/v1")

    @responses.activate
    def test_probe_request_exception_raises(self):
        """Generic RequestException (not ConnectionError/Timeout) also raises TeaConnectionError."""
        responses.head("https://api.example.com/v1", body=requests.exceptions.TooManyRedirects("too many"))
        with pytest.raises(TeaConnectionError):
            probe_endpoint("https://api.example.com/v1")


class TestEndpointFailover:
    """Multi-endpoint failover in from_well_known."""

    WELL_KNOWN_DOC = {
        "schemaVersion": 1,
        "endpoints": [
            {"url": "https://primary.example.com", "versions": ["0.3.0-beta.2"], "priority": 1.0},
            {"url": "https://fallback.example.com", "versions": ["0.3.0-beta.2"], "priority": 0.5},
        ],
    }

    @responses.activate
    def test_failover_to_second_on_connection_error(self):
        responses.get("https://example.com/.well-known/tea", json=self.WELL_KNOWN_DOC)
        responses.head(
            "https://primary.example.com/v0.3.0-beta.2",
            body=requests.ConnectionError("refused"),
        )
        responses.head("https://fallback.example.com/v0.3.0-beta.2", status=200)

        client = TeaClient.from_well_known("example.com")
        assert client is not None
        client.close()

    @responses.activate
    def test_failover_to_second_on_500(self):
        responses.get("https://example.com/.well-known/tea", json=self.WELL_KNOWN_DOC)
        responses.head("https://primary.example.com/v0.3.0-beta.2", status=500)
        responses.head("https://fallback.example.com/v0.3.0-beta.2", status=200)

        client = TeaClient.from_well_known("example.com")
        assert client is not None
        client.close()

    @responses.activate
    def test_all_endpoints_fail_raises_last_error(self):
        responses.get("https://example.com/.well-known/tea", json=self.WELL_KNOWN_DOC)
        responses.head(
            "https://primary.example.com/v0.3.0-beta.2",
            body=requests.ConnectionError("refused"),
        )
        responses.head(
            "https://fallback.example.com/v0.3.0-beta.2",
            body=requests.ConnectionError("also refused"),
        )

        with pytest.raises(TeaConnectionError):
            TeaClient.from_well_known("example.com")

    @responses.activate
    def test_single_endpoint_success_no_failover(self):
        doc = {
            "schemaVersion": 1,
            "endpoints": [{"url": "https://only.example.com", "versions": ["0.3.0-beta.2"]}],
        }
        responses.get("https://example.com/.well-known/tea", json=doc)
        responses.head("https://only.example.com/v0.3.0-beta.2", status=200)

        client = TeaClient.from_well_known("example.com")
        assert client is not None
        client.close()

    @responses.activate
    def test_failover_uses_correct_base_url(self):
        """After failover, the client should use the fallback endpoint's URL."""
        responses.get("https://example.com/.well-known/tea", json=self.WELL_KNOWN_DOC)
        responses.head("https://primary.example.com/v0.3.0-beta.2", status=503)
        responses.head("https://fallback.example.com/v0.3.0-beta.2", status=200)
        responses.get(
            "https://fallback.example.com/v0.3.0-beta.2/product/f6a7b8c9-d0e1-2345-fabc-456789012345",
            json={"uuid": "f6a7b8c9-d0e1-2345-fabc-456789012345", "name": "P", "identifiers": []},
        )

        client = TeaClient.from_well_known("example.com")
        product = client.get_product("f6a7b8c9-d0e1-2345-fabc-456789012345")
        assert product.name == "P"
        client.close()


class TestPagination:
    @responses.activate
    def test_get_product_releases_pagination_params(self, client, base_url):
        responses.get(
            f"{base_url}/product/a1b2c3d4-e5f6-7890-abcd-ef1234567890/releases",
            json={
                "timestamp": "2024-03-20T15:30:00Z",
                "pageStartIndex": 50,
                "pageSize": 25,
                "totalResults": 200,
                "results": [],
            },
        )
        resp = client.get_product_releases("a1b2c3d4-e5f6-7890-abcd-ef1234567890", page_offset=50, page_size=25)
        request = responses.calls[0].request
        assert "pageOffset=50" in str(request.url)
        assert "pageSize=25" in str(request.url)
        assert resp.page_start_index == 50


class TestProductReleaseCollections:
    @responses.activate
    def test_get_product_release_collections(self, client, base_url):
        responses.get(
            f"{base_url}/productRelease/b2c3d4e5-f6a7-8901-bcde-f12345678901/collections",
            json=[
                {"uuid": "b2c3d4e5-f6a7-8901-bcde-f12345678901", "version": 1, "artifacts": []},
                {"uuid": "b2c3d4e5-f6a7-8901-bcde-f12345678901", "version": 2, "artifacts": []},
            ],
        )
        collections = client.get_product_release_collections("b2c3d4e5-f6a7-8901-bcde-f12345678901")
        assert len(collections) == 2
        assert collections[0].version == 1

    @responses.activate
    def test_get_product_release_collection_by_version(self, client, base_url):
        responses.get(
            f"{base_url}/productRelease/b2c3d4e5-f6a7-8901-bcde-f12345678901/collection/5",
            json={"uuid": "b2c3d4e5-f6a7-8901-bcde-f12345678901", "version": 5, "artifacts": []},
        )
        collection = client.get_product_release_collection("b2c3d4e5-f6a7-8901-bcde-f12345678901", 5)
        assert collection.version == 5


class TestValidationErrors:
    @responses.activate
    def test_validate_raises_tea_validation_error(self, client, base_url):
        # Missing required fields triggers Pydantic ValidationError → TeaValidationError
        responses.get(f"{base_url}/product/f6a7b8c9-d0e1-2345-fabc-456789012345", json={"bad": "data"})
        with pytest.raises(TeaValidationError, match="Invalid Product response"):
            client.get_product("f6a7b8c9-d0e1-2345-fabc-456789012345")

    @responses.activate
    def test_validate_list_raises_tea_validation_error(self, client, base_url):
        # List with invalid items triggers Pydantic ValidationError → TeaValidationError
        responses.get(
            f"{base_url}/component/c3d4e5f6-a7b8-9012-cdef-123456789012/releases",
            json=[{"bad": "data"}],
        )
        with pytest.raises(TeaValidationError, match="Invalid Release response"):
            client.get_component_releases("c3d4e5f6-a7b8-9012-cdef-123456789012")

    @responses.activate
    def test_validate_list_rejects_non_list_response(self, client, base_url):
        responses.get(f"{base_url}/component/c3d4e5f6-a7b8-9012-cdef-123456789012/releases", json={"not": "a list"})
        with pytest.raises(TeaValidationError, match="Expected list"):
            client.get_component_releases("c3d4e5f6-a7b8-9012-cdef-123456789012")


class TestValidatePathSegment:
    def test_accepts_uuid(self):
        assert _validate_path_segment("d4d9f54a-abcf-11ee-ac79-1a52914d44b1") == "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"

    def test_normalizes_uppercase_uuid(self):
        assert _validate_path_segment("D4D9F54A-ABCF-11EE-AC79-1A52914D44B1") == "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"

    def test_normalizes_uuid_without_hyphens(self):
        assert _validate_path_segment("d4d9f54aabcf11eeac791a52914d44b1") == "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"

    @pytest.mark.parametrize(
        "value",
        [
            "../../etc/passwd",
            "abc-123",
            "not-a-uuid",
            "",
            "abc\x00def",
        ],
    )
    def test_rejects_unsafe_values(self, value):
        with pytest.raises(TeaValidationError, match="Invalid uuid"):
            _validate_path_segment(value)

    def test_error_message_includes_guidance(self):
        with pytest.raises(TeaValidationError, match="valid UUID"):
            _validate_path_segment("../traversal")


class TestContextManager:
    @responses.activate
    def test_client_as_context_manager(self, base_url):
        responses.get(
            f"{base_url}/component/a7b8c9d0-e1f2-3456-abcd-567890123456",
            json={"uuid": "a7b8c9d0-e1f2-3456-abcd-567890123456", "name": "C1", "identifiers": []},
        )
        with TeaClient(base_url=base_url) as client:
            component = client.get_component("a7b8c9d0-e1f2-3456-abcd-567890123456")
            assert component.name == "C1"


_CLE_RESPONSE = {
    "events": [
        {
            "id": 1,
            "type": "released",
            "effective": "2024-01-01T00:00:00Z",
            "published": "2024-01-01T00:00:00Z",
            "version": "1.0.0",
        }
    ]
}


class TestCLE:
    @responses.activate
    def test_get_product_cle(self, client, base_url):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(f"{base_url}/product/{uuid}/cle", json=_CLE_RESPONSE)
        cle = client.get_product_cle(uuid)
        assert isinstance(cle, CLE)
        assert len(cle.events) == 1
        assert cle.events[0].type == "released"
        assert cle.events[0].version == "1.0.0"
        assert cle.events[0].id == 1

    @responses.activate
    def test_get_product_release_cle(self, client, base_url):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(f"{base_url}/productRelease/{uuid}/cle", json=_CLE_RESPONSE)
        cle = client.get_product_release_cle(uuid)
        assert isinstance(cle, CLE)
        assert f"/productRelease/{uuid}/cle" in responses.calls[0].request.url

    @responses.activate
    def test_get_component_cle(self, client, base_url):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(f"{base_url}/component/{uuid}/cle", json=_CLE_RESPONSE)
        cle = client.get_component_cle(uuid)
        assert isinstance(cle, CLE)
        assert f"/component/{uuid}/cle" in responses.calls[0].request.url

    @responses.activate
    def test_get_component_release_cle(self, client, base_url):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(f"{base_url}/componentRelease/{uuid}/cle", json=_CLE_RESPONSE)
        cle = client.get_component_release_cle(uuid)
        assert isinstance(cle, CLE)
        assert f"/componentRelease/{uuid}/cle" in responses.calls[0].request.url

    def test_get_product_cle_rejects_unsafe_uuid(self, client):
        with pytest.raises(TeaValidationError, match="Invalid uuid"):
            client.get_product_cle("../../etc/passwd")

    @responses.activate
    def test_get_product_cle_malformed_response_raises(self, client, base_url):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(f"{base_url}/product/{uuid}/cle", json={"bad": "data"})
        with pytest.raises(TeaValidationError, match="Invalid CLE response"):
            client.get_product_cle(uuid)


class TestProbeEndpointMtls:
    """probe_endpoint passes mTLS config to the standalone HEAD request."""

    @responses.activate
    def test_probe_with_mtls_config(self):
        responses.head("https://api.example.com/v1", status=200)
        mtls = MtlsConfig(client_cert=Path("/tmp/cert.pem"), client_key=Path("/tmp/key.pem"))
        probe_endpoint("https://api.example.com/v1", mtls=mtls)  # should not raise

    @responses.activate
    def test_probe_with_mtls_ca_bundle(self):
        responses.head("https://api.example.com/v1", status=200)
        mtls = MtlsConfig(
            client_cert=Path("/tmp/cert.pem"), client_key=Path("/tmp/key.pem"), ca_bundle=Path("/tmp/ca.pem")
        )
        probe_endpoint("https://api.example.com/v1", mtls=mtls)  # should not raise

    @responses.activate
    def test_from_well_known_passes_mtls_to_probe(self):
        """from_well_known must propagate mTLS config to probe_endpoint."""
        responses.get(
            "https://example.com/.well-known/tea",
            json={
                "schemaVersion": 1,
                "endpoints": [{"url": "https://api.example.com", "versions": ["0.3.0-beta.2"]}],
            },
        )
        responses.head("https://api.example.com/v0.3.0-beta.2", status=200)
        mtls = MtlsConfig(client_cert=Path("/tmp/cert.pem"), client_key=Path("/tmp/key.pem"))
        client = TeaClient.from_well_known("example.com", mtls=mtls)
        assert client is not None
        client.close()


class TestPageSizeValidation:
    """page_size parameter is validated in search/paginated methods."""

    def test_validate_page_size_rejects_zero(self):
        with pytest.raises(TeaValidationError, match="page_size must be between 1"):
            _validate_page_size(0)

    def test_validate_page_size_rejects_negative(self):
        with pytest.raises(TeaValidationError, match="page_size must be between 1"):
            _validate_page_size(-1)

    def test_validate_page_size_rejects_too_large(self):
        with pytest.raises(TeaValidationError, match="page_size must be between 1"):
            _validate_page_size(_MAX_PAGE_SIZE + 1)

    def test_validate_page_size_accepts_one(self):
        _validate_page_size(1)  # should not raise

    def test_validate_page_size_accepts_max(self):
        _validate_page_size(_MAX_PAGE_SIZE)  # should not raise

    def test_search_products_rejects_bad_page_size(self, client):
        with pytest.raises(TeaValidationError, match="page_size"):
            client.search_products("PURL", "pkg:pypi/foo", page_size=0)

    def test_get_product_releases_rejects_bad_page_size(self, client):
        with pytest.raises(TeaValidationError, match="page_size"):
            client.get_product_releases("a1b2c3d4-e5f6-7890-abcd-ef1234567890", page_size=-1)

    def test_search_product_releases_rejects_bad_page_size(self, client):
        with pytest.raises(TeaValidationError, match="page_size"):
            client.search_product_releases("PURL", "pkg:pypi/foo", page_size=_MAX_PAGE_SIZE + 1)


class TestPageOffsetValidation:
    """page_offset parameter is validated in search/paginated methods."""

    def test_validate_page_offset_rejects_negative(self):
        with pytest.raises(TeaValidationError, match="page_offset must be >= 0"):
            _validate_page_offset(-1)

    def test_validate_page_offset_accepts_zero(self):
        _validate_page_offset(0)  # should not raise

    def test_validate_page_offset_accepts_positive(self):
        _validate_page_offset(100)  # should not raise

    def test_search_products_rejects_negative_offset(self, client):
        with pytest.raises(TeaValidationError, match="page_offset"):
            client.search_products("PURL", "pkg:pypi/foo", page_offset=-1)

    def test_get_product_releases_rejects_negative_offset(self, client):
        with pytest.raises(TeaValidationError, match="page_offset"):
            client.get_product_releases("a1b2c3d4-e5f6-7890-abcd-ef1234567890", page_offset=-1)

    def test_search_product_releases_rejects_negative_offset(self, client):
        with pytest.raises(TeaValidationError, match="page_offset"):
            client.search_product_releases("PURL", "pkg:pypi/foo", page_offset=-1)


class TestCollectionVersionValidation:
    """Collection version parameter is validated before making API calls."""

    def test_validate_collection_version_rejects_zero(self):
        with pytest.raises(TeaValidationError, match="Collection version must be >= 1"):
            _validate_collection_version(0)

    def test_validate_collection_version_rejects_negative(self):
        with pytest.raises(TeaValidationError, match="Collection version must be >= 1"):
            _validate_collection_version(-1)

    def test_validate_collection_version_accepts_one(self):
        _validate_collection_version(1)  # should not raise

    def test_get_product_release_collection_rejects_zero(self, client):
        with pytest.raises(TeaValidationError, match="Collection version"):
            client.get_product_release_collection("b2c3d4e5-f6a7-8901-bcde-f12345678901", 0)

    def test_get_component_release_collection_rejects_zero(self, client):
        with pytest.raises(TeaValidationError, match="Collection version"):
            client.get_component_release_collection("d4e5f6a7-b8c9-0123-defa-234567890123", 0)


class TestWeakChecksumWarning:
    """P2-5: Weak hash algorithms emit a warning."""

    @responses.activate
    def test_md5_checksum_warns(self, client, tmp_path):
        import hashlib
        import warnings

        content = b"test content"
        responses.get("https://artifacts.example.com/sbom.json", body=content)
        md5 = hashlib.md5(content).hexdigest()
        checksums = [Checksum(algorithm_type=ChecksumAlgorithm.MD5, algorithm_value=md5)]
        dest = tmp_path / "sbom.json"
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            client.download_artifact("https://artifacts.example.com/sbom.json", dest, verify_checksums=checksums)
        weak_warnings = [x for x in w if "weak hash" in str(x.message).lower()]
        assert len(weak_warnings) == 1

    @responses.activate
    def test_sha256_no_warning(self, client, tmp_path):
        import hashlib
        import warnings

        content = b"test content"
        responses.get("https://artifacts.example.com/sbom.json", body=content)
        sha256 = hashlib.sha256(content).hexdigest()
        checksums = [Checksum(algorithm_type=ChecksumAlgorithm.SHA_256, algorithm_value=sha256)]
        dest = tmp_path / "sbom.json"
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            client.download_artifact("https://artifacts.example.com/sbom.json", dest, verify_checksums=checksums)
        weak_warnings = [x for x in w if "weak hash" in str(x.message).lower()]
        assert len(weak_warnings) == 0
