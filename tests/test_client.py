import pytest
import responses

from libtea.client import TeaClient, _validate_path_segment
from libtea.exceptions import TeaDiscoveryError, TeaValidationError
from libtea.models import (
    CLE,
    Artifact,
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
                        "uuid": "abc-123",
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
                        "uuid": "rel-1",
                        "version": "1.0.0",
                        "createdDate": "2024-01-01T00:00:00Z",
                        "components": [{"uuid": "comp-1"}],
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
            f"{base_url}/product/abc-123",
            json={
                "uuid": "abc-123",
                "name": "Test Product",
                "identifiers": [{"idType": "PURL", "idValue": "pkg:npm/test"}],
            },
        )
        product = client.get_product("abc-123")
        assert isinstance(product, Product)
        assert product.name == "Test Product"

    @responses.activate
    def test_get_product_releases(self, client, base_url):
        responses.get(
            f"{base_url}/product/abc-123/releases",
            json={
                "timestamp": "2024-03-20T15:30:00Z",
                "pageStartIndex": 0,
                "pageSize": 100,
                "totalResults": 1,
                "results": [
                    {
                        "uuid": "rel-1",
                        "version": "1.0.0",
                        "createdDate": "2024-01-01T00:00:00Z",
                        "components": [{"uuid": "comp-1"}],
                    }
                ],
            },
        )
        resp = client.get_product_releases("abc-123")
        assert isinstance(resp, PaginatedProductReleaseResponse)
        assert resp.total_results == 1


class TestProductRelease:
    @responses.activate
    def test_get_product_release(self, client, base_url):
        responses.get(
            f"{base_url}/productRelease/rel-1",
            json={
                "uuid": "rel-1",
                "version": "1.0.0",
                "createdDate": "2024-01-01T00:00:00Z",
                "components": [{"uuid": "comp-1"}],
            },
        )
        release = client.get_product_release("rel-1")
        assert isinstance(release, ProductRelease)
        assert release.version == "1.0.0"

    @responses.activate
    def test_get_product_release_collection_latest(self, client, base_url):
        responses.get(
            f"{base_url}/productRelease/rel-1/collection/latest",
            json={
                "uuid": "rel-1",
                "version": 1,
                "artifacts": [],
            },
        )
        collection = client.get_product_release_collection_latest("rel-1")
        assert isinstance(collection, Collection)


class TestComponent:
    @responses.activate
    def test_get_component(self, client, base_url):
        responses.get(
            f"{base_url}/component/comp-1",
            json={
                "uuid": "comp-1",
                "name": "Test Component",
                "identifiers": [],
            },
        )
        component = client.get_component("comp-1")
        assert isinstance(component, Component)
        assert component.name == "Test Component"

    @responses.activate
    def test_get_component_releases(self, client, base_url):
        responses.get(
            f"{base_url}/component/comp-1/releases",
            json=[
                {"uuid": "cr-1", "version": "1.0.0", "createdDate": "2024-01-01T00:00:00Z"},
            ],
        )
        releases = client.get_component_releases("comp-1")
        assert len(releases) == 1
        assert isinstance(releases[0], Release)


class TestComponentRelease:
    @responses.activate
    def test_get_component_release(self, client, base_url):
        responses.get(
            f"{base_url}/componentRelease/cr-1",
            json={
                "release": {"uuid": "cr-1", "version": "1.0.0", "createdDate": "2024-01-01T00:00:00Z"},
                "latestCollection": {"uuid": "cr-1", "version": 1, "artifacts": []},
            },
        )
        result = client.get_component_release("cr-1")
        assert isinstance(result, ComponentReleaseWithCollection)
        assert result.release.version == "1.0.0"
        assert result.latest_collection is not None

    @responses.activate
    def test_get_component_release_missing_collection_raises(self, client, base_url):
        """Per TEA spec, latestCollection is required — missing it should raise."""
        responses.get(
            f"{base_url}/componentRelease/cr-2",
            json={
                "release": {"uuid": "cr-2", "version": "2.0.0", "createdDate": "2024-01-01T00:00:00Z"},
            },
        )
        with pytest.raises(TeaValidationError, match="Invalid ComponentReleaseWithCollection"):
            client.get_component_release("cr-2")

    @responses.activate
    def test_get_component_release_collection_latest(self, client, base_url):
        responses.get(
            f"{base_url}/componentRelease/cr-1/collection/latest",
            json={"uuid": "cr-1", "version": 2, "artifacts": []},
        )
        collection = client.get_component_release_collection_latest("cr-1")
        assert isinstance(collection, Collection)
        assert collection.version == 2

    @responses.activate
    def test_get_component_release_collections(self, client, base_url):
        responses.get(
            f"{base_url}/componentRelease/cr-1/collections",
            json=[
                {"uuid": "cr-1", "version": 1, "artifacts": []},
                {"uuid": "cr-1", "version": 2, "artifacts": []},
            ],
        )
        collections = client.get_component_release_collections("cr-1")
        assert len(collections) == 2

    @responses.activate
    def test_get_component_release_collection_by_version(self, client, base_url):
        responses.get(
            f"{base_url}/componentRelease/cr-1/collection/3",
            json={"uuid": "cr-1", "version": 3, "artifacts": []},
        )
        collection = client.get_component_release_collection("cr-1", 3)
        assert collection.version == 3


class TestArtifact:
    @responses.activate
    def test_get_artifact(self, client, base_url):
        responses.get(
            f"{base_url}/artifact/art-1",
            json={
                "uuid": "art-1",
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
        artifact = client.get_artifact("art-1")
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
    def test_from_well_known_passes_token(self, base_url):
        responses.get(
            "https://example.com/.well-known/tea",
            json={
                "schemaVersion": 1,
                "endpoints": [{"url": "https://api.example.com", "versions": ["0.3.0-beta.2"]}],
            },
        )
        responses.get(
            "https://api.example.com/v0.3.0-beta.2/product/abc",
            json={"uuid": "abc", "name": "P", "identifiers": []},
        )
        client = TeaClient.from_well_known("example.com", token="secret")
        client.get_product("abc")
        assert responses.calls[1].request.headers["authorization"] == "Bearer secret"
        client.close()


class TestPagination:
    @responses.activate
    def test_get_product_releases_pagination_params(self, client, base_url):
        responses.get(
            f"{base_url}/product/abc-123/releases",
            json={
                "timestamp": "2024-03-20T15:30:00Z",
                "pageStartIndex": 50,
                "pageSize": 25,
                "totalResults": 200,
                "results": [],
            },
        )
        resp = client.get_product_releases("abc-123", page_offset=50, page_size=25)
        request = responses.calls[0].request
        assert "pageOffset=50" in str(request.url)
        assert "pageSize=25" in str(request.url)
        assert resp.page_start_index == 50


class TestProductReleaseCollections:
    @responses.activate
    def test_get_product_release_collections(self, client, base_url):
        responses.get(
            f"{base_url}/productRelease/rel-1/collections",
            json=[
                {"uuid": "rel-1", "version": 1, "artifacts": []},
                {"uuid": "rel-1", "version": 2, "artifacts": []},
            ],
        )
        collections = client.get_product_release_collections("rel-1")
        assert len(collections) == 2
        assert collections[0].version == 1

    @responses.activate
    def test_get_product_release_collection_by_version(self, client, base_url):
        responses.get(
            f"{base_url}/productRelease/rel-1/collection/5",
            json={"uuid": "rel-1", "version": 5, "artifacts": []},
        )
        collection = client.get_product_release_collection("rel-1", 5)
        assert collection.version == 5


class TestValidationErrors:
    @responses.activate
    def test_validate_raises_tea_validation_error(self, client, base_url):
        # Missing required fields triggers Pydantic ValidationError → TeaValidationError
        responses.get(f"{base_url}/product/abc", json={"bad": "data"})
        with pytest.raises(TeaValidationError, match="Invalid Product response"):
            client.get_product("abc")

    @responses.activate
    def test_validate_list_raises_tea_validation_error(self, client, base_url):
        # List with invalid items triggers Pydantic ValidationError → TeaValidationError
        responses.get(
            f"{base_url}/component/comp-1/releases",
            json=[{"bad": "data"}],
        )
        with pytest.raises(TeaValidationError, match="Invalid Release response"):
            client.get_component_releases("comp-1")

    @responses.activate
    def test_validate_list_rejects_non_list_response(self, client, base_url):
        responses.get(f"{base_url}/component/comp-1/releases", json={"not": "a list"})
        with pytest.raises(TeaValidationError, match="Expected list"):
            client.get_component_releases("comp-1")


class TestValidatePathSegment:
    def test_accepts_uuid(self):
        assert _validate_path_segment("d4d9f54a-abcf-11ee-ac79-1a52914d44b1") == "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"

    def test_accepts_alphanumeric(self):
        assert _validate_path_segment("abc123") == "abc123"

    @pytest.mark.parametrize(
        "value",
        [
            "../../etc/passwd",
            "abc/def",
            "abc def",
            "abc?query=1",
            "abc#fragment",
            "abc@host",
            "abc.def",
            "",
            "a" * 129,
            "abc\x00def",
        ],
    )
    def test_rejects_unsafe_values(self, value):
        with pytest.raises(TeaValidationError, match="Invalid uuid"):
            _validate_path_segment(value)

    def test_error_message_includes_guidance(self):
        with pytest.raises(TeaValidationError, match="alphanumeric characters and hyphens"):
            _validate_path_segment("../traversal")


class TestContextManager:
    @responses.activate
    def test_client_as_context_manager(self, base_url):
        responses.get(
            f"{base_url}/component/c1",
            json={"uuid": "c1", "name": "C1", "identifiers": []},
        )
        with TeaClient(base_url=base_url) as client:
            component = client.get_component("c1")
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

    @responses.activate
    def test_get_product_release_cle(self, client, base_url):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(f"{base_url}/productRelease/{uuid}/cle", json=_CLE_RESPONSE)
        cle = client.get_product_release_cle(uuid)
        assert isinstance(cle, CLE)

    @responses.activate
    def test_get_component_cle(self, client, base_url):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(f"{base_url}/component/{uuid}/cle", json=_CLE_RESPONSE)
        cle = client.get_component_cle(uuid)
        assert isinstance(cle, CLE)

    @responses.activate
    def test_get_component_release_cle(self, client, base_url):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(f"{base_url}/componentRelease/{uuid}/cle", json=_CLE_RESPONSE)
        cle = client.get_component_release_cle(uuid)
        assert isinstance(cle, CLE)
