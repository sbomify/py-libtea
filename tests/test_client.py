import pytest
import responses

from libtea.client import TeaClient
from libtea.models import (
    Artifact,
    Collection,
    Component,
    ComponentReleaseWithCollection,
    PaginatedProductReleaseResponse,
    Product,
    ProductRelease,
    Release,
)
from tests.conftest import BASE_URL as BASE


class TestProduct:
    @responses.activate
    def test_get_product(self, client):
        responses.get(
            f"{BASE}/product/abc-123",
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
    def test_get_product_releases(self, client):
        responses.get(
            f"{BASE}/product/abc-123/releases",
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
    def test_get_product_release(self, client):
        responses.get(
            f"{BASE}/productRelease/rel-1",
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
    def test_get_product_release_collection_latest(self, client):
        responses.get(
            f"{BASE}/productRelease/rel-1/collection/latest",
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
    def test_get_component(self, client):
        responses.get(
            f"{BASE}/component/comp-1",
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
    def test_get_component_releases(self, client):
        responses.get(
            f"{BASE}/component/comp-1/releases",
            json=[
                {"uuid": "cr-1", "version": "1.0.0", "createdDate": "2024-01-01T00:00:00Z"},
            ],
        )
        releases = client.get_component_releases("comp-1")
        assert len(releases) == 1
        assert isinstance(releases[0], Release)


class TestComponentRelease:
    @responses.activate
    def test_get_component_release(self, client):
        responses.get(
            f"{BASE}/componentRelease/cr-1",
            json={
                "release": {"uuid": "cr-1", "version": "1.0.0", "createdDate": "2024-01-01T00:00:00Z"},
                "latestCollection": {"uuid": "cr-1", "version": 1, "artifacts": []},
            },
        )
        result = client.get_component_release("cr-1")
        assert isinstance(result, ComponentReleaseWithCollection)
        assert result.release.version == "1.0.0"

    @responses.activate
    def test_get_component_release_collection_latest(self, client):
        responses.get(
            f"{BASE}/componentRelease/cr-1/collection/latest",
            json={"uuid": "cr-1", "version": 2, "artifacts": []},
        )
        collection = client.get_component_release_collection_latest("cr-1")
        assert isinstance(collection, Collection)
        assert collection.version == 2

    @responses.activate
    def test_get_component_release_collections(self, client):
        responses.get(
            f"{BASE}/componentRelease/cr-1/collections",
            json=[
                {"uuid": "cr-1", "version": 1, "artifacts": []},
                {"uuid": "cr-1", "version": 2, "artifacts": []},
            ],
        )
        collections = client.get_component_release_collections("cr-1")
        assert len(collections) == 2

    @responses.activate
    def test_get_component_release_collection_by_version(self, client):
        responses.get(
            f"{BASE}/componentRelease/cr-1/collection/3",
            json={"uuid": "cr-1", "version": 3, "artifacts": []},
        )
        collection = client.get_component_release_collection("cr-1", 3)
        assert collection.version == 3


class TestArtifact:
    @responses.activate
    def test_get_artifact(self, client):
        responses.get(
            f"{BASE}/artifact/art-1",
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
    def test_discover(self, client):
        tei = "urn:tei:uuid:example.com:d4d9f54a-abcf-11ee-ac79-1a52914d44b"
        responses.get(
            f"{BASE}/discovery",
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
    def test_discover_empty_result(self, client):
        responses.get(f"{BASE}/discovery", json=[])
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
        from libtea.exceptions import TeaDiscoveryError

        responses.get(
            "https://example.com/.well-known/tea",
            json={
                "schemaVersion": 1,
                "endpoints": [{"url": "https://api.example.com", "versions": ["99.0.0"]}],
            },
        )
        with pytest.raises(TeaDiscoveryError):
            TeaClient.from_well_known("example.com")

    @responses.activate
    def test_from_well_known_passes_token(self):
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
    def test_get_product_releases_pagination_params(self, client):
        responses.get(
            f"{BASE}/product/abc-123/releases",
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


class TestContextManager:
    @responses.activate
    def test_client_as_context_manager(self):
        responses.get(
            f"{BASE}/component/c1",
            json={"uuid": "c1", "name": "C1", "identifiers": []},
        )
        with TeaClient(base_url=BASE) as client:
            component = client.get_component("c1")
            assert component.name == "C1"
