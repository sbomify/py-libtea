"""Tests for pagination iterators and bulk fetch helpers."""

import pytest
import responses

from libtea.client import TeaClient
from libtea.models import Product, ProductRelease

BASE_URL = "https://api.example.com/tea/v1"


def _product_json(uuid: str, name: str) -> dict:
    return {"uuid": uuid, "name": name, "identifiers": []}


def _release_json(uuid: str, version: str) -> dict:
    return {
        "uuid": uuid,
        "version": version,
        "createdDate": "2024-01-01T00:00:00Z",
        "components": [],
    }


class TestIterProducts:
    @responses.activate
    def test_iter_products_single_page(self):
        responses.get(
            f"{BASE_URL}/products",
            json={
                "timestamp": "2024-03-20T15:30:00Z",
                "pageStartIndex": 0,
                "pageSize": 100,
                "totalResults": 2,
                "results": [
                    _product_json("a1b2c3d4-e5f6-7890-abcd-ef1234567890", "P1"),
                    _product_json("b2c3d4e5-f6a7-8901-bcde-f12345678901", "P2"),
                ],
            },
        )
        with TeaClient(BASE_URL) as client:
            products = list(client.iter_products("PURL", "pkg:pypi/foo"))
        assert len(products) == 2
        assert all(isinstance(p, Product) for p in products)
        assert products[0].name == "P1"
        assert products[1].name == "P2"

    @responses.activate
    def test_iter_products_multi_page(self):
        # Page 1
        responses.get(
            f"{BASE_URL}/products",
            json={
                "timestamp": "2024-03-20T15:30:00Z",
                "pageStartIndex": 0,
                "pageSize": 2,
                "totalResults": 3,
                "results": [
                    _product_json("a1b2c3d4-e5f6-7890-abcd-ef1234567890", "P1"),
                    _product_json("b2c3d4e5-f6a7-8901-bcde-f12345678901", "P2"),
                ],
            },
        )
        # Page 2
        responses.get(
            f"{BASE_URL}/products",
            json={
                "timestamp": "2024-03-20T15:30:00Z",
                "pageStartIndex": 2,
                "pageSize": 2,
                "totalResults": 3,
                "results": [
                    _product_json("c3d4e5f6-a7b8-9012-cdef-123456789012", "P3"),
                ],
            },
        )
        with TeaClient(BASE_URL) as client:
            products = list(client.iter_products("PURL", "pkg:pypi/foo", page_size=2))
        assert len(products) == 3
        assert products[2].name == "P3"

    @responses.activate
    def test_iter_products_empty(self):
        responses.get(
            f"{BASE_URL}/products",
            json={
                "timestamp": "2024-03-20T15:30:00Z",
                "pageStartIndex": 0,
                "pageSize": 100,
                "totalResults": 0,
                "results": [],
            },
        )
        with TeaClient(BASE_URL) as client:
            products = list(client.iter_products("PURL", "pkg:pypi/nonexistent"))
        assert products == []


class TestIterProductReleases:
    @responses.activate
    def test_iter_product_releases_empty(self):
        responses.get(
            f"{BASE_URL}/productReleases",
            json={
                "timestamp": "2024-03-20T15:30:00Z",
                "pageStartIndex": 0,
                "pageSize": 100,
                "totalResults": 0,
                "results": [],
            },
        )
        with TeaClient(BASE_URL) as client:
            releases = list(client.iter_product_releases("PURL", "pkg:pypi/nonexistent"))
        assert releases == []

    @responses.activate
    def test_iter_product_releases_multi_page(self):
        responses.get(
            f"{BASE_URL}/productReleases",
            json={
                "timestamp": "2024-03-20T15:30:00Z",
                "pageStartIndex": 0,
                "pageSize": 1,
                "totalResults": 2,
                "results": [_release_json("a1b2c3d4-e5f6-7890-abcd-ef1234567890", "1.0.0")],
            },
        )
        responses.get(
            f"{BASE_URL}/productReleases",
            json={
                "timestamp": "2024-03-20T15:30:00Z",
                "pageStartIndex": 1,
                "pageSize": 1,
                "totalResults": 2,
                "results": [_release_json("b2c3d4e5-f6a7-8901-bcde-f12345678901", "2.0.0")],
            },
        )
        with TeaClient(BASE_URL) as client:
            releases = list(client.iter_product_releases("PURL", "pkg:pypi/foo", page_size=1))
        assert len(releases) == 2
        assert releases[1].version == "2.0.0"


class TestIterReleasesForProduct:
    @responses.activate
    def test_iter_releases_for_product_empty(self):
        uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        responses.get(
            f"{BASE_URL}/product/{uuid}/releases",
            json={
                "timestamp": "2024-03-20T15:30:00Z",
                "pageStartIndex": 0,
                "pageSize": 100,
                "totalResults": 0,
                "results": [],
            },
        )
        with TeaClient(BASE_URL) as client:
            releases = list(client.iter_releases_for_product(uuid))
        assert releases == []

    @responses.activate
    def test_iter_releases_for_product_multi_page(self):
        uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        responses.get(
            f"{BASE_URL}/product/{uuid}/releases",
            json={
                "timestamp": "2024-03-20T15:30:00Z",
                "pageStartIndex": 0,
                "pageSize": 1,
                "totalResults": 2,
                "results": [_release_json("b2c3d4e5-f6a7-8901-bcde-f12345678901", "1.0.0")],
            },
        )
        responses.get(
            f"{BASE_URL}/product/{uuid}/releases",
            json={
                "timestamp": "2024-03-20T15:30:00Z",
                "pageStartIndex": 1,
                "pageSize": 1,
                "totalResults": 2,
                "results": [_release_json("c3d4e5f6-a7b8-9012-cdef-123456789012", "2.0.0")],
            },
        )
        with TeaClient(BASE_URL) as client:
            releases = list(client.iter_releases_for_product(uuid, page_size=1))
        assert len(releases) == 2
        assert all(isinstance(r, ProductRelease) for r in releases)


class TestPaginateValidation:
    def test_iter_products_rejects_zero_page_size(self):
        from libtea.exceptions import TeaValidationError

        with TeaClient(BASE_URL) as client:
            with pytest.raises(TeaValidationError, match="page_size"):
                list(client.iter_products("PURL", "pkg:pypi/foo", page_size=0))

    def test_iter_products_rejects_negative_page_size(self):
        from libtea.exceptions import TeaValidationError

        with TeaClient(BASE_URL) as client:
            with pytest.raises(TeaValidationError, match="page_size"):
                list(client.iter_products("PURL", "pkg:pypi/foo", page_size=-1))

    def test_iter_products_rejects_oversized_page_size(self):
        from libtea.exceptions import TeaValidationError

        with TeaClient(BASE_URL) as client:
            with pytest.raises(TeaValidationError, match="page_size"):
                list(client.iter_products("PURL", "pkg:pypi/foo", page_size=10001))


class TestBulkFetch:
    @responses.activate
    def test_get_products_parallel(self):
        uuids = [
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "b2c3d4e5-f6a7-8901-bcde-f12345678901",
        ]
        for i, uid in enumerate(uuids):
            responses.get(
                f"{BASE_URL}/product/{uid}",
                json=_product_json(uid, f"Product{i}"),
            )
        with TeaClient(BASE_URL) as client:
            products = client.get_products(uuids)
        assert len(products) == 2
        assert products[0].name == "Product0"
        assert products[1].name == "Product1"

    @responses.activate
    def test_get_product_releases_bulk(self):
        uuids = [
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "b2c3d4e5-f6a7-8901-bcde-f12345678901",
        ]
        for i, uid in enumerate(uuids):
            responses.get(
                f"{BASE_URL}/productRelease/{uid}",
                json=_release_json(uid, f"{i + 1}.0.0"),
            )
        with TeaClient(BASE_URL) as client:
            releases = client.get_product_releases_bulk(uuids)
        assert len(releases) == 2
        assert releases[0].version == "1.0.0"

    @responses.activate
    def test_get_artifacts_bulk(self):
        uuids = [
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "b2c3d4e5-f6a7-8901-bcde-f12345678901",
        ]
        for uid in uuids:
            responses.get(
                f"{BASE_URL}/artifact/{uid}",
                json={"uuid": uid, "name": "SBOM", "type": "BOM", "formats": []},
            )
        with TeaClient(BASE_URL) as client:
            artifacts = client.get_artifacts(uuids)
        assert len(artifacts) == 2

    @responses.activate
    def test_bulk_preserves_order(self):
        uuids = [
            "c3d4e5f6-a7b8-9012-cdef-123456789012",
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "b2c3d4e5-f6a7-8901-bcde-f12345678901",
        ]
        for uid in uuids:
            responses.get(
                f"{BASE_URL}/product/{uid}",
                json=_product_json(uid, f"P-{uid[:8]}"),
            )
        with TeaClient(BASE_URL) as client:
            products = client.get_products(uuids)
        assert [p.uuid for p in products] == uuids

    @responses.activate
    def test_bulk_empty_list(self):
        with TeaClient(BASE_URL) as client:
            products = client.get_products([])
        assert products == []

    @responses.activate
    def test_bulk_error_propagation(self):
        import pytest

        from libtea.exceptions import TeaNotFoundError

        responses.get(
            f"{BASE_URL}/product/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            status=404,
            json={"error": "OBJECT_UNKNOWN"},
        )
        with TeaClient(BASE_URL) as client:
            with pytest.raises(TeaNotFoundError):
                client.get_products(["a1b2c3d4-e5f6-7890-abcd-ef1234567890"])

    def test_max_workers_rejects_zero(self):
        with TeaClient(BASE_URL) as client:
            with pytest.raises(ValueError, match="max_workers must be >= 1"):
                client.get_products(["a1b2c3d4-e5f6-7890-abcd-ef1234567890"], max_workers=0)

    @responses.activate
    def test_bulk_max_workers_one(self):
        """max_workers=1 (serial execution) should work correctly."""
        uuids = [
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "b2c3d4e5-f6a7-8901-bcde-f12345678901",
        ]
        for i, uid in enumerate(uuids):
            responses.get(
                f"{BASE_URL}/product/{uid}",
                json=_product_json(uid, f"Product{i}"),
            )
        with TeaClient(BASE_URL) as client:
            products = client.get_products(uuids, max_workers=1)
        assert len(products) == 2
