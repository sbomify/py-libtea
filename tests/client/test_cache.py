"""Tests for response caching (TTL) in TeaClient."""

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
import responses

from libtea.client import TeaClient

BASE_URL = "https://api.example.com/tea/v1"

UUID1 = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
UUID2 = "b2c3d4e5-f6a7-8901-bcde-f12345678901"


def _product_json(uuid: str, name: str) -> dict:
    return {"uuid": uuid, "name": name, "identifiers": []}


class TestResponseCache:
    @responses.activate
    def test_cache_hit_avoids_second_request(self):
        """Second call within TTL should return cached result without HTTP."""
        responses.get(
            f"{BASE_URL}/product/{UUID1}",
            json=_product_json(UUID1, "Cached"),
        )
        with TeaClient(BASE_URL, cache_ttl=60.0) as client:
            p1 = client.get_product(UUID1)
            p2 = client.get_product(UUID1)
        assert p1.name == "Cached"
        assert p2.name == "Cached"
        assert len(responses.calls) == 1

    @responses.activate
    def test_cache_disabled_by_default(self):
        """Without cache_ttl, every call hits the network."""
        responses.get(
            f"{BASE_URL}/product/{UUID1}",
            json=_product_json(UUID1, "NoCacheProd"),
        )
        responses.get(
            f"{BASE_URL}/product/{UUID1}",
            json=_product_json(UUID1, "NoCacheProd"),
        )
        with TeaClient(BASE_URL) as client:
            client.get_product(UUID1)
            client.get_product(UUID1)
        assert len(responses.calls) == 2

    @responses.activate
    def test_cache_expires_after_ttl(self):
        """After TTL elapses, the next call should make a fresh HTTP request."""
        call_count = 0
        # Call order: [0] store after 1st HTTP, [1] lookup for 2nd request,
        # [2] store after 2nd HTTP.  200-100=100 > TTL(10) → cache miss.
        real_monotonic_values = [100.0, 200.0, 200.0, 200.0]

        def fake_monotonic() -> float:
            nonlocal call_count
            val = real_monotonic_values[min(call_count, len(real_monotonic_values) - 1)]
            call_count += 1
            return val

        responses.get(
            f"{BASE_URL}/product/{UUID1}",
            json=_product_json(UUID1, "V1"),
        )
        responses.get(
            f"{BASE_URL}/product/{UUID1}",
            json=_product_json(UUID1, "V2"),
        )
        with patch("libtea._http.time.monotonic", side_effect=fake_monotonic):
            with TeaClient(BASE_URL, cache_ttl=10.0) as client:
                p1 = client.get_product(UUID1)
                p2 = client.get_product(UUID1)
        assert p1.name == "V1"
        assert p2.name == "V2"
        assert len(responses.calls) == 2

    @responses.activate
    def test_cache_different_params_are_separate(self):
        """Different query parameters should not share cache entries."""
        responses.get(
            f"{BASE_URL}/products",
            json={
                "timestamp": "2024-01-01T00:00:00Z",
                "pageStartIndex": 0,
                "pageSize": 100,
                "totalResults": 1,
                "results": [_product_json(UUID1, "Foo")],
            },
        )
        responses.get(
            f"{BASE_URL}/products",
            json={
                "timestamp": "2024-01-01T00:00:00Z",
                "pageStartIndex": 0,
                "pageSize": 100,
                "totalResults": 1,
                "results": [_product_json(UUID2, "Bar")],
            },
        )
        with TeaClient(BASE_URL, cache_ttl=60.0) as client:
            r1 = client.search_products("PURL", "pkg:pypi/foo")
            r2 = client.search_products("PURL", "pkg:pypi/bar")
        assert r1.results[0].name == "Foo"
        assert r2.results[0].name == "Bar"
        assert len(responses.calls) == 2

    @responses.activate
    def test_clear_cache(self):
        """clear_cache() should force the next call to hit the network."""
        responses.get(
            f"{BASE_URL}/product/{UUID1}",
            json=_product_json(UUID1, "Before"),
        )
        responses.get(
            f"{BASE_URL}/product/{UUID1}",
            json=_product_json(UUID1, "After"),
        )
        with TeaClient(BASE_URL, cache_ttl=60.0) as client:
            p1 = client.get_product(UUID1)
            client.clear_cache()
            p2 = client.get_product(UUID1)
        assert p1.name == "Before"
        assert p2.name == "After"
        assert len(responses.calls) == 2

    @responses.activate
    def test_clear_cache_noop_without_ttl(self):
        """clear_cache() should not raise when caching is disabled."""
        with TeaClient(BASE_URL) as client:
            client.clear_cache()  # should not raise

    def test_cache_ttl_rejects_zero(self):
        with pytest.raises(ValueError, match="cache_ttl must be > 0"):
            TeaClient(BASE_URL, cache_ttl=0.0)

    def test_cache_ttl_rejects_negative(self):
        with pytest.raises(ValueError, match="cache_ttl must be > 0"):
            TeaClient(BASE_URL, cache_ttl=-5.0)

    @responses.activate
    def test_bulk_fetch_with_cache(self):
        """Bulk fetch with caching enabled should not crash (thread safety)."""
        uuids = [UUID1, UUID2]
        for uid in uuids:
            responses.get(
                f"{BASE_URL}/product/{uid}",
                json=_product_json(uid, f"P-{uid[:8]}"),
            )
        with TeaClient(BASE_URL, cache_ttl=60.0) as client:
            products = client.get_products(uuids)
        assert len(products) == 2

    @responses.activate
    def test_cache_evicts_oldest_when_full(self):
        """Cache should evict the oldest entry when max size is reached."""
        with TeaClient(BASE_URL, cache_ttl=60.0) as client:
            # Shrink max entries for testing
            client._http._cache_max_entries = 2

            # Fill cache with 2 entries
            responses.get(f"{BASE_URL}/product/{UUID1}", json=_product_json(UUID1, "First"))
            responses.get(f"{BASE_URL}/product/{UUID2}", json=_product_json(UUID2, "Second"))
            client.get_product(UUID1)
            client.get_product(UUID2)
            assert len(responses.calls) == 2

            # Add a 3rd entry — should evict UUID1
            uuid3 = "c3d4e5f6-a7b8-9012-cdef-123456789012"
            responses.get(f"{BASE_URL}/product/{uuid3}", json=_product_json(uuid3, "Third"))
            client.get_product(uuid3)
            assert len(client._http._cache) == 2

            # UUID2 and UUID3 should still be cached
            client.get_product(UUID2)
            client.get_product(uuid3)
            assert len(responses.calls) == 3  # no new HTTP calls

            # UUID1 was evicted — should trigger a new HTTP call
            responses.get(f"{BASE_URL}/product/{UUID1}", json=_product_json(UUID1, "First-Refetched"))
            client.get_product(UUID1)
            assert len(responses.calls) == 4

    @responses.activate
    def test_concurrent_cache_reads_are_safe(self):
        """Multiple threads reading the same cached entry should not raise."""
        responses.get(
            f"{BASE_URL}/product/{UUID1}",
            json=_product_json(UUID1, "Concurrent"),
        )
        with TeaClient(BASE_URL, cache_ttl=60.0) as client:
            # Warm the cache with a single request
            client.get_product(UUID1)
            # Hit the cache from 10 threads concurrently
            with ThreadPoolExecutor(max_workers=10) as pool:
                futures = [pool.submit(client.get_product, UUID1) for _ in range(50)]
                results = [f.result() for f in futures]
        assert all(p.name == "Concurrent" for p in results)
        # Only the initial warm-up call should have hit the network
        assert len(responses.calls) == 1
