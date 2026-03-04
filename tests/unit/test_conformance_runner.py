import responses

from libtea.conformance import ConformanceResult, run_conformance

BASE_URL = "https://api.example.com/tea/v1"


class TestRunConformance:
    @responses.activate
    def test_run_with_no_seed_data(self):
        """Run with no TEI/UUIDs — discovery skips, list endpoints run."""
        paginated_empty = {
            "timestamp": "2024-01-01T00:00:00Z",
            "pageStartIndex": 0,
            "pageSize": 10,
            "totalResults": 0,
            "results": [],
        }
        responses.get(f"{BASE_URL}/products", json=paginated_empty)
        responses.get(f"{BASE_URL}/productReleases", json=paginated_empty)
        responses.get(
            f"{BASE_URL}/product/00000000-0000-0000-0000-000000000000",
            status=404,
            json={"error": "OBJECT_UNKNOWN"},
        )
        responses.get(f"{BASE_URL}/discovery", status=404, json={"error": "OBJECT_UNKNOWN"})

        result = run_conformance(BASE_URL)
        assert isinstance(result, ConformanceResult)
        assert result.base_url == BASE_URL
        assert len(result.checks) > 0
        assert result.passed + result.failed + result.skipped == len(result.checks)
