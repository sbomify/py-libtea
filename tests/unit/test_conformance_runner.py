import responses

from libtea.conformance import ConformanceResult, run_conformance

BASE_URL = "https://api.example.com/tea/v1"

_PAGINATED_EMPTY = {
    "timestamp": "2024-01-01T00:00:00Z",
    "pageStartIndex": 0,
    "pageSize": 10,
    "totalResults": 0,
    "results": [],
}


def _setup_empty_server() -> None:
    """Register mock responses for a server with no data."""
    responses.get(f"{BASE_URL}/products", json=_PAGINATED_EMPTY)
    responses.get(f"{BASE_URL}/productReleases", json=_PAGINATED_EMPTY)
    responses.get(
        f"{BASE_URL}/product/00000000-0000-0000-0000-000000000000",
        status=404,
        json={"error": "OBJECT_UNKNOWN"},
    )
    responses.get(f"{BASE_URL}/discovery", status=404, json={"error": "OBJECT_UNKNOWN"})


class TestRunConformance:
    @responses.activate
    def test_run_with_no_seed_data(self):
        """Run with no TEI/UUIDs — discovery skips, list endpoints run."""
        _setup_empty_server()
        result = run_conformance(BASE_URL)
        assert isinstance(result, ConformanceResult)
        assert result.base_url == BASE_URL
        assert len(result.checks) > 0
        assert result.passed + result.failed + result.skipped + result.warned == len(result.checks)

    @responses.activate
    def test_passes_tei_to_context(self):
        """TEI is forwarded to the check context."""
        _setup_empty_server()
        responses.get(f"{BASE_URL}/discovery", json=[], status=200)
        result = run_conformance(BASE_URL, tei="urn:tei:uuid:example.com:abc")
        discovery_check = next(c for c in result.checks if c.name == "discovery")
        assert discovery_check.status.value in ("pass", "fail")

    @responses.activate
    def test_passes_seed_uuids_to_context(self):
        """Explicit UUIDs are forwarded to the check context."""
        product_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        _setup_empty_server()
        responses.get(
            f"{BASE_URL}/product/{product_uuid}",
            json={"uuid": product_uuid, "name": "P", "identifiers": []},
        )
        responses.get(
            f"{BASE_URL}/product/{product_uuid}/releases",
            json=_PAGINATED_EMPTY,
        )
        responses.get(
            f"{BASE_URL}/product/{product_uuid}/cle",
            status=404,
            json={"error": "OBJECT_UNKNOWN"},
        )
        result = run_conformance(BASE_URL, product_uuid=product_uuid)
        get_product_check = next(c for c in result.checks if c.name == "get_product")
        assert get_product_check.status.value == "pass"

    @responses.activate
    def test_returns_all_checks(self):
        """Result includes one entry per check in ALL_CHECKS."""
        from libtea.conformance._checks import ALL_CHECKS

        _setup_empty_server()
        result = run_conformance(BASE_URL)
        assert len(result.checks) == len(ALL_CHECKS)

    @responses.activate
    def test_with_token(self):
        """Token is forwarded to TeaClient."""
        _setup_empty_server()
        result = run_conformance(BASE_URL, token="my-secret-token")
        assert isinstance(result, ConformanceResult)

    @responses.activate
    def test_with_timeout(self):
        """Custom timeout is forwarded to TeaClient."""
        _setup_empty_server()
        result = run_conformance(BASE_URL, timeout=5.0)
        assert isinstance(result, ConformanceResult)
