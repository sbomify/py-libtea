import pytest
import requests
import responses

from libtea.discovery import fetch_well_known, parse_tei, select_endpoint
from libtea.exceptions import TeaDiscoveryError
from libtea.models import TeaEndpoint, TeaWellKnown


class TestParseTei:
    def test_uuid_tei(self):
        tei = "urn:tei:uuid:products.example.com:d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        tei_type, domain, identifier = parse_tei(tei)
        assert tei_type == "uuid"
        assert domain == "products.example.com"
        assert identifier == "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"

    def test_purl_tei(self):
        tei = "urn:tei:purl:cyclonedx.org:pkg:pypi/cyclonedx-python-lib@8.4.0"
        tei_type, domain, identifier = parse_tei(tei)
        assert tei_type == "purl"
        assert domain == "cyclonedx.org"
        assert identifier == "pkg:pypi/cyclonedx-python-lib@8.4.0"

    def test_hash_tei(self):
        tei = "urn:tei:hash:cyclonedx.org:SHA256:fd44efd601f651c8865acf0dfeacb0df19a2b50ec69ead0262096fd2f67197b9"
        tei_type, domain, identifier = parse_tei(tei)
        assert tei_type == "hash"
        assert domain == "cyclonedx.org"
        assert identifier == "SHA256:fd44efd601f651c8865acf0dfeacb0df19a2b50ec69ead0262096fd2f67197b9"

    def test_invalid_tei_no_urn_prefix(self):
        with pytest.raises(TeaDiscoveryError, match="Invalid TEI"):
            parse_tei("not-a-tei")

    def test_invalid_tei_wrong_prefix(self):
        with pytest.raises(TeaDiscoveryError, match="Invalid TEI"):
            parse_tei("urn:other:uuid:example.com:123")

    def test_invalid_tei_too_few_parts(self):
        with pytest.raises(TeaDiscoveryError, match="Invalid TEI"):
            parse_tei("urn:tei:uuid")

    def test_invalid_tei_empty_string(self):
        with pytest.raises(TeaDiscoveryError, match="Invalid TEI"):
            parse_tei("")

    def test_tei_with_slash_in_purl_identifier(self):
        tei = "urn:tei:purl:cyclonedx.org:pkg:maven/org.apache/log4j@2.24.3"
        tei_type, domain, identifier = parse_tei(tei)
        assert tei_type == "purl"
        assert domain == "cyclonedx.org"
        assert identifier == "pkg:maven/org.apache/log4j@2.24.3"


class TestFetchWellKnown:
    @responses.activate
    def test_fetch_well_known_success(self):
        responses.get(
            "https://example.com/.well-known/tea",
            json={
                "schemaVersion": 1,
                "endpoints": [{"url": "https://api.example.com", "versions": ["1.0.0"]}],
            },
        )
        wk = fetch_well_known("example.com")
        assert wk.schema_version == 1
        assert len(wk.endpoints) == 1

    @responses.activate
    def test_fetch_well_known_404_raises_discovery_error(self):
        responses.get("https://example.com/.well-known/tea", status=404)
        with pytest.raises(TeaDiscoveryError, match="HTTP 404"):
            fetch_well_known("example.com")

    @responses.activate
    def test_fetch_well_known_connection_error(self):
        responses.get("https://example.com/.well-known/tea", body=requests.ConnectionError("refused"))
        with pytest.raises(TeaDiscoveryError, match="Failed to connect"):
            fetch_well_known("example.com")

    @responses.activate
    def test_fetch_well_known_500_raises_discovery_error(self):
        responses.get("https://example.com/.well-known/tea", status=500)
        with pytest.raises(TeaDiscoveryError):
            fetch_well_known("example.com")

    @responses.activate
    def test_fetch_well_known_non_json_raises_discovery_error(self):
        responses.get("https://example.com/.well-known/tea", body="not json")
        with pytest.raises(TeaDiscoveryError, match="Invalid JSON"):
            fetch_well_known("example.com")

    @responses.activate
    def test_fetch_well_known_invalid_schema_raises_discovery_error(self):
        responses.get("https://example.com/.well-known/tea", json={"bad": "data"})
        with pytest.raises(TeaDiscoveryError, match="Invalid .well-known/tea"):
            fetch_well_known("example.com")


class TestSelectEndpoint:
    def _make_well_known(self, endpoints: list[dict]) -> TeaWellKnown:
        return TeaWellKnown(
            schema_version=1,
            endpoints=[TeaEndpoint(**ep) for ep in endpoints],
        )

    def test_selects_matching_version(self):
        wk = self._make_well_known(
            [
                {"url": "https://api.example.com", "versions": ["1.0.0"]},
            ]
        )
        ep = select_endpoint(wk, "1.0.0")
        assert ep.url == "https://api.example.com"

    def test_selects_highest_priority(self):
        wk = self._make_well_known(
            [
                {"url": "https://low.example.com", "versions": ["1.0.0"], "priority": 0.5},
                {"url": "https://high.example.com", "versions": ["1.0.0"], "priority": 1.0},
            ]
        )
        ep = select_endpoint(wk, "1.0.0")
        assert ep.url == "https://high.example.com"

    def test_no_matching_version_raises(self):
        wk = self._make_well_known(
            [
                {"url": "https://api.example.com", "versions": ["2.0.0"]},
            ]
        )
        with pytest.raises(TeaDiscoveryError, match="No compatible endpoint"):
            select_endpoint(wk, "1.0.0")

    def test_prefers_highest_matching_version(self):
        wk = self._make_well_known(
            [
                {"url": "https://old.example.com", "versions": ["0.1.0"]},
                {"url": "https://new.example.com", "versions": ["0.1.0", "1.0.0"]},
            ]
        )
        ep = select_endpoint(wk, "1.0.0")
        assert ep.url == "https://new.example.com"

    def test_empty_endpoints_raises(self):
        wk = TeaWellKnown(schema_version=1, endpoints=[])
        with pytest.raises(TeaDiscoveryError, match="No compatible endpoint"):
            select_endpoint(wk, "1.0.0")

    def test_none_priority_vs_explicit_priority(self):
        wk = self._make_well_known(
            [
                {"url": "https://none-priority.example.com", "versions": ["1.0.0"]},
                {"url": "https://high-priority.example.com", "versions": ["1.0.0"], "priority": 2.0},
            ]
        )
        ep = select_endpoint(wk, "1.0.0")
        assert ep.url == "https://high-priority.example.com"
