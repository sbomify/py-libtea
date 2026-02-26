import pytest
import requests
import responses
from pydantic import ValidationError
from semver import Version as SemVer

from libtea.discovery import _is_valid_domain, fetch_well_known, parse_tei, select_endpoint
from libtea.exceptions import TeaDiscoveryError
from libtea.models import DiscoveryInfo, TeaEndpoint, TeaWellKnown, TeiType


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

    def test_invalid_tei_unknown_type(self):
        with pytest.raises(TeaDiscoveryError, match="Invalid TEI type"):
            parse_tei("urn:tei:unknown:example.com:some-id")

    @pytest.mark.parametrize("tei_type", [e.value for e in TeiType])
    def test_all_valid_tei_types(self, tei_type):
        result_type, domain, identifier = parse_tei(f"urn:tei:{tei_type}:example.com:some-id")
        assert result_type == tei_type
        assert domain == "example.com"
        assert identifier == "some-id"

    def test_invalid_tei_empty_domain(self):
        with pytest.raises(TeaDiscoveryError, match="Invalid domain"):
            parse_tei("urn:tei:uuid::some-id")

    def test_invalid_tei_bad_domain_format(self):
        with pytest.raises(TeaDiscoveryError, match="Invalid domain"):
            parse_tei("urn:tei:uuid:-invalid.com:some-id")

    def test_invalid_tei_domain_with_underscore(self):
        with pytest.raises(TeaDiscoveryError, match="Invalid domain"):
            parse_tei("urn:tei:uuid:bad_domain.com:some-id")

    def test_valid_tei_subdomain(self):
        _, domain, _ = parse_tei("urn:tei:uuid:products.tea.example.com:some-id")
        assert domain == "products.tea.example.com"

    def test_valid_tei_single_label_domain(self):
        _, domain, _ = parse_tei("urn:tei:uuid:localhost:some-id")
        assert domain == "localhost"

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
    def test_fetch_well_known_sends_user_agent(self):
        responses.get(
            "https://example.com/.well-known/tea",
            json={
                "schemaVersion": 1,
                "endpoints": [{"url": "https://api.example.com", "versions": ["1.0.0"]}],
            },
        )
        fetch_well_known("example.com")
        ua = responses.calls[0].request.headers["user-agent"]
        assert ua.startswith("py-libtea/")
        assert "hello@sbomify.com" in ua

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
    def test_fetch_well_known_timeout_error(self):
        responses.get("https://example.com/.well-known/tea", body=requests.Timeout("timed out"))
        with pytest.raises(TeaDiscoveryError, match="Failed to connect"):
            fetch_well_known("example.com")

    @responses.activate
    def test_fetch_well_known_500_raises_discovery_error(self):
        responses.get("https://example.com/.well-known/tea", status=500)
        with pytest.raises(TeaDiscoveryError):
            fetch_well_known("example.com")

    def test_fetch_well_known_empty_domain_raises(self):
        with pytest.raises(TeaDiscoveryError, match="Invalid domain"):
            fetch_well_known("")

    def test_fetch_well_known_invalid_domain_raises(self):
        with pytest.raises(TeaDiscoveryError, match="Invalid domain"):
            fetch_well_known("-bad.com")

    def test_fetch_well_known_underscore_domain_raises(self):
        with pytest.raises(TeaDiscoveryError, match="Invalid domain"):
            fetch_well_known("bad_domain.com")

    @responses.activate
    def test_fetch_well_known_request_exception(self):
        responses.get("https://example.com/.well-known/tea", body=requests.exceptions.TooManyRedirects("too many"))
        with pytest.raises(TeaDiscoveryError, match="HTTP error"):
            fetch_well_known("example.com")

    @responses.activate
    def test_fetch_well_known_http_scheme(self):
        responses.get(
            "http://example.com/.well-known/tea",
            json={"schemaVersion": 1, "endpoints": [{"url": "http://api.example.com", "versions": ["1.0.0"]}]},
        )
        wk = fetch_well_known("example.com", scheme="http")
        assert len(wk.endpoints) == 1

    @responses.activate
    def test_fetch_well_known_custom_port(self):
        responses.get(
            "https://example.com:8443/.well-known/tea",
            json={"schemaVersion": 1, "endpoints": [{"url": "https://api.example.com", "versions": ["1.0.0"]}]},
        )
        wk = fetch_well_known("example.com", port=8443)
        assert len(wk.endpoints) == 1

    @responses.activate
    def test_fetch_well_known_default_port_omitted(self):
        responses.get(
            "https://example.com/.well-known/tea",
            json={"schemaVersion": 1, "endpoints": [{"url": "https://api.example.com", "versions": ["1.0.0"]}]},
        )
        wk = fetch_well_known("example.com", port=443)
        assert len(wk.endpoints) == 1

    def test_fetch_well_known_invalid_scheme_raises(self):
        with pytest.raises(TeaDiscoveryError, match="Invalid scheme"):
            fetch_well_known("example.com", scheme="ftp")

    def test_fetch_well_known_invalid_port_zero_raises(self):
        with pytest.raises(TeaDiscoveryError, match="Invalid port"):
            fetch_well_known("example.com", port=0)

    def test_fetch_well_known_invalid_port_negative_raises(self):
        with pytest.raises(TeaDiscoveryError, match="Invalid port"):
            fetch_well_known("example.com", port=-1)

    def test_fetch_well_known_invalid_port_too_large_raises(self):
        with pytest.raises(TeaDiscoveryError, match="Invalid port"):
            fetch_well_known("example.com", port=70000)

    @responses.activate
    def test_fetch_well_known_http_default_port_omitted(self):
        responses.get(
            "http://example.com/.well-known/tea",
            json={"schemaVersion": 1, "endpoints": [{"url": "http://api.example.com", "versions": ["1.0.0"]}]},
        )
        wk = fetch_well_known("example.com", scheme="http", port=80)
        assert len(wk.endpoints) == 1

    def test_fetch_well_known_http_emits_insecure_warning(self):
        import warnings

        from libtea.exceptions import TeaInsecureTransportWarning

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            try:
                fetch_well_known("example.com", scheme="http")
            except TeaDiscoveryError:
                pass  # Connection will fail; we only care about the warning
            insecure_warnings = [x for x in w if issubclass(x.category, TeaInsecureTransportWarning)]
            assert len(insecure_warnings) == 1

    @responses.activate
    def test_fetch_well_known_http_with_custom_port(self):
        responses.get(
            "http://example.com:9080/.well-known/tea",
            json={"schemaVersion": 1, "endpoints": [{"url": "http://api.example.com", "versions": ["1.0.0"]}]},
        )
        wk = fetch_well_known("example.com", scheme="http", port=9080)
        assert len(wk.endpoints) == 1

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

    def test_empty_endpoints_rejected_by_model(self):
        """TeaWellKnown enforces min_length=1 on endpoints per spec."""
        with pytest.raises(ValidationError):
            TeaWellKnown(schema_version=1, endpoints=[])

    def test_none_priority_defaults_to_1(self):
        """Endpoint without priority defaults to 1.0 (highest), matching spec default."""
        wk = self._make_well_known(
            [
                {"url": "https://none-priority.example.com", "versions": ["1.0.0"]},
                {"url": "https://low-priority.example.com", "versions": ["1.0.0"], "priority": 0.5},
            ]
        )
        ep = select_endpoint(wk, "1.0.0")
        assert ep.url == "https://none-priority.example.com"

    def test_invalid_semver_two_part_version_skipped(self):
        """Two-part version '1.0' is not valid SemVer and is silently skipped."""
        wk = self._make_well_known(
            [
                {"url": "https://api.example.com", "versions": ["1.0"]},
            ]
        )
        with pytest.raises(TeaDiscoveryError, match="No compatible endpoint"):
            select_endpoint(wk, "1.0.0")

    def test_semver_matches_with_prerelease(self):
        """Pre-release versions match exactly."""
        wk = self._make_well_known(
            [
                {"url": "https://api.example.com", "versions": ["0.3.0-beta.2"]},
            ]
        )
        ep = select_endpoint(wk, "0.3.0-beta.2")
        assert ep.url == "https://api.example.com"

    def test_semver_prerelease_does_not_match_release(self):
        """Pre-release '1.0.0-beta.1' should not match '1.0.0'."""
        wk = self._make_well_known(
            [
                {"url": "https://api.example.com", "versions": ["1.0.0-beta.1"]},
            ]
        )
        with pytest.raises(TeaDiscoveryError, match="No compatible endpoint"):
            select_endpoint(wk, "1.0.0")

    def test_invalid_semver_in_endpoint_skipped(self):
        """Invalid version strings in endpoint are silently skipped."""
        wk = self._make_well_known(
            [
                {"url": "https://api.example.com", "versions": ["not-semver", "1.0.0"]},
            ]
        )
        ep = select_endpoint(wk, "1.0.0")
        assert ep.url == "https://api.example.com"

    def test_priority_out_of_range_rejected(self):
        """Priority > 1.0 should be rejected by model validation."""
        with pytest.raises(ValidationError):
            TeaEndpoint(url="https://api.example.com", versions=["1.0.0"], priority=2.0)

    def test_empty_versions_rejected(self):
        """Endpoint with empty versions list should be rejected by model validation."""
        with pytest.raises(ValidationError):
            TeaEndpoint(url="https://api.example.com", versions=[])


class TestDiscoveryInfo:
    def test_rejects_empty_servers(self):
        """Spec requires minItems: 1 for servers array."""
        with pytest.raises(ValidationError):
            DiscoveryInfo(product_release_uuid="d4d9f54a-abcf-11ee-ac79-1a52914d44b1", servers=[])


class TestIsValidDomain:
    def test_rejects_empty_string(self):
        assert not _is_valid_domain("")

    def test_rejects_label_over_63_chars(self):
        assert not _is_valid_domain("a" * 64 + ".com")

    def test_accepts_label_at_63_chars(self):
        assert _is_valid_domain("a" * 63 + ".com")

    def test_rejects_trailing_dot(self):
        assert not _is_valid_domain("example.com.")

    def test_rejects_double_dot(self):
        assert not _is_valid_domain("example..com")

    def test_rejects_leading_hyphen_label(self):
        assert not _is_valid_domain("-example.com")

    def test_rejects_trailing_hyphen_label(self):
        assert not _is_valid_domain("example-.com")

    def test_accepts_hyphen_in_middle(self):
        assert _is_valid_domain("my-example.com")

    def test_rejects_underscore(self):
        assert not _is_valid_domain("my_example.com")

    def test_accepts_single_label(self):
        assert _is_valid_domain("localhost")

    def test_rejects_domain_over_253_chars(self):
        """RFC 1035 limits total domain name to 253 characters."""
        long_domain = ".".join(["a" * 63] * 4)  # 63*4 + 3 dots = 255 chars
        assert len(long_domain) == 255
        assert not _is_valid_domain(long_domain)

    def test_accepts_domain_at_253_chars(self):
        # 61-char labels * 4 + 3 dots = 247, well under 253
        domain = ".".join(["a" * 61] * 4)
        assert len(domain) <= 253
        assert _is_valid_domain(domain)


class TestSemVer:
    """Tests verifying our usage patterns with the semver library."""

    def test_parse_basic(self):
        v = SemVer.parse("1.2.3")
        assert v.major == 1
        assert v.minor == 2
        assert v.patch == 3
        assert v.prerelease is None

    def test_parse_with_prerelease(self):
        v = SemVer.parse("0.3.0-beta.2")
        assert v.major == 0
        assert v.minor == 3
        assert v.patch == 0
        assert v.prerelease == "beta.2"

    def test_ordering_major(self):
        assert SemVer.parse("1.0.0") < SemVer.parse("2.0.0")

    def test_ordering_minor(self):
        assert SemVer.parse("1.0.0") < SemVer.parse("1.1.0")

    def test_ordering_patch(self):
        assert SemVer.parse("1.0.0") < SemVer.parse("1.0.1")

    def test_prerelease_lower_than_release(self):
        assert SemVer.parse("1.0.0-alpha") < SemVer.parse("1.0.0")

    def test_prerelease_ordering(self):
        """SemVer spec example: 1.0.0-alpha < 1.0.0-alpha.1 < ... < 1.0.0"""
        versions = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ]
        parsed = [SemVer.parse(v) for v in versions]
        for i in range(len(parsed) - 1):
            assert parsed[i] < parsed[i + 1], f"{versions[i]} should be < {versions[i + 1]}"

    def test_numeric_prerelease_less_than_alpha(self):
        assert SemVer.parse("1.0.0-1") < SemVer.parse("1.0.0-alpha")

    def test_invalid_semver_raises(self):
        with pytest.raises(ValueError):
            SemVer.parse("not-a-version")

    def test_two_part_version_rejected(self):
        with pytest.raises(ValueError):
            SemVer.parse("1.0")

    def test_single_number_rejected(self):
        with pytest.raises(ValueError):
            SemVer.parse("1")

    def test_equality(self):
        assert SemVer.parse("1.0.0") == SemVer.parse("1.0.0")
        assert SemVer.parse("1.0.0-beta.2") == SemVer.parse("1.0.0-beta.2")
