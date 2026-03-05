"""Tests for the tea-cli CLI."""

import json
import re

import pytest
import responses

click = pytest.importorskip("click", reason="click not installed (install libtea[cli])")

from click.testing import CliRunner  # noqa: E402

from libtea.cli import app  # noqa: E402

runner = CliRunner()

BASE_URL = "https://api.example.com/tea/v1"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


class TestCliEntryPoint:
    """P0-1: Entry point wrapper handles missing CLI extras gracefully."""

    def test_entry_point_importable(self):
        from libtea._cli_entry import main

        assert callable(main)

    def test_entry_point_registered_in_pyproject(self):
        """Verify pyproject.toml points to the wrapper, not directly to cli:app."""
        from pathlib import Path

        pyproject = Path(__file__).parent.parent.parent / "pyproject.toml"
        content = pyproject.read_text()
        assert 'tea-cli = "libtea._cli_entry:main"' in content


class TestCLINoServer:
    def test_no_base_url_or_domain_errors(self):
        result = runner.invoke(app, ["get-product", "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"])
        assert result.exit_code == 1

    def test_both_base_url_and_domain_errors(self):
        result = runner.invoke(
            app,
            ["get-product", "d4d9f54a-abcf-11ee-ac79-1a52914d44b1", "--base-url", BASE_URL, "--domain", "example.com"],
        )
        assert result.exit_code == 1

    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "tea-cli" in result.output

    def test_help(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "discover" in result.output
        assert "inspect" in result.output


class TestCLICommands:
    @responses.activate
    def test_get_product(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/product/{uuid}",
            json={"uuid": uuid, "name": "Test Product", "identifiers": []},
        )
        result = runner.invoke(app, ["--json", "get-product", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "Test Product"

    @responses.activate
    def test_discover(self):
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        responses.get(
            f"{BASE_URL}/discovery",
            json=[
                {
                    "productReleaseUuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "servers": [{"rootUrl": "https://tea.example.com", "versions": ["1.0.0"]}],
                }
            ],
        )
        result = runner.invoke(app, ["--json", "discover", tei, "--base-url", BASE_URL])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1

    @responses.activate
    def test_get_artifact(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/artifact/{uuid}",
            json={"uuid": uuid, "name": "SBOM", "type": "BOM", "formats": []},
        )
        result = runner.invoke(app, ["--json", "get-artifact", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "SBOM"

    @responses.activate
    def test_search_products(self):
        responses.get(
            f"{BASE_URL}/products",
            json={
                "timestamp": "2024-01-01T00:00:00Z",
                "pageStartIndex": 0,
                "pageSize": 100,
                "totalResults": 0,
                "results": [],
            },
        )
        result = runner.invoke(
            app, ["search-products", "--id-type", "PURL", "--id-value", "pkg:pypi/test", "--base-url", BASE_URL]
        )
        assert result.exit_code == 0

    @responses.activate
    def test_search_releases(self):
        responses.get(
            f"{BASE_URL}/productReleases",
            json={
                "timestamp": "2024-01-01T00:00:00Z",
                "pageStartIndex": 0,
                "pageSize": 100,
                "totalResults": 0,
                "results": [],
            },
        )
        result = runner.invoke(
            app, ["search-releases", "--id-type", "PURL", "--id-value", "pkg:pypi/test", "--base-url", BASE_URL]
        )
        assert result.exit_code == 0

    @responses.activate
    def test_get_release_product(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/productRelease/{uuid}",
            json={
                "uuid": uuid,
                "version": "1.0.0",
                "createdDate": "2024-01-01T00:00:00Z",
                "components": [],
            },
        )
        result = runner.invoke(app, ["get-release", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 0

    @responses.activate
    def test_get_release_component(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/componentRelease/{uuid}",
            json={
                "release": {
                    "uuid": uuid,
                    "version": "1.0.0",
                    "createdDate": "2024-01-01T00:00:00Z",
                },
                "latestCollection": {
                    "uuid": uuid,
                    "version": 1,
                    "artifacts": [],
                },
            },
        )
        result = runner.invoke(app, ["get-release", uuid, "--component", "--base-url", BASE_URL])
        assert result.exit_code == 0

    @responses.activate
    def test_get_collection_latest(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/productRelease/{uuid}/collection/latest",
            json={"uuid": uuid, "version": 1, "artifacts": []},
        )
        result = runner.invoke(app, ["get-collection", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 0

    @responses.activate
    def test_get_collection_by_version(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/productRelease/{uuid}/collection/2",
            json={"uuid": uuid, "version": 2, "artifacts": []},
        )
        result = runner.invoke(app, ["get-collection", uuid, "--version", "2", "--base-url", BASE_URL])
        assert result.exit_code == 0

    @responses.activate
    def test_get_collection_component(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/componentRelease/{uuid}/collection/latest",
            json={"uuid": uuid, "version": 1, "artifacts": []},
        )
        result = runner.invoke(app, ["get-collection", uuid, "--component", "--base-url", BASE_URL])
        assert result.exit_code == 0

    @responses.activate
    def test_get_collection_component_with_version(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/componentRelease/{uuid}/collection/3",
            json={"uuid": uuid, "version": 3, "artifacts": []},
        )
        result = runner.invoke(app, ["get-collection", uuid, "--component", "--version", "3", "--base-url", BASE_URL])
        assert result.exit_code == 0

    @responses.activate
    def test_download(self, tmp_path):
        artifact_url = "https://cdn.example.com/sbom.json"
        responses.get(artifact_url, body=b'{"bomFormat": "CycloneDX"}')
        dest = tmp_path / "sbom.json"
        result = runner.invoke(app, ["download", artifact_url, str(dest), "--base-url", BASE_URL])
        assert result.exit_code == 0
        assert dest.exists()

    @responses.activate
    def test_download_with_checksum(self, tmp_path):
        import hashlib

        content = b'{"bomFormat": "CycloneDX"}'
        artifact_url = "https://cdn.example.com/sbom.json"
        responses.get(artifact_url, body=content)
        sha256 = hashlib.sha256(content).hexdigest()
        dest = tmp_path / "sbom.json"
        result = runner.invoke(
            app,
            ["download", artifact_url, str(dest), "--checksum", f"SHA-256:{sha256}", "--base-url", BASE_URL],
        )
        assert result.exit_code == 0
        assert dest.exists()

    def test_download_invalid_checksum_format(self, tmp_path):
        dest = tmp_path / "sbom.json"
        result = runner.invoke(
            app, ["download", "https://cdn.example.com/f", str(dest), "--checksum", "badhash", "--base-url", BASE_URL]
        )
        assert result.exit_code == 1

    def test_download_unknown_algorithm(self, tmp_path):
        dest = tmp_path / "sbom.json"
        result = runner.invoke(
            app,
            ["download", "https://cdn.example.com/f", str(dest), "--checksum", "BOGUS:abc123", "--base-url", BASE_URL],
        )
        assert result.exit_code == 1

    @responses.activate
    def test_download_checksum_underscore_normalization(self, tmp_path):
        """Underscore form (SHA_256) is normalized to hyphen form (SHA-256)."""
        artifact_url = "https://cdn.example.com/sbom.json"
        content = b'{"bomFormat": "CycloneDX"}'
        import hashlib

        sha256 = hashlib.sha256(content).hexdigest()
        responses.get(artifact_url, body=content)
        dest = tmp_path / "sbom.json"
        result = runner.invoke(
            app,
            ["download", artifact_url, str(dest), "--checksum", f"SHA_256:{sha256}", "--base-url", BASE_URL],
        )
        assert result.exit_code == 0
        assert dest.exists()

    @responses.activate
    def test_download_with_max_download_bytes(self, tmp_path):
        artifact_url = "https://cdn.example.com/sbom.json"
        responses.get(artifact_url, body=b'{"bomFormat": "CycloneDX"}')
        dest = tmp_path / "sbom.json"
        result = runner.invoke(
            app,
            ["download", artifact_url, str(dest), "--max-download-bytes", "10000", "--base-url", BASE_URL],
        )
        assert result.exit_code == 0
        assert dest.exists()

    @responses.activate
    def test_inspect(self):
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        comp_uuid = "c3d4e5f6-a7b8-9012-cdef-123456789012"
        responses.get(
            f"{BASE_URL}/discovery",
            json=[
                {
                    "productReleaseUuid": uuid,
                    "servers": [{"rootUrl": "https://tea.example.com", "versions": ["1.0.0"]}],
                }
            ],
        )
        responses.get(
            f"{BASE_URL}/productRelease/{uuid}",
            json={
                "uuid": uuid,
                "version": "1.0.0",
                "createdDate": "2024-01-01T00:00:00Z",
                "components": [{"uuid": comp_uuid, "release": comp_uuid}],
            },
        )
        responses.get(
            f"{BASE_URL}/componentRelease/{comp_uuid}",
            json={
                "release": {"uuid": comp_uuid, "version": "1.0.0", "createdDate": "2024-01-01T00:00:00Z"},
                "latestCollection": {"uuid": comp_uuid, "version": 1, "artifacts": []},
            },
        )
        result = runner.invoke(app, ["--json", "inspect", tei, "--base-url", BASE_URL])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["productRelease"]["uuid"] == uuid
        assert len(data[0]["components"]) == 1
        assert "discovery" in data[0]
        assert data[0]["discovery"]["productReleaseUuid"] == uuid

    def test_error_output_goes_to_stderr(self):
        result = runner.invoke(app, ["get-product", "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"])
        assert result.exit_code == 1
        assert "Error:" in result.output


class TestCLIErrorPaths:
    @responses.activate
    def test_get_product_server_error(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(f"{BASE_URL}/product/{uuid}", status=500)
        result = runner.invoke(app, ["get-product", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 1

    @responses.activate
    def test_discover_not_found(self):
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        responses.get(f"{BASE_URL}/discovery", status=404, json={"error": "OBJECT_UNKNOWN"})
        result = runner.invoke(app, ["discover", tei, "--base-url", BASE_URL])
        assert result.exit_code == 1


class TestCLIDiscoveryPath:
    """P2-3: Tests for --domain discovery path."""

    @responses.activate
    def test_domain_discovery(self):
        responses.get(
            "https://example.com/.well-known/tea",
            json={
                "schemaVersion": 1,
                "endpoints": [{"url": "https://api.example.com", "versions": ["0.3.0-beta.2"]}],
            },
        )
        responses.head("https://api.example.com/v0.3.0-beta.2", status=200)
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            "https://api.example.com/v0.3.0-beta.2/product/" + uuid,
            json={"uuid": uuid, "name": "Test Product", "identifiers": []},
        )
        result = runner.invoke(app, ["--json", "get-product", uuid, "--domain", "example.com"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "Test Product"

    @responses.activate
    def test_domain_discovery_with_http(self):
        responses.get(
            "http://example.com/.well-known/tea",
            json={
                "schemaVersion": 1,
                "endpoints": [{"url": "http://api.example.com", "versions": ["0.3.0-beta.2"]}],
            },
        )
        responses.head("http://api.example.com/v0.3.0-beta.2", status=200)
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            "http://api.example.com/v0.3.0-beta.2/product/" + uuid,
            json={"uuid": uuid, "name": "Test Product", "identifiers": []},
        )
        result = runner.invoke(app, ["get-product", uuid, "--domain", "example.com", "--use-http"])
        assert result.exit_code == 0


class TestCLIAuthOptions:
    """P1-4: Tests for --auth CLI options."""

    @responses.activate
    def test_basic_auth_option(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/product/{uuid}",
            json={"uuid": uuid, "name": "Test Product", "identifiers": []},
        )
        result = runner.invoke(app, ["get-product", uuid, "--base-url", BASE_URL, "--auth", "user:pass"])
        assert result.exit_code == 0
        assert responses.calls[0].request.headers["Authorization"].startswith("Basic ")

    def test_invalid_auth_format(self):
        result = runner.invoke(
            app, ["get-product", "d4d9f54a-abcf-11ee-ac79-1a52914d44b1", "--base-url", BASE_URL, "--auth", "nopassword"]
        )
        assert result.exit_code == 1

    def test_auth_empty_username_rejected(self):
        result = runner.invoke(
            app, ["get-product", "d4d9f54a-abcf-11ee-ac79-1a52914d44b1", "--base-url", BASE_URL, "--auth", ":password"]
        )
        assert result.exit_code == 1
        assert "username must not be empty" in result.stderr

    def test_token_over_http_shows_clean_error(self):
        result = runner.invoke(
            app,
            [
                "get-product",
                "d4d9f54a-abcf-11ee-ac79-1a52914d44b1",
                "--base-url",
                "http://example.com/v1",
                "--token",
                "t",
            ],
        )
        assert result.exit_code == 1
        assert "plaintext HTTP" in _strip_ansi(result.output)


class TestCLIInspectOptions:
    """P3-7: Tests for inspect --max-components."""

    @responses.activate
    def test_inspect_max_components_truncates(self):
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        comp_uuids = [
            "c0000000-0000-0000-0000-000000000000",
            "c0000000-0000-0000-0000-000000000001",
            "c0000000-0000-0000-0000-000000000002",
            "c0000000-0000-0000-0000-000000000003",
            "c0000000-0000-0000-0000-000000000004",
        ]
        responses.get(
            f"{BASE_URL}/discovery",
            json=[
                {
                    "productReleaseUuid": uuid,
                    "servers": [{"rootUrl": "https://tea.example.com", "versions": ["1.0.0"]}],
                }
            ],
        )
        responses.get(
            f"{BASE_URL}/productRelease/{uuid}",
            json={
                "uuid": uuid,
                "version": "1.0.0",
                "createdDate": "2024-01-01T00:00:00Z",
                "components": [{"uuid": c, "release": c} for c in comp_uuids],
            },
        )
        for c in comp_uuids[:2]:
            responses.get(
                f"{BASE_URL}/componentRelease/{c}",
                json={
                    "release": {"uuid": c, "version": "1.0.0", "createdDate": "2024-01-01T00:00:00Z"},
                    "latestCollection": {"uuid": c, "version": 1, "artifacts": []},
                },
            )
        result = runner.invoke(app, ["--json", "inspect", tei, "--max-components", "2", "--base-url", BASE_URL])
        assert result.exit_code == 0
        output = result.output
        # CliRunner mixes stdout/stderr; extract JSON array from the output
        json_start = output.index("[")
        json_end = output.rindex("]") + 1
        data = json.loads(output[json_start:json_end])
        assert len(data[0]["components"]) == 2
        assert data[0]["truncated"] is True
        assert data[0]["totalComponents"] == 5
        assert "Warning: truncated" in output


class TestCLIMoreErrorPaths:
    """Additional CLI error path coverage."""

    @responses.activate
    def test_search_products_error(self):
        responses.get(f"{BASE_URL}/products", status=500)
        result = runner.invoke(
            app, ["search-products", "--id-type", "PURL", "--id-value", "pkg:pypi/test", "--base-url", BASE_URL]
        )
        assert result.exit_code == 1

    @responses.activate
    def test_search_releases_error(self):
        responses.get(f"{BASE_URL}/productReleases", status=500)
        result = runner.invoke(
            app, ["search-releases", "--id-type", "PURL", "--id-value", "pkg:pypi/test", "--base-url", BASE_URL]
        )
        assert result.exit_code == 1

    @responses.activate
    def test_get_release_error(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(f"{BASE_URL}/productRelease/{uuid}", status=500)
        result = runner.invoke(app, ["get-release", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 1

    @responses.activate
    def test_get_collection_error(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(f"{BASE_URL}/productRelease/{uuid}/collection/latest", status=500)
        result = runner.invoke(app, ["get-collection", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 1

    @responses.activate
    def test_get_artifact_error(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(f"{BASE_URL}/artifact/{uuid}", status=500)
        result = runner.invoke(app, ["get-artifact", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 1

    @responses.activate
    def test_download_server_error(self, tmp_path):
        artifact_url = "https://cdn.example.com/sbom.json"
        responses.get(artifact_url, status=500)
        dest = tmp_path / "sbom.json"
        result = runner.invoke(app, ["download", artifact_url, str(dest), "--base-url", BASE_URL])
        assert result.exit_code == 1

    @responses.activate
    def test_inspect_error(self):
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        responses.get(f"{BASE_URL}/discovery", status=500)
        result = runner.invoke(app, ["inspect", tei, "--base-url", BASE_URL])
        assert result.exit_code == 1


class TestCLIInspectGetComponentFallback:
    """Test the inspect command's get_component fallback for ComponentRef without release."""

    @responses.activate
    def test_inspect_component_ref_without_release_no_releases(self):
        """Unpinned component with no releases — shows basic component data only."""
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        comp_uuid = "c3d4e5f6-a7b8-9012-cdef-123456789099"
        responses.get(
            f"{BASE_URL}/discovery",
            json=[
                {
                    "productReleaseUuid": uuid,
                    "servers": [{"rootUrl": "https://tea.example.com", "versions": ["1.0.0"]}],
                }
            ],
        )
        responses.get(
            f"{BASE_URL}/productRelease/{uuid}",
            json={
                "uuid": uuid,
                "version": "1.0.0",
                "createdDate": "2024-01-01T00:00:00Z",
                "components": [{"uuid": comp_uuid}],
            },
        )
        responses.get(
            f"{BASE_URL}/component/{comp_uuid}",
            json={"uuid": comp_uuid, "name": "Component Without Release", "identifiers": []},
        )
        responses.get(f"{BASE_URL}/component/{comp_uuid}/releases", json=[])
        result = runner.invoke(app, ["--json", "inspect", tei, "--base-url", BASE_URL])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data[0]["components"]) == 1
        assert data[0]["components"][0]["name"] == "Component Without Release"
        assert "resolvedRelease" not in data[0]["components"][0]

    @responses.activate
    def test_inspect_component_ref_resolves_latest_release(self):
        """Unpinned component with releases — resolves latest and includes artifacts."""
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        comp_uuid = "c3d4e5f6-a7b8-9012-cdef-123456789099"
        rel_uuid = "d4e5f6a7-b8c9-0123-defa-456789012345"
        responses.get(
            f"{BASE_URL}/discovery",
            json=[
                {
                    "productReleaseUuid": uuid,
                    "servers": [{"rootUrl": "https://tea.example.com", "versions": ["1.0.0"]}],
                }
            ],
        )
        responses.get(
            f"{BASE_URL}/productRelease/{uuid}",
            json={
                "uuid": uuid,
                "version": "1.0.0",
                "createdDate": "2024-01-01T00:00:00Z",
                "components": [{"uuid": comp_uuid}],
            },
        )
        responses.get(
            f"{BASE_URL}/component/{comp_uuid}",
            json={"uuid": comp_uuid, "name": "App Component", "identifiers": []},
        )
        responses.get(
            f"{BASE_URL}/component/{comp_uuid}/releases",
            json=[{"uuid": rel_uuid, "version": "2.0.0", "createdDate": "2024-06-01T00:00:00Z"}],
        )
        responses.get(
            f"{BASE_URL}/componentRelease/{rel_uuid}",
            json={
                "release": {"uuid": rel_uuid, "version": "2.0.0", "createdDate": "2024-06-01T00:00:00Z"},
                "latestCollection": {
                    "uuid": uuid,
                    "version": 1,
                    "artifacts": [
                        {
                            "uuid": rel_uuid,
                            "name": "SBOM",
                            "type": "BOM",
                            "formats": [{"mediaType": "application/json", "url": "https://cdn/sbom.json"}],
                        }
                    ],
                },
            },
        )
        result = runner.invoke(app, ["--json", "inspect", tei, "--base-url", BASE_URL])
        assert result.exit_code == 0
        data = json.loads(result.output)
        comp = data[0]["components"][0]
        assert comp["name"] == "App Component"
        assert comp["resolvedNote"] == "latest release (not pinned)"
        assert comp["resolvedRelease"]["release"]["version"] == "2.0.0"
        assert comp["resolvedRelease"]["latestCollection"]["artifacts"][0]["name"] == "SBOM"

    @responses.activate
    def test_inspect_component_ref_release_resolution_error(self):
        """Unpinned component where release resolution fails — falls back to basic data."""
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        comp_uuid = "c3d4e5f6-a7b8-9012-cdef-123456789099"
        responses.get(
            f"{BASE_URL}/discovery",
            json=[
                {
                    "productReleaseUuid": uuid,
                    "servers": [{"rootUrl": "https://tea.example.com", "versions": ["1.0.0"]}],
                }
            ],
        )
        responses.get(
            f"{BASE_URL}/productRelease/{uuid}",
            json={
                "uuid": uuid,
                "version": "1.0.0",
                "createdDate": "2024-01-01T00:00:00Z",
                "components": [{"uuid": comp_uuid}],
            },
        )
        responses.get(
            f"{BASE_URL}/component/{comp_uuid}",
            json={"uuid": comp_uuid, "name": "Broken Component", "identifiers": []},
        )
        responses.get(f"{BASE_URL}/component/{comp_uuid}/releases", status=500)
        result = runner.invoke(app, ["--json", "inspect", tei, "--base-url", BASE_URL])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        comp = data[0]["components"][0]
        assert comp["name"] == "Broken Component"
        assert "resolvedRelease" not in comp
        assert "Warning: could not resolve releases for component" in result.stderr


class TestCLITeiAutoDiscovery:
    """Test TEI auto-discovery: when neither --base-url nor --domain is given."""

    @responses.activate
    def test_discover_auto_extracts_domain_from_tei(self):
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        responses.get(
            "https://example.com/.well-known/tea",
            json={
                "schemaVersion": 1,
                "endpoints": [{"url": "https://api.example.com", "versions": ["0.3.0-beta.2"]}],
            },
        )
        responses.head("https://api.example.com/v0.3.0-beta.2", status=200)
        responses.get(
            "https://api.example.com/v0.3.0-beta.2/discovery",
            json=[
                {
                    "productReleaseUuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "servers": [{"rootUrl": "https://tea.example.com", "versions": ["1.0.0"]}],
                }
            ],
        )
        result = runner.invoke(app, ["--json", "discover", tei])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1


class TestCLIEntryPointErrors:
    """Test _cli_entry.py error handling."""

    def test_cli_entry_import_error(self):
        """Test that _cli_entry handles missing CLI extras gracefully."""
        from libtea._cli_entry import main

        assert callable(main)

    def test_cli_entry_main_invokes_app(self):
        """Test that main() calls app() when click is available."""
        from unittest.mock import patch

        with patch("libtea.cli.app") as mock_app:
            from libtea._cli_entry import main

            main()
            mock_app.assert_called_once()


class TestCLIJsonFlag:
    """Tests for the --json flag and default rich output."""

    @responses.activate
    def test_json_flag_produces_valid_json(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/product/{uuid}",
            json={"uuid": uuid, "name": "Test Product", "identifiers": []},
        )
        result = runner.invoke(app, ["--json", "get-product", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["uuid"] == uuid
        assert data["name"] == "Test Product"

    @responses.activate
    def test_default_output_is_rich_not_json(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/product/{uuid}",
            json={"uuid": uuid, "name": "Test Product", "identifiers": []},
        )
        result = runner.invoke(app, ["get-product", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 0
        # Rich output should NOT be valid JSON
        with pytest.raises(json.JSONDecodeError):
            json.loads(result.output)
        # But should contain key data
        assert "Test Product" in result.output
        assert uuid in result.output


class TestCLIDebugFlag:
    """Tests for the --debug / -d flag."""

    @responses.activate
    def test_debug_flag_produces_debug_output(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/product/{uuid}",
            json={"uuid": uuid, "name": "Test Product", "identifiers": []},
        )
        result = runner.invoke(app, ["--debug", "--json", "get-product", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 0
        # Debug output goes to stderr; click CliRunner captures both in output
        combined = result.output + (result.stderr if hasattr(result, "stderr") else "")
        # Should still produce valid JSON on stdout
        assert "Test Product" in combined

    @responses.activate
    def test_debug_short_flag(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/product/{uuid}",
            json={"uuid": uuid, "name": "Test Product", "identifiers": []},
        )
        result = runner.invoke(app, ["-d", "--json", "get-product", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 0

    def test_debug_flag_shown_in_help(self):
        result = runner.invoke(app, ["get-product", "--help"])
        plain = _strip_ansi(result.output)
        assert "--debug" in plain
        assert "-d" in plain


class TestCLIVerboseFlag:
    """Tests for the --verbose / -v flag."""

    @responses.activate
    def test_verbose_flag_configures_logging_correctly(self):
        """--verbose should set libtea to DEBUG and suppress urllib3/requests."""
        import logging

        # Save original logger levels to restore after test
        loggers = {name: logging.getLogger(name) for name in ("libtea", "urllib3", "requests")}
        original_levels = {name: lg.level for name, lg in loggers.items()}

        try:
            uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
            responses.get(
                f"{BASE_URL}/product/{uuid}",
                json={"uuid": uuid, "name": "Test Product", "identifiers": []},
            )
            result = runner.invoke(app, ["-v", "--json", "get-product", uuid, "--base-url", BASE_URL])
            assert result.exit_code == 0
            # Verify JSON output is valid
            data = json.loads(result.output)
            assert data["name"] == "Test Product"
            # Verify logging levels were configured correctly
            assert logging.getLogger("libtea").level == logging.DEBUG
            assert logging.getLogger("urllib3").level == logging.WARNING
            assert logging.getLogger("requests").level == logging.WARNING
        finally:
            for name, level in original_levels.items():
                logging.getLogger(name).setLevel(level)

    @responses.activate
    def test_verbose_short_flag(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/product/{uuid}",
            json={"uuid": uuid, "name": "Test Product", "identifiers": []},
        )
        result = runner.invoke(app, ["--verbose", "--json", "get-product", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 0

    @responses.activate
    def test_debug_overrides_verbose_suppression(self):
        """When both -v and -d are used, -d should enable full firehose (urllib3 at DEBUG, not WARNING)."""
        import logging

        loggers = {name: logging.getLogger(name) for name in ("libtea", "urllib3", "requests")}
        original_levels = {name: lg.level for name, lg in loggers.items()}

        try:
            uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
            responses.get(
                f"{BASE_URL}/product/{uuid}",
                json={"uuid": uuid, "name": "Test Product", "identifiers": []},
            )
            result = runner.invoke(app, ["-v", "-d", "--json", "get-product", uuid, "--base-url", BASE_URL])
            assert result.exit_code == 0
            # -d should override -v's suppression: urllib3/requests at DEBUG, not WARNING
            assert logging.getLogger("urllib3").level == logging.DEBUG
            assert logging.getLogger("requests").level == logging.DEBUG
        finally:
            for name, level in original_levels.items():
                logging.getLogger(name).setLevel(level)

    @responses.activate
    def test_group_level_debug_not_overridden_by_subcommand(self):
        """Group-level -d should not be undone by subcommand shared_options."""
        import logging

        loggers = {name: logging.getLogger(name) for name in ("libtea", "urllib3", "requests")}
        original_levels = {name: lg.level for name, lg in loggers.items()}

        try:
            uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
            responses.get(
                f"{BASE_URL}/product/{uuid}",
                json={"uuid": uuid, "name": "Test Product", "identifiers": []},
            )
            # -d before subcommand (group-level), no flags on subcommand
            result = runner.invoke(app, ["-d", "--json", "get-product", uuid, "--base-url", BASE_URL])
            assert result.exit_code == 0
            assert logging.getLogger("libtea").level == logging.DEBUG
            assert logging.getLogger("urllib3").level == logging.DEBUG
        finally:
            for name, level in original_levels.items():
                logging.getLogger(name).setLevel(level)

    @responses.activate
    def test_group_level_verbose_not_overridden_by_subcommand(self):
        """Group-level -v should not be undone by subcommand shared_options."""
        import logging

        loggers = {name: logging.getLogger(name) for name in ("libtea", "urllib3", "requests")}
        original_levels = {name: lg.level for name, lg in loggers.items()}

        try:
            uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
            responses.get(
                f"{BASE_URL}/product/{uuid}",
                json={"uuid": uuid, "name": "Test Product", "identifiers": []},
            )
            # -v before subcommand (group-level), no flags on subcommand
            result = runner.invoke(app, ["-v", "--json", "get-product", uuid, "--base-url", BASE_URL])
            assert result.exit_code == 0
            assert logging.getLogger("libtea").level == logging.DEBUG
            # -v suppresses urllib3/requests
            assert logging.getLogger("urllib3").level == logging.WARNING
        finally:
            for name, level in original_levels.items():
                logging.getLogger(name).setLevel(level)

    def test_verbose_flag_shown_in_help(self):
        result = runner.invoke(app, ["get-product", "--help"])
        plain = _strip_ansi(result.output)
        assert "--verbose" in plain
        assert "-v" in plain


class TestCLIAllowPrivateIps:
    """Tests for the --allow-private-ips flag position flexibility."""

    @responses.activate
    def test_allow_private_ips_before_subcommand(self):
        """--allow-private-ips works when placed before the subcommand name."""
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/product/{uuid}",
            json={"uuid": uuid, "name": "Test Product", "identifiers": []},
        )
        result = runner.invoke(app, ["--allow-private-ips", "--json", "get-product", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "Test Product"

    @responses.activate
    def test_allow_private_ips_after_subcommand(self):
        """--allow-private-ips works when placed after the subcommand name."""
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/product/{uuid}",
            json={"uuid": uuid, "name": "Test Product", "identifiers": []},
        )
        result = runner.invoke(app, ["--json", "get-product", uuid, "--allow-private-ips", "--base-url", BASE_URL])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "Test Product"


class TestCLIDiscoverQuiet:
    """Tests for the discover --quiet / -q flag."""

    @responses.activate
    def test_quiet_outputs_uuid_only(self):
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        responses.get(
            f"{BASE_URL}/discovery",
            json=[
                {
                    "productReleaseUuid": uuid,
                    "servers": [{"rootUrl": "https://tea.example.com", "versions": ["1.0.0"]}],
                }
            ],
        )
        result = runner.invoke(app, ["discover", "--quiet", tei, "--base-url", BASE_URL])
        assert result.exit_code == 0
        assert result.output.strip() == uuid

    @responses.activate
    def test_quiet_short_flag(self):
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        responses.get(
            f"{BASE_URL}/discovery",
            json=[
                {
                    "productReleaseUuid": uuid,
                    "servers": [{"rootUrl": "https://tea.example.com", "versions": ["1.0.0"]}],
                }
            ],
        )
        result = runner.invoke(app, ["discover", "-q", tei, "--base-url", BASE_URL])
        assert result.exit_code == 0
        assert result.output.strip() == uuid

    @responses.activate
    def test_quiet_multiple_results(self):
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        uuid1 = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        uuid2 = "b2c3d4e5-f6a7-8901-bcde-f12345678901"
        responses.get(
            f"{BASE_URL}/discovery",
            json=[
                {
                    "productReleaseUuid": uuid1,
                    "servers": [{"rootUrl": "https://tea1.example.com", "versions": ["1.0.0"]}],
                },
                {
                    "productReleaseUuid": uuid2,
                    "servers": [{"rootUrl": "https://tea2.example.com", "versions": ["1.0.0"]}],
                },
            ],
        )
        result = runner.invoke(app, ["discover", "-q", tei, "--base-url", BASE_URL])
        assert result.exit_code == 0
        lines = result.output.strip().split("\n")
        assert lines == [uuid1, uuid2]

    def test_quiet_flag_shown_in_help(self):
        result = runner.invoke(app, ["discover", "--help"])
        plain = _strip_ansi(result.output)
        assert "--quiet" in plain
        assert "-q" in plain


class TestNewCommands:
    """Tests for newly added CLI commands: get-product-releases, get-component,
    get-component-releases, list-collections, get-cle."""

    @responses.activate
    def test_get_product_releases(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/product/{uuid}/releases",
            json={
                "timestamp": "2024-01-01T00:00:00Z",
                "pageStartIndex": 0,
                "pageSize": 100,
                "totalResults": 1,
                "results": [
                    {
                        "uuid": uuid,
                        "version": "1.0.0",
                        "createdDate": "2024-01-01T00:00:00Z",
                        "components": [],
                    }
                ],
            },
        )
        result = runner.invoke(app, ["--json", "get-product-releases", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["totalResults"] == 1
        assert data["results"][0]["version"] == "1.0.0"

    @responses.activate
    def test_get_product_releases_with_pagination(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/product/{uuid}/releases",
            json={
                "timestamp": "2024-01-01T00:00:00Z",
                "pageStartIndex": 10,
                "pageSize": 5,
                "totalResults": 20,
                "results": [],
            },
        )
        result = runner.invoke(
            app,
            ["--json", "get-product-releases", uuid, "--page-offset", "10", "--page-size", "5", "--base-url", BASE_URL],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["pageStartIndex"] == 10

    @responses.activate
    def test_get_component(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/component/{uuid}",
            json={"uuid": uuid, "name": "My Component", "identifiers": []},
        )
        result = runner.invoke(app, ["--json", "get-component", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "My Component"

    @responses.activate
    def test_get_component_rich_output(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/component/{uuid}",
            json={"uuid": uuid, "name": "My Component", "identifiers": []},
        )
        result = runner.invoke(app, ["get-component", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 0
        assert "My Component" in result.output

    @responses.activate
    def test_get_component_releases(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        rel_uuid = "e5e0a65b-bddf-22ff-bd8a-2b63a25e55c2"
        responses.get(
            f"{BASE_URL}/component/{uuid}/releases",
            json=[
                {"uuid": rel_uuid, "version": "1.0.0", "createdDate": "2024-01-01T00:00:00Z"},
                {"uuid": uuid, "version": "2.0.0", "createdDate": "2024-06-01T00:00:00Z"},
            ],
        )
        result = runner.invoke(app, ["--json", "get-component-releases", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 2
        assert data[0]["version"] == "1.0.0"

    @responses.activate
    def test_get_component_releases_rich_output(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/component/{uuid}/releases",
            json=[
                {
                    "uuid": uuid,
                    "version": "1.0.0",
                    "componentName": "App",
                    "createdDate": "2024-01-01T00:00:00Z",
                },
            ],
        )
        result = runner.invoke(app, ["get-component-releases", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 0
        assert "Component Releases" in result.output

    @responses.activate
    def test_list_collections_product_release(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/productRelease/{uuid}/collections",
            json=[
                {"uuid": uuid, "version": 1, "artifacts": []},
                {"uuid": uuid, "version": 2, "artifacts": []},
            ],
        )
        result = runner.invoke(app, ["--json", "list-collections", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 2

    @responses.activate
    def test_list_collections_component_release(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/componentRelease/{uuid}/collections",
            json=[{"uuid": uuid, "version": 1, "artifacts": []}],
        )
        result = runner.invoke(app, ["--json", "list-collections", uuid, "--component", "--base-url", BASE_URL])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1

    @responses.activate
    def test_list_collections_rich_output(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/productRelease/{uuid}/collections",
            json=[
                {"uuid": uuid, "version": 1, "date": "2024-01-01T00:00:00Z", "artifacts": []},
                {"uuid": uuid, "version": 2, "date": "2024-06-01T00:00:00Z", "artifacts": []},
            ],
        )
        result = runner.invoke(app, ["list-collections", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 0
        assert "Collections" in result.output

    @responses.activate
    def test_get_cle_product_release(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/productRelease/{uuid}/cle",
            json={
                "events": [
                    {
                        "id": 1,
                        "type": "released",
                        "effective": "2024-01-15T00:00:00Z",
                        "published": "2024-01-15T00:00:00Z",
                        "version": "1.0.0",
                    }
                ]
            },
        )
        result = runner.invoke(app, ["--json", "get-cle", uuid, "--entity", "product-release", "--base-url", BASE_URL])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["events"]) == 1
        assert data["events"][0]["type"] == "released"

    @responses.activate
    def test_get_cle_product(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/product/{uuid}/cle",
            json={
                "events": [
                    {
                        "id": 1,
                        "type": "endOfLife",
                        "effective": "2025-12-31T00:00:00Z",
                        "published": "2025-01-01T00:00:00Z",
                    }
                ]
            },
        )
        result = runner.invoke(app, ["--json", "get-cle", uuid, "--entity", "product", "--base-url", BASE_URL])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["events"][0]["type"] == "endOfLife"

    @responses.activate
    def test_get_cle_component(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/component/{uuid}/cle",
            json={
                "events": [
                    {
                        "id": 1,
                        "type": "released",
                        "effective": "2024-01-15T00:00:00Z",
                        "published": "2024-01-15T00:00:00Z",
                        "version": "1.0.0",
                    }
                ]
            },
        )
        result = runner.invoke(app, ["--json", "get-cle", uuid, "--entity", "component", "--base-url", BASE_URL])
        assert result.exit_code == 0

    @responses.activate
    def test_get_cle_component_release(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/componentRelease/{uuid}/cle",
            json={
                "events": [
                    {
                        "id": 1,
                        "type": "released",
                        "effective": "2024-01-15T00:00:00Z",
                        "published": "2024-01-15T00:00:00Z",
                        "version": "1.0.0",
                    }
                ]
            },
        )
        result = runner.invoke(
            app, ["--json", "get-cle", uuid, "--entity", "component-release", "--base-url", BASE_URL]
        )
        assert result.exit_code == 0

    def test_get_cle_invalid_entity(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        result = runner.invoke(app, ["get-cle", uuid, "--entity", "invalid", "--base-url", BASE_URL])
        assert result.exit_code == 2
        assert "Invalid value for '--entity'" in result.output

    @responses.activate
    def test_get_cle_default_entity_is_product_release(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/productRelease/{uuid}/cle",
            json={
                "events": [
                    {
                        "id": 1,
                        "type": "released",
                        "effective": "2024-01-15T00:00:00Z",
                        "published": "2024-01-15T00:00:00Z",
                        "version": "1.0.0",
                    }
                ]
            },
        )
        result = runner.invoke(app, ["--json", "get-cle", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["events"]) == 1

    @responses.activate
    def test_get_cle_rich_output(self):
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/productRelease/{uuid}/cle",
            json={
                "events": [
                    {
                        "id": 1,
                        "type": "released",
                        "effective": "2024-01-15T00:00:00Z",
                        "published": "2024-01-15T00:00:00Z",
                        "version": "1.0.0",
                    }
                ]
            },
        )
        result = runner.invoke(app, ["get-cle", uuid, "--base-url", BASE_URL])
        assert result.exit_code == 0
        assert "Lifecycle Events" in result.output

    def test_new_commands_in_help(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "get-product-releases" in result.output
        assert "get-component" in result.output
        assert "get-component-releases" in result.output
        assert "list-collections" in result.output
        assert "get-cle" in result.output


class TestCLIErrorHandlingCoverage:
    """Coverage for error paths on commands not yet tested for errors."""

    @responses.activate
    def test_get_product_releases_error(self):
        responses.get(
            f"{BASE_URL}/product/d4d9f54a-abcf-11ee-ac79-1a52914d44b1/releases",
            status=404,
            json={"error": "OBJECT_UNKNOWN"},
        )
        result = runner.invoke(
            app, ["get-product-releases", "d4d9f54a-abcf-11ee-ac79-1a52914d44b1", "--base-url", BASE_URL]
        )
        assert result.exit_code == 1

    @responses.activate
    def test_get_component_error(self):
        responses.get(
            f"{BASE_URL}/component/d4d9f54a-abcf-11ee-ac79-1a52914d44b1", status=404, json={"error": "OBJECT_UNKNOWN"}
        )
        result = runner.invoke(app, ["get-component", "d4d9f54a-abcf-11ee-ac79-1a52914d44b1", "--base-url", BASE_URL])
        assert result.exit_code == 1

    @responses.activate
    def test_get_component_releases_error(self):
        responses.get(
            f"{BASE_URL}/component/d4d9f54a-abcf-11ee-ac79-1a52914d44b1/releases",
            status=404,
            json={"error": "OBJECT_UNKNOWN"},
        )
        result = runner.invoke(
            app, ["get-component-releases", "d4d9f54a-abcf-11ee-ac79-1a52914d44b1", "--base-url", BASE_URL]
        )
        assert result.exit_code == 1

    @responses.activate
    def test_list_collections_error(self):
        responses.get(
            f"{BASE_URL}/productRelease/d4d9f54a-abcf-11ee-ac79-1a52914d44b1/collections",
            status=404,
            json={"error": "OBJECT_UNKNOWN"},
        )
        result = runner.invoke(
            app, ["list-collections", "d4d9f54a-abcf-11ee-ac79-1a52914d44b1", "--base-url", BASE_URL]
        )
        assert result.exit_code == 1

    @responses.activate
    def test_get_cle_error(self):
        responses.get(
            f"{BASE_URL}/productRelease/d4d9f54a-abcf-11ee-ac79-1a52914d44b1/cle",
            status=404,
            json={"error": "OBJECT_UNKNOWN"},
        )
        result = runner.invoke(app, ["get-cle", "d4d9f54a-abcf-11ee-ac79-1a52914d44b1", "--base-url", BASE_URL])
        assert result.exit_code == 1


class TestDomainFromTeiCoverage:
    """Coverage for _domain_from_tei exception path."""

    def test_invalid_tei_falls_back_to_error(self):
        result = runner.invoke(app, ["discover", "not-a-valid-tei"])
        assert result.exit_code == 1


class TestJsonListOutput:
    """Coverage for _output JSON list branch."""

    @responses.activate
    def test_component_releases_json_list(self):
        responses.get(
            f"{BASE_URL}/component/d4d9f54a-abcf-11ee-ac79-1a52914d44b1/releases",
            json=[
                {
                    "uuid": "e5e0a65b-bcdf-22ff-bd80-2b63a25e55c2",
                    "version": "1.0.0",
                    "createdDate": "2024-01-01T00:00:00Z",
                }
            ],
        )
        result = runner.invoke(
            app, ["--json", "get-component-releases", "d4d9f54a-abcf-11ee-ac79-1a52914d44b1", "--base-url", BASE_URL]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert data[0]["uuid"] == "e5e0a65b-bcdf-22ff-bd80-2b63a25e55c2"


class TestCliEntryImportError:
    """Coverage for _cli_entry.py ImportError branch."""

    def test_missing_click_prints_install_hint(self):
        import subprocess
        import sys

        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; sys.modules['click'] = None; from libtea._cli_entry import main; main()",
            ],
            capture_output=True,
            text=True,
        )
        # The import error handling results in SystemExit(1)
        assert result.returncode == 1


class TestConformanceCommand:
    @responses.activate
    def test_conformance_json_output(self):
        paginated_empty = {
            "timestamp": "2024-01-01T00:00:00Z",
            "pageStartIndex": 0,
            "pageSize": 10,
            "totalResults": 0,
            "results": [],
        }
        responses.get("https://tea.example.com/v1/products", json=paginated_empty)
        responses.get("https://tea.example.com/v1/productReleases", json=paginated_empty)
        responses.get(
            "https://tea.example.com/v1/product/00000000-0000-0000-0000-000000000000",
            status=404,
            json={"error": "OBJECT_UNKNOWN"},
        )
        responses.get(
            "https://tea.example.com/v1/discovery",
            status=404,
            json={"error": "OBJECT_UNKNOWN"},
        )
        result = runner.invoke(app, ["conformance", "--base-url", "https://tea.example.com/v1", "--json"])
        assert result.exit_code in (0, 1)
        assert "base_url" in result.output or "checks" in result.output


class TestDownloadTeiMode:
    """Tests for the TEI URN discover-and-download mode of the download command."""

    @responses.activate
    def test_tei_mode_downloads_artifacts(self, tmp_path):
        """TEI source triggers discover → collection → download flow."""
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        pr_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        artifact_url = "https://cdn.example.com/sbom.cdx.json"
        responses.get(
            f"{BASE_URL}/discovery",
            json=[
                {
                    "productReleaseUuid": pr_uuid,
                    "servers": [{"rootUrl": BASE_URL, "versions": ["1.0.0"]}],
                }
            ],
        )
        responses.get(
            f"{BASE_URL}/productRelease/{pr_uuid}/collection/latest",
            json={
                "uuid": pr_uuid,
                "version": 1,
                "artifacts": [
                    {
                        "uuid": "art-uuid-1",
                        "name": "SBOM",
                        "type": "BOM",
                        "formats": [
                            {
                                "mediaType": "application/vnd.cyclonedx+json",
                                "url": artifact_url,
                                "checksums": [],
                            }
                        ],
                    }
                ],
            },
        )
        responses.get(artifact_url, body=b'{"bomFormat": "CycloneDX"}')
        dest = tmp_path / "output"
        result = runner.invoke(app, ["download", tei, str(dest), "--base-url", BASE_URL])
        assert result.exit_code == 0
        assert (dest / "sbom.cdx.json").exists()
        assert "Downloaded sbom.cdx.json" in result.output

    @responses.activate
    def test_tei_mode_no_discovery_results(self):
        """TEI with no discovery results exits with error."""
        tei = "urn:tei:purl:example.com:pkg:pypi/nonexistent@1.0"
        responses.get(f"{BASE_URL}/discovery", json=[])
        result = runner.invoke(app, ["download", tei, "-y", "--base-url", BASE_URL])
        assert result.exit_code == 1
        assert "No results found" in result.output

    @responses.activate
    def test_tei_mode_artifact_download_failure_warns(self, tmp_path):
        """Failed artifact download warns but doesn't abort."""
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        pr_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        good_url = "https://cdn.example.com/good.json"
        bad_url = "https://cdn.example.com/bad.json"
        responses.get(
            f"{BASE_URL}/discovery",
            json=[
                {
                    "productReleaseUuid": pr_uuid,
                    "servers": [{"rootUrl": BASE_URL, "versions": ["1.0.0"]}],
                }
            ],
        )
        responses.get(
            f"{BASE_URL}/productRelease/{pr_uuid}/collection/latest",
            json={
                "uuid": pr_uuid,
                "version": 1,
                "artifacts": [
                    {
                        "name": "BadArt",
                        "formats": [{"url": bad_url, "checksums": []}],
                    },
                    {
                        "name": "GoodArt",
                        "formats": [{"url": good_url, "checksums": []}],
                    },
                ],
            },
        )
        responses.get(bad_url, status=500)
        responses.get(good_url, body=b"OK")
        dest = tmp_path / "output"
        result = runner.invoke(app, ["download", tei, str(dest), "--base-url", BASE_URL])
        assert result.exit_code == 0
        assert "Warning: failed to download bad.json" in result.output
        assert (dest / "good.json").exists()

    @responses.activate
    def test_tei_mode_all_downloads_fail(self, tmp_path):
        """If all artifact downloads fail, exit with error."""
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        pr_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        artifact_url = "https://cdn.example.com/sbom.json"
        responses.get(
            f"{BASE_URL}/discovery",
            json=[
                {
                    "productReleaseUuid": pr_uuid,
                    "servers": [{"rootUrl": BASE_URL, "versions": ["1.0.0"]}],
                }
            ],
        )
        responses.get(
            f"{BASE_URL}/productRelease/{pr_uuid}/collection/latest",
            json={
                "uuid": pr_uuid,
                "version": 1,
                "artifacts": [{"name": "SBOM", "formats": [{"url": artifact_url, "checksums": []}]}],
            },
        )
        responses.get(artifact_url, status=500)
        dest = tmp_path / "output"
        result = runner.invoke(app, ["download", tei, str(dest), "--base-url", BASE_URL])
        assert result.exit_code == 1
        assert "All 1 artifact download(s) failed" in result.output

    @responses.activate
    def test_url_mode_still_works(self, tmp_path):
        """Direct URL mode is unchanged."""
        artifact_url = "https://cdn.example.com/sbom.json"
        responses.get(artifact_url, body=b'{"bomFormat": "CycloneDX"}')
        dest = tmp_path / "sbom.json"
        result = runner.invoke(app, ["download", artifact_url, str(dest), "--base-url", BASE_URL])
        assert result.exit_code == 0
        assert dest.exists()

    @responses.activate
    def test_tei_mode_prompts_when_dest_omitted(self):
        """Omitting DEST in TEI mode prompts for confirmation."""
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        responses.get(f"{BASE_URL}/discovery", json=[])
        # Answer 'y' to the prompt
        result = runner.invoke(app, ["download", tei, "--base-url", BASE_URL], input="y\n")
        assert result.exit_code == 1
        assert "Download artifacts into current directory" in result.output
        assert "No results found" in result.output

    @responses.activate
    def test_tei_mode_prompt_abort(self):
        """Answering 'n' to the prompt aborts the download."""
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        responses.get(f"{BASE_URL}/discovery", json=[])
        result = runner.invoke(app, ["download", tei, "--base-url", BASE_URL], input="n\n")
        assert result.exit_code == 1
        assert "Aborted" in result.output

    @responses.activate
    def test_tei_mode_yes_flag_skips_prompt(self):
        """The -y flag skips the confirmation prompt."""
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        responses.get(f"{BASE_URL}/discovery", json=[])
        result = runner.invoke(app, ["download", tei, "-y", "--base-url", BASE_URL])
        assert result.exit_code == 1
        assert "Download artifacts into current directory" not in result.output
        assert "No results found" in result.output

    def test_url_mode_requires_dest(self):
        """URL mode without DEST shows an error."""
        result = runner.invoke(app, ["download", "https://cdn.example.com/sbom.json", "--base-url", BASE_URL])
        assert result.exit_code == 1
        assert "DEST is required" in result.output

    @responses.activate
    def test_tei_mode_skips_formats_without_url(self, tmp_path):
        """Formats with no URL are silently skipped."""
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        pr_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        good_url = "https://cdn.example.com/sbom.json"
        responses.get(
            f"{BASE_URL}/discovery",
            json=[
                {
                    "productReleaseUuid": pr_uuid,
                    "servers": [{"rootUrl": BASE_URL, "versions": ["1.0.0"]}],
                }
            ],
        )
        responses.get(
            f"{BASE_URL}/productRelease/{pr_uuid}/collection/latest",
            json={
                "uuid": pr_uuid,
                "version": 1,
                "artifacts": [
                    {
                        "name": "SBOM",
                        "formats": [
                            {"mediaType": "application/xml", "checksums": []},
                            {"url": good_url, "checksums": []},
                        ],
                    }
                ],
            },
        )
        responses.get(good_url, body=b"OK")
        dest = tmp_path / "output"
        result = runner.invoke(app, ["download", tei, str(dest), "--base-url", BASE_URL])
        assert result.exit_code == 0
        assert (dest / "sbom.json").exists()

    def test_tei_mode_rejects_checksum_flag(self):
        """--checksum is rejected in TEI mode."""
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        result = runner.invoke(app, ["download", tei, "/tmp/out", "--checksum", "SHA-256:abc", "--base-url", BASE_URL])
        assert result.exit_code == 1
        assert "--checksum is not supported in TEI mode" in result.output

    @responses.activate
    def test_tei_mode_checksum_verification(self, tmp_path):
        """Checksums from server metadata are verified in TEI mode."""
        import hashlib

        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        pr_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        content = b'{"bomFormat": "CycloneDX"}'
        sha256 = hashlib.sha256(content).hexdigest()
        artifact_url = "https://cdn.example.com/sbom.cdx.json"
        responses.get(
            f"{BASE_URL}/discovery",
            json=[{"productReleaseUuid": pr_uuid, "servers": [{"rootUrl": BASE_URL, "versions": ["1.0.0"]}]}],
        )
        responses.get(
            f"{BASE_URL}/productRelease/{pr_uuid}/collection/latest",
            json={
                "uuid": pr_uuid,
                "version": 1,
                "artifacts": [
                    {
                        "name": "SBOM",
                        "formats": [
                            {
                                "url": artifact_url,
                                "checksums": [{"algType": "SHA-256", "algValue": sha256}],
                            }
                        ],
                    }
                ],
            },
        )
        responses.get(artifact_url, body=content)
        dest = tmp_path / "output"
        result = runner.invoke(app, ["download", tei, str(dest), "--base-url", BASE_URL])
        assert result.exit_code == 0
        assert "(checksum OK)" in result.output

    @responses.activate
    def test_tei_mode_checksum_failure_shown_without_error_prefix(self, tmp_path):
        """Checksum mismatch uses 'Checksum FAILED' prefix (no misleading 'Error:' prefix)."""
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        pr_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        artifact_url = "https://cdn.example.com/sbom.cdx.json"
        responses.get(
            f"{BASE_URL}/discovery",
            json=[{"productReleaseUuid": pr_uuid, "servers": [{"rootUrl": BASE_URL, "versions": ["1.0.0"]}]}],
        )
        responses.get(
            f"{BASE_URL}/productRelease/{pr_uuid}/collection/latest",
            json={
                "uuid": pr_uuid,
                "version": 1,
                "artifacts": [
                    {
                        "name": "SBOM",
                        "formats": [
                            {
                                "url": artifact_url,
                                "checksums": [{"algType": "SHA-256", "algValue": "0000bad"}],
                            }
                        ],
                    }
                ],
            },
        )
        responses.get(artifact_url, body=b"content")
        dest = tmp_path / "output"
        result = runner.invoke(app, ["download", tei, str(dest), "--base-url", BASE_URL])
        assert result.exit_code == 1
        assert "Checksum FAILED" in result.output
        assert "Error: checksum" not in result.output

    @responses.activate
    def test_tei_mode_empty_artifacts_in_collection(self, tmp_path):
        """Collection with empty artifacts list shows 'no downloadable URLs' error."""
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        pr_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        responses.get(
            f"{BASE_URL}/discovery",
            json=[{"productReleaseUuid": pr_uuid, "servers": [{"rootUrl": BASE_URL, "versions": ["1.0.0"]}]}],
        )
        responses.get(
            f"{BASE_URL}/productRelease/{pr_uuid}/collection/latest",
            json={"uuid": pr_uuid, "version": 1, "artifacts": []},
        )
        dest = tmp_path / "output"
        result = runner.invoke(app, ["download", tei, str(dest), "--base-url", BASE_URL])
        assert result.exit_code == 1
        assert "No downloadable artifact URLs found" in result.output

    @responses.activate
    def test_tei_mode_multiple_discoveries(self, tmp_path):
        """TEI resolving to multiple product releases downloads from all."""
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        pr1 = "a1b2c3d4-0000-0000-0000-000000000001"
        pr2 = "a1b2c3d4-0000-0000-0000-000000000002"
        url1 = "https://cdn.example.com/sbom1.json"
        url2 = "https://cdn.example.com/sbom2.json"
        responses.get(
            f"{BASE_URL}/discovery",
            json=[
                {"productReleaseUuid": pr1, "servers": [{"rootUrl": BASE_URL, "versions": ["1.0.0"]}]},
                {"productReleaseUuid": pr2, "servers": [{"rootUrl": BASE_URL, "versions": ["1.0.0"]}]},
            ],
        )
        responses.get(
            f"{BASE_URL}/productRelease/{pr1}/collection/latest",
            json={"uuid": pr1, "version": 1, "artifacts": [{"name": "A", "formats": [{"url": url1, "checksums": []}]}]},
        )
        responses.get(
            f"{BASE_URL}/productRelease/{pr2}/collection/latest",
            json={"uuid": pr2, "version": 1, "artifacts": [{"name": "B", "formats": [{"url": url2, "checksums": []}]}]},
        )
        responses.get(url1, body=b"one")
        responses.get(url2, body=b"two")
        dest = tmp_path / "output"
        result = runner.invoke(app, ["download", tei, str(dest), "--base-url", BASE_URL])
        assert result.exit_code == 0
        assert (dest / "sbom1.json").exists()
        assert (dest / "sbom2.json").exists()

    @responses.activate
    def test_tei_mode_filename_collision_deduplicates(self, tmp_path):
        """Duplicate filenames get a numeric suffix to avoid overwriting."""
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        pr_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        url1 = "https://cdn1.example.com/sbom.json"
        url2 = "https://cdn2.example.com/sbom.json"
        responses.get(
            f"{BASE_URL}/discovery",
            json=[{"productReleaseUuid": pr_uuid, "servers": [{"rootUrl": BASE_URL, "versions": ["1.0.0"]}]}],
        )
        responses.get(
            f"{BASE_URL}/productRelease/{pr_uuid}/collection/latest",
            json={
                "uuid": pr_uuid,
                "version": 1,
                "artifacts": [
                    {"name": "A", "formats": [{"url": url1, "checksums": []}]},
                    {"name": "B", "formats": [{"url": url2, "checksums": []}]},
                ],
            },
        )
        responses.get(url1, body=b"first")
        responses.get(url2, body=b"second")
        dest = tmp_path / "output"
        result = runner.invoke(app, ["download", tei, str(dest), "--base-url", BASE_URL])
        assert result.exit_code == 0
        assert (dest / "sbom.json").exists()
        assert (dest / "sbom-1.json").exists()
        assert (dest / "sbom.json").read_bytes() == b"first"
        assert (dest / "sbom-1.json").read_bytes() == b"second"


class TestArtifactFilename:
    """Tests for _artifact_filename derivation logic."""

    def test_filename_from_url(self):
        from libtea.cli import _artifact_filename
        from libtea.models import Artifact, ArtifactFormat

        fmt = ArtifactFormat(url="https://cdn.example.com/path/to/sbom.cdx.json")
        art = Artifact(name="SBOM")
        assert _artifact_filename(fmt, art, 0) == "sbom.cdx.json"

    def test_filename_fallback_to_artifact_name(self):
        from libtea.cli import _artifact_filename
        from libtea.models import Artifact, ArtifactFormat

        fmt = ArtifactFormat(media_type="application/json")
        art = Artifact(name="my-sbom")
        assert _artifact_filename(fmt, art, 0) == "my-sbom.json"

    def test_filename_fallback_no_name(self):
        from libtea.cli import _artifact_filename
        from libtea.models import Artifact, ArtifactFormat

        fmt = ArtifactFormat(media_type="application/vnd.cyclonedx+json")
        art = Artifact()
        assert _artifact_filename(fmt, art, 3) == "artifact-3.cdx.json"

    def test_filename_url_without_extension_falls_back(self):
        """URLs ending in generic segments like /download use artifact name instead."""
        from libtea.cli import _artifact_filename
        from libtea.models import Artifact, ArtifactFormat

        fmt = ArtifactFormat(url="https://cdn.example.com/artifacts/uuid/download", media_type="application/json")
        art = Artifact(name="my-sbom")
        assert _artifact_filename(fmt, art, 0) == "my-sbom.json"

    def test_filename_unknown_media_type(self):
        from libtea.cli import _artifact_filename
        from libtea.models import Artifact, ArtifactFormat

        fmt = ArtifactFormat(media_type="application/octet-stream")
        art = Artifact(name="blob")
        assert _artifact_filename(fmt, art, 0) == "blob"

    def test_filename_path_traversal_sanitized(self):
        """Malicious artifact names with path traversal are sanitized."""
        from libtea.cli import _artifact_filename
        from libtea.models import Artifact, ArtifactFormat

        fmt = ArtifactFormat(media_type="application/json")
        art = Artifact(name="../../etc/passwd")
        assert _artifact_filename(fmt, art, 0) == "passwd.json"

    def test_filename_absolute_path_sanitized(self):
        """Absolute path in artifact name is sanitized to basename."""
        from libtea.cli import _artifact_filename
        from libtea.models import Artifact, ArtifactFormat

        fmt = ArtifactFormat(media_type="application/json")
        art = Artifact(name="/etc/cron.d/malicious")
        assert _artifact_filename(fmt, art, 0) == "malicious.json"

    def test_ext_from_media_type(self):
        from libtea.cli import _ext_from_media_type

        assert _ext_from_media_type("application/json") == ".json"
        assert _ext_from_media_type("application/xml") == ".xml"
        assert _ext_from_media_type("text/xml") == ".xml"
        assert _ext_from_media_type("application/spdx+json") == ".spdx.json"
        assert _ext_from_media_type("application/vnd.cyclonedx+json") == ".cdx.json"
        assert _ext_from_media_type("application/vnd.cyclonedx+xml") == ".cdx.xml"
        assert _ext_from_media_type("application/octet-stream") == ""
        assert _ext_from_media_type(None) == ""

    def test_deduplicate_filename(self):
        from libtea.cli import _deduplicate_filename

        seen: set[str] = set()
        assert _deduplicate_filename("sbom.json", seen) == "sbom.json"
        assert _deduplicate_filename("sbom.json", seen) == "sbom-1.json"
        assert _deduplicate_filename("sbom.json", seen) == "sbom-2.json"
        assert _deduplicate_filename("other.xml", seen) == "other.xml"

    def test_sanitize_filename(self):
        from libtea.cli import _sanitize_filename

        assert _sanitize_filename("normal.json") == "normal.json"
        assert _sanitize_filename("../../etc/passwd") == "passwd"
        assert _sanitize_filename("/etc/shadow") == "shadow"
        assert _sanitize_filename("..") == ""
        assert _sanitize_filename(".") == ""


class TestCLIUXImprovements:
    """Tests for CLI UX improvements (examples, flags, help text)."""

    def test_top_level_help_shows_quick_start(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "Quick start:" in result.output
        assert "TEA_BASE_URL" in result.output
        assert "TEA_TOKEN" in result.output
        assert "Exit codes:" in result.output

    def test_command_help_shows_examples(self):
        for cmd in [
            "discover",
            "download",
            "inspect",
            "get-product",
            "get-release",
            "get-collection",
            "get-product-releases",
            "get-component",
            "get-component-releases",
            "list-collections",
            "get-cle",
            "get-artifact",
            "search-products",
            "search-releases",
            "conformance",
        ]:
            result = runner.invoke(app, [cmd, "--help"])
            assert "Examples:" in result.output, f"{cmd} --help missing Examples section"

    def test_no_input_flag_skips_download_prompt(self, tmp_path):
        """--no-input suppresses the confirmation prompt like --yes."""
        result = runner.invoke(
            app,
            ["download", "urn:tei:purl:example.com:pkg:pypi/test@1.0", "--no-input", "--base-url", BASE_URL],
        )
        # Will fail with connection error, but should NOT prompt
        assert result.exit_code == 1
        assert "Download artifacts into current directory" not in result.output

    @responses.activate
    def test_dry_run_shows_would_download(self, tmp_path):
        """--dry-run lists artifacts without actually downloading."""
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        pr_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        artifact_url = "https://cdn.example.com/sbom.cdx.json"
        responses.get(
            f"{BASE_URL}/discovery",
            json=[{"productReleaseUuid": pr_uuid, "servers": [{"rootUrl": BASE_URL, "versions": ["1.0.0"]}]}],
        )
        responses.get(
            f"{BASE_URL}/productRelease/{pr_uuid}/collection/latest",
            json={
                "uuid": pr_uuid,
                "version": 1,
                "artifacts": [
                    {"name": "SBOM", "formats": [{"url": artifact_url, "checksums": []}]},
                ],
            },
        )
        dest = tmp_path / "output"
        result = runner.invoke(app, ["download", tei, str(dest), "--dry-run", "--base-url", BASE_URL])
        assert result.exit_code == 0
        assert "Would download:" in result.output
        assert "sbom.cdx.json" in result.output
        assert not dest.exists()

    def test_dry_run_rejected_in_url_mode(self):
        """--dry-run is only valid in TEI mode."""
        result = runner.invoke(
            app,
            ["download", "https://example.com/sbom.json", "out.json", "--dry-run", "--base-url", BASE_URL],
        )
        assert result.exit_code == 1
        assert "--dry-run is only supported in TEI mode" in result.output

    @responses.activate
    def test_quiet_suppresses_download_progress(self, tmp_path):
        """--quiet suppresses 'Downloaded ...' messages but still succeeds."""
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        pr_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        artifact_url = "https://cdn.example.com/sbom.json"
        responses.get(
            f"{BASE_URL}/discovery",
            json=[{"productReleaseUuid": pr_uuid, "servers": [{"rootUrl": BASE_URL, "versions": ["1.0.0"]}]}],
        )
        responses.get(
            f"{BASE_URL}/productRelease/{pr_uuid}/collection/latest",
            json={
                "uuid": pr_uuid,
                "version": 1,
                "artifacts": [
                    {"name": "SBOM", "formats": [{"url": artifact_url, "checksums": []}]},
                ],
            },
        )
        responses.get(artifact_url, body=b"content")
        dest = tmp_path / "output"
        result = runner.invoke(app, ["download", tei, str(dest), "--quiet", "--base-url", BASE_URL])
        assert result.exit_code == 0
        assert "Downloaded" not in result.output

    @responses.activate
    def test_no_color_flag(self, tmp_path):
        """--no-color writes output without ANSI escape codes to file."""
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/product/{uuid}",
            json={"uuid": uuid, "name": "Test Product", "identifiers": []},
        )
        # Write Rich output to file with --no-color to verify ANSI stripping
        out_file = tmp_path / "no_color.txt"
        result = runner.invoke(
            app, ["get-product", uuid, "--base-url", BASE_URL, "--no-color", "--output", str(out_file)]
        )
        assert result.exit_code == 0
        content = out_file.read_text()
        assert "Test Product" in content
        assert "\x1b[" not in content

    @responses.activate
    def test_output_flag_writes_to_file(self, tmp_path):
        """--output writes JSON to a file."""
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/product/{uuid}",
            json={"uuid": uuid, "name": "Test Product", "identifiers": []},
        )
        out_file = tmp_path / "result.json"
        result = runner.invoke(app, ["--json", "get-product", uuid, "--base-url", BASE_URL, "--output", str(out_file)])
        assert result.exit_code == 0
        data = json.loads(out_file.read_text())
        assert data["name"] == "Test Product"

    @responses.activate
    def test_output_flag_writes_rich_to_file(self, tmp_path):
        """--output without --json writes Rich output to file."""
        uuid = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
        responses.get(
            f"{BASE_URL}/product/{uuid}",
            json={"uuid": uuid, "name": "Test Product", "identifiers": []},
        )
        out_file = tmp_path / "result.txt"
        result = runner.invoke(app, ["get-product", uuid, "--base-url", BASE_URL, "--output", str(out_file)])
        assert result.exit_code == 0
        content = out_file.read_text()
        assert "Test Product" in content
        assert "\x1b[" not in content

    @responses.activate
    def test_quiet_suppresses_url_mode_download_message(self, tmp_path):
        """--quiet suppresses 'Downloaded to ...' in URL mode."""
        url = f"{BASE_URL}/artifacts/abc/download"
        responses.get(url, body=b"content")
        dest = tmp_path / "out.json"
        result = runner.invoke(app, ["download", url, str(dest), "--quiet", "--base-url", BASE_URL])
        assert result.exit_code == 0
        assert "Downloaded to" not in result.output
        assert dest.read_bytes() == b"content"
