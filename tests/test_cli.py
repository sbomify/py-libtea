"""Tests for the tea-cli CLI."""

import json

import pytest
import responses

typer = pytest.importorskip("typer", reason="typer not installed (install libtea[cli])")

from typer.testing import CliRunner  # noqa: E402

from libtea.cli import app  # noqa: E402

runner = CliRunner()

BASE_URL = "https://api.example.com/tea/v1"


class TestCliEntryPoint:
    """P0-1: Entry point wrapper handles missing typer gracefully."""

    def test_entry_point_importable(self):
        from libtea._cli_entry import main

        assert callable(main)

    def test_entry_point_registered_in_pyproject(self):
        """Verify pyproject.toml points to the wrapper, not directly to cli:app."""
        from pathlib import Path

        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        content = pyproject.read_text()
        assert 'tea-cli = "libtea._cli_entry:main"' in content


class TestCLINoServer:
    def test_no_base_url_or_domain_errors(self):
        result = runner.invoke(app, ["get-product", "some-uuid"])
        assert result.exit_code == 1

    def test_both_base_url_and_domain_errors(self):
        result = runner.invoke(app, ["get-product", "some-uuid", "--base-url", BASE_URL, "--domain", "example.com"])
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
        result = runner.invoke(app, ["get-product", uuid, "--base-url", BASE_URL])
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
                    "productReleaseUuid": "abc-123",
                    "servers": [{"rootUrl": "https://tea.example.com", "versions": ["1.0.0"]}],
                }
            ],
        )
        result = runner.invoke(app, ["discover", tei, "--base-url", BASE_URL])
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
        result = runner.invoke(app, ["get-artifact", uuid, "--base-url", BASE_URL])
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
        uuid = "abc-123"
        comp_uuid = "comp-456"
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
            f"{BASE_URL}/componentRelease/{comp_uuid}",
            json={
                "release": {"uuid": comp_uuid, "version": "1.0.0", "createdDate": "2024-01-01T00:00:00Z"},
                "latestCollection": {"uuid": comp_uuid, "version": 1, "artifacts": []},
            },
        )
        result = runner.invoke(app, ["inspect", tei, "--base-url", BASE_URL])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["productRelease"]["uuid"] == uuid
        assert len(data[0]["components"]) == 1
        assert "discovery" in data[0]
        assert data[0]["discovery"]["productReleaseUuid"] == uuid

    def test_error_output_goes_to_stderr(self):
        result = runner.invoke(app, ["get-product", "some-uuid"])
        assert result.exit_code == 1


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
        result = runner.invoke(app, ["get-product", uuid, "--domain", "example.com"])
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
    """P1-4: Tests for --auth and mTLS CLI options."""

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
        result = runner.invoke(app, ["get-product", "some-uuid", "--base-url", BASE_URL, "--auth", "nopassword"])
        assert result.exit_code == 1

    def test_client_key_without_cert_errors(self):
        result = runner.invoke(
            app, ["get-product", "some-uuid", "--base-url", BASE_URL, "--client-key", "/tmp/key.pem"]
        )
        assert result.exit_code == 1

    def test_client_cert_without_key_errors(self):
        result = runner.invoke(
            app, ["get-product", "some-uuid", "--base-url", BASE_URL, "--client-cert", "/tmp/cert.pem"]
        )
        assert result.exit_code == 1


class TestCLIInspectOptions:
    """P3-7: Tests for inspect --max-components."""

    @responses.activate
    def test_inspect_max_components_truncates(self):
        tei = "urn:tei:purl:example.com:pkg:pypi/test@1.0"
        uuid = "abc-123"
        comp_uuids = [f"comp-{i}" for i in range(5)]
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
                "components": [{"uuid": c} for c in comp_uuids],
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
        result = runner.invoke(app, ["inspect", tei, "--max-components", "2", "--base-url", BASE_URL])
        assert result.exit_code == 0
        # CliRunner mixes stdout/stderr; extract JSON before the warning line
        output = result.output
        json_end = output.rfind("]") + 1
        data = json.loads(output[:json_end])
        assert len(data[0]["components"]) == 2
        assert data[0]["truncated"] is True
        assert data[0]["totalComponents"] == 5
        assert "Warning: truncated" in output
