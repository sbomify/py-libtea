"""Tests for the tea-cli CLI."""

import json

import responses
from typer.testing import CliRunner

from libtea.cli import app

runner = CliRunner()

BASE_URL = "https://api.example.com/tea/v1"


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

    def test_error_output_goes_to_stderr(self):
        result = runner.invoke(app, ["get-product", "some-uuid"])
        assert result.exit_code == 1
