import hashlib
from unittest.mock import patch

import pytest
import requests
import responses

from libtea._http import TeaHttpClient, _get_package_version
from libtea.exceptions import (
    TeaAuthenticationError,
    TeaConnectionError,
    TeaNotFoundError,
    TeaRequestError,
    TeaServerError,
    TeaValidationError,
)


class TestTeaHttpClient:
    @responses.activate
    def test_get_json_success(self, http_client, base_url):
        responses.get(f"{base_url}/product/abc", json={"uuid": "abc", "name": "Test"})
        data = http_client.get_json("/product/abc")
        assert data == {"uuid": "abc", "name": "Test"}

    @responses.activate
    def test_get_json_with_bearer_token(self, base_url):
        responses.get(f"{base_url}/product/abc", json={"uuid": "abc"})
        client = TeaHttpClient(base_url=base_url, token="my-token")
        client.get_json("/product/abc")
        assert responses.calls[0].request.headers["authorization"] == "Bearer my-token"
        client.close()

    @responses.activate
    def test_404_raises_not_found_with_error_type(self, http_client, base_url):
        responses.get(f"{base_url}/product/missing", json={"error": "OBJECT_UNKNOWN"}, status=404)
        with pytest.raises(TeaNotFoundError) as exc_info:
            http_client.get_json("/product/missing")
        assert exc_info.value.error_type == "OBJECT_UNKNOWN"

    @responses.activate
    def test_404_with_object_not_shareable(self, http_client, base_url):
        responses.get(f"{base_url}/product/restricted", json={"error": "OBJECT_NOT_SHAREABLE"}, status=404)
        with pytest.raises(TeaNotFoundError) as exc_info:
            http_client.get_json("/product/restricted")
        assert exc_info.value.error_type == "OBJECT_NOT_SHAREABLE"

    @responses.activate
    def test_404_with_non_json_body(self, http_client, base_url):
        responses.get(f"{base_url}/product/missing", body="Not Found", status=404)
        with pytest.raises(TeaNotFoundError) as exc_info:
            http_client.get_json("/product/missing")
        assert exc_info.value.error_type is None

    @responses.activate
    def test_401_raises_auth_error(self, http_client, base_url):
        responses.get(f"{base_url}/product/abc", status=401)
        with pytest.raises(TeaAuthenticationError):
            http_client.get_json("/product/abc")

    @responses.activate
    def test_403_raises_auth_error(self, http_client, base_url):
        responses.get(f"{base_url}/product/abc", status=403)
        with pytest.raises(TeaAuthenticationError):
            http_client.get_json("/product/abc")

    @responses.activate
    def test_400_raises_request_error(self, http_client, base_url):
        responses.get(f"{base_url}/product/abc", status=400)
        with pytest.raises(TeaRequestError):
            http_client.get_json("/product/abc")

    @responses.activate
    def test_500_raises_server_error(self, http_client, base_url):
        responses.get(f"{base_url}/product/abc", status=500)
        with pytest.raises(TeaServerError):
            http_client.get_json("/product/abc")

    @responses.activate
    def test_502_raises_server_error(self, http_client, base_url):
        responses.get(f"{base_url}/product/abc", status=502)
        with pytest.raises(TeaServerError):
            http_client.get_json("/product/abc")

    @responses.activate
    def test_connection_error(self, http_client, base_url):
        responses.get(f"{base_url}/product/abc", body=requests.ConnectionError("refused"))
        with pytest.raises(TeaConnectionError):
            http_client.get_json("/product/abc")

    @responses.activate
    def test_timeout_raises_connection_error(self, http_client, base_url):
        responses.get(f"{base_url}/product/abc", body=requests.Timeout("timed out"))
        with pytest.raises(TeaConnectionError, match="timed out"):
            http_client.get_json("/product/abc")

    @responses.activate
    def test_stream_to_file(self, http_client, tmp_path):
        content = b"file content here"
        responses.get("https://artifacts.example.com/sbom.xml", body=content)
        dest = tmp_path / "sbom.xml"
        http_client.download_with_hashes(url="https://artifacts.example.com/sbom.xml", dest=dest)
        assert dest.read_bytes() == content

    @responses.activate
    def test_download_cleans_up_partial_file_on_transport_error(self, http_client, tmp_path):
        responses.get("https://artifacts.example.com/sbom.xml", body=requests.ConnectionError("refused"))
        dest = tmp_path / "sbom.xml"
        with pytest.raises(TeaConnectionError):
            http_client.download_with_hashes(url="https://artifacts.example.com/sbom.xml", dest=dest)
        assert not dest.exists()

    @responses.activate
    def test_get_json_non_json_response_raises_validation_error(self, http_client, base_url):
        responses.get(f"{base_url}/product/abc", body="not json", status=200)
        with pytest.raises(TeaValidationError, match="Invalid JSON"):
            http_client.get_json("/product/abc")

    @responses.activate
    def test_download_creates_parent_directories(self, http_client, tmp_path):
        content = b"nested file"
        responses.get("https://artifacts.example.com/sbom.xml", body=content)
        dest = tmp_path / "a" / "b" / "sbom.xml"
        http_client.download_with_hashes(url="https://artifacts.example.com/sbom.xml", dest=dest)
        assert dest.read_bytes() == content

    @responses.activate
    def test_user_agent_includes_version(self, base_url):
        responses.get(f"{base_url}/product/abc", json={"uuid": "abc"})
        client = TeaHttpClient(base_url=base_url)
        client.get_json("/product/abc")
        ua = responses.calls[0].request.headers["user-agent"]
        assert ua.startswith("py-libtea/")
        assert "hello@sbomify.com" in ua
        client.close()

    @responses.activate
    def test_context_manager(self, base_url):
        responses.get(f"{base_url}/product/abc", json={"uuid": "abc"})
        with TeaHttpClient(base_url=base_url) as client:
            data = client.get_json("/product/abc")
            assert data["uuid"] == "abc"

    @responses.activate
    def test_download_blake2b_256(self, http_client, tmp_path):
        content = b"blake2b test content"
        responses.get("https://artifacts.example.com/file.bin", body=content)
        dest = tmp_path / "file.bin"
        digests = http_client.download_with_hashes(
            url="https://artifacts.example.com/file.bin",
            dest=dest,
            algorithms=["BLAKE2b-256"],
        )
        expected = hashlib.blake2b(content, digest_size=32).hexdigest()
        assert digests["BLAKE2b-256"] == expected

    @responses.activate
    def test_download_generic_exception_cleans_up(self, http_client, tmp_path):
        responses.get("https://artifacts.example.com/file.bin", status=500)
        dest = tmp_path / "file.bin"
        with pytest.raises(TeaServerError):
            http_client.download_with_hashes(url="https://artifacts.example.com/file.bin", dest=dest)
        assert not dest.exists()


class TestBaseUrlValidation:
    def test_rejects_ftp_scheme(self):
        with pytest.raises(ValueError, match="http or https scheme"):
            TeaHttpClient(base_url="ftp://example.com/api")

    def test_rejects_empty_scheme(self):
        with pytest.raises(ValueError, match="http or https scheme"):
            TeaHttpClient(base_url="example.com/api")

    def test_rejects_missing_hostname(self):
        with pytest.raises(ValueError, match="must include a hostname"):
            TeaHttpClient(base_url="http:///path/only")

    def test_accepts_http(self):
        client = TeaHttpClient(base_url="http://example.com/api")
        assert client._base_url == "http://example.com/api"
        client.close()

    def test_accepts_https(self):
        client = TeaHttpClient(base_url="https://example.com/api")
        assert client._base_url == "https://example.com/api"
        client.close()

    def test_strips_trailing_slash(self):
        client = TeaHttpClient(base_url="https://example.com/api/")
        assert client._base_url == "https://example.com/api"
        client.close()


class TestGetPackageVersion:
    def test_fallback_to_tomllib(self):
        with patch("importlib.metadata.version", side_effect=Exception("not installed")):
            result = _get_package_version()
            # Falls back to tomllib parsing of pyproject.toml
            assert isinstance(result, str)

    def test_fallback_to_unknown(self):
        with (
            patch("importlib.metadata.version", side_effect=Exception("not installed")),
            patch("tomllib.load", side_effect=Exception("parse error")),
        ):
            result = _get_package_version()
            assert result == "unknown"
