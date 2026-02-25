import pytest
import requests
import responses

from libtea._http import TeaHttpClient
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
