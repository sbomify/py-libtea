import hashlib
import warnings
from pathlib import Path
from unittest.mock import patch

import pytest
import requests
import responses

from libtea._http import (
    _MAX_DOWNLOAD_REDIRECTS,
    MtlsConfig,
    TeaHttpClient,
    _get_package_version,
)
from libtea.exceptions import (
    TeaAuthenticationError,
    TeaConnectionError,
    TeaInsecureTransportWarning,
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
        with pytest.raises(TeaNotFoundError, match="HTTP 404") as exc_info:
            http_client.get_json("/product/missing")
        assert exc_info.value.error_type == "OBJECT_UNKNOWN"

    @responses.activate
    def test_404_with_object_not_shareable(self, http_client, base_url):
        responses.get(f"{base_url}/product/restricted", json={"error": "OBJECT_NOT_SHAREABLE"}, status=404)
        with pytest.raises(TeaNotFoundError, match="HTTP 404") as exc_info:
            http_client.get_json("/product/restricted")
        assert exc_info.value.error_type == "OBJECT_NOT_SHAREABLE"

    @responses.activate
    def test_404_with_non_json_body(self, http_client, base_url):
        responses.get(f"{base_url}/product/missing", body="Not Found", status=404)
        with pytest.raises(TeaNotFoundError, match="HTTP 404") as exc_info:
            http_client.get_json("/product/missing")
        assert exc_info.value.error_type is None

    @responses.activate
    def test_401_raises_auth_error(self, http_client, base_url):
        responses.get(f"{base_url}/product/abc", status=401)
        with pytest.raises(TeaAuthenticationError, match="HTTP 401"):
            http_client.get_json("/product/abc")

    @responses.activate
    def test_403_raises_auth_error(self, http_client, base_url):
        responses.get(f"{base_url}/product/abc", status=403)
        with pytest.raises(TeaAuthenticationError, match="HTTP 403"):
            http_client.get_json("/product/abc")

    @responses.activate
    def test_400_raises_request_error(self, http_client, base_url):
        responses.get(f"{base_url}/product/abc", status=400)
        with pytest.raises(TeaRequestError, match="HTTP 400"):
            http_client.get_json("/product/abc")

    @responses.activate
    def test_500_raises_server_error(self, http_client, base_url):
        responses.get(f"{base_url}/product/abc", status=500)
        with pytest.raises(TeaServerError, match="HTTP 500"):
            http_client.get_json("/product/abc")

    @responses.activate
    def test_502_raises_server_error(self, http_client, base_url):
        responses.get(f"{base_url}/product/abc", status=502)
        with pytest.raises(TeaServerError, match="HTTP 502"):
            http_client.get_json("/product/abc")

    @responses.activate
    def test_3xx_raises_request_error(self, http_client, base_url):
        responses.get(f"{base_url}/product/abc", status=301)
        with pytest.raises(TeaRequestError, match="redirect.*HTTP 301"):
            http_client.get_json("/product/abc")

    @responses.activate
    def test_connection_error(self, http_client, base_url):
        responses.get(f"{base_url}/product/abc", body=requests.ConnectionError("refused"))
        with pytest.raises(TeaConnectionError, match="refused"):
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
        with pytest.raises(TeaConnectionError, match="refused"):
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
        with pytest.raises(TeaServerError, match="HTTP 500"):
            http_client.download_with_hashes(url="https://artifacts.example.com/file.bin", dest=dest)
        assert not dest.exists()

    @responses.activate
    def test_bearer_token_not_sent_to_artifact_url(self, tmp_path, base_url):
        """The separate download session must NOT leak the bearer token to artifact hosts."""
        artifact_url = "https://cdn.example.com/sbom.xml"
        responses.get(artifact_url, body=b"content")
        client = TeaHttpClient(base_url=base_url, token="secret-token")
        client.download_with_hashes(url=artifact_url, dest=tmp_path / "f.xml")
        assert "authorization" not in responses.calls[0].request.headers
        client.close()

    @responses.activate
    def test_download_zero_byte_file(self, http_client, tmp_path):
        responses.get("https://artifacts.example.com/empty.xml", body=b"")
        dest = tmp_path / "empty.xml"
        digests = http_client.download_with_hashes(
            url="https://artifacts.example.com/empty.xml",
            dest=dest,
            algorithms=["SHA-256"],
        )
        assert dest.read_bytes() == b""
        assert digests["SHA-256"] == hashlib.sha256(b"").hexdigest()

    @responses.activate
    def test_download_multi_chunk_file(self, http_client, tmp_path):
        """Content larger than chunk_size (8192) exercises multi-chunk hashing."""
        content = b"x" * 20000
        responses.get("https://artifacts.example.com/large.bin", body=content)
        dest = tmp_path / "large.bin"
        digests = http_client.download_with_hashes(
            url="https://artifacts.example.com/large.bin",
            dest=dest,
            algorithms=["SHA-256"],
        )
        assert dest.read_bytes() == content
        assert digests["SHA-256"] == hashlib.sha256(content).hexdigest()

    @responses.activate
    def test_4xx_includes_response_body(self, http_client, base_url):
        """4xx errors (other than 401/403/404) should include the response body."""
        responses.get(f"{base_url}/product/abc", body="Bad request: missing field", status=422)
        with pytest.raises(TeaRequestError, match="missing field"):
            http_client.get_json("/product/abc")


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

    def test_http_without_token_warns(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            client = TeaHttpClient(base_url="http://example.com/api")
            client.close()
        assert any(issubclass(warning.category, TeaInsecureTransportWarning) for warning in w)

    def test_http_with_token_raises(self):
        with pytest.raises(ValueError, match="Cannot use bearer token with plaintext HTTP"):
            TeaHttpClient(base_url="http://example.com/api", token="my-secret")

    def test_accepts_https(self):
        client = TeaHttpClient(base_url="https://example.com/api")
        assert client._base_url == "https://example.com/api"
        client.close()

    def test_strips_trailing_slash(self):
        client = TeaHttpClient(base_url="https://example.com/api/")
        assert client._base_url == "https://example.com/api"
        client.close()


class TestGetPackageVersion:
    def test_returns_version_string(self):
        result = _get_package_version()
        assert isinstance(result, str)
        assert result != ""

    def test_fallback_to_unknown(self):
        from importlib.metadata import PackageNotFoundError

        with patch("importlib.metadata.version", side_effect=PackageNotFoundError("libtea")):
            result = _get_package_version()
            assert result == "unknown"


class TestRequestExceptionCatchAll:
    @responses.activate
    def test_request_exception_in_get_json(self, http_client, base_url):
        """RequestException subclasses beyond ConnectionError/Timeout are caught."""
        responses.get(f"{base_url}/product/abc", body=requests.exceptions.TooManyRedirects("too many"))
        with pytest.raises(TeaConnectionError, match="too many"):
            http_client.get_json("/product/abc")

    @responses.activate
    def test_download_timeout_cleans_up(self, http_client, tmp_path):
        """Timeout during download cleans up partial file."""
        responses.get("https://artifacts.example.com/sbom.xml", body=requests.Timeout("timed out"))
        dest = tmp_path / "sbom.xml"
        with pytest.raises(TeaConnectionError, match="timed out"):
            http_client.download_with_hashes(url="https://artifacts.example.com/sbom.xml", dest=dest)
        assert not dest.exists()

    @responses.activate
    def test_download_request_exception_cleans_up(self, http_client, tmp_path):
        """RequestException during download cleans up partial file."""
        responses.get(
            "https://artifacts.example.com/sbom.xml",
            body=requests.exceptions.ChunkedEncodingError("broken"),
        )
        dest = tmp_path / "sbom.xml"
        with pytest.raises(TeaConnectionError, match="Download failed"):
            http_client.download_with_hashes(url="https://artifacts.example.com/sbom.xml", dest=dest)
        assert not dest.exists()


class TestEmptyBodyErrors:
    @responses.activate
    def test_4xx_with_empty_body(self, http_client, base_url):
        """4xx with no body produces a clean error message."""
        responses.get(f"{base_url}/product/abc", body="", status=422)
        with pytest.raises(TeaRequestError, match="Client error: HTTP 422"):
            http_client.get_json("/product/abc")

    @responses.activate
    def test_404_with_json_array_body(self, http_client, base_url):
        """404 with non-dict JSON body does not crash."""
        responses.get(f"{base_url}/product/abc", json=["not", "a", "dict"], status=404)
        with pytest.raises(TeaNotFoundError) as exc_info:
            http_client.get_json("/product/abc")
        assert exc_info.value.error_type is None


BASE_URL = "https://api.example.com/tea/v1"


class TestBasicAuth:
    @responses.activate
    def test_basic_auth_sends_header(self):
        responses.get(f"{BASE_URL}/test", json={"ok": True})
        with TeaHttpClient(base_url=BASE_URL, basic_auth=("user", "pass")) as client:
            client.get_json("/test")
        assert responses.calls[0].request.headers["Authorization"].startswith("Basic ")

    def test_token_and_basic_auth_raises(self):
        with pytest.raises(ValueError, match="Cannot use both"):
            TeaHttpClient(base_url=BASE_URL, token="tok", basic_auth=("user", "pass"))

    def test_basic_auth_over_http_raises(self):
        with pytest.raises(ValueError, match="Cannot use basic auth with plaintext HTTP"):
            TeaHttpClient(base_url="http://example.com/api", basic_auth=("user", "pass"))

    def test_close_clears_auth(self):
        client = TeaHttpClient(base_url=BASE_URL, basic_auth=("user", "pass"))
        assert client._session.auth is not None
        client.close()
        assert client._session.auth is None

    def test_close_clears_mtls_cert(self):
        """P2-4: close() should clear mTLS cert references."""
        mtls = MtlsConfig(client_cert=Path("/tmp/cert.pem"), client_key=Path("/tmp/key.pem"))
        client = TeaHttpClient(base_url=BASE_URL, mtls=mtls)
        assert client._session.cert is not None
        client.close()
        assert client._session.cert is None

    @responses.activate
    def test_basic_auth_not_sent_to_download(self, tmp_path):
        """Basic auth must NOT leak to artifact download URLs."""
        artifact_url = "https://cdn.example.com/sbom.xml"
        responses.get(artifact_url, body=b"content")
        with TeaHttpClient(base_url=BASE_URL, basic_auth=("user", "pass")) as client:
            client.download_with_hashes(url=artifact_url, dest=tmp_path / "test_dl.xml")
        assert "Authorization" not in responses.calls[0].request.headers


class TestMtlsConfig:
    def test_mtls_sets_cert_on_session(self):
        mtls = MtlsConfig(client_cert=Path("/tmp/cert.pem"), client_key=Path("/tmp/key.pem"))
        client = TeaHttpClient(base_url=BASE_URL, mtls=mtls)
        assert client._session.cert == ("/tmp/cert.pem", "/tmp/key.pem")
        client.close()

    def test_mtls_with_ca_bundle(self):
        mtls = MtlsConfig(
            client_cert=Path("/tmp/cert.pem"), client_key=Path("/tmp/key.pem"), ca_bundle=Path("/tmp/ca.pem")
        )
        client = TeaHttpClient(base_url=BASE_URL, mtls=mtls)
        assert client._session.verify == "/tmp/ca.pem"
        client.close()

    def test_mtls_without_ca_uses_default(self):
        mtls = MtlsConfig(client_cert=Path("/tmp/cert.pem"), client_key=Path("/tmp/key.pem"))
        client = TeaHttpClient(base_url=BASE_URL, mtls=mtls)
        assert client._session.verify is True
        client.close()


class TestRetryConfig:
    def test_default_retry_is_configured(self):
        client = TeaHttpClient(base_url=BASE_URL)
        adapter = client._session.get_adapter(BASE_URL)
        assert adapter.max_retries.total == 3
        assert 500 in adapter.max_retries.status_forcelist
        client.close()

    def test_custom_retry_config(self):
        client = TeaHttpClient(base_url=BASE_URL, max_retries=5, backoff_factor=1.0)
        adapter = client._session.get_adapter(BASE_URL)
        assert adapter.max_retries.total == 5
        assert adapter.max_retries.backoff_factor == 1.0
        client.close()

    def test_zero_retries_disables(self):
        client = TeaHttpClient(base_url=BASE_URL, max_retries=0)
        adapter = client._session.get_adapter(BASE_URL)
        assert adapter.max_retries.total == 0
        client.close()

    def test_negative_retries_raises(self):
        with pytest.raises(ValueError, match="max_retries must be >= 0"):
            TeaHttpClient(base_url=BASE_URL, max_retries=-1)

    def test_retry_after_header_ignored(self):
        """P2-2: Server-controlled Retry-After must not be honored to prevent stalling."""
        client = TeaHttpClient(base_url=BASE_URL)
        adapter = client._session.get_adapter(BASE_URL)
        assert adapter.max_retries.respect_retry_after_header is False
        client.close()


class TestDownloadRedirectHandling:
    """Download follows redirects with SSRF validation at each hop."""

    @responses.activate
    def test_follows_redirect_to_safe_url(self, http_client, tmp_path):
        responses.get(
            "https://artifacts.example.com/sbom.xml",
            status=302,
            headers={"Location": "https://cdn.example.com/sbom.xml"},
        )
        responses.get("https://cdn.example.com/sbom.xml", body=b"content")
        dest = tmp_path / "sbom.xml"
        with patch("libtea._security.socket.getaddrinfo", return_value=[]):
            http_client.download_with_hashes(url="https://artifacts.example.com/sbom.xml", dest=dest)
        assert dest.read_bytes() == b"content"

    @responses.activate
    def test_rejects_redirect_to_internal_ip(self, http_client, tmp_path):
        responses.get(
            "https://artifacts.example.com/sbom.xml",
            status=302,
            headers={"Location": "http://169.254.169.254/latest/meta-data/"},
        )
        dest = tmp_path / "sbom.xml"
        with patch("libtea._security.socket.getaddrinfo", return_value=[]):
            with pytest.raises(TeaValidationError, match="private/internal"):
                http_client.download_with_hashes(url="https://artifacts.example.com/sbom.xml", dest=dest)

    @responses.activate
    def test_rejects_redirect_without_location(self, http_client, tmp_path):
        responses.get("https://artifacts.example.com/sbom.xml", status=302, headers={})
        dest = tmp_path / "sbom.xml"
        with patch("libtea._security.socket.getaddrinfo", return_value=[]):
            with pytest.raises(TeaRequestError, match="Redirect without Location"):
                http_client.download_with_hashes(url="https://artifacts.example.com/sbom.xml", dest=dest)

    @responses.activate
    def test_too_many_redirects(self, http_client, tmp_path):
        for i in range(_MAX_DOWNLOAD_REDIRECTS + 1):
            responses.get(
                f"https://artifacts.example.com/hop{i}",
                status=302,
                headers={"Location": f"https://artifacts.example.com/hop{i + 1}"},
            )
        dest = tmp_path / "sbom.xml"
        with patch("libtea._security.socket.getaddrinfo", return_value=[]):
            with pytest.raises(TeaConnectionError, match="Too many redirects"):
                http_client.download_with_hashes(url="https://artifacts.example.com/hop0", dest=dest)


class TestDownloadSizeLimit:
    """Download size limit prevents unbounded downloads."""

    @responses.activate
    def test_download_within_limit(self, http_client, tmp_path):
        content = b"small"
        responses.get("https://artifacts.example.com/small.bin", body=content)
        dest = tmp_path / "small.bin"
        with patch("libtea._security.socket.getaddrinfo", return_value=[]):
            http_client.download_with_hashes(
                url="https://artifacts.example.com/small.bin", dest=dest, max_download_bytes=1000
            )
        assert dest.read_bytes() == content

    @responses.activate
    def test_download_exceeds_limit_raises(self, http_client, tmp_path):
        content = b"x" * 2000
        responses.get("https://artifacts.example.com/large.bin", body=content)
        dest = tmp_path / "large.bin"
        with patch("libtea._security.socket.getaddrinfo", return_value=[]):
            with pytest.raises(TeaValidationError, match="exceeds size limit"):
                http_client.download_with_hashes(
                    url="https://artifacts.example.com/large.bin", dest=dest, max_download_bytes=1000
                )
        assert not dest.exists()

    @responses.activate
    def test_no_limit_by_default(self, http_client, tmp_path):
        content = b"x" * 100000
        responses.get("https://artifacts.example.com/big.bin", body=content)
        dest = tmp_path / "big.bin"
        with patch("libtea._security.socket.getaddrinfo", return_value=[]):
            http_client.download_with_hashes(url="https://artifacts.example.com/big.bin", dest=dest)
        assert dest.read_bytes() == content


class TestTruncationIndicator:
    """Error messages indicate when response body is truncated."""

    @responses.activate
    def test_4xx_long_body_shows_truncated(self, http_client, base_url):
        long_body = "x" * 300
        responses.get(f"{base_url}/product/abc", body=long_body, status=422)
        with pytest.raises(TeaRequestError, match="truncated"):
            http_client.get_json("/product/abc")

    @responses.activate
    def test_4xx_short_body_no_truncation(self, http_client, base_url):
        responses.get(f"{base_url}/product/abc", body="short error", status=422)
        with pytest.raises(TeaRequestError) as exc_info:
            http_client.get_json("/product/abc")
        assert "truncated" not in str(exc_info.value)


class TestResponseSizeLimit:
    """API response body size limit protection (SEC-04)."""

    @responses.activate
    def test_rejects_oversized_content_length(self):
        """Content-Length header advertising oversized body triggers rejection."""
        client = TeaHttpClient("https://api.example.com/v1")
        client._max_response_bytes = 5  # Very small limit
        responses.get(
            "https://api.example.com/v1/product/abc",
            json={"uuid": "abc"},
            status=200,
        )
        with pytest.raises(TeaValidationError, match="Response too large|exceeds limit"):
            client.get_json("/product/abc")
        client.close()

    @responses.activate
    def test_rejects_oversized_body(self):
        """Body exceeding limit is rejected even without Content-Length."""
        client = TeaHttpClient("https://api.example.com/v1")
        client._max_response_bytes = 100
        large_body = b'{"data": "' + b"x" * 200 + b'"}'
        responses.get("https://api.example.com/v1/product/abc", body=large_body, status=200)
        with pytest.raises(TeaValidationError, match="exceeds limit"):
            client.get_json("/product/abc")
        client.close()

    @responses.activate
    def test_normal_response_passes(self):
        """Normal-sized responses pass the size check."""
        client = TeaHttpClient("https://api.example.com/v1")
        responses.get("https://api.example.com/v1/product/abc", json={"uuid": "abc"}, status=200)
        result = client.get_json("/product/abc")
        assert result == {"uuid": "abc"}
        client.close()
