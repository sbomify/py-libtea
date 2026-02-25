import hashlib
import warnings
from unittest.mock import patch

import pytest
import requests
import responses

from libtea._http import TeaHttpClient, _build_hashers, _get_package_version, _validate_download_url
from libtea.exceptions import (
    TeaAuthenticationError,
    TeaChecksumError,
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


class TestBuildHashers:
    def test_blake3_raises(self):
        with pytest.raises(TeaChecksumError, match="BLAKE3"):
            _build_hashers(["BLAKE3"])

    def test_unknown_algorithm_raises(self):
        with pytest.raises(TeaChecksumError, match="Unsupported checksum algorithm"):
            _build_hashers(["UNKNOWN-ALG"])

    @pytest.mark.parametrize(
        "algorithm",
        ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512"],
    )
    def test_standard_algorithms(self, algorithm):
        hashers = _build_hashers([algorithm])
        assert algorithm in hashers
        # Verify the hasher produces a hex digest
        hashers[algorithm].update(b"test")
        assert len(hashers[algorithm].hexdigest()) > 0

    @pytest.mark.parametrize("algorithm,digest_size", [("BLAKE2b-256", 32), ("BLAKE2b-384", 48), ("BLAKE2b-512", 64)])
    def test_blake2b_variants(self, algorithm, digest_size):
        hashers = _build_hashers([algorithm])
        assert algorithm in hashers
        hashers[algorithm].update(b"test")
        # BLAKE2b hex digest length = digest_size * 2
        assert len(hashers[algorithm].hexdigest()) == digest_size * 2

    @responses.activate
    def test_all_algorithms_produce_correct_digests(self, tmp_path):
        """End-to-end: download with each algorithm and verify the digest is correct."""
        content = b"algorithm test content"
        url = "https://artifacts.example.com/test.bin"
        responses.get(url, body=content)

        client = TeaHttpClient(base_url="https://api.example.com")
        all_algs = ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512"]

        dest = tmp_path / "test.bin"
        digests = client.download_with_hashes(url=url, dest=dest, algorithms=all_algs)
        client.close()

        assert digests["MD5"] == hashlib.md5(content).hexdigest()
        assert digests["SHA-1"] == hashlib.sha1(content).hexdigest()
        assert digests["SHA-256"] == hashlib.sha256(content).hexdigest()
        assert digests["SHA-384"] == hashlib.sha384(content).hexdigest()
        assert digests["SHA-512"] == hashlib.sha512(content).hexdigest()
        assert digests["SHA3-256"] == hashlib.new("sha3_256", content).hexdigest()
        assert digests["SHA3-384"] == hashlib.new("sha3_384", content).hexdigest()
        assert digests["SHA3-512"] == hashlib.new("sha3_512", content).hexdigest()


class TestValidateDownloadUrl:
    def test_rejects_file_scheme(self):
        with pytest.raises(TeaValidationError, match="http or https scheme"):
            _validate_download_url("file:///etc/passwd")

    def test_rejects_ftp_scheme(self):
        with pytest.raises(TeaValidationError, match="http or https scheme"):
            _validate_download_url("ftp://evil.com/file")

    def test_rejects_data_scheme(self):
        with pytest.raises(TeaValidationError, match="http or https scheme"):
            _validate_download_url("data:text/html,<h1>hi</h1>")

    def test_rejects_gopher_scheme(self):
        with pytest.raises(TeaValidationError, match="http or https scheme"):
            _validate_download_url("gopher://evil.com")

    def test_rejects_unknown_scheme(self):
        with pytest.raises(TeaValidationError, match="http or https scheme"):
            _validate_download_url("javascript:alert(1)")

    def test_rejects_missing_hostname(self):
        with pytest.raises(TeaValidationError, match="must include a hostname"):
            _validate_download_url("http:///path/only")

    def test_accepts_http(self):
        _validate_download_url("http://example.com/file.xml")

    def test_accepts_https(self):
        _validate_download_url("https://cdn.example.com/sbom.json")


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
