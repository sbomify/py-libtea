"""Internal HTTP client wrapping requests with TEA error handling."""

import hashlib
import logging
import warnings
from pathlib import Path
from types import TracebackType
from typing import Any, Self
from urllib.parse import urlparse

import requests

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

logger = logging.getLogger("libtea")

# Hash algorithm registry: {TEA name: (hashlib name, digest_size)}.
# When digest_size is None, hashlib.new(name) is used with its default size.
# When digest_size is set, hashlib.blake2b(digest_size=N) is used instead.
# BLAKE3 is intentionally excluded — handled separately in _build_hashers.
_HASH_REGISTRY: dict[str, tuple[str, int | None]] = {
    "MD5": ("md5", None),
    "SHA-1": ("sha1", None),
    "SHA-256": ("sha256", None),
    "SHA-384": ("sha384", None),
    "SHA-512": ("sha512", None),
    "SHA3-256": ("sha3_256", None),
    "SHA3-384": ("sha3_384", None),
    "SHA3-512": ("sha3_512", None),
    "BLAKE2b-256": ("blake2b", 32),
    "BLAKE2b-384": ("blake2b", 48),
    "BLAKE2b-512": ("blake2b", 64),
}


def _get_package_version() -> str:
    """Get the package version for User-Agent header."""
    try:
        from importlib.metadata import PackageNotFoundError, version

        return version("libtea")
    except (PackageNotFoundError, ValueError):
        return "unknown"


USER_AGENT = f"py-libtea/{_get_package_version()} (hello@sbomify.com)"

_BLOCKED_SCHEMES = frozenset({"file", "ftp", "gopher", "data"})


def _build_hashers(algorithms: list[str]) -> dict[str, Any]:
    """Build hashlib hasher objects for the given algorithm names."""
    hashers: dict[str, Any] = {}
    for alg in algorithms:
        if alg == "BLAKE3":
            raise TeaChecksumError(
                "BLAKE3 is not supported by Python's hashlib. "
                "Install the 'blake3' package or use a different algorithm.",
                algorithm="BLAKE3",
            )
        entry = _HASH_REGISTRY.get(alg)
        if entry is None:
            raise TeaChecksumError(
                f"Unsupported checksum algorithm: {alg!r}. Supported: {', '.join(sorted(_HASH_REGISTRY.keys()))}",
                algorithm=alg,
            )
        hashlib_name, digest_size = entry
        if digest_size is not None:
            hashers[alg] = hashlib.blake2b(digest_size=digest_size)
        else:
            hashers[alg] = hashlib.new(hashlib_name)
    return hashers


def _validate_download_url(url: str) -> None:
    """Reject download URLs that use non-HTTP schemes."""
    parsed = urlparse(url)
    if parsed.scheme in _BLOCKED_SCHEMES or parsed.scheme not in ("http", "https"):
        raise TeaValidationError(f"Artifact download URL must use http or https scheme, got {parsed.scheme!r}")
    if not parsed.hostname:
        raise TeaValidationError(f"Artifact download URL must include a hostname: {url!r}")


class TeaHttpClient:
    """Low-level HTTP client for TEA API requests.

    Handles authentication headers, error mapping, and streaming downloads.
    Uses a separate unauthenticated session for artifact downloads to avoid
    leaking bearer tokens to third-party hosts.

    Args:
        base_url: TEA server base URL.
        token: Optional bearer token. Rejected with plaintext HTTP.
        timeout: Request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        timeout: float = 30.0,
    ):
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"base_url must use http or https scheme, got {parsed.scheme!r}")
        if not parsed.hostname:
            raise ValueError(f"base_url must include a hostname: {base_url!r}")
        if parsed.scheme == "http" and token:
            raise ValueError("Cannot use bearer token with plaintext HTTP. Use https:// or remove the token.")
        if parsed.scheme == "http":
            warnings.warn(
                "Using plaintext HTTP is insecure. Use HTTPS in production.",
                TeaInsecureTransportWarning,
                stacklevel=2,
            )
        self._base_url = parsed.geturl().rstrip("/")
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers["user-agent"] = USER_AGENT
        if token:
            self._session.headers["authorization"] = f"Bearer {token}"

    def get_json(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        """Send GET request and return parsed JSON.

        Args:
            path: URL path relative to base URL (e.g. ``/product/{uuid}``).
            params: Optional query parameters.

        Returns:
            Parsed JSON response body.

        Raises:
            TeaConnectionError: On network failure.
            TeaNotFoundError: On HTTP 404.
            TeaAuthenticationError: On HTTP 401/403.
            TeaServerError: On HTTP 5xx.
        """
        url = f"{self._base_url}{path}"
        try:
            response = self._session.get(url, params=params, timeout=self._timeout, allow_redirects=False)
        except requests.ConnectionError as exc:
            logger.warning("Connection error for %s: %s", url, exc)
            raise TeaConnectionError(str(exc)) from exc
        except requests.Timeout as exc:
            logger.warning("Timeout for %s: %s", url, exc)
            raise TeaConnectionError(str(exc)) from exc
        except requests.RequestException as exc:
            logger.warning("Request error for %s: %s", url, exc)
            raise TeaConnectionError(str(exc)) from exc

        self._raise_for_status(response)
        try:
            return response.json()
        except ValueError as exc:
            raise TeaValidationError(f"Invalid JSON in response: {exc}") from exc

    def download_with_hashes(self, url: str, dest: Path, algorithms: list[str] | None = None) -> dict[str, str]:
        """Download a file and compute checksums on-the-fly.

        Uses a separate unauthenticated session so that the bearer token
        is not leaked to third-party artifact hosts (CDNs, Maven Central, etc.).

        Args:
            url: Direct download URL.
            dest: Local file path to write to. Parent directories are created.
            algorithms: Optional list of checksum algorithm names to compute.

        Returns:
            Dict mapping algorithm name to hex digest string.

        Raises:
            TeaConnectionError: On network failure. Partial files are deleted.
            TeaChecksumError: If an unsupported algorithm is requested.
        """
        _validate_download_url(url)
        hashers = _build_hashers(algorithms) if algorithms else {}

        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            with requests.Session() as download_session:
                download_session.headers["user-agent"] = USER_AGENT
                response = download_session.get(url, stream=True, timeout=self._timeout)
                self._raise_for_status(response)
                with open(dest, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                        for h in hashers.values():
                            h.update(chunk)
        except (requests.ConnectionError, requests.Timeout) as exc:
            dest.unlink(missing_ok=True)
            raise TeaConnectionError(str(exc)) from exc
        except requests.RequestException as exc:
            dest.unlink(missing_ok=True)
            raise TeaConnectionError(f"Download failed: {exc}") from exc
        except Exception:
            try:
                dest.unlink(missing_ok=True)
            except OSError:
                logger.warning("Failed to clean up partial download at %s", dest)
            raise

        return {alg: h.hexdigest() for alg, h in hashers.items()}

    def close(self) -> None:
        self._session.headers.pop("authorization", None)
        self._session.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    @staticmethod
    def _raise_for_status(response: requests.Response) -> None:
        """Map HTTP status codes to typed exceptions."""
        status = response.status_code
        if 200 <= status < 300:
            return
        if 300 <= status < 400:
            raise TeaRequestError(f"Unexpected redirect: HTTP {status}")
        if status in (401, 403):
            logger.warning("Authentication failed: HTTP %d for %s", status, response.url)
            raise TeaAuthenticationError(f"Authentication failed: HTTP {status}")
        if status == 404:
            error_type = None
            try:
                body = response.json()
                if isinstance(body, dict):
                    error_type = body.get("error")
            except ValueError:
                pass
            raise TeaNotFoundError(f"Not found: HTTP {status}", error_type=error_type)
        if status >= 500:
            raise TeaServerError(f"Server error: HTTP {status}")
        # Remaining 4xx codes (400, 405-499 excluding 401/403/404)
        body_text = response.text[:200] if response.text else ""
        msg = f"Client error: HTTP {status}"
        if body_text:
            msg = f"{msg} — {body_text}"
        raise TeaRequestError(msg)
