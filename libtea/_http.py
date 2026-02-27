"""Internal HTTP client wrapping ``requests`` with TEA-specific error handling.

This module is an implementation detail. Public consumers should use
:class:`~libtea.client.TeaClient` instead.
"""

import hashlib
import ipaddress
import logging
import socket
import warnings
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Self
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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


@dataclass(frozen=True)
class MtlsConfig:
    """Client certificate configuration for mutual TLS (mTLS).

    Attributes:
        client_cert: Path to the PEM-encoded client certificate.
        client_key: Path to the PEM-encoded client private key.
        ca_bundle: Optional path to a CA bundle for server certificate
            verification. When ``None``, the system default CA store is used.
    """

    client_cert: Path
    client_key: Path
    ca_bundle: Path | None = None


def _build_hashers(algorithms: list[str]) -> dict[str, Any]:
    """Build ``hashlib`` hasher objects for the given TEA algorithm names.

    Args:
        algorithms: List of TEA checksum algorithm names (e.g. ``["SHA-256", "BLAKE2b-256"]``).

    Returns:
        Dict mapping algorithm name to a fresh hashlib hash object.

    Raises:
        TeaChecksumError: If BLAKE3 is requested (not in stdlib) or the algorithm is unknown.
    """
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


_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata.google.internal.",
    }
)

# RFC 6598 CGNAT range — ipaddress.is_private misses this on Python 3.11+.
_CGNAT_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")

_MAX_DOWNLOAD_REDIRECTS = 10


def _is_internal_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if the IP address is non-global: private, loopback, link-local, reserved, unspecified, multicast, or CGNAT."""
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        return True
    if addr.is_unspecified or addr.is_multicast:
        return True
    if isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT_NETWORK:
        return True
    return False


def _validate_resolved_ips(hostname: str) -> None:
    """Resolve hostname via DNS and reject if any resolved IP is private/internal.

    Note: There is an inherent TOCTOU (time-of-check-time-of-use) gap between
    this DNS check and the actual HTTP request made by ``requests``.  A DNS
    rebinding attack could return a safe IP here and a malicious IP for the
    subsequent connection.  Fully closing this gap would require socket-level
    IP pinning, which ``requests`` does not support.  This check still raises
    the bar significantly against naive SSRF attempts.
    """
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        logger.warning("DNS resolution failed for %s during SSRF check; proceeding with request", hostname)
        return
    for _, _, _, _, sockaddr in addr_infos:
        resolved_ip = sockaddr[0]
        try:
            addr = ipaddress.ip_address(resolved_ip)
            if _is_internal_ip(addr):
                raise TeaValidationError(
                    f"Artifact download URL hostname {hostname!r} resolves to private/internal IP: {resolved_ip}"
                )
        except ValueError:
            pass


def _validate_download_url(url: str) -> None:
    """Reject download URLs that use non-HTTP schemes or target internal networks."""
    parsed = urlparse(url)
    if parsed.scheme in _BLOCKED_SCHEMES or parsed.scheme not in ("http", "https"):
        raise TeaValidationError(f"Artifact download URL must use http or https scheme, got {parsed.scheme!r}")
    if not parsed.hostname:
        raise TeaValidationError(f"Artifact download URL must include a hostname: {url!r}")

    hostname = parsed.hostname.lower()
    if hostname in _BLOCKED_HOSTNAMES:
        raise TeaValidationError(f"Artifact download URL must not target internal hosts: {hostname!r}")

    try:
        addr = ipaddress.ip_address(hostname)
        if _is_internal_ip(addr):
            raise TeaValidationError(f"Artifact download URL must not target private/internal IP: {hostname!r}")
    except ValueError:
        # Not an IP literal — resolve hostname and check resolved IPs (DNS rebinding protection)
        _validate_resolved_ips(hostname)


class TeaHttpClient:
    """Low-level HTTP client for TEA API requests.

    Handles authentication headers, error mapping, and streaming downloads.
    Uses a separate unauthenticated session for artifact downloads to avoid
    leaking bearer tokens to third-party hosts (CDNs, Maven Central, etc.).

    Args:
        base_url: TEA server base URL (e.g. ``https://tea.example.com/v1``).
        token: Optional bearer token. Mutually exclusive with ``basic_auth``.
            Rejected when ``base_url`` uses plaintext HTTP.
        basic_auth: Optional ``(username, password)`` tuple for HTTP Basic auth.
            Mutually exclusive with ``token``. Rejected with plaintext HTTP.
        timeout: Request timeout in seconds (default 30).
        mtls: Optional :class:`MtlsConfig` for mutual TLS authentication.
        max_retries: Number of retries on 5xx responses (default 3). Set to 0 to disable.
        backoff_factor: Exponential backoff factor between retries (default 0.5).

    Raises:
        ValueError: If ``base_url`` is invalid, or both ``token`` and ``basic_auth`` are set,
            or credentials are used with plaintext HTTP.
    """

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        basic_auth: tuple[str, str] | None = None,
        timeout: float = 30.0,
        mtls: MtlsConfig | None = None,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
    ):
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"base_url must use http or https scheme, got {parsed.scheme!r}")
        if not parsed.hostname:
            raise ValueError(f"base_url must include a hostname: {base_url!r}")
        if token and basic_auth:
            raise ValueError("Cannot use both token and basic_auth.")
        if parsed.scheme == "http" and token:
            raise ValueError("Cannot use bearer token with plaintext HTTP. Use https:// or remove the token.")
        if parsed.scheme == "http" and basic_auth:
            raise ValueError("Cannot use basic auth with plaintext HTTP. Use https:// or remove basic_auth.")
        if max_retries < 0:
            raise ValueError(f"max_retries must be >= 0, got {max_retries}")
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
        elif basic_auth:
            self._session.auth = basic_auth

        if mtls:
            self._session.cert = (str(mtls.client_cert), str(mtls.client_key))
            if mtls.ca_bundle:
                self._session.verify = str(mtls.ca_bundle)

        retry = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=(500, 502, 503, 504),
            allowed_methods=["GET", "HEAD", "OPTIONS"],
            raise_on_status=False,
            respect_retry_after_header=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

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

    def download_with_hashes(
        self,
        url: str,
        dest: Path,
        algorithms: list[str] | None = None,
        *,
        max_download_bytes: int | None = None,
    ) -> dict[str, str]:
        """Download a file and compute checksums on-the-fly.

        Uses a separate unauthenticated session so that the bearer token
        is not leaked to third-party artifact hosts (CDNs, Maven Central, etc.).
        Redirects are followed manually with SSRF validation at each hop.

        Args:
            url: Direct download URL.
            dest: Local file path to write to. Parent directories are created.
            algorithms: Optional list of checksum algorithm names to compute.
            max_download_bytes: Optional maximum download size in bytes.

        Returns:
            Dict mapping algorithm name to hex digest string.

        Raises:
            TeaConnectionError: On network failure. Partial files are deleted.
            TeaChecksumError: If an unsupported algorithm is requested.
            TeaValidationError: If download exceeds max_download_bytes or fails SSRF check.
        """
        _validate_download_url(url)
        hashers = _build_hashers(algorithms) if algorithms else {}

        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            with requests.Session() as download_session:
                download_session.headers["user-agent"] = USER_AGENT

                # Follow redirects manually with SSRF validation at each hop
                current_url = url
                response = None
                for _ in range(_MAX_DOWNLOAD_REDIRECTS):
                    response = download_session.get(
                        current_url, stream=True, timeout=self._timeout, allow_redirects=False
                    )
                    if 300 <= response.status_code < 400:
                        location = response.headers.get("Location")
                        if not location:
                            raise TeaRequestError(f"Redirect without Location header: HTTP {response.status_code}")
                        current_url = urljoin(current_url, location)
                        _validate_download_url(current_url)
                        response.close()
                        continue
                    break
                else:
                    raise TeaConnectionError(f"Too many redirects (max {_MAX_DOWNLOAD_REDIRECTS})")

                self._raise_for_status(response)

                downloaded = 0
                with open(dest, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        downloaded += len(chunk)
                        if max_download_bytes is not None and downloaded > max_download_bytes:
                            raise TeaValidationError(f"Download exceeds size limit of {max_download_bytes} bytes")
                        f.write(chunk)
                        for h in hashers.values():
                            h.update(chunk)
        except (requests.ConnectionError, requests.Timeout) as exc:
            dest.unlink(missing_ok=True)
            raise TeaConnectionError(str(exc)) from exc
        except requests.RequestException as exc:
            dest.unlink(missing_ok=True)
            raise TeaConnectionError(f"Download failed: {exc}") from exc
        except BaseException:
            try:
                dest.unlink(missing_ok=True)
            except OSError:
                logger.warning("Failed to clean up partial download at %s", dest)
            raise

        return {alg: h.hexdigest() for alg, h in hashers.items()}

    def close(self) -> None:
        """Close the HTTP session and clear sensitive credentials from memory."""
        self._session.headers.pop("authorization", None)
        self._session.auth = None
        self._session.cert = None
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
        """Map HTTP status codes to typed :mod:`~libtea.exceptions`.

        2xx passes through, 3xx raises :class:`TeaRequestError`,
        401/403 raises :class:`TeaAuthenticationError`, 404 raises
        :class:`TeaNotFoundError`, 5xx raises :class:`TeaServerError`,
        and remaining 4xx codes raise :class:`TeaRequestError`.
        """
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
        body_text = (response.text or "")[:200]
        if len(response.text or "") > 200:
            body_text += " (truncated)"
        msg = f"Client error: HTTP {status}"
        if body_text:
            msg = f"{msg} — {body_text}"
        raise TeaRequestError(msg)
