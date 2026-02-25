"""Internal HTTP client wrapping requests with TEA error handling."""

import hashlib
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from libtea.exceptions import (
    TeaAuthenticationError,
    TeaConnectionError,
    TeaNotFoundError,
    TeaRequestError,
    TeaServerError,
    TeaValidationError,
)


def _get_package_version() -> str:
    """Get the package version for User-Agent header."""
    try:
        from importlib.metadata import version

        return version("libtea")
    except Exception:
        try:
            import tomllib

            pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
            if pyproject_path.exists():
                with open(pyproject_path, "rb") as f:
                    pyproject_data = tomllib.load(f)
                return pyproject_data.get("project", {}).get("version", "unknown")
        except Exception:
            pass
        return "unknown"


USER_AGENT = f"py-libtea/{_get_package_version()} (hello@sbomify.com)"


class TeaHttpClient:
    """Low-level HTTP client for TEA API requests."""

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
        self._base_url = parsed.geturl().rstrip("/")
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers["user-agent"] = USER_AGENT
        if token:
            self._session.headers["authorization"] = f"Bearer {token}"

    def get_json(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        """Send GET request and return parsed JSON."""
        url = f"{self._base_url}{path}"
        try:
            response = self._session.get(url, params=params, timeout=self._timeout)
        except requests.ConnectionError as exc:
            raise TeaConnectionError(str(exc)) from exc
        except requests.Timeout as exc:
            raise TeaConnectionError(str(exc)) from exc

        self._raise_for_status(response)
        try:
            return response.json()
        except ValueError as exc:
            raise TeaValidationError(f"Invalid JSON in response: {exc}") from exc

    def download_with_hashes(self, url: str, dest: Path, algorithms: list[str] | None = None) -> dict[str, str]:
        """Download a file and compute checksums on-the-fly. Returns {algorithm: hex_digest}.

        Uses a separate unauthenticated session so that the bearer token
        is not leaked to third-party artifact hosts (CDNs, Maven Central, etc.).
        """
        from libtea.exceptions import TeaChecksumError

        hashers: dict[str, Any] = {}
        if algorithms:
            alg_map = {
                "MD5": "md5",
                "SHA-1": "sha1",
                "SHA-256": "sha256",
                "SHA-384": "sha384",
                "SHA-512": "sha512",
                "SHA3-256": "sha3_256",
                "SHA3-384": "sha3_384",
                "SHA3-512": "sha3_512",
                "BLAKE2b-256": "blake2b",
                "BLAKE2b-384": "blake2b",
                "BLAKE2b-512": "blake2b",
            }
            blake2b_sizes = {"BLAKE2b-256": 32, "BLAKE2b-384": 48, "BLAKE2b-512": 64}
            for alg in algorithms:
                if alg == "BLAKE3":
                    raise TeaChecksumError(
                        "BLAKE3 is not supported by Python's hashlib. "
                        "Install the 'blake3' package or use a different algorithm.",
                        algorithm="BLAKE3",
                    )
                hashlib_name = alg_map.get(alg)
                if hashlib_name == "blake2b":
                    hashers[alg] = hashlib.blake2b(digest_size=blake2b_sizes[alg])
                elif hashlib_name:
                    hashers[alg] = hashlib.new(hashlib_name)

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
        except Exception:
            dest.unlink(missing_ok=True)
            raise

        return {alg: h.hexdigest() for alg, h in hashers.items()}

    def close(self) -> None:
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @staticmethod
    def _raise_for_status(response: requests.Response) -> None:
        """Map HTTP status codes to typed exceptions."""
        status = response.status_code
        if 200 <= status < 300:
            return

        if status in (401, 403):
            raise TeaAuthenticationError(f"Authentication failed: HTTP {status}")
        elif status == 404:
            error_type = None
            try:
                body = response.json()
                error_type = body.get("error")
            except Exception:
                pass
            raise TeaNotFoundError(f"Not found: HTTP {status}", error_type=error_type)
        elif 400 <= status < 500:
            raise TeaRequestError(f"Client error: HTTP {status}")
        elif status >= 500:
            raise TeaServerError(f"Server error: HTTP {status}")
