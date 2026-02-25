"""Internal HTTP client wrapping httpx with TEA error handling."""

import hashlib
from pathlib import Path
from typing import Any

import httpx

from libtea.exceptions import (
    TeaAuthenticationError,
    TeaConnectionError,
    TeaNotFoundError,
    TeaRequestError,
    TeaServerError,
)


class TeaHttpClient:
    """Low-level HTTP client for TEA API requests."""

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        timeout: float = 30.0,
    ):
        headers = {"user-agent": "py-libtea"}
        if token:
            headers["authorization"] = f"Bearer {token}"

        self._timeout = timeout
        self._client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
        )

    def get_json(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        """Send GET request and return parsed JSON."""
        try:
            response = self._client.get(path, params=params)
        except httpx.TransportError as exc:
            raise TeaConnectionError(str(exc)) from exc

        self._raise_for_status(response)
        return response.json()

    def download_with_hashes(self, url: str, dest: Path, algorithms: list[str] | None = None) -> dict[str, str]:
        """Download a file and compute checksums on-the-fly. Returns {algorithm: hex_digest}.

        Uses a separate unauthenticated httpx client so that the bearer token
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

        try:
            with httpx.Client(
                headers={"user-agent": "py-libtea"},
                timeout=self._timeout,
            ) as download_client:
                with download_client.stream("GET", url) as response:
                    self._raise_for_status(response)
                    with open(dest, "wb") as f:
                        for chunk in response.iter_bytes(chunk_size=8192):
                            f.write(chunk)
                            for h in hashers.values():
                                h.update(chunk)
        except httpx.TransportError as exc:
            dest.unlink(missing_ok=True)
            raise TeaConnectionError(str(exc)) from exc
        except Exception:
            dest.unlink(missing_ok=True)
            raise

        return {alg: h.hexdigest() for alg, h in hashers.items()}

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
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
