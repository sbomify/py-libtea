"""Internal HTTP client wrapping httpx with TEA error handling."""

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

    def download(self, url: str, dest: Path) -> None:
        """Download a file from an absolute URL to dest path."""
        try:
            with self._client.stream("GET", url) as response:
                self._raise_for_status(response)
                with open(dest, "wb") as f:
                    for chunk in response.iter_bytes(chunk_size=8192):
                        f.write(chunk)
        except httpx.TransportError as exc:
            raise TeaConnectionError(str(exc)) from exc

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
