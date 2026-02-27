"""TeaClient — main entry point for the TEA consumer (read-only) API.

Provides high-level methods for discovery, product/component lookup,
collection retrieval, CLE queries, and artifact download with checksum
verification. All HTTP is delegated to :class:`~libtea._http.TeaHttpClient`.
"""

import hmac
import logging
import uuid as _uuid
import warnings
from pathlib import Path
from types import TracebackType
from typing import Any, Self, TypeVar

import requests
from pydantic import BaseModel, ValidationError

from libtea._http import USER_AGENT, MtlsConfig, TeaHttpClient
from libtea.discovery import fetch_well_known, select_endpoints
from libtea.exceptions import (
    TeaChecksumError,
    TeaConnectionError,
    TeaDiscoveryError,
    TeaServerError,
    TeaValidationError,
)
from libtea.models import (
    CLE,
    Artifact,
    Checksum,
    Collection,
    Component,
    ComponentReleaseWithCollection,
    DiscoveryInfo,
    PaginatedProductReleaseResponse,
    PaginatedProductResponse,
    Product,
    ProductRelease,
    Release,
)

logger = logging.getLogger("libtea")

TEA_SPEC_VERSION = "0.3.0-beta.2"

_M = TypeVar("_M", bound=BaseModel)


def _validate(model_cls: type[_M], data: Any) -> _M:
    """Validate a JSON-decoded value against a Pydantic model.

    Wraps :meth:`pydantic.BaseModel.model_validate`, converting any
    :class:`~pydantic.ValidationError` into :class:`TeaValidationError`
    so callers only need to catch the ``TeaError`` hierarchy.
    """
    try:
        return model_cls.model_validate(data)
    except ValidationError as exc:
        raise TeaValidationError(f"Invalid {model_cls.__name__} response: {exc}") from exc


def _validate_list(model_cls: type[_M], data: Any) -> list[_M]:
    """Validate a JSON array where each element conforms to a Pydantic model.

    Raises :class:`TeaValidationError` if ``data`` is not a list or any
    element fails validation.
    """
    if not isinstance(data, list):
        raise TeaValidationError(f"Expected list for {model_cls.__name__}, got {type(data).__name__}")
    try:
        return [model_cls.model_validate(item) for item in data]
    except ValidationError as exc:
        raise TeaValidationError(f"Invalid {model_cls.__name__} response: {exc}") from exc


def _validate_path_segment(value: str, name: str = "uuid") -> str:
    """Validate that a value is a valid UUID per TEA spec (RFC 4122).

    The TEA OpenAPI spec defines all path ``{uuid}`` parameters as
    ``format: uuid`` with pattern ``^[0-9a-f]{8}-...-[0-9a-f]{12}$``.

    Raises:
        TeaValidationError: If the value is empty or not a valid UUID.
    """
    if not value:
        raise TeaValidationError(f"Invalid {name}: must not be empty.")
    try:
        parsed = _uuid.UUID(value)
    except ValueError:
        raise TeaValidationError(
            f"Invalid {name}: {value!r}. Must be a valid UUID (e.g. 'd4d9f54a-abcf-11ee-ac79-1a52914d44b1')."
        )
    return str(parsed)


_MAX_PAGE_SIZE = 10000


def _validate_page_size(page_size: int) -> None:
    """Validate that page_size is within acceptable bounds."""
    if page_size < 1 or page_size > _MAX_PAGE_SIZE:
        raise TeaValidationError(f"page_size must be between 1 and {_MAX_PAGE_SIZE}, got {page_size}")


def _validate_page_offset(page_offset: int) -> None:
    """Validate that page_offset is non-negative."""
    if page_offset < 0:
        raise TeaValidationError(f"page_offset must be >= 0, got {page_offset}")


def _validate_collection_version(version: int) -> None:
    """Validate that a collection version number is >= 1 per spec."""
    if version < 1:
        raise TeaValidationError(f"Collection version must be >= 1, got {version}")


_WEAK_HASH_ALGORITHMS = frozenset({"MD5", "SHA-1"})


def _probe_endpoint(url: str, timeout: float = 5.0, mtls: MtlsConfig | None = None) -> None:
    """Probe a URL to verify the server is reachable.

    Uses a standalone HEAD request with no auth and no retries so that
    failover between candidates is fast.

    Args:
        url: Endpoint URL to probe.
        timeout: Request timeout in seconds.
        mtls: Optional mutual TLS configuration for mTLS-only deployments.

    Raises:
        TeaConnectionError: If the endpoint is unreachable.
        TeaServerError: If the endpoint returns HTTP 5xx.
    """
    kwargs: dict[str, Any] = {
        "timeout": timeout,
        "allow_redirects": False,
        "headers": {"user-agent": USER_AGENT},
    }
    if mtls:
        kwargs["cert"] = (str(mtls.client_cert), str(mtls.client_key))
        if mtls.ca_bundle:
            kwargs["verify"] = str(mtls.ca_bundle)
    try:
        resp = requests.head(url, **kwargs)
        resp.close()
    except requests.RequestException as exc:
        raise TeaConnectionError(str(exc)) from exc
    if resp.status_code >= 500:
        raise TeaServerError(f"Server error: HTTP {resp.status_code}")


class TeaClient:
    """Synchronous client for the Transparency Exchange API (consumer / read-only).

    Supports context-manager usage for automatic resource cleanup::

        with TeaClient("https://tea.example.com/v1", token="...") as client:
            product = client.get_product(uuid)

    Args:
        base_url: TEA server base URL (e.g. ``https://tea.example.com/v1``).
        token: Optional bearer token for authentication. Mutually exclusive
            with ``basic_auth``. Rejected with plaintext HTTP.
        basic_auth: Optional ``(username, password)`` tuple for HTTP Basic auth.
            Mutually exclusive with ``token``. Rejected with plaintext HTTP.
        timeout: Request timeout in seconds (default 30).
        mtls: Optional :class:`~libtea.MtlsConfig` for mutual TLS authentication.
        max_retries: Number of automatic retries on 5xx responses (default 3).
        backoff_factor: Exponential backoff multiplier between retries (default 0.5).
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
        self._http = TeaHttpClient(
            base_url=base_url,
            token=token,
            basic_auth=basic_auth,
            timeout=timeout,
            mtls=mtls,
            max_retries=max_retries,
            backoff_factor=backoff_factor,
        )

    @classmethod
    def from_well_known(
        cls,
        domain: str,
        *,
        token: str | None = None,
        basic_auth: tuple[str, str] | None = None,
        timeout: float = 30.0,
        version: str = TEA_SPEC_VERSION,
        scheme: str = "https",
        port: int | None = None,
        mtls: MtlsConfig | None = None,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
    ) -> Self:
        """Create a client by discovering the TEA endpoint from a domain's .well-known/tea.

        Fetches the ``.well-known/tea`` document, selects all endpoints compatible
        with the requested ``version`` (SemVer match), and probes each in priority
        order. If an endpoint is unreachable or returns a server error, the next
        candidate is tried (per TEA spec: "MUST retry ... with the next endpoint").

        Args:
            domain: Domain name to resolve (e.g. ``tea.example.com``).
            token: Optional bearer token.
            basic_auth: Optional ``(username, password)`` tuple.
            timeout: Request timeout in seconds (default 30).
            version: TEA spec SemVer to match against (default: library's built-in version).
            scheme: URL scheme for discovery — ``"https"`` (default) or ``"http"``.
            port: Optional port for ``.well-known`` resolution.
            mtls: Optional :class:`~libtea.MtlsConfig`.
            max_retries: Retry count on 5xx (default 3).
            backoff_factor: Backoff multiplier (default 0.5).

        Returns:
            A connected :class:`TeaClient` pointing at the best reachable endpoint.

        Raises:
            TeaDiscoveryError: If no compatible or reachable endpoint is found.
            TeaConnectionError: If all candidate endpoints are unreachable.
            TeaServerError: If all candidate endpoints return 5xx.
        """
        well_known = fetch_well_known(domain, timeout=timeout, scheme=scheme, port=port, mtls=mtls)
        candidates = select_endpoints(well_known, version)

        last_error: Exception | None = None
        for endpoint in candidates:
            base_url = f"{endpoint.url.rstrip('/')}/v{version}"
            try:
                _probe_endpoint(base_url, timeout=min(timeout, 5.0), mtls=mtls)
            except (TeaConnectionError, TeaServerError) as exc:
                logger.warning("Endpoint %s unreachable, trying next: %s", base_url, exc)
                last_error = exc
                continue
            return cls(
                base_url=base_url,
                token=token,
                basic_auth=basic_auth,
                timeout=timeout,
                mtls=mtls,
                max_retries=max_retries,
                backoff_factor=backoff_factor,
            )

        if last_error:
            raise last_error
        raise TeaDiscoveryError(f"No reachable endpoint found for version {version!r}")  # pragma: no cover

    # --- Discovery ---

    def discover(self, tei: str) -> list[DiscoveryInfo]:
        """Resolve a TEI to product release UUID(s) via the discovery endpoint.

        Args:
            tei: TEI URN string (e.g. ``urn:tei:purl:example.com:pkg:pypi/lib@1.0``).

        Returns:
            List of discovery results, each with a product release UUID and servers.

        Raises:
            TeaValidationError: If the response is malformed.
            TeaConnectionError: On network failure.
        """
        # requests auto-encodes query params — do NOT pre-encode with quote()
        data = self._http.get_json("/discovery", params={"tei": tei})
        return _validate_list(DiscoveryInfo, data)

    # --- Products ---

    def search_products(
        self, id_type: str, id_value: str, *, page_offset: int = 0, page_size: int = 100
    ) -> PaginatedProductResponse:
        """Search for products by identifier (e.g. PURL, CPE, TEI).

        Args:
            id_type: Identifier type (e.g. ``"PURL"``, ``"CPE"``, ``"TEI"``).
            id_value: Identifier value to search for.
            page_offset: Zero-based page offset (default 0).
            page_size: Number of results per page (default 100, max 10000).

        Returns:
            Paginated response containing matching products.
        """
        _validate_page_size(page_size)
        _validate_page_offset(page_offset)
        data = self._http.get_json(
            "/products",
            params={"idType": id_type, "idValue": id_value, "pageOffset": page_offset, "pageSize": page_size},
        )
        return _validate(PaginatedProductResponse, data)

    def get_product(self, uuid: str) -> Product:
        """Get a TEA product by UUID.

        Args:
            uuid: Product UUID.

        Returns:
            The product with its identifiers.
        """
        data = self._http.get_json(f"/product/{_validate_path_segment(uuid)}")
        return _validate(Product, data)

    def get_product_releases(
        self, uuid: str, *, page_offset: int = 0, page_size: int = 100
    ) -> PaginatedProductReleaseResponse:
        """Get paginated releases for a product.

        Args:
            uuid: Product UUID.
            page_offset: Zero-based page offset.
            page_size: Number of results per page.

        Returns:
            Paginated response containing product releases.
        """
        _validate_page_size(page_size)
        _validate_page_offset(page_offset)
        data = self._http.get_json(
            f"/product/{_validate_path_segment(uuid)}/releases",
            params={"pageOffset": page_offset, "pageSize": page_size},
        )
        return _validate(PaginatedProductReleaseResponse, data)

    # --- Product Releases ---

    def search_product_releases(
        self, id_type: str, id_value: str, *, page_offset: int = 0, page_size: int = 100
    ) -> PaginatedProductReleaseResponse:
        """Search for product releases by identifier (e.g. PURL, CPE, TEI).

        Args:
            id_type: Identifier type (e.g. ``"PURL"``, ``"CPE"``, ``"TEI"``).
            id_value: Identifier value to search for.
            page_offset: Zero-based page offset (default 0).
            page_size: Number of results per page (default 100, max 10000).

        Returns:
            Paginated response containing matching product releases.
        """
        _validate_page_size(page_size)
        _validate_page_offset(page_offset)
        data = self._http.get_json(
            "/productReleases",
            params={"idType": id_type, "idValue": id_value, "pageOffset": page_offset, "pageSize": page_size},
        )
        return _validate(PaginatedProductReleaseResponse, data)

    def get_product_release(self, uuid: str) -> ProductRelease:
        """Get a product release by UUID.

        Args:
            uuid: Product release UUID.

        Returns:
            The product release with its component references.
        """
        data = self._http.get_json(f"/productRelease/{_validate_path_segment(uuid)}")
        return _validate(ProductRelease, data)

    def get_product_release_collection_latest(self, uuid: str) -> Collection:
        """Get the latest collection for a product release.

        Args:
            uuid: Product release UUID.

        Returns:
            The latest collection with its artifacts.
        """
        data = self._http.get_json(f"/productRelease/{_validate_path_segment(uuid)}/collection/latest")
        return _validate(Collection, data)

    def get_product_release_collections(self, uuid: str) -> list[Collection]:
        """Get all collection versions for a product release.

        Args:
            uuid: Product release UUID.

        Returns:
            List of all collection versions.
        """
        data = self._http.get_json(f"/productRelease/{_validate_path_segment(uuid)}/collections")
        return _validate_list(Collection, data)

    def get_product_release_collection(self, uuid: str, version: int) -> Collection:
        """Get a specific collection version for a product release.

        Args:
            uuid: Product release UUID.
            version: Collection version number (starts at 1).

        Returns:
            The requested collection version.
        """
        _validate_collection_version(version)
        data = self._http.get_json(f"/productRelease/{_validate_path_segment(uuid)}/collection/{version}")
        return _validate(Collection, data)

    # --- Components ---

    def get_component(self, uuid: str) -> Component:
        """Get a TEA component by UUID.

        Args:
            uuid: Component UUID.

        Returns:
            The component with its identifiers.
        """
        data = self._http.get_json(f"/component/{_validate_path_segment(uuid)}")
        return _validate(Component, data)

    def get_component_releases(self, uuid: str) -> list[Release]:
        """Get all releases for a component.

        Unlike product releases, component releases are not paginated.

        Args:
            uuid: Component UUID.

        Returns:
            List of component releases.
        """
        data = self._http.get_json(f"/component/{_validate_path_segment(uuid)}/releases")
        return _validate_list(Release, data)

    # --- Component Releases ---

    def get_component_release(self, uuid: str) -> ComponentReleaseWithCollection:
        """Get a component release with its latest collection.

        Args:
            uuid: Component release UUID.

        Returns:
            The release bundled with its latest collection of artifacts.
        """
        data = self._http.get_json(f"/componentRelease/{_validate_path_segment(uuid)}")
        return _validate(ComponentReleaseWithCollection, data)

    def get_component_release_collection_latest(self, uuid: str) -> Collection:
        """Get the latest collection for a component release.

        Args:
            uuid: Component release UUID.

        Returns:
            The latest collection with its artifacts.
        """
        data = self._http.get_json(f"/componentRelease/{_validate_path_segment(uuid)}/collection/latest")
        return _validate(Collection, data)

    def get_component_release_collections(self, uuid: str) -> list[Collection]:
        """Get all collection versions for a component release.

        Args:
            uuid: Component release UUID.

        Returns:
            List of all collection versions.
        """
        data = self._http.get_json(f"/componentRelease/{_validate_path_segment(uuid)}/collections")
        return _validate_list(Collection, data)

    def get_component_release_collection(self, uuid: str, version: int) -> Collection:
        """Get a specific collection version for a component release.

        Args:
            uuid: Component release UUID.
            version: Collection version number (starts at 1).

        Returns:
            The requested collection version.
        """
        _validate_collection_version(version)
        data = self._http.get_json(f"/componentRelease/{_validate_path_segment(uuid)}/collection/{version}")
        return _validate(Collection, data)

    # --- CLE ---

    def get_product_cle(self, uuid: str) -> CLE:
        """Get CLE (Common Lifecycle Enumeration) data for a product.

        Args:
            uuid: Product UUID.

        Returns:
            The CLE document with lifecycle events and optional definitions.
        """
        data = self._http.get_json(f"/product/{_validate_path_segment(uuid)}/cle")
        return _validate(CLE, data)

    def get_product_release_cle(self, uuid: str) -> CLE:
        """Get CLE data for a product release.

        Args:
            uuid: Product release UUID.

        Returns:
            The CLE document with lifecycle events and optional definitions.
        """
        data = self._http.get_json(f"/productRelease/{_validate_path_segment(uuid)}/cle")
        return _validate(CLE, data)

    def get_component_cle(self, uuid: str) -> CLE:
        """Get CLE data for a component.

        Args:
            uuid: Component UUID.

        Returns:
            The CLE document with lifecycle events and optional definitions.
        """
        data = self._http.get_json(f"/component/{_validate_path_segment(uuid)}/cle")
        return _validate(CLE, data)

    def get_component_release_cle(self, uuid: str) -> CLE:
        """Get CLE data for a component release.

        Args:
            uuid: Component release UUID.

        Returns:
            The CLE document with lifecycle events and optional definitions.
        """
        data = self._http.get_json(f"/componentRelease/{_validate_path_segment(uuid)}/cle")
        return _validate(CLE, data)

    # --- Artifacts ---

    def get_artifact(self, uuid: str) -> Artifact:
        """Get artifact metadata by UUID.

        Args:
            uuid: Artifact UUID.

        Returns:
            The artifact with its formats and download URLs.
        """
        data = self._http.get_json(f"/artifact/{_validate_path_segment(uuid)}")
        return _validate(Artifact, data)

    def download_artifact(
        self,
        url: str,
        dest: Path,
        *,
        verify_checksums: list[Checksum] | None = None,
        max_download_bytes: int | None = None,
    ) -> Path:
        """Download an artifact file, optionally verifying checksums.

        Uses a separate unauthenticated session so the bearer token is not
        leaked to third-party artifact hosts.

        Args:
            url: Direct download URL for the artifact.
            dest: Local file path to write to.
            verify_checksums: Optional list of checksums to verify after download.
                On mismatch the downloaded file is deleted.
            max_download_bytes: Optional maximum download size in bytes.

        Returns:
            The destination path.

        Raises:
            TeaChecksumError: If checksum verification fails.
            TeaConnectionError: On network failure.
            TeaValidationError: If download exceeds max_download_bytes.
        """
        if verify_checksums:
            weak = {cs.algorithm_type.value for cs in verify_checksums} & _WEAK_HASH_ALGORITHMS
            if weak:
                warnings.warn(
                    f"Verifying with weak hash algorithm(s): {', '.join(sorted(weak))}. Prefer SHA-256 or stronger.",
                    stacklevel=2,
                )
        algorithms = [cs.algorithm_type.value for cs in verify_checksums] if verify_checksums else None
        computed = self._http.download_with_hashes(
            url, dest, algorithms=algorithms, max_download_bytes=max_download_bytes
        )

        if verify_checksums:
            self._verify_checksums(verify_checksums, computed, url, dest)

        return dest

    @staticmethod
    def _verify_checksums(checksums: list[Checksum], computed: dict[str, str], url: str, dest: Path) -> None:
        """Verify computed checksums against expected values, cleaning up on failure.

        Uses :func:`hmac.compare_digest` for constant-time comparison.
        Deletes the downloaded file at ``dest`` on the first mismatch.

        Raises:
            TeaChecksumError: If any checksum does not match.
        """
        for cs in checksums:
            alg_name = cs.algorithm_type.value
            expected = cs.algorithm_value.lower()
            if alg_name not in computed:
                dest.unlink(missing_ok=True)
                raise TeaChecksumError(
                    f"No computed digest for algorithm: {alg_name}",
                    algorithm=alg_name,
                    expected=expected,
                    actual=None,
                )
            actual = computed[alg_name].lower()
            if not hmac.compare_digest(actual, expected):
                dest.unlink(missing_ok=True)
                logger.error(
                    "Checksum mismatch for %s: algorithm=%s expected=%s actual=%s",
                    url,
                    alg_name,
                    expected,
                    actual,
                )
                raise TeaChecksumError(
                    f"{alg_name} mismatch: expected {expected}, got {actual}",
                    algorithm=alg_name,
                    expected=expected,
                    actual=actual,
                )

    # --- Lifecycle ---

    def close(self) -> None:
        """Close the underlying HTTP session and clear credentials."""
        self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()
