"""TeaClient - main entry point for the TEA consumer API."""

import hmac
import logging
from pathlib import Path
from types import TracebackType
from typing import Any, Self, TypeVar

from pydantic import BaseModel, ValidationError

from libtea._http import TeaHttpClient
from libtea.discovery import fetch_well_known, select_endpoint
from libtea.exceptions import TeaChecksumError, TeaValidationError
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

# Restrict URL path segments to safe characters to prevent path traversal and injection.
_SAFE_PATH_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")


def _validate(model_cls: type[_M], data: Any) -> _M:
    """Validate data against a Pydantic model, wrapping errors in TeaValidationError."""
    try:
        return model_cls.model_validate(data)
    except ValidationError as exc:
        raise TeaValidationError(f"Invalid {model_cls.__name__} response: {exc}") from exc


def _validate_list(model_cls: type[_M], data: Any) -> list[_M]:
    """Validate a list of items against a Pydantic model."""
    if not isinstance(data, list):
        raise TeaValidationError(f"Expected list for {model_cls.__name__}, got {type(data).__name__}")
    try:
        return [model_cls.model_validate(item) for item in data]
    except ValidationError as exc:
        raise TeaValidationError(f"Invalid {model_cls.__name__} response: {exc}") from exc


def _validate_path_segment(value: str, name: str = "uuid") -> str:
    """Validate that a value is safe to interpolate into a URL path."""
    if not value:
        raise TeaValidationError(f"Invalid {name}: must not be empty.")
    if len(value) > 128 or not all(c in _SAFE_PATH_CHARS for c in value):
        raise TeaValidationError(
            f"Invalid {name}: {value!r}. Must contain only alphanumeric characters and hyphens, max 128 characters."
        )
    return value


class TeaClient:
    """Synchronous client for the Transparency Exchange API.

    Args:
        base_url: TEA server base URL (e.g. ``https://tea.example.com/v1``).
        token: Optional bearer token for authentication.
        timeout: Request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        timeout: float = 30.0,
    ):
        self._http = TeaHttpClient(base_url=base_url, token=token, timeout=timeout)

    @classmethod
    def from_well_known(
        cls,
        domain: str,
        *,
        token: str | None = None,
        timeout: float = 30.0,
        version: str = TEA_SPEC_VERSION,
        scheme: str = "https",
        port: int | None = None,
    ) -> Self:
        """Create a client by discovering the TEA endpoint from a domain's .well-known/tea."""
        well_known = fetch_well_known(domain, timeout=timeout, scheme=scheme, port=port)
        endpoint = select_endpoint(well_known, version)
        base_url = f"{endpoint.url.rstrip('/')}/v{version}"
        return cls(base_url=base_url, token=token, timeout=timeout)

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
        """Search for products by identifier (e.g. PURL, CPE, TEI)."""
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
        data = self._http.get_json(
            f"/product/{_validate_path_segment(uuid)}/releases",
            params={"pageOffset": page_offset, "pageSize": page_size},
        )
        return _validate(PaginatedProductReleaseResponse, data)

    # --- Product Releases ---

    def search_product_releases(
        self, id_type: str, id_value: str, *, page_offset: int = 0, page_size: int = 100
    ) -> PaginatedProductReleaseResponse:
        """Search for product releases by identifier (e.g. PURL, CPE, TEI)."""
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
        data = self._http.get_json(f"/componentRelease/{_validate_path_segment(uuid)}/collection/{version}")
        return _validate(Collection, data)

    # --- CLE ---

    def get_product_cle(self, uuid: str) -> CLE:
        """Get CLE (Common Lifecycle Enumeration) data for a product."""
        data = self._http.get_json(f"/product/{_validate_path_segment(uuid)}/cle")
        return _validate(CLE, data)

    def get_product_release_cle(self, uuid: str) -> CLE:
        """Get CLE data for a product release."""
        data = self._http.get_json(f"/productRelease/{_validate_path_segment(uuid)}/cle")
        return _validate(CLE, data)

    def get_component_cle(self, uuid: str) -> CLE:
        """Get CLE data for a component."""
        data = self._http.get_json(f"/component/{_validate_path_segment(uuid)}/cle")
        return _validate(CLE, data)

    def get_component_release_cle(self, uuid: str) -> CLE:
        """Get CLE data for a component release."""
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
    ) -> Path:
        """Download an artifact file, optionally verifying checksums.

        Uses a separate unauthenticated session so the bearer token is not
        leaked to third-party artifact hosts.

        Args:
            url: Direct download URL for the artifact.
            dest: Local file path to write to.
            verify_checksums: Optional list of checksums to verify after download.
                On mismatch the downloaded file is deleted.

        Returns:
            The destination path.

        Raises:
            TeaChecksumError: If checksum verification fails.
            TeaConnectionError: On network failure.
        """
        algorithms = [cs.algorithm_type.value for cs in verify_checksums] if verify_checksums else None
        computed = self._http.download_with_hashes(url, dest, algorithms=algorithms)

        if verify_checksums:
            self._verify_checksums(verify_checksums, computed, url, dest)

        return dest

    @staticmethod
    def _verify_checksums(checksums: list[Checksum], computed: dict[str, str], url: str, dest: Path) -> None:
        """Verify computed checksums against expected values, cleaning up on failure."""
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
