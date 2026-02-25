"""TeaClient - main entry point for the TEA consumer API."""

import hmac
import logging
import re
from pathlib import Path
from types import TracebackType
from typing import Any, Self, TypeVar

from pydantic import BaseModel, ValidationError

from libtea._http import TeaHttpClient
from libtea.discovery import fetch_well_known, select_endpoint
from libtea.exceptions import TeaChecksumError, TeaValidationError
from libtea.models import (
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
_SAFE_PATH_SEGMENT_RE = re.compile(r"^[a-zA-Z0-9\-]{1,128}$")


def _validate(model_cls: type[_M], data: Any) -> _M:
    """Validate data against a Pydantic model, wrapping errors in TeaValidationError."""
    try:
        return model_cls.model_validate(data)
    except ValidationError as exc:
        raise TeaValidationError(f"Invalid {model_cls.__name__} response: {exc}") from exc


def _validate_list(model_cls: type[_M], data: list[Any]) -> list[_M]:
    """Validate a list of items against a Pydantic model."""
    try:
        return [model_cls.model_validate(item) for item in data]
    except ValidationError as exc:
        raise TeaValidationError(f"Invalid {model_cls.__name__} response: {exc}") from exc


def _validate_path_segment(value: str, name: str = "uuid") -> str:
    """Validate that a value is safe to interpolate into a URL path."""
    if not _SAFE_PATH_SEGMENT_RE.match(value):
        raise TeaValidationError(
            f"Invalid {name}: {value!r}. Must contain only alphanumeric characters and hyphens, max 128 characters."
        )
    return value


class TeaClient:
    """Synchronous client for the Transparency Exchange API."""

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
    ) -> Self:
        """Create a client by discovering the TEA endpoint from a domain's .well-known/tea."""
        well_known = fetch_well_known(domain, timeout=timeout)
        endpoint = select_endpoint(well_known, version)
        base_url = f"{endpoint.url.rstrip('/')}/v{version}"
        return cls(base_url=base_url, token=token, timeout=timeout)

    # --- Discovery ---

    def discover(self, tei: str) -> list[DiscoveryInfo]:
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
        data = self._http.get_json(f"/product/{_validate_path_segment(uuid)}")
        return _validate(Product, data)

    def get_product_releases(
        self, uuid: str, *, page_offset: int = 0, page_size: int = 100
    ) -> PaginatedProductReleaseResponse:
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
        data = self._http.get_json(f"/productRelease/{_validate_path_segment(uuid)}")
        return _validate(ProductRelease, data)

    def get_product_release_collection_latest(self, uuid: str) -> Collection:
        data = self._http.get_json(f"/productRelease/{_validate_path_segment(uuid)}/collection/latest")
        return _validate(Collection, data)

    def get_product_release_collections(self, uuid: str) -> list[Collection]:
        data = self._http.get_json(f"/productRelease/{_validate_path_segment(uuid)}/collections")
        return _validate_list(Collection, data)

    def get_product_release_collection(self, uuid: str, version: int) -> Collection:
        data = self._http.get_json(f"/productRelease/{_validate_path_segment(uuid)}/collection/{version}")
        return _validate(Collection, data)

    # --- Components ---

    def get_component(self, uuid: str) -> Component:
        data = self._http.get_json(f"/component/{_validate_path_segment(uuid)}")
        return _validate(Component, data)

    def get_component_releases(self, uuid: str) -> list[Release]:
        data = self._http.get_json(f"/component/{_validate_path_segment(uuid)}/releases")
        return _validate_list(Release, data)

    # --- Component Releases ---

    def get_component_release(self, uuid: str) -> ComponentReleaseWithCollection:
        data = self._http.get_json(f"/componentRelease/{_validate_path_segment(uuid)}")
        return _validate(ComponentReleaseWithCollection, data)

    def get_component_release_collection_latest(self, uuid: str) -> Collection:
        data = self._http.get_json(f"/componentRelease/{_validate_path_segment(uuid)}/collection/latest")
        return _validate(Collection, data)

    def get_component_release_collections(self, uuid: str) -> list[Collection]:
        data = self._http.get_json(f"/componentRelease/{_validate_path_segment(uuid)}/collections")
        return _validate_list(Collection, data)

    def get_component_release_collection(self, uuid: str, version: int) -> Collection:
        data = self._http.get_json(f"/componentRelease/{_validate_path_segment(uuid)}/collection/{version}")
        return _validate(Collection, data)

    # --- Artifacts ---

    def get_artifact(self, uuid: str) -> Artifact:
        data = self._http.get_json(f"/artifact/{_validate_path_segment(uuid)}")
        return _validate(Artifact, data)

    def download_artifact(
        self,
        url: str,
        dest: Path,
        *,
        verify_checksums: list[Checksum] | None = None,
    ) -> Path:
        """Download an artifact file, optionally verifying checksums."""
        algorithms = [cs.alg_type.value for cs in verify_checksums] if verify_checksums else None
        computed = self._http.download_with_hashes(url, dest, algorithms=algorithms)

        if verify_checksums:
            self._verify_checksums(verify_checksums, computed, url, dest)

        return dest

    @staticmethod
    def _verify_checksums(checksums: list[Checksum], computed: dict[str, str], url: str, dest: Path) -> None:
        """Verify computed checksums against expected values, cleaning up on failure."""
        for cs in checksums:
            alg_name = cs.alg_type.value
            expected = cs.alg_value.lower()
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
