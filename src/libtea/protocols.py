"""Protocol definition for the TEA client, enabling mock/test implementations.

Provides :class:`TeaClientProtocol` — a :class:`typing.Protocol` that captures
the full public API surface of :class:`~libtea.client.TeaClient`.  Consumers can
type-hint their dependencies as ``TeaClientProtocol`` and substitute test doubles
without subclassing.
"""

from collections.abc import Iterator
from pathlib import Path
from types import TracebackType
from typing import Protocol, Self, runtime_checkable

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


@runtime_checkable
class TeaClientProtocol(Protocol):
    """Structural interface for the TEA consumer client.

    All public methods of :class:`~libtea.client.TeaClient` are declared here
    so that consumers can program against this protocol for easier testing.

    Note: ``from_well_known`` is a classmethod on :class:`~libtea.client.TeaClient`
    and is intentionally not included in this instance-level protocol. To mock the
    discovery flow, patch :func:`~libtea.discovery.fetch_well_known` and
    :func:`~libtea._http.probe_endpoint` instead.
    """

    # --- Discovery ---

    def discover(self, tei: str) -> list[DiscoveryInfo]: ...

    # --- Products ---

    def list_products(self, *, page_offset: int = 0, page_size: int = 100) -> PaginatedProductResponse: ...

    def search_products(
        self, id_type: str, id_value: str, *, page_offset: int = 0, page_size: int = 100
    ) -> PaginatedProductResponse: ...

    def get_product(self, uuid: str) -> Product: ...

    def get_product_releases(
        self, uuid: str, *, page_offset: int = 0, page_size: int = 100
    ) -> PaginatedProductReleaseResponse: ...

    # --- Product Releases ---

    def list_product_releases(
        self, *, page_offset: int = 0, page_size: int = 100
    ) -> PaginatedProductReleaseResponse: ...

    def search_product_releases(
        self, id_type: str, id_value: str, *, page_offset: int = 0, page_size: int = 100
    ) -> PaginatedProductReleaseResponse: ...

    def get_product_release(self, uuid: str) -> ProductRelease: ...

    def get_product_release_collection_latest(self, uuid: str) -> Collection: ...

    def get_product_release_collections(self, uuid: str) -> list[Collection]: ...

    def get_product_release_collection(self, uuid: str, version: int) -> Collection: ...

    # --- Components ---

    def get_component(self, uuid: str) -> Component: ...

    def get_component_releases(self, uuid: str) -> list[Release]: ...

    # --- Component Releases ---

    def get_component_release(self, uuid: str) -> ComponentReleaseWithCollection: ...

    def get_component_release_collection_latest(self, uuid: str) -> Collection: ...

    def get_component_release_collections(self, uuid: str) -> list[Collection]: ...

    def get_component_release_collection(self, uuid: str, version: int) -> Collection: ...

    # --- CLE ---

    def get_product_cle(self, uuid: str) -> CLE: ...

    def get_product_release_cle(self, uuid: str) -> CLE: ...

    def get_component_cle(self, uuid: str) -> CLE: ...

    def get_component_release_cle(self, uuid: str) -> CLE: ...

    # --- Artifacts ---

    def get_artifact(self, uuid: str) -> Artifact: ...

    def download_artifact(
        self,
        url: str,
        dest: Path,
        *,
        verify_checksums: list[Checksum] | None = None,
        max_download_bytes: int | None = None,
    ) -> Path: ...

    # --- Pagination iterators ---

    def iter_products(self, id_type: str, id_value: str, *, page_size: int = 100) -> Iterator[Product]: ...

    def iter_product_releases(
        self, id_type: str, id_value: str, *, page_size: int = 100
    ) -> Iterator[ProductRelease]: ...

    def iter_releases_for_product(self, uuid: str, *, page_size: int = 100) -> Iterator[ProductRelease]: ...

    # --- Bulk fetch ---

    def get_products(self, uuids: list[str], *, max_workers: int = 5) -> list[Product]: ...

    def get_product_releases_bulk(self, uuids: list[str], *, max_workers: int = 5) -> list[ProductRelease]: ...

    def get_artifacts(self, uuids: list[str], *, max_workers: int = 5) -> list[Artifact]: ...

    # --- Cache ---

    def clear_cache(self) -> None: ...

    # --- Lifecycle ---

    def close(self) -> None: ...

    def __enter__(self) -> Self: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...
