"""TeaClient — main entry point for the TEA consumer (read-only) API.

Provides high-level methods for discovery, product/component lookup,
collection retrieval, CLE queries, and artifact download with checksum
verification. All HTTP is delegated to :class:`~libtea._http.TeaHttpClient`.
"""

import hmac
import logging
import typing
import warnings
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import TracebackType
from typing import Self, TypeVar
from urllib.parse import urlsplit

from semver import Version

from libtea._hashing import WEAK_HASH_ALGORITHMS
from libtea._http import TeaHttpClient, probe_endpoint
from libtea._validation import (
    _MAX_PAGE_SIZE_V1,
    _validate,
    _validate_artifact_version,
    _validate_collection_version,
    _validate_list,
    _validate_page_size,
    _validate_path_segment,
)
from libtea.discovery import _advertised_version, fetch_well_known, select_best_endpoint, select_endpoints
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
    PaginatedCollectionResponse,
    PaginatedComponentReleaseResponse,
    PaginatedComponentResponse,
    PaginatedProductReleaseResponse,
    PaginatedProductResponse,
    Product,
    ProductRelease,
    ProductReleaseWithCollection,
    Release,
    _PaginatedResponse,
)

logger = logging.getLogger("libtea")

TEA_SPEC_VERSION = "1.0.0"
# Highest first. Major 0 is the legacy (0.4.0) wire format; major 1 is current.
SUPPORTED_SPEC_VERSIONS: tuple[str, ...] = ("1.0.0", "0.4.0")
_SUPPORTED_MAJORS = frozenset(Version.parse(v).major for v in SUPPORTED_SPEC_VERSIONS)

_T = TypeVar("_T")

# ponytail: hard ceiling of 10,000 pages per pagination run (1M results at pageSize 100) so a server
# minting endless distinct tokens cannot loop forever; make it a parameter if real catalogs get that big.
_MAX_PAGES = 10_000


def _resolve_spec_version(base_url: str, explicit: str | None) -> Version:
    """Resolve the TEA spec version: explicit argument, then a ``/v<semver>`` URL suffix, then the default."""
    candidate = explicit
    if candidate is None:
        last_segment = urlsplit(base_url).path.rstrip("/").rpartition("/")[2]
        if last_segment.startswith("v") and Version.is_valid(last_segment[1:]):
            candidate = last_segment[1:]
    if candidate is None:
        return Version.parse(TEA_SPEC_VERSION)
    try:
        version = Version.parse(candidate)
    except ValueError:
        version = None
    if version is None or version.major not in _SUPPORTED_MAJORS:
        raise ValueError(
            f"Unsupported TEA spec version {candidate!r}; supported versions: {', '.join(SUPPORTED_SPEC_VERSIONS)}"
        )
    return version


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
        max_retries: Number of automatic retries on 5xx responses (default 3).
        backoff_factor: Exponential backoff multiplier between retries (default 0.5).
        spec_version: TEA spec SemVer the server speaks. Defaults to the ``/v<semver>``
            suffix of ``base_url`` when present, else :data:`TEA_SPEC_VERSION`. Major 0
            (``0.4.0``) selects the legacy wire format; major 1 selects 1.0.0.

    Raises:
        ValueError: If the resolved spec version is not valid SemVer or its major
            version is not supported.
    """

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        basic_auth: tuple[str, str] | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        allow_private_ips: bool = False,
        cache_ttl: float | None = None,
        spec_version: str | None = None,
    ):
        resolved = _resolve_spec_version(base_url, spec_version)
        self.spec_version: str = str(resolved)
        self.is_legacy: bool = resolved.major == 0
        self._allow_private_ips = allow_private_ips
        self._http = TeaHttpClient(
            base_url=base_url,
            token=token,
            basic_auth=basic_auth,
            timeout=timeout,
            max_retries=max_retries,
            backoff_factor=backoff_factor,
            cache_ttl=cache_ttl,
        )

    @classmethod
    def from_well_known(
        cls,
        domain: str,
        *,
        token: str | None = None,
        basic_auth: tuple[str, str] | None = None,
        timeout: float = 30.0,
        version: str | None = None,
        scheme: str = "https",
        port: int | None = None,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        allow_private_ips: bool = False,
        cache_ttl: float | None = None,
    ) -> Self:
        """Create a client by discovering the TEA endpoint from a domain's .well-known/tea.

        Fetches the ``.well-known/tea`` document, selects all endpoints compatible
        with the requested ``version`` (SemVer match), and probes each in priority
        order. If an endpoint is unreachable or returns a server error, the next
        candidate is tried (per TEA spec: "MUST retry ... with the next endpoint").
        The API path uses each endpoint's version string exactly as advertised
        (build metadata included, e.g. ``/v1.0.0+build.5``).
        With the default ``version=None`` the candidates span every supported version,
        highest first, so failover can also fall back from ``1.0.0`` to ``0.4.0``.

        Args:
            domain: Domain name to resolve (e.g. ``tea.example.com``).
            token: Optional bearer token.
            basic_auth: Optional ``(username, password)`` tuple.
            timeout: Request timeout in seconds (default 30).
            version: TEA spec SemVer to match against. The default (``None``) negotiates
                the highest of :data:`SUPPORTED_SPEC_VERSIONS` the server advertises:
                ``1.0.0`` first, then ``0.4.0``. Only when neither is advertised exactly does it
                downgrade to a compatible version (e.g. ``0.3.0``), with a warning.
            scheme: URL scheme for discovery — ``"https"`` (default) or ``"http"``.
            port: Optional port for ``.well-known`` resolution.
            max_retries: Retry count on 5xx (default 3).
            backoff_factor: Backoff multiplier (default 0.5).
            allow_private_ips: Allow artifact downloads from private/internal IPs
                (default False). Only affects artifact downloads, not discovery
                redirect validation which always enforces SSRF protection.
            cache_ttl: Optional response cache TTL in seconds.

        Returns:
            A connected :class:`TeaClient` pointing at the best reachable endpoint.

        Raises:
            TeaDiscoveryError: If no compatible or reachable endpoint is found
                (wraps the last probe failure as ``__cause__``), or the negotiated
                version is not one this client supports.
        """
        well_known = fetch_well_known(domain, timeout=timeout, scheme=scheme, port=port)
        # Ordered (endpoint URL, advertised version) attempts: highest version first, then endpoint priority.
        # Without an explicit ``version`` every supported version contributes, so failover can cross versions.
        wanted_versions = (version,) if version is not None else SUPPORTED_SPEC_VERSIONS
        attempts: dict[tuple[str, str], None] = {}  # insertion-ordered set
        if version is None:
            # Exact matches first: a prerelease such as ``1.0.0-rc.1`` is not a version this client supports,
            # so a compatible downgrade is only a fallback when no supported version is advertised as-is.
            for wanted in SUPPORTED_SPEC_VERSIONS:
                try:
                    exact = select_endpoints(well_known, wanted)
                except TeaDiscoveryError:
                    continue
                for endpoint in exact:
                    attempts[(endpoint.url, _advertised_version(endpoint, wanted))] = None
        if not attempts:
            for wanted in wanted_versions:
                try:
                    best = select_best_endpoint(well_known, wanted)
                except TeaDiscoveryError:
                    if version is not None:
                        raise
                    continue
                matched_version = best.matched_version
                try:
                    # Rejects an unsupported version (possible with an explicit ``version``) before any probe.
                    _resolve_spec_version(best.endpoint.url, matched_version)
                except ValueError as exc:
                    raise TeaDiscoveryError(f"Cannot use negotiated version {matched_version!r}: {exc}") from exc
                for endpoint in select_endpoints(well_known, matched_version):
                    # Build metadata does not affect precedence, so each endpoint may spell the version differently.
                    attempts[(endpoint.url, _advertised_version(endpoint, matched_version))] = None
        if not attempts:
            offered = sorted({v for ep in well_known.endpoints for v in ep.versions})
            raise TeaDiscoveryError(
                f"No compatible endpoint found for any version tried {list(SUPPORTED_SPEC_VERSIONS)}. "
                f"Available versions: {offered}"
            )

        errors: list[tuple[str, Exception]] = []
        for url, advertised in attempts:
            base_url = f"{url.rstrip('/')}/v{advertised}"
            try:
                probe_endpoint(base_url, timeout=min(timeout, 5.0))
            except (TeaConnectionError, TeaServerError) as exc:
                logger.warning("Endpoint %s unreachable, trying next: %s", base_url, exc)
                errors.append((base_url, exc))
                continue
            return cls(
                base_url=base_url,
                token=token,
                basic_auth=basic_auth,
                timeout=timeout,
                max_retries=max_retries,
                backoff_factor=backoff_factor,
                allow_private_ips=allow_private_ips,
                cache_ttl=cache_ttl,
                spec_version=advertised,
            )

        summary = "; ".join(f"{url}: {exc}" for url, exc in errors)
        raise TeaDiscoveryError(f"All {len(errors)} endpoint(s) failed: {summary}") from errors[-1][1]

    # --- Discovery ---

    def discover(self, tei: str | None = None, *, purl: str | None = None) -> list[DiscoveryInfo]:
        """Resolve a TEI, or a PURL within this server's inventory, to product release UUID(s).

        Exactly one of ``tei`` and ``purl`` must be given. Discovery by PURL needs an API base the
        client already knows and is only available on TEA 1.x servers.

        Args:
            tei: TEI string, sent verbatim (e.g. ``tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1``).
                Use the form the server speaks: the ``tei://`` URI on TEA 1.x, the legacy URN on 0.4.0.
            purl: Package URL, sent verbatim (e.g. ``pkg:maven/org.apache.logging.log4j/log4j-core@2.24.3``).

        Returns:
            List of discovery results, each with a product release UUID and servers.

        Raises:
            TeaValidationError: If not exactly one of ``tei`` and ``purl`` is given, if ``purl`` is used on a
                TEA 0.x server, or if the response is malformed, or empty on a TEA 1.x server.
            TeaConnectionError: On network failure.
        """
        if (tei is None) == (purl is None):
            raise TeaValidationError("Provide exactly one of tei or purl")
        if purl is not None and self.is_legacy:
            raise TeaValidationError("Discovery by PURL requires a TEA 1.x server")
        # requests auto-encodes query params — do NOT pre-encode with quote()
        data = self._http.get_json("/discovery", params={"tei": tei} if tei is not None else {"purl": purl})
        results = _validate_list(DiscoveryInfo, data, legacy=self.is_legacy)
        if not results and not self.is_legacy:
            raise TeaValidationError("Invalid discovery response: expected a non-empty array")
        return results

    # --- Pagination parameters ---

    def _page_params(self, page_token: str | None, page_size: int) -> dict[str, typing.Any]:
        """Build the paging query: an opaque ``pageToken`` on TEA 1.x, an integer ``pageOffset`` on 0.x."""
        if page_token is not None and not isinstance(page_token, str):
            raise TeaValidationError(
                f"page_token must be a string (a previous page's nextPageToken), got {type(page_token).__name__}"
            )
        if not self.is_legacy:
            _validate_page_size(page_size, _MAX_PAGE_SIZE_V1)
            return {"pageSize": page_size} if page_token is None else {"pageSize": page_size, "pageToken": page_token}
        _validate_page_size(page_size)
        if page_token is not None and not (page_token.isascii() and page_token.isdigit()):
            raise TeaValidationError(
                f"page_token for a TEA 0.x server must be a non-negative integer offset, got {page_token!r}"
            )
        return {"pageOffset": int(page_token or 0), "pageSize": page_size}

    def _all_pages(self, path: str, model_cls: type[_PaginatedResponse[_T]]) -> list[_T]:
        """Fetch every page of a TEA 1.x list endpoint that 0.4.0 served as a bare array."""

        def fetch_page(*, page_token: str | None, page_size: int) -> _PaginatedResponse[_T]:
            data = self._http.get_json(path, params=self._page_params(page_token, page_size))
            return _validate(model_cls, data, legacy=self.is_legacy)

        # ponytail: drains every page into memory; expose an iterator if lists get large
        return list(self._paginate(fetch_page, _MAX_PAGE_SIZE_V1))

    # --- Products ---

    def list_products(self, *, page_token: str | None = None, page_size: int = 100) -> PaginatedProductResponse:
        """List all products (no identifier filter).

        Args:
            page_token: ``nextPageToken`` from the previous page, or ``None`` for the first page.
            page_size: Number of results per page (default 100; max 100 on TEA 1.x, 10000 on 0.x).

        Returns:
            Paginated response containing products.
        """
        data = self._http.get_json(
            "/products",
            params=self._page_params(page_token, page_size),
        )
        return _validate(PaginatedProductResponse, data, legacy=self.is_legacy)

    def search_products(
        self, id_type: str, id_value: str, *, page_token: str | None = None, page_size: int = 100
    ) -> PaginatedProductResponse:
        """Search for products by identifier (e.g. PURL, CPE, TEI).

        Args:
            id_type: Identifier type (e.g. ``"PURL"``, ``"CPE"``, ``"TEI"``).
            id_value: Identifier value to search for.
            page_token: ``nextPageToken`` from the previous page, or ``None`` for the first page.
            page_size: Number of results per page (default 100; max 100 on TEA 1.x, 10000 on 0.x).

        Returns:
            Paginated response containing matching products.
        """
        data = self._http.get_json(
            "/products",
            params={"idType": id_type, "idValue": id_value, **self._page_params(page_token, page_size)},
        )
        return _validate(PaginatedProductResponse, data, legacy=self.is_legacy)

    def get_product(self, uuid: str) -> Product:
        """Get a TEA product by UUID.

        Args:
            uuid: Product UUID.

        Returns:
            The product with its identifiers.
        """
        data = self._http.get_json(f"/product/{_validate_path_segment(uuid)}")
        return _validate(Product, data, legacy=self.is_legacy)

    def get_product_releases(
        self, uuid: str, *, page_token: str | None = None, page_size: int = 100
    ) -> PaginatedProductReleaseResponse:
        """Get paginated releases for a product.

        Args:
            uuid: Product UUID.
            page_token: ``nextPageToken`` from the previous page, or ``None`` for the first page.
            page_size: Number of results per page (default 100; max 100 on TEA 1.x, 10000 on 0.x).

        Returns:
            Paginated response containing product releases.
        """
        data = self._http.get_json(
            f"/product/{_validate_path_segment(uuid)}/releases",
            params=self._page_params(page_token, page_size),
        )
        return _validate(PaginatedProductReleaseResponse, data, legacy=self.is_legacy)

    # --- Product Releases ---

    def list_product_releases(
        self, *, page_token: str | None = None, page_size: int = 100
    ) -> PaginatedProductReleaseResponse:
        """List all product releases (no identifier filter).

        Args:
            page_token: ``nextPageToken`` from the previous page, or ``None`` for the first page.
            page_size: Number of results per page (default 100; max 100 on TEA 1.x, 10000 on 0.x).

        Returns:
            Paginated response containing product releases.
        """
        data = self._http.get_json(
            "/productReleases",
            params=self._page_params(page_token, page_size),
        )
        return _validate(PaginatedProductReleaseResponse, data, legacy=self.is_legacy)

    def search_product_releases(
        self, id_type: str, id_value: str, *, page_token: str | None = None, page_size: int = 100
    ) -> PaginatedProductReleaseResponse:
        """Search for product releases by identifier (e.g. PURL, CPE, TEI).

        Args:
            id_type: Identifier type (e.g. ``"PURL"``, ``"CPE"``, ``"TEI"``).
            id_value: Identifier value to search for.
            page_token: ``nextPageToken`` from the previous page, or ``None`` for the first page.
            page_size: Number of results per page (default 100; max 100 on TEA 1.x, 10000 on 0.x).

        Returns:
            Paginated response containing matching product releases.
        """
        data = self._http.get_json(
            "/productReleases",
            params={"idType": id_type, "idValue": id_value, **self._page_params(page_token, page_size)},
        )
        return _validate(PaginatedProductReleaseResponse, data, legacy=self.is_legacy)

    def get_product_release(self, uuid: str) -> ProductReleaseWithCollection:
        """Get a product release by UUID.

        Args:
            uuid: Product release UUID.

        Returns:
            The product release with its component references and, on TEA 1.x
            servers, its latest collection.
        """
        data = self._http.get_json(f"/productRelease/{_validate_path_segment(uuid)}")
        return _validate(ProductReleaseWithCollection, data, legacy=self.is_legacy)

    def get_product_release_collection_latest(self, uuid: str) -> Collection:
        """Get the latest collection for a product release.

        Args:
            uuid: Product release UUID.

        Returns:
            The latest collection with its artifacts.
        """
        data = self._http.get_json(f"/productRelease/{_validate_path_segment(uuid)}/collection/latest")
        return _validate(Collection, data, legacy=self.is_legacy)

    def get_product_release_collections(self, uuid: str) -> list[Collection]:
        """Get all collection versions for a product release.

        Args:
            uuid: Product release UUID.

        Returns:
            List of all collection versions.
        """
        path = f"/productRelease/{_validate_path_segment(uuid)}/collections"
        if not self.is_legacy:
            return self._all_pages(path, PaginatedCollectionResponse)
        return _validate_list(Collection, self._http.get_json(path), legacy=self.is_legacy)

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
        return _validate(Collection, data, legacy=self.is_legacy)

    # --- Components ---

    def get_component(self, uuid: str) -> Component:
        """Get a TEA component by UUID.

        Args:
            uuid: Component UUID.

        Returns:
            The component with its identifiers.
        """
        data = self._http.get_json(f"/component/{_validate_path_segment(uuid)}")
        return _validate(Component, data, legacy=self.is_legacy)

    def get_component_releases(self, uuid: str) -> list[Release]:
        """Get all releases for a component.

        TEA 1.x paginates this endpoint and every page is fetched; TEA 0.4.0 returns a bare array.

        Args:
            uuid: Component UUID.

        Returns:
            List of component releases.
        """
        path = f"/component/{_validate_path_segment(uuid)}/releases"
        if not self.is_legacy:
            return self._all_pages(path, PaginatedComponentReleaseResponse)
        return _validate_list(Release, self._http.get_json(path), legacy=self.is_legacy)

    def list_components(self, *, page_token: str | None = None, page_size: int = 100) -> PaginatedComponentResponse:
        """List all components (no identifier filter).

        Args:
            page_token: ``nextPageToken`` from the previous page, or ``None`` for the first page.
            page_size: Number of results per page (default 100; max 100 on TEA 1.x, 10000 on 0.x).

        Returns:
            Paginated response containing components.
        """
        data = self._http.get_json(
            "/components",
            params=self._page_params(page_token, page_size),
        )
        return _validate(PaginatedComponentResponse, data, legacy=self.is_legacy)

    def search_components(
        self, id_type: str, id_value: str, *, page_token: str | None = None, page_size: int = 100
    ) -> PaginatedComponentResponse:
        """Search for components by identifier (e.g. PURL, CPE, TEI).

        Args:
            id_type: Identifier type (e.g. ``"PURL"``, ``"CPE"``, ``"TEI"``).
            id_value: Identifier value to search for.
            page_token: ``nextPageToken`` from the previous page, or ``None`` for the first page.
            page_size: Number of results per page (default 100; max 100 on TEA 1.x, 10000 on 0.x).

        Returns:
            Paginated response containing matching components.
        """
        data = self._http.get_json(
            "/components",
            params={"idType": id_type, "idValue": id_value, **self._page_params(page_token, page_size)},
        )
        return _validate(PaginatedComponentResponse, data, legacy=self.is_legacy)

    # --- Component Releases ---

    def get_component_release(self, uuid: str) -> ComponentReleaseWithCollection:
        """Get a component release with its latest collection.

        Args:
            uuid: Component release UUID.

        Returns:
            The release bundled with its latest collection of artifacts.
        """
        data = self._http.get_json(f"/componentRelease/{_validate_path_segment(uuid)}")
        return _validate(ComponentReleaseWithCollection, data, legacy=self.is_legacy)

    def get_component_release_collection_latest(self, uuid: str) -> Collection:
        """Get the latest collection for a component release.

        Args:
            uuid: Component release UUID.

        Returns:
            The latest collection with its artifacts.
        """
        data = self._http.get_json(f"/componentRelease/{_validate_path_segment(uuid)}/collection/latest")
        return _validate(Collection, data, legacy=self.is_legacy)

    def get_component_release_collections(self, uuid: str) -> list[Collection]:
        """Get all collection versions for a component release.

        Args:
            uuid: Component release UUID.

        Returns:
            List of all collection versions.
        """
        path = f"/componentRelease/{_validate_path_segment(uuid)}/collections"
        if not self.is_legacy:
            return self._all_pages(path, PaginatedCollectionResponse)
        return _validate_list(Collection, self._http.get_json(path), legacy=self.is_legacy)

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
        return _validate(Collection, data, legacy=self.is_legacy)

    def list_component_releases(
        self, *, page_token: str | None = None, page_size: int = 100
    ) -> PaginatedComponentReleaseResponse:
        """List all component releases (no identifier filter).

        Args:
            page_token: ``nextPageToken`` from the previous page, or ``None`` for the first page.
            page_size: Number of results per page (default 100; max 100 on TEA 1.x, 10000 on 0.x).

        Returns:
            Paginated response containing component releases.
        """
        data = self._http.get_json(
            "/componentReleases",
            params=self._page_params(page_token, page_size),
        )
        return _validate(PaginatedComponentReleaseResponse, data, legacy=self.is_legacy)

    def search_component_releases(
        self, id_type: str, id_value: str, *, page_token: str | None = None, page_size: int = 100
    ) -> PaginatedComponentReleaseResponse:
        """Search for component releases by identifier (e.g. PURL, CPE, TEI).

        Args:
            id_type: Identifier type (e.g. ``"PURL"``, ``"CPE"``, ``"TEI"``).
            id_value: Identifier value to search for.
            page_token: ``nextPageToken`` from the previous page, or ``None`` for the first page.
            page_size: Number of results per page (default 100; max 100 on TEA 1.x, 10000 on 0.x).

        Returns:
            Paginated response containing matching component releases.
        """
        data = self._http.get_json(
            "/componentReleases",
            params={"idType": id_type, "idValue": id_value, **self._page_params(page_token, page_size)},
        )
        return _validate(PaginatedComponentReleaseResponse, data, legacy=self.is_legacy)

    # --- CLE ---

    def get_product_cle(self, uuid: str) -> CLE:
        """Get CLE (Common Lifecycle Enumeration) data for a product.

        Args:
            uuid: Product UUID.

        Returns:
            The CLE document with lifecycle events and optional definitions.
        """
        data = self._http.get_json(f"/product/{_validate_path_segment(uuid)}/cle")
        return _validate(CLE, data, legacy=self.is_legacy)

    def get_product_release_cle(self, uuid: str) -> CLE:
        """Get CLE data for a product release.

        Args:
            uuid: Product release UUID.

        Returns:
            The CLE document with lifecycle events and optional definitions.
        """
        data = self._http.get_json(f"/productRelease/{_validate_path_segment(uuid)}/cle")
        return _validate(CLE, data, legacy=self.is_legacy)

    def get_component_cle(self, uuid: str) -> CLE:
        """Get CLE data for a component.

        Args:
            uuid: Component UUID.

        Returns:
            The CLE document with lifecycle events and optional definitions.
        """
        data = self._http.get_json(f"/component/{_validate_path_segment(uuid)}/cle")
        return _validate(CLE, data, legacy=self.is_legacy)

    def get_component_release_cle(self, uuid: str) -> CLE:
        """Get CLE data for a component release.

        Args:
            uuid: Component release UUID.

        Returns:
            The CLE document with lifecycle events and optional definitions.
        """
        data = self._http.get_json(f"/componentRelease/{_validate_path_segment(uuid)}/cle")
        return _validate(CLE, data, legacy=self.is_legacy)

    # --- Artifacts ---

    def get_artifact(self, uuid: str) -> Artifact:
        """Get the latest revision of artifact metadata by UUID.

        Args:
            uuid: Artifact UUID.

        Returns:
            The artifact with its formats and download URLs.
        """
        data = self._http.get_json(f"/artifact/{_validate_path_segment(uuid)}/latest")
        return _validate(Artifact, data, legacy=self.is_legacy)

    def get_artifact_version(self, uuid: str, version: int) -> Artifact:
        """Get a specific version of artifact metadata by UUID.

        Args:
            uuid: Artifact UUID.
            version: Artifact version number (starts at 1).

        Returns:
            The artifact with its formats and download URLs.
        """
        _validate_artifact_version(version)
        data = self._http.get_json(f"/artifact/{_validate_path_segment(uuid)}/{version}")
        return _validate(Artifact, data, legacy=self.is_legacy)

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
        return self._download(url, dest, verify_checksums, max_download_bytes)

    def download_artifact_content(
        self,
        uuid: str,
        dest: Path,
        *,
        media_type: str,
        version: int | None = None,
        verify_checksums: list[Checksum] | None = None,
        max_download_bytes: int | None = None,
    ) -> Path:
        """Download artifact content hosted by the TEA server itself (a format without ``url``).

        Fetches ``/artifact/{uuid}/{version}/download?mediaType=...`` (``latest`` when
        ``version`` is omitted) with the client's credentials. A redirect is followed
        without credentials, so the token is only ever sent to the API base. When the API base is a
        private address and its download endpoint redirects to its own host, the redirect hop is
        SSRF-checked, so it needs ``allow_private_ips=True``.

        Args:
            uuid: Artifact UUID.
            dest: Local file path to write to.
            media_type: Media type of the format to download.
            version: Artifact version number (starts at 1), or ``None`` for the latest.
            verify_checksums: Optional list of checksums to verify after download.
                On mismatch the downloaded file is deleted.
            max_download_bytes: Optional maximum download size in bytes.

        Returns:
            The destination path.

        Raises:
            TeaValidationError: On a TEA 0.x server, or if download exceeds max_download_bytes.
            TeaRequestError: If the server has no format for ``media_type`` (``NO_ACCEPTABLE_FORMAT``).
            TeaChecksumError: If checksum verification fails.
            TeaConnectionError: On network failure.
        """
        if self.is_legacy:
            raise TeaValidationError("Server-hosted artifact download requires a TEA 1.x server")
        if version is not None:
            _validate_artifact_version(version)
        revision = "latest" if version is None else version
        url = f"{self._http._base_url}/artifact/{_validate_path_segment(uuid)}/{revision}/download"
        return self._download(
            url, dest, verify_checksums, max_download_bytes, params={"mediaType": media_type}, authenticated=True
        )

    def _download(
        self,
        url: str,
        dest: Path,
        verify_checksums: list[Checksum] | None,
        max_download_bytes: int | None,
        *,
        params: dict[str, str] | None = None,
        authenticated: bool = False,
    ) -> Path:
        """Download with on-the-fly hashing, warning on weak algorithms and verifying checksums."""
        algorithms = [cs.algorithm_type.value for cs in verify_checksums] if verify_checksums else None
        if algorithms:
            weak = set(algorithms) & WEAK_HASH_ALGORITHMS
            if weak:
                warnings.warn(
                    f"Verifying with weak hash algorithm(s): {', '.join(sorted(weak))}. Prefer SHA-256 or stronger.",
                    stacklevel=3,
                )
        computed = self._http.download_with_hashes(
            url,
            dest,
            algorithms=algorithms,
            max_download_bytes=max_download_bytes,
            allow_private_ips=self._allow_private_ips,
            params=params,
            authenticated=authenticated,
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

    # --- Pagination iterators ---

    @staticmethod
    def _paginate(fetch_page: typing.Callable[..., typing.Any], page_size: int, **kwargs: typing.Any) -> Iterator[_T]:
        """Generic paginator: calls *fetch_page* with page_token/page_size, following ``nextPageToken``."""
        token: str | None = None
        seen: set[str] = set()
        for _ in range(_MAX_PAGES):
            page = fetch_page(**kwargs, page_token=token, page_size=page_size)
            yield from page.results
            if not page.has_next:  # an empty page may still carry a token; seen-set and cap bound the loop
                return
            token = page.next_page_token
            if token in seen:
                raise TeaServerError(f"Server repeated pageToken {token!r}; stopping pagination")
            seen.add(token)
        raise TeaServerError(f"Pagination exceeded {_MAX_PAGES} pages; stopping")

    def iter_products(self, id_type: str, id_value: str, *, page_size: int = 100) -> Iterator[Product]:
        """Iterate over all products matching an identifier, auto-paginating.

        Args:
            id_type: Identifier type (e.g. ``"PURL"``, ``"CPE"``).
            id_value: Identifier value to search for.
            page_size: Number of results per page (default 100).

        Yields:
            Each matching :class:`Product`.
        """
        return self._paginate(self.search_products, page_size, id_type=id_type, id_value=id_value)

    def iter_product_releases(self, id_type: str, id_value: str, *, page_size: int = 100) -> Iterator[ProductRelease]:
        """Iterate over all product releases matching an identifier, auto-paginating.

        Args:
            id_type: Identifier type (e.g. ``"PURL"``, ``"CPE"``).
            id_value: Identifier value to search for.
            page_size: Number of results per page (default 100).

        Yields:
            Each matching :class:`ProductRelease`.
        """
        return self._paginate(self.search_product_releases, page_size, id_type=id_type, id_value=id_value)

    def iter_releases_for_product(self, uuid: str, *, page_size: int = 100) -> Iterator[ProductRelease]:
        """Iterate over all releases for a specific product UUID, auto-paginating.

        This is the auto-paginated counterpart of :meth:`get_product_releases`.
        Compare with :meth:`iter_product_releases` which searches by identifier.

        Args:
            uuid: Product UUID.
            page_size: Number of results per page (default 100).

        Yields:
            Each :class:`ProductRelease` for the product.
        """
        return self._paginate(self.get_product_releases, page_size, uuid=uuid)

    def iter_components(self, id_type: str, id_value: str, *, page_size: int = 100) -> Iterator[Component]:
        """Iterate over all components matching an identifier, auto-paginating.

        Args:
            id_type: Identifier type (e.g. ``"PURL"``, ``"CPE"``).
            id_value: Identifier value to search for.
            page_size: Number of results per page (default 100).

        Yields:
            Each matching :class:`Component`.
        """
        return self._paginate(self.search_components, page_size, id_type=id_type, id_value=id_value)

    def iter_component_releases(self, id_type: str, id_value: str, *, page_size: int = 100) -> Iterator[Release]:
        """Iterate over all component releases matching an identifier, auto-paginating.

        Args:
            id_type: Identifier type (e.g. ``"PURL"``, ``"CPE"``).
            id_value: Identifier value to search for.
            page_size: Number of results per page (default 100).

        Yields:
            Each matching :class:`Release`.
        """
        return self._paginate(self.search_component_releases, page_size, id_type=id_type, id_value=id_value)

    # --- Bulk fetch ---

    def get_products(self, uuids: list[str], *, max_workers: int = 5) -> list[Product]:
        """Fetch multiple products by UUID in parallel.

        Concurrency caveat: workers share a single ``requests.Session`` which
        is not documented as thread-safe.  This works reliably for typical
        workloads but may exhibit race conditions under heavy load.  Use
        ``max_workers=1`` for strictly safe serial execution.  A thread-safe
        transport is planned for the httpx migration.

        Args:
            uuids: List of product UUIDs.
            max_workers: Maximum concurrent threads (default 5).

        Returns:
            Products in the same order as ``uuids``.

        Raises:
            TeaError: From the first failing UUID in input order.
        """
        return self._bulk_fetch(self.get_product, uuids, max_workers=max_workers)

    def get_product_releases_bulk(self, uuids: list[str], *, max_workers: int = 5) -> list[ProductRelease]:
        """Fetch multiple product releases by UUID in parallel.

        See :meth:`get_products` for concurrency caveats.

        Args:
            uuids: List of product release UUIDs.
            max_workers: Maximum concurrent threads (default 5).

        Returns:
            Product releases in the same order as ``uuids``.

        Raises:
            TeaError: From the first failing UUID in input order.
        """
        return self._bulk_fetch(self.get_product_release, uuids, max_workers=max_workers)

    def get_artifacts(self, uuids: list[str], *, max_workers: int = 5) -> list[Artifact]:
        """Fetch multiple artifacts by UUID in parallel.

        See :meth:`get_products` for concurrency caveats.

        Args:
            uuids: List of artifact UUIDs.
            max_workers: Maximum concurrent threads (default 5).

        Returns:
            Artifacts in the same order as ``uuids``.

        Raises:
            TeaError: From the first failing UUID in input order.
        """
        return self._bulk_fetch(self.get_artifact, uuids, max_workers=max_workers)

    @staticmethod
    def _bulk_fetch(fn: typing.Callable[[str], _T], uuids: list[str], *, max_workers: int = 5) -> list[_T]:
        """Fetch multiple resources in parallel, preserving input order.

        Note: ``fn`` is typically a bound method that issues HTTP requests via
        a shared ``requests.Session``. The ``requests`` library does not
        document ``Session`` as thread-safe, so concurrent use may expose race
        conditions in connection pooling. A per-thread session or async client
        is planned for the httpx migration.
        """
        if not uuids:
            return []
        if max_workers < 1:
            raise ValueError(f"max_workers must be >= 1, got {max_workers}")
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(fn, uid) for uid in uuids]
            try:
                return [f.result() for f in futures]
            except Exception:
                # Cancel pending futures so we don't block waiting for
                # in-flight work after the first failure.
                for f in futures:
                    f.cancel()
                raise

    # --- Cache ---

    def clear_cache(self) -> None:
        """Clear the response cache (no-op if caching is disabled)."""
        self._http.clear_cache()

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
