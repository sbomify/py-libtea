"""Conformance check functions for validating TEA server compliance.

Each check function takes a ``TeaClient`` and a mutable ``CheckContext`` and
returns a ``CheckResult``.  Checks populate the context with discovered UUIDs
so later checks can build on earlier results.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from libtea.client import TeaClient
from libtea.conformance._types import CheckResult, CheckStatus
from libtea.exceptions import TeaError, TeaNotFoundError

# Canonical zero UUID used for 404 tests.
_ZERO_UUID = "00000000-0000-0000-0000-000000000000"

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------


@dataclass
class CheckContext:
    """Mutable bag of UUIDs discovered during a conformance run.

    Earlier checks populate fields so that later checks can reference them
    without requiring the caller to supply every UUID up front.
    """

    tei: str | None = None
    product_uuid: str | None = None
    product_release_uuid: str | None = None
    component_uuid: str | None = None
    component_release_uuid: str | None = None
    artifact_uuid: str | None = None
    collected_uuids: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pass(name: str, msg: str) -> CheckResult:
    return CheckResult(name=name, status=CheckStatus.PASS, message=msg)


def _fail(name: str, msg: str, details: str = "") -> CheckResult:
    return CheckResult(name=name, status=CheckStatus.FAIL, message=msg, details=details)


def _skip(name: str, msg: str) -> CheckResult:
    return CheckResult(name=name, status=CheckStatus.SKIP, message=msg)


def _collect(ctx: CheckContext, uuid: str | None) -> None:
    """Append a UUID to the collected list if it looks non-empty."""
    if uuid:
        ctx.collected_uuids.append(uuid)


# ---------------------------------------------------------------------------
# Discovery checks
# ---------------------------------------------------------------------------


def check_discovery(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Discover a TEI and populate product_release_uuid from the first result."""
    name = "discovery"
    if not ctx.tei:
        return _skip(name, "No TEI provided")
    try:
        results = client.discover(ctx.tei)
    except TeaError as exc:
        return _fail(name, f"discover() failed: {exc}", details=str(exc))
    if not results:
        return _fail(name, "discover() returned empty list")
    first = results[0]
    ctx.product_release_uuid = ctx.product_release_uuid or first.product_release_uuid
    _collect(ctx, first.product_release_uuid)
    return _pass(name, f"Discovered {len(results)} result(s)")


def check_discovery_404(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Discover a fake TEI and expect TeaNotFoundError or empty list."""
    name = "discovery_404"
    fake_tei = "urn:tei:uuid:nonexistent.example.com:00000000-0000-0000-0000-000000000000"
    try:
        results = client.discover(fake_tei)
    except TeaNotFoundError:
        return _pass(name, "Server returned 404 for unknown TEI")
    except TeaError as exc:
        return _fail(name, f"Unexpected error: {exc}", details=str(exc))
    if not results:
        return _pass(name, "Server returned empty list for unknown TEI")
    return _fail(name, f"Expected 404 or empty list, got {len(results)} result(s)")


# ---------------------------------------------------------------------------
# Product checks
# ---------------------------------------------------------------------------


def check_list_products(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """List products and populate product_uuid from the first result."""
    name = "list_products"
    try:
        resp = client.list_products(page_size=10)
    except TeaError as exc:
        return _fail(name, f"list_products() failed: {exc}", details=str(exc))
    if not resp.results:
        return _skip(name, "No products on server")
    first = resp.results[0]
    ctx.product_uuid = ctx.product_uuid or first.uuid
    _collect(ctx, first.uuid)
    return _pass(name, f"Listed {resp.total_results} product(s)")


def check_search_products(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Search products by the first identifier of a known product."""
    name = "search_products"
    if not ctx.product_uuid:
        return _skip(name, "No product UUID available")
    try:
        product = client.get_product(ctx.product_uuid)
    except TeaError as exc:
        return _fail(name, f"get_product() failed: {exc}", details=str(exc))
    if not product.identifiers:
        return _skip(name, "Product has no identifiers to search by")
    ident = product.identifiers[0]
    if not ident.id_type or not ident.id_value:
        return _skip(name, "First identifier missing type or value")
    try:
        resp = client.search_products(ident.id_type, ident.id_value)
    except TeaError as exc:
        return _fail(name, f"search_products() failed: {exc}", details=str(exc))
    if resp.total_results < 1:
        return _fail(name, "Search returned no results for a known identifier")
    return _pass(name, f"Search returned {resp.total_results} product(s)")


def check_get_product(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Get a product by UUID."""
    name = "get_product"
    if not ctx.product_uuid:
        return _skip(name, "No product UUID available")
    try:
        product = client.get_product(ctx.product_uuid)
    except TeaError as exc:
        return _fail(name, f"get_product() failed: {exc}", details=str(exc))
    _collect(ctx, product.uuid)
    return _pass(name, f"Got product: {product.name}")


def check_get_product_404(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Get a product with a zero UUID and expect TeaNotFoundError."""
    name = "get_product_404"
    try:
        client.get_product(_ZERO_UUID)
    except TeaNotFoundError:
        return _pass(name, "Server returned 404 for unknown product")
    except TeaError as exc:
        return _fail(name, f"Expected TeaNotFoundError, got: {type(exc).__name__}: {exc}", details=str(exc))
    return _fail(name, "Expected 404 but got a successful response")


def check_product_releases(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Get releases for a product and populate product_release_uuid."""
    name = "product_releases"
    if not ctx.product_uuid:
        return _skip(name, "No product UUID available")
    try:
        resp = client.get_product_releases(ctx.product_uuid)
    except TeaError as exc:
        return _fail(name, f"get_product_releases() failed: {exc}", details=str(exc))
    if not resp.results:
        return _skip(name, "Product has no releases")
    first = resp.results[0]
    ctx.product_release_uuid = ctx.product_release_uuid or first.uuid
    _collect(ctx, first.uuid)
    return _pass(name, f"Got {resp.total_results} release(s)")


# ---------------------------------------------------------------------------
# Product release checks
# ---------------------------------------------------------------------------


def check_list_product_releases(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """List product releases and populate product_release_uuid."""
    name = "list_product_releases"
    try:
        resp = client.list_product_releases(page_size=10)
    except TeaError as exc:
        return _fail(name, f"list_product_releases() failed: {exc}", details=str(exc))
    if not resp.results:
        return _skip(name, "No product releases on server")
    first = resp.results[0]
    ctx.product_release_uuid = ctx.product_release_uuid or first.uuid
    _collect(ctx, first.uuid)
    return _pass(name, f"Listed {resp.total_results} product release(s)")


def check_search_product_releases(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Search product releases by the first identifier of a known release."""
    name = "search_product_releases"
    if not ctx.product_release_uuid:
        return _skip(name, "No product release UUID available")
    try:
        release = client.get_product_release(ctx.product_release_uuid)
    except TeaError as exc:
        return _fail(name, f"get_product_release() failed: {exc}", details=str(exc))
    if not release.identifiers:
        return _skip(name, "Product release has no identifiers to search by")
    ident = release.identifiers[0]
    if not ident.id_type or not ident.id_value:
        return _skip(name, "First identifier missing type or value")
    try:
        resp = client.search_product_releases(ident.id_type, ident.id_value)
    except TeaError as exc:
        return _fail(name, f"search_product_releases() failed: {exc}", details=str(exc))
    if resp.total_results < 1:
        return _fail(name, "Search returned no results for a known identifier")
    return _pass(name, f"Search returned {resp.total_results} release(s)")


def check_get_product_release(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Get a product release by UUID and populate component_uuid from components."""
    name = "get_product_release"
    if not ctx.product_release_uuid:
        return _skip(name, "No product release UUID available")
    try:
        release = client.get_product_release(ctx.product_release_uuid)
    except TeaError as exc:
        return _fail(name, f"get_product_release() failed: {exc}", details=str(exc))
    _collect(ctx, release.uuid)
    if release.components:
        ctx.component_uuid = ctx.component_uuid or release.components[0].uuid
        _collect(ctx, release.components[0].uuid)
    return _pass(name, f"Got release v{release.version}")


def check_product_release_collection_latest(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Get the latest collection for a product release and populate artifact_uuid."""
    name = "product_release_collection_latest"
    if not ctx.product_release_uuid:
        return _skip(name, "No product release UUID available")
    try:
        collection = client.get_product_release_collection_latest(ctx.product_release_uuid)
    except TeaError as exc:
        return _fail(name, f"get_product_release_collection_latest() failed: {exc}", details=str(exc))
    if collection.artifacts:
        for artifact in collection.artifacts:
            if artifact.uuid:
                ctx.artifact_uuid = ctx.artifact_uuid or artifact.uuid
                _collect(ctx, artifact.uuid)
                break
    return _pass(name, f"Got collection v{collection.version} with {len(collection.artifacts)} artifact(s)")


def check_product_release_collections(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Get all collection versions for a product release."""
    name = "product_release_collections"
    if not ctx.product_release_uuid:
        return _skip(name, "No product release UUID available")
    try:
        collections = client.get_product_release_collections(ctx.product_release_uuid)
    except TeaError as exc:
        return _fail(name, f"get_product_release_collections() failed: {exc}", details=str(exc))
    return _pass(name, f"Got {len(collections)} collection version(s)")


def check_product_release_collection_version(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Get collection version 1 for a product release."""
    name = "product_release_collection_version"
    if not ctx.product_release_uuid:
        return _skip(name, "No product release UUID available")
    try:
        collection = client.get_product_release_collection(ctx.product_release_uuid, 1)
    except TeaNotFoundError:
        return _skip(name, "Collection version 1 not found")
    except TeaError as exc:
        return _fail(name, f"get_product_release_collection() failed: {exc}", details=str(exc))
    return _pass(name, f"Got collection version {collection.version}")


# ---------------------------------------------------------------------------
# Component checks
# ---------------------------------------------------------------------------


def check_get_component(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Get a component by UUID."""
    name = "get_component"
    if not ctx.component_uuid:
        return _skip(name, "No component UUID available")
    try:
        component = client.get_component(ctx.component_uuid)
    except TeaError as exc:
        return _fail(name, f"get_component() failed: {exc}", details=str(exc))
    _collect(ctx, component.uuid)
    return _pass(name, f"Got component: {component.name}")


def check_component_releases(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Get releases for a component and populate component_release_uuid."""
    name = "component_releases"
    if not ctx.component_uuid:
        return _skip(name, "No component UUID available")
    try:
        releases = client.get_component_releases(ctx.component_uuid)
    except TeaError as exc:
        return _fail(name, f"get_component_releases() failed: {exc}", details=str(exc))
    if not releases:
        return _skip(name, "Component has no releases")
    first = releases[0]
    ctx.component_release_uuid = ctx.component_release_uuid or first.uuid
    _collect(ctx, first.uuid)
    return _pass(name, f"Got {len(releases)} release(s)")


def check_component_release(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Get a component release with its latest collection and populate artifact_uuid."""
    name = "component_release"
    if not ctx.component_release_uuid:
        return _skip(name, "No component release UUID available")
    try:
        result = client.get_component_release(ctx.component_release_uuid)
    except TeaError as exc:
        return _fail(name, f"get_component_release() failed: {exc}", details=str(exc))
    _collect(ctx, result.release.uuid)
    if result.latest_collection and result.latest_collection.artifacts:
        for artifact in result.latest_collection.artifacts:
            if artifact.uuid:
                ctx.artifact_uuid = ctx.artifact_uuid or artifact.uuid
                _collect(ctx, artifact.uuid)
                break
    return _pass(name, f"Got release v{result.release.version}")


def check_component_release_collections(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Get all collection versions for a component release."""
    name = "component_release_collections"
    if not ctx.component_release_uuid:
        return _skip(name, "No component release UUID available")
    try:
        collections = client.get_component_release_collections(ctx.component_release_uuid)
    except TeaError as exc:
        return _fail(name, f"get_component_release_collections() failed: {exc}", details=str(exc))
    return _pass(name, f"Got {len(collections)} collection version(s)")


# ---------------------------------------------------------------------------
# Artifact checks
# ---------------------------------------------------------------------------


def check_get_artifact(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Get an artifact by UUID."""
    name = "get_artifact"
    if not ctx.artifact_uuid:
        return _skip(name, "No artifact UUID available")
    try:
        artifact = client.get_artifact(ctx.artifact_uuid)
    except TeaError as exc:
        return _fail(name, f"get_artifact() failed: {exc}", details=str(exc))
    _collect(ctx, artifact.uuid)
    return _pass(name, f"Got artifact: {artifact.name or artifact.uuid}")


# ---------------------------------------------------------------------------
# CLE checks
# ---------------------------------------------------------------------------


def _check_cle_for(
    client: TeaClient,
    uuid: str | None,
    entity: str,
    getter_name: str,
) -> CheckResult:
    """Shared implementation for per-entity CLE checks."""
    name = f"{entity}_cle"
    if not uuid:
        return _skip(name, f"No {entity.replace('_', ' ')} UUID available")
    getter = getattr(client, getter_name)
    try:
        cle = getter(uuid)
    except TeaNotFoundError:
        return _skip(name, f"Server does not have CLE for this {entity.replace('_', ' ')}")
    except TeaError as exc:
        return _fail(name, f"{getter_name}() failed: {exc}", details=str(exc))
    return _pass(name, f"Got CLE with {len(cle.events)} event(s)")


def check_product_cle(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Get CLE data for a product."""
    return _check_cle_for(client, ctx.product_uuid, "product", "get_product_cle")


def check_product_release_cle(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Get CLE data for a product release."""
    return _check_cle_for(client, ctx.product_release_uuid, "product_release", "get_product_release_cle")


def check_component_cle(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Get CLE data for a component."""
    return _check_cle_for(client, ctx.component_uuid, "component", "get_component_cle")


def check_component_release_cle(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Get CLE data for a component release."""
    return _check_cle_for(client, ctx.component_release_uuid, "component_release", "get_component_release_cle")


def check_cle_event_ordering(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Verify CLE events are ordered by id descending."""
    name = "cle_event_ordering"
    # Try each CLE source in priority order until we find one with >= 2 events.
    cle = None
    for uuid, getter_name in [
        (ctx.product_uuid, "get_product_cle"),
        (ctx.product_release_uuid, "get_product_release_cle"),
        (ctx.component_uuid, "get_component_cle"),
        (ctx.component_release_uuid, "get_component_release_cle"),
    ]:
        if not uuid:
            continue
        getter = getattr(client, getter_name)
        try:
            candidate = getter(uuid)
        except TeaNotFoundError:
            continue
        except TeaError:
            continue
        if len(candidate.events) >= 2:
            cle = candidate
            break
    if cle is None:
        return _skip(name, "No CLE source with 2+ events available to check ordering")
    ids = [e.id for e in cle.events]
    if ids == sorted(ids, reverse=True):
        return _pass(name, f"CLE events ordered by id descending ({len(ids)} events)")
    return _fail(name, f"CLE events not ordered by id descending: {ids}")


# ---------------------------------------------------------------------------
# Cross-cutting checks
# ---------------------------------------------------------------------------


def check_uuid_format(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Validate all collected UUIDs match the canonical lowercase UUID format."""
    name = "uuid_format"
    if not ctx.collected_uuids:
        return _skip(name, "No UUIDs collected")
    invalid: list[str] = []
    for uuid in ctx.collected_uuids:
        if not _UUID_RE.match(uuid):
            invalid.append(uuid)
    if invalid:
        return _fail(name, f"{len(invalid)} UUID(s) have invalid format", details=", ".join(invalid[:10]))
    return _pass(name, f"All {len(ctx.collected_uuids)} UUID(s) match canonical format")


def check_pagination_fields(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Verify that the /products listing exposes expected pagination metadata fields."""
    name = "pagination_fields"
    try:
        result = client.list_products(page_size=10)
    except TeaError as exc:
        return _fail(name, f"list_products() failed: {exc}", details=str(exc))

    issues: list[str] = []
    if result.page_size != 10:
        issues.append(f"page_size: requested 10, got {result.page_size!r}")
    if result.page_start_index < 0:
        issues.append(f"page_start_index is negative: {result.page_start_index}")
    if result.total_results < 0:
        issues.append(f"total_results is negative: {result.total_results}")
    if not result.timestamp:
        issues.append("timestamp is empty")
    if issues:
        return _fail(name, "Pagination metadata issues", details="; ".join(issues))
    return _pass(name, "Pagination metadata fields present and valid")


def check_camel_case_fields(client: TeaClient, ctx: CheckContext) -> CheckResult:
    """Confirm server uses camelCase field names (validated by Pydantic parsing)."""
    name = "camel_case_fields"
    # Only treat this as confirmed when we have UUIDs that were discovered
    # during earlier checks (not merely supplied by the user).
    if ctx.collected_uuids:
        return _pass(name, "camelCase confirmed (Pydantic parsed server data with camelCase aliases)")
    return _skip(name, "No discovered data available to confirm camelCase fields")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ALL_CHECKS: list[Callable[[TeaClient, CheckContext], CheckResult]] = [
    # Discovery
    check_discovery,
    check_discovery_404,
    # Products
    check_list_products,
    check_search_products,
    check_get_product,
    check_get_product_404,
    check_product_releases,
    # Product releases
    check_list_product_releases,
    check_search_product_releases,
    check_get_product_release,
    check_product_release_collection_latest,
    check_product_release_collections,
    check_product_release_collection_version,
    # Components
    check_get_component,
    check_component_releases,
    check_component_release,
    check_component_release_collections,
    # Artifacts
    check_get_artifact,
    # CLE
    check_product_cle,
    check_product_release_cle,
    check_component_cle,
    check_component_release_cle,
    check_cle_event_ordering,
    # Cross-cutting
    check_uuid_format,
    check_pagination_fields,
    check_camel_case_fields,
]
