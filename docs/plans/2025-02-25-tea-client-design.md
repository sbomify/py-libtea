# TEA Client Library Design - v0.1.0

## Overview

py-libtea is a Python client library for the Transparency Exchange API (TEA) v0.3.0-beta.2.
This document covers the design for the initial v0.1.0 release targeting consumer-side functionality.

## Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Approach | Hand-crafted client | Auto-generated client already possible via CycloneDX's openapi-generator config; hand-crafted provides Pythonic ergonomics and implements discovery flow which generators can't |
| HTTP client | requests | Battle-tested, widely adopted, minimal dependency footprint |
| Data models | Pydantic v2 (>= 2.1) | Automatic JSON deserialization, validation, great editor support. Floor is 2.1+ because `pydantic.alias_generators.to_camel` was introduced in 2.1 |
| Sync/Async | Sync only (v0.1.0) | Primary consumers are CLI tools and CI pipelines; async is additive and can be introduced later without breaking changes |
| Python | >= 3.11 | Matches existing pyproject.toml constraint; enables `StrEnum` and modern type syntax |

## Scope

### In scope (v0.1.0)

- TEI parsing and validation
- `.well-known/tea` discovery (fetch and parse)
- Endpoint selection by version and priority (exact string match)
- Product browsing: get product by UUID
- Product Release: get by UUID, get latest collection
- Component browsing: get component by UUID, get releases
- Component Release: get by UUID, get latest collection, get specific collection version
- Collection access: list collections, get by version
- Artifact metadata: get artifact by UUID
- Artifact download with checksum verification
- Bearer token authentication
- Error handling with typed exceptions (all errors are `TeaError` subclasses)

### Deferred

- CLE (Common Lifecycle Enumeration) endpoints and models (4 endpoints, 6 schemas in spec)
- Query/search endpoints (`/products`, `/productReleases` with identifier filters)
- Full DNS-based TEI resolution (v0.1.0 uses direct base URL or `.well-known` only)
- SemVer-based version matching in endpoint selection (v0.1.0 uses exact string match)
- Endpoint failover with retry/backoff on 5xx/DNS/TLS failures (spec MUST requirement)
- Basic auth (`basicAuth` security scheme in spec) and mTLS authentication
- Async client (`AsyncTeaClient`)
- Pagination auto-iteration
- Publisher API (blocked on TEA spec — see `docs/FUTURE.md`)

### Known Limitations (v0.1.0)

- Endpoint selection uses exact string match, not SemVer 2.0.0 comparison as spec recommends
- No endpoint failover: if the selected endpoint fails, the error propagates to the caller
- `fetch_well_known` uses a standalone `requests.get()` call, not routed through `_http.py` (no User-Agent or retry). This is intentional since `.well-known` is typically public
- BLAKE3 checksum is in the enum but not supported at runtime (Python's `hashlib` does not include it). A clear `TeaChecksumError` is raised if a server provides a BLAKE3-only checksum

## Architecture

### Package Structure

```
libtea/
    __init__.py          # Public API exports, __version__
    py.typed             # PEP 561 marker
    client.py            # TeaClient - main entry point
    discovery.py         # TEI parsing, .well-known fetching, endpoint selection
    models.py            # Pydantic models for all TEA domain objects
    exceptions.py        # Exception hierarchy
    _http.py             # Internal requests wrapper (session management, auth, error mapping)
```

### Data Models (models.py)

All models use Pydantic v2 `BaseModel` with `alias_generator=to_camel` for camelCase JSON mapping and `populate_by_name=True` for snake_case Python access. All enums use `StrEnum` (Python 3.11+). Models do NOT use `from __future__ import annotations` (breaks Pydantic v2 runtime type evaluation).

**Shared types:**
- `Identifier` - idType (enum: CPE, TEI, PURL) + idValue
- `Checksum` - algType (enum) + algValue, with `@field_validator` to normalize both hyphen (`SHA-256`) and underscore (`SHA_256`) forms from servers
- `ChecksumAlgorithm` - enum: MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, BLAKE2b-256, BLAKE2b-384, BLAKE2b-512, BLAKE3
- `IdentifierType` - enum: CPE, TEI, PURL

**Domain objects:**
- `Product` - uuid, name, identifiers
- `ProductRelease` - uuid, product, productName, version, createdDate, releaseDate, preRelease, identifiers, components
- `ComponentRef` - uuid, release (optional)
- `Component` - uuid, name, identifiers
- `Release` (Component Release) - uuid, component, componentName, version, createdDate, releaseDate, preRelease, identifiers, distributions
- `ReleaseDistribution` - distributionType, description, identifiers, url, signatureUrl, checksums
- `ComponentReleaseWithCollection` - release, latestCollection
- `Collection` - uuid, version, date, belongsTo, updateReason, artifacts
- `CollectionBelongsTo` - enum: COMPONENT_RELEASE, PRODUCT_RELEASE
- `CollectionUpdateReason` - type (enum) + comment
- `CollectionUpdateReasonType` - enum: INITIAL_RELEASE, VEX_UPDATED, ARTIFACT_UPDATED, ARTIFACT_ADDED, ARTIFACT_REMOVED
- `Artifact` - uuid, name, type (enum), distributionTypes, formats
- `ArtifactType` - enum: ATTESTATION, BOM, BUILD_META, CERTIFICATION, FORMULATION, LICENSE, RELEASE_NOTES, SECURITY_TXT, THREAT_MODEL, VULNERABILITIES, OTHER
- `ArtifactFormat` - mediaType, description, url, signatureUrl, checksums

**Discovery types:**
- `TeaWellKnown` - schemaVersion (`Literal[1]`), endpoints
- `TeaEndpoint` - url, versions, priority
- `DiscoveryInfo` - productReleaseUuid, servers
- `TeaServerInfo` - rootUrl, versions, priority

**Pagination:**
- `PaginationDetails` - timestamp, pageStartIndex, pageSize, totalResults
- `PaginatedProductResponse` - pagination fields + results (list of Product)
- `PaginatedProductReleaseResponse` - pagination fields + results (list of ProductRelease)

**Error:**
- `ErrorResponse` - error (enum: OBJECT_UNKNOWN, OBJECT_NOT_SHAREABLE)

### Client API (client.py)

```python
class TeaClient:
    def __init__(self, base_url: str, *, token: str | None = None, timeout: float = 30.0): ...

    # Discovery
    @classmethod
    def from_well_known(cls, domain: str, *, token: str | None = None) -> "TeaClient": ...
    def discover(self, tei: str) -> list[DiscoveryInfo]: ...

    # Products
    def get_product(self, uuid: str) -> Product: ...
    def get_product_releases(self, uuid: str, *, page_offset: int = 0, page_size: int = 100) -> PaginatedProductReleaseResponse: ...

    # Product Releases
    def get_product_release(self, uuid: str) -> ProductRelease: ...
    def get_product_release_collection_latest(self, uuid: str) -> Collection: ...
    def get_product_release_collections(self, uuid: str) -> list[Collection]: ...
    def get_product_release_collection(self, uuid: str, version: int) -> Collection: ...

    # Components
    def get_component(self, uuid: str) -> Component: ...
    def get_component_releases(self, uuid: str) -> list[Release]: ...

    # Component Releases
    def get_component_release(self, uuid: str) -> ComponentReleaseWithCollection: ...
    def get_component_release_collection_latest(self, uuid: str) -> Collection: ...
    def get_component_release_collections(self, uuid: str) -> list[Collection]: ...
    def get_component_release_collection(self, uuid: str, version: int) -> Collection: ...

    # Artifacts
    def get_artifact(self, uuid: str) -> Artifact: ...
    def download_artifact(self, url: str, dest: Path, *, verify_checksums: list[Checksum] | None = None) -> Path: ...
```

### Discovery (discovery.py)

```python
def parse_tei(tei: str) -> tuple[str, str, str]:
    """Parse TEI URN into (type, domain, identifier)."""

def fetch_well_known(domain: str, *, timeout: float = 10.0) -> TeaWellKnown:
    """Fetch and parse .well-known/tea from domain via HTTPS."""

def select_endpoint(well_known: TeaWellKnown, supported_version: str) -> TeaEndpoint:
    """Select best endpoint by version match and priority."""
```

### Exception Hierarchy (exceptions.py)

```
TeaError (base)
    TeaConnectionError - network/connection failures
    TeaAuthenticationError - 401/403 responses
    TeaNotFoundError - 404 responses, with error_type: ErrorType | None
    TeaRequestError - 400 and other client errors
    TeaServerError - 5xx responses
    TeaDiscoveryError - discovery-specific failures (bad TEI, no .well-known, no compatible endpoint)
    TeaChecksumError - checksum verification failure on artifact download
    TeaValidationError - malformed server response that fails Pydantic validation
```

All exceptions from the client are `TeaError` subclasses. Raw `pydantic.ValidationError` from malformed server responses is caught and wrapped in `TeaValidationError`.

### Internal HTTP Layer (_http.py)

- Wraps `requests.Session` with base URL, auth headers, timeout, and user-agent
- Maps HTTP status codes to typed exceptions
- Handles JSON deserialization via Pydantic models
- User-Agent follows `py-libtea/{version} (hello@sbomify.com)` pattern matching sbomify-action

## Authentication

v0.1.0 supports bearer token auth only. The token is passed at client construction and sent as `Authorization: Bearer <token>` on API requests to the configured base URL. The token is NOT forwarded to artifact download URLs (which may be on third-party hosts like CDNs). A separate unauthenticated `requests.Session` is used for downloads. Unauthenticated access (no token) is also supported for public TEA servers.

## Error Handling

- All API errors raise typed exceptions from the hierarchy above
- HTTP 404 with TEA error body (`OBJECT_UNKNOWN`, `OBJECT_NOT_SHAREABLE`) is parsed into the exception
- Network errors are wrapped in `TeaConnectionError`
- Auth errors (401, 403) raise `TeaAuthenticationError` (no failover per spec)

## Checksum Verification

`download_artifact` streams the artifact to disk and computes checksums on-the-fly. If `verify_checksums` is provided, the computed hash is compared after download. On mismatch, the file is deleted and `TeaChecksumError` is raised.

Supported algorithms map directly to Python's `hashlib`: MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, BLAKE2b-256, BLAKE2b-384, BLAKE2b-512. BLAKE3 is defined in the enum for spec completeness but is NOT supported at runtime (not in stdlib `hashlib`). If a server provides only BLAKE3 checksums, a `TeaChecksumError` is raised with a clear message. Checksum hex values are compared case-insensitively.

## Dependencies

**Runtime:**
- `requests` >= 2.31.0 - HTTP client
- `pydantic` >= 2.1.0 - data models (2.1+ required for `to_camel` alias generator)

**Dev:**
- `pytest`, `pytest-cov` (already configured)
- `ruff` (already configured)
- `responses` - mock requests for testing

## Testing Strategy

- Shared fixtures in `tests/conftest.py` (base URL, client, http_client with yield cleanup)
- Unit tests for TEI parsing, endpoint selection, `.well-known` fetching, model deserialization
- Unit tests with mocked HTTP (responses) for all client methods including error paths
- Unit tests for checksum verification (valid, mismatch, case sensitivity, unsupported algorithm)
- Tests for optional field handling (minimal required-only payloads)
- Tests for `from_well_known` classmethod and token forwarding
- Integration test fixtures with example JSON from the TEA spec
- All tests run via `uv run pytest`
