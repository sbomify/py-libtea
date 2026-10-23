# libtea

[![CI](https://github.com/sbomify/py-libtea/actions/workflows/ci.yaml/badge.svg)](https://github.com/sbomify/py-libtea/actions/workflows/ci.yaml)
[![PyPI version](https://img.shields.io/pypi/v/libtea.svg)](https://pypi.org/project/libtea/)
[![Python](https://img.shields.io/pypi/pyversions/libtea.svg)](https://pypi.org/project/libtea/)
[![License](https://img.shields.io/github/license/sbomify/py-libtea.svg)](https://github.com/sbomify/py-libtea/blob/master/LICENSE)
[![sbomified](https://sbomify.com/assets/images/logo/badge.svg)](https://trust.sbomify.com/component/py-libtea/)

Python client library for the [Transparency Exchange API (TEA)](https://transparency.exchange/) 1.0.0, with compatibility for 0.4.0 servers.

TEA is an open standard for discovering and retrieving software transparency artifacts (SBOMs, VEX, build metadata) for any software product or component. A [TEI identifier](https://github.com/CycloneDX/transparency-exchange-api/blob/main/discovery/readme.md) resolves via DNS to the right endpoint, similar to how email uses MX records — so consumers can fetch artifacts without knowing which server hosts them.

**Specification:** [Ecma TC54-TG1](https://tc54.org/tea/) | [OpenAPI spec](https://github.com/CycloneDX/transparency-exchange-api)

> **Status**: Alpha — API is subject to change.
>
> **Upgrading?** libtea now targets TEA 1.0.0. See [Upgrading](#upgrading) for the Python API changes.

### Features

- Auto-discovery via `.well-known/tea` and TEIs (`tei://` URIs; the legacy URN form for 0.4.0 servers)
- Discovery by PURL on TEA 1.x servers
- Spec version negotiation — prefers TEA 1.0.0, falls back to 0.4.0 servers, and fails over across both
- Products, components, releases, and versioned collections
- Search by PURL, CPE, or TEI identifier
- Token-based pagination (`nextPageToken`) with auto-iterators for search results
- Bulk parallel fetch for products, releases, and artifacts
- Common Lifecycle Enumeration (CLE) — ECMA-428 lifecycle events
- Artifact download with on-the-fly checksum verification (SHA-1 through BLAKE2b; MD5 on 0.4.0 servers only)
- Download of artifact content hosted by the TEA server itself (TEA 1.x)
- Optional TTL response caching
- Endpoint failover with SemVer-compatible version selection
- SSRF protection — blocks private IPs, cloud metadata endpoints, DNS rebinding
- Bearer token and HTTP basic auth authentication
- Bearer token isolation — tokens are never sent to artifact download hosts
- `TeaClientProtocol` for dependency inversion and test doubles
- Typed Pydantic v2 models with full camelCase/snake_case conversion
- Structured exception hierarchy with error context
- CLI with rich-formatted output, JSON mode, and verbose logging
- Conformance test suite for validating TEA server compliance (programmatic, CLI, and pytest plugin)
- Server-side helpers (`tea_datetime_serializer`) for TEA API implementations
- Unfiltered listing endpoints (`list_products`, `list_product_releases`)

## Installation

```bash
pip install libtea
```

To include the CLI (`tea-cli`):

```bash
pip install libtea[cli]
```

To run conformance tests against a TEA server:

```bash
pip install libtea[conformance]
```

## Quick start

```python
from libtea import TeaClient

# Auto-discover the TEA server from the domain's .well-known/tea
with TeaClient.from_well_known("example.com") as client:
    # Discover a product by TEI
    results = client.discover("tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1")
    for info in results:
        print(info.product_release_uuid, info.servers)

    # Get a product release
    pr = client.get_product_release(results[0].product_release_uuid)
    print(pr.version, pr.product_name)
```

Or connect directly to a known endpoint. The `/v<semver>` suffix selects the spec version; `trust.sbomify.com` is a working TEA 0.4.0 server:

```python
client = TeaClient(
    base_url="https://trust.sbomify.com/tea/v0.4.0",
    timeout=30.0,
)

# A TEA 1.0.0 server
client = TeaClient(base_url="https://tea.example.com/tea/v1.0.0", timeout=30.0)
```

`from_well_known` negotiates the spec version for you (TEA 1.0.0 first, then 0.4.0). You can also pin a version and set the timeout:

```python
client = TeaClient.from_well_known(
    "trust.sbomify.com",
    timeout=15.0,
    version="0.4.0",  # default: None, i.e. negotiate 1.0.0 first, then 0.4.0
)
```

## Usage

### Spec versions

libtea speaks TEA 1.0.0 and 0.4.0. Each client knows which one it talks to, and its behaviour follows that version, never the shape of a response:

```python
client = TeaClient("https://trust.sbomify.com/tea/v0.4.0")
client.spec_version  # "0.4.0"
client.is_legacy  # True for 0.4.0, False for 1.x
```

The version comes from the `spec_version=` argument, else a `/v<semver>` suffix on `base_url`, else the default (`TEA_SPEC_VERSION`, `"1.0.0"`). A base URL without a version suffix, such as `https://tea.example.com/v1`, is treated as TEA 1.0.0. `libtea.client.SUPPORTED_SPEC_VERSIONS` lists the supported versions, highest first.

On a 0.4.0 server:

- the page token is the next result offset as a string, and `total_results`, `page_start_index`, `page_size` and `timestamp` are filled in (they are `None` on 1.x);
- `page_size` may be up to 10000 (up to 100 on 1.x);
- MD5 checksums are accepted;
- fields that only 1.0.0 requires may be missing;
- discovery by PURL and `download_artifact_content` are unavailable and raise `TeaValidationError`.

### Discovery

```python
from libtea import TeaClient

with TeaClient.from_well_known("example.com") as client:
    # Discover product releases via TEI
    results = client.discover("tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1")
    for info in results:
        print(info.product_release_uuid, info.servers)

    # Discover by PURL in this server's inventory (TEA 1.x servers only)
    results = client.discover(purl="pkg:github/sbomify/sbomify")
```

`discover` takes exactly one of `tei` and `purl`. The value is sent to the server verbatim, so pass a TEI in the form the server speaks: `tei://<domain>/<type>/<identifier>` for TEA 1.x, the legacy URN form for 0.4.0 servers (see [Upgrading](#upgrading)). On a 1.x server an unknown TEI is a 404 (`TeaNotFoundError`).

Low-level discovery functions are also available:

```python
from libtea.discovery import parse_tei, fetch_well_known, select_endpoint

# Parse a TEI: ("uuid", "example.com", "d4d9f54a-abcf-11ee-ac79-1a52914d44b1")
tei_type, domain, identifier = parse_tei("tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1")

# Fetch and select an endpoint manually
well_known = fetch_well_known(domain)
endpoint = select_endpoint(well_known, "1.0.0")
print(endpoint.url, endpoint.priority)
```

Known TEI types: `uuid`, `purl`, `hash`, `swid`, `eanupc`, `gtin`, `asin`, `udi` (`TeiType`). In the `tei://` form `parse_tei` accepts any type matching `[a-z][a-z0-9]*` (a lowercase letter, then lowercase letters or digits), so types added to the spec's registry keep working. A `purl` identifier in that form is the unpadded Base64URL encoding of the PURL; libtea passes it through unchanged.

### Search

```python
with TeaClient.from_well_known("trust.sbomify.com") as client:
    # Search by PURL
    results = client.search_products("PURL", "pkg:github/sbomify/sbomify")
    for product in results.results:
        print(product.name, product.uuid)

    # Search product releases, following the page token
    page = client.search_product_releases("PURL", "pkg:github/sbomify/sbomify", page_size=100)
    while True:
        for release in page.results:
            print(release.version)
        if not page.has_next:
            break
        page = client.search_product_releases(
            "PURL",
            "pkg:github/sbomify/sbomify",
            page_token=page.next_page_token,
            page_size=100,
        )
```

Each page has `results`, `has_next` and an opaque `next_page_token`, which you pass back as `page_token`. `page_size` is at most 100 on TEA 1.x servers. The 0.4.0 offset fields (`total_results` and the like) are `None` on 1.x; see [Spec versions](#spec-versions).

### Listing (unfiltered)

```python
with TeaClient.from_well_known("trust.sbomify.com") as client:
    # List all products (no identifier filter)
    products = client.list_products(page_size=50)
    for product in products.results:
        print(product.name, product.uuid)

    # List all product releases
    releases = client.list_product_releases(page_size=50)
    print(len(releases.results), releases.has_next)
```

### Auto-paginated iterators

For iterating over large result sets without manual page management:

```python
with TeaClient.from_well_known("trust.sbomify.com") as client:
    # Iterate all matching products (handles pagination automatically)
    for product in client.iter_products("PURL", "pkg:github/sbomify/sbomify"):
        print(product.name)

    # Iterate all product releases by identifier
    for release in client.iter_product_releases("PURL", "pkg:github/sbomify/sbomify"):
        print(release.version)

    # Iterate all releases for a specific product UUID
    for release in client.iter_releases_for_product("product-uuid"):
        print(release.version, release.created_date)
```

The iterators follow `next_page_token` and raise `TeaServerError` if a server repeats a token or keeps paging past 10,000 pages.

### Bulk parallel fetch

Fetch multiple resources by UUID in parallel:

```python
with TeaClient.from_well_known("trust.sbomify.com") as client:
    products = client.get_products(["uuid-1", "uuid-2", "uuid-3"])
    releases = client.get_product_releases_bulk(["uuid-1", "uuid-2"])
    artifacts = client.get_artifacts(["uuid-1", "uuid-2"])
```

Results are returned in the same order as the input UUIDs. Use `max_workers=1` for serial execution.

### Products and releases

```python
with TeaClient.from_well_known("trust.sbomify.com") as client:
    product = client.get_product("product-uuid")
    print(product.name, product.identifiers)

    releases = client.get_product_releases("product-uuid", page_size=25)
    for release in releases.results:
        print(release.version, release.created_date)

    # Single product release
    pr = client.get_product_release("release-uuid")
    print(pr.version, pr.components)
    print(len(pr.latest_collection.artifacts))  # latest_collection is None on 0.4.0 servers

    # Product release collections
    latest = client.get_product_release_collection_latest("release-uuid")
    all_versions = client.get_product_release_collections("release-uuid")
    specific = client.get_product_release_collection("release-uuid", 3)
```

### Components

```python
with TeaClient.from_well_known("trust.sbomify.com") as client:
    component = client.get_component("component-uuid")
    releases = client.get_component_releases("component-uuid")  # a list; every page is fetched on 1.x

    # Get a component release with its latest collection
    cr = client.get_component_release("release-uuid")
    print(cr.release.version, len(cr.latest_collection.artifacts))
```

### Collections and artifacts

```python
with TeaClient.from_well_known("trust.sbomify.com") as client:
    collection = client.get_component_release_collection_latest("release-uuid")
    for artifact in collection.artifacts:
        print(artifact.name, artifact.type)

    # All collection versions for a component release
    all_versions = client.get_component_release_collections("release-uuid")

    # Specific collection version
    collection_v3 = client.get_component_release_collection("release-uuid", 3)
```

### Downloading artifacts with checksum verification

```python
from pathlib import Path

with TeaClient.from_well_known("trust.sbomify.com") as client:
    artifact = client.get_artifact("artifact-uuid")
    fmt = artifact.formats[0]

    # Downloads and verifies checksums on-the-fly; returns the dest path
    path = client.download_artifact(
        fmt.url,
        Path("sbom.json"),
        verify_checksums=list(fmt.checksums),
    )
```

A format without a `url` is hosted by the TEA server itself (TEA 1.x). Fetch it through the server's download endpoint:

```python
from pathlib import Path

from libtea import TeaClient

with TeaClient("https://tea.example.com/tea/v1.0.0") as client:
    artifact = client.get_artifact("artifact-uuid")
    fmt = artifact.formats[0]

    if fmt.url is None:  # hosted by the TEA server itself
        path = client.download_artifact_content(
            artifact.uuid,
            Path("sbom.json"),
            media_type=fmt.media_type,  # required on TEA 1.x
            version=artifact.version,  # omit for the latest version
            verify_checksums=list(fmt.checksums),
        )
```

Supported checksum algorithms: SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, BLAKE2b-256, BLAKE2b-384, BLAKE2b-512, and MD5 on 0.4.0 servers (TEA 1.0.0 dropped MD5, so a 1.x response that carries it is rejected). BLAKE3 is recognized in the model but not verifiable (Python's `hashlib` has no BLAKE3 support — a clear error is raised).

`download_artifact` uses a separate unauthenticated HTTP session so the bearer token is never leaked to third-party hosts (CDNs, Maven Central, etc.). `download_artifact_content` sends the token only on its first request, to the API base, and never on a redirect. On checksum mismatch, the downloaded file is automatically deleted.

### Common Lifecycle Enumeration (CLE)

```python
with TeaClient.from_well_known("trust.sbomify.com") as client:
    # Get lifecycle events for a product release
    cle = client.get_product_release_cle("release-uuid")
    for event in cle.events:
        print(event.type, event.effective)

    # CLE is available for all entity types
    client.get_product_cle("product-uuid")
    client.get_component_cle("component-uuid")
    client.get_component_release_cle("release-uuid")
```

### Authentication

```python
from libtea import TeaClient

# Bearer token
client = TeaClient.from_well_known("trust.sbomify.com", token="your-token")

# HTTP basic auth
client = TeaClient.from_well_known("trust.sbomify.com", basic_auth=("user", "password"))
```

### Response caching

Enable optional TTL-based caching to avoid repeated API calls:

```python
# Cache GET responses for 5 minutes
client = TeaClient("https://trust.sbomify.com/tea/v0.4.0", cache_ttl=300)
product = client.get_product("uuid")  # HTTP call
product = client.get_product("uuid")  # served from cache

client.clear_cache()  # manually invalidate
```

Only JSON API responses are cached — artifact downloads are never cached.

### Private network access

By default, artifact downloads are blocked from private/internal IPs (SSRF protection). For local development:

```python
client = TeaClient.from_well_known(
    "trust.local",
    scheme="http",
    allow_private_ips=True,  # allows downloads from 127.0.0.1, 10.x, etc.
)
```

Scheme validation and cloud metadata endpoint blocking are always enforced. If the API base itself is a private address and its download endpoint redirects to its own host, `download_artifact_content` checks that redirect too, so it needs `allow_private_ips=True`.

### Testing with TeaClientProtocol

Use the `TeaClientProtocol` for dependency inversion in consumer code:

```python
from libtea import TeaClientProtocol


def fetch_sbom(client: TeaClientProtocol, product_uuid: str):
    """Accepts any object matching the TeaClient interface."""
    product = client.get_product(product_uuid)
    return product.name
```

This allows using mock objects in tests without depending on the concrete `TeaClient` class.

## CLI

The `tea-cli` command provides a terminal interface for all TEA operations. Install with `pip install libtea[cli]`. See the [full CLI reference](docs/cli.md) for detailed documentation.

### Global options

These flags can be placed before or after the subcommand name. They appear under each subcommand's `--help` output.

```
--json             Output raw JSON instead of rich-formatted tables
--verbose, -v      Show verbose output (libtea debug logs)
--debug, -d        Show debug output (full HTTP firehose including urllib3)
--allow-private-ips  Allow artifact downloads from private/internal IPs
--version          Show version
```

All commands also accept connection options: `--base-url`, `--domain`, `--token`, `--auth`, `--use-http`, `--port`.

### Discover

```bash
# Discover product releases via TEI (the TEI's domain is used to find the server)
tea-cli discover "tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1"

# UUIDs only (for scripting)
tea-cli discover -q "tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1"

# JSON output
tea-cli --json discover "tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1"

# Resolve a PURL on a TEA 1.x server (needs --base-url)
tea-cli discover --purl "pkg:github/sbomify/sbomify" --base-url https://tea.example.com/tea/v1.0.0
```

### Inspect (full flow)

```bash
# TEI -> discovery -> releases -> components -> artifacts in one shot
tea-cli inspect "tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1"

# Limit component resolution
tea-cli inspect --max-components 10 "tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
```

### Search

```bash
# Search products by PURL
tea-cli search-products --id-type PURL --id-value "pkg:github/sbomify/sbomify" \
    --domain trust.sbomify.com

# Search product releases
tea-cli search-releases --id-type PURL --id-value "pkg:github/sbomify/sbomify" \
    --domain trust.sbomify.com --page-size 50

# Next page: pass the token printed under the results (an offset on TEA 0.x servers)
tea-cli search-releases --id-type PURL --id-value "pkg:github/sbomify/sbomify" \
    --domain trust.sbomify.com --page-size 50 --page-token "<token>"
```

### Products and releases

```bash
# Get product details
tea-cli get-product <product-uuid> --domain trust.sbomify.com

# List releases for a product
tea-cli get-product-releases <product-uuid> --domain trust.sbomify.com

# Get a specific release (product or component)
tea-cli get-release <release-uuid> --domain trust.sbomify.com
tea-cli get-release <release-uuid> --component --domain trust.sbomify.com
```

### Components

```bash
# Get component details
tea-cli get-component <component-uuid> --domain trust.sbomify.com

# List component releases
tea-cli get-component-releases <component-uuid> --domain trust.sbomify.com
```

### Collections and artifacts

```bash
# Get latest collection (default) or specific version
tea-cli get-collection <release-uuid> --domain trust.sbomify.com
tea-cli get-collection <release-uuid> --version 3 --domain trust.sbomify.com

# List all collection versions
tea-cli list-collections <release-uuid> --domain trust.sbomify.com

# Get artifact metadata
tea-cli get-artifact <artifact-uuid> --domain trust.sbomify.com
```

### Download

```bash
# Download an artifact with checksum verification
tea-cli download "https://cdn.example.com/sbom.json" ./sbom.json \
    --checksum "SHA-256:abc123..." \
    --domain trust.sbomify.com

# Download every artifact of a TEI (formats without a url are fetched from the TEA 1.x server)
tea-cli download "tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1" ./sboms/
```

### Lifecycle (CLE)

```bash
# Get lifecycle events for different entity types
tea-cli get-cle <uuid> --entity product-release --domain trust.sbomify.com
tea-cli get-cle <uuid> --entity product --domain trust.sbomify.com
tea-cli get-cle <uuid> --entity component --domain trust.sbomify.com
tea-cli get-cle <uuid> --entity component-release --domain trust.sbomify.com
```

### Conformance

```bash
# Run conformance checks against a TEA server
tea-cli conformance --base-url https://tea.example.com/v1

# With TEI for discovery-driven testing
tea-cli conformance --base-url https://tea.example.com/v1 --tei "tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1"

# JSON output for CI pipelines
tea-cli conformance --base-url https://tea.example.com/v1 --json
```

### Environment variables

| Variable | Description |
|----------|-------------|
| `TEA_BASE_URL` | TEA server base URL (alternative to `--base-url`) |
| `TEA_TOKEN` | Bearer token (alternative to `--token`) |
| `TEA_AUTH` | Basic auth as `USER:PASSWORD` (alternative to `--auth`) |

### Shell completion

```bash
# Bash (add to ~/.bashrc)
eval "$(_TEA_CLI_COMPLETE=bash_source tea-cli)"

# Zsh (add to ~/.zshrc)
eval "$(_TEA_CLI_COMPLETE=zsh_source tea-cli)"

# Fish (add to ~/.config/fish/completions/tea-cli.fish)
_TEA_CLI_COMPLETE=fish_source tea-cli | source
```

## Conformance testing

The conformance suite validates that a TEA server correctly implements the specification. It runs 28 checks covering discovery, products, releases, components, artifacts, CLE, and cross-cutting concerns (UUID format, pagination, camelCase).

### Programmatic

```python
from libtea.conformance import run_conformance

result = run_conformance(
    "https://tea.example.com/v1",
    tei="tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1",
)
print(f"{result.passed} passed, {result.failed} failed, {result.skipped} skipped")
```

### CLI

```bash
tea-cli conformance --base-url https://tea.example.com/v1 --tei "tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
tea-cli conformance --base-url https://tea.example.com/v1 --json
```

### pytest plugin

```bash
pytest --tea-base-url https://tea.example.com/v1 --tea-tei "tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
```

The plugin generates one test per conformance check. See the [conformance docs](docs/conformance.md) for the full check reference.

## Server helpers

For TEA server implementations that use libtea models as response schemas:

```python
from datetime import datetime, timezone
from libtea.server import tea_datetime_serializer

# Serialize to TEA spec format: "2024-03-20T15:30:00Z"
tea_datetime_serializer(datetime.now(timezone.utc))
```

## Error handling

All exceptions inherit from `TeaError`:

```python
from libtea.exceptions import TeaError, TeaNotFoundError, TeaRequestError

try:
    product = client.get_product("d4d9f54a-abcf-11ee-ac79-1a52914d44b1")
except TeaNotFoundError as exc:
    print(exc.error_type)  # "OBJECT_UNKNOWN" ("OBJECT_NOT_SHAREABLE" on 0.4.0 servers)
except TeaError:
    print("Something went wrong")

try:
    client.list_products(page_token="stale-token")
except TeaRequestError as exc:
    print(exc.error_type)  # "INVALID_PAGE_TOKEN" from a TEA 1.x server; None if the body has no TEA error
except TeaError:
    print("Something went wrong")
```

The UUID argument must be well formed (a malformed one raises `TeaValidationError` before any request). A TEA 0.x client also rejects a non-numeric `page_token` with `TeaValidationError`, so the second example needs a 1.x server.

`error_type` is the `error` value of the server's TEA error body. `libtea.ErrorType` lists the known values (`OBJECT_UNKNOWN`, `NOT_IMPLEMENTED`, `NO_ACCEPTABLE_FORMAT`, `SIGNATURE_NOT_FOUND`, `INVALID_REQUEST`, `INVALID_PAGE_TOKEN`, and `OBJECT_NOT_SHAREABLE` on 0.4.0); servers may send others, which pass through as plain strings. Compare with `==`.

Exception hierarchy:

| Exception | When |
|-----------|------|
| `TeaConnectionError` | Network failure or timeout |
| `TeaAuthenticationError` | HTTP 401/403 |
| `TeaNotFoundError` | HTTP 404 (`.error_type` has the TEA error code) |
| `TeaRequestError` | Other HTTP 4xx (`.error_type` has the TEA error code) |
| `TeaServerError` | HTTP 5xx |
| `TeaDiscoveryError` | Invalid TEI, `.well-known` failure, or no compatible endpoint |
| `TeaChecksumError` | Checksum mismatch (`.algorithm`, `.expected`, `.actual`) |
| `TeaValidationError` | Malformed server response |
| `TeaInsecureTransportWarning` | Warning emitted when using plaintext HTTP |

Using a bearer token over plaintext HTTP raises `ValueError` immediately — HTTPS is required for authenticated requests.

## Upgrading

libtea now targets TEA 1.0.0 and still talks to 0.4.0 servers. These Python API changes can break code written against libtea 0.5.1.

**Spec versions**

- A base URL without a `/v<semver>` suffix (and no `spec_version=`) is now TEA 1.0.0, not 0.4.0. `TEA_SPEC_VERSION` is `"1.0.0"`. To keep talking to a 0.4.0 server, pass `spec_version="0.4.0"` or end the base URL in `/v0.4.0`.
- `TeaClient.from_well_known(version=None)` now negotiates: it prefers 1.0.0, falls back to 0.4.0, and fails over across both. It used to default to `"0.4.0"`. Pass `version="0.4.0"` to pin the old behaviour. It downgrades to another compatible version (with a warning) only when neither is advertised exactly; a prerelease such as `1.0.0-rc.1` does not count as 1.0.0. The API path uses the version spelling exactly as the server advertises it (for example `/v1.0.0+build.5`).
- A base URL ending in `/v<semver>` with a major version other than 0 or 1 (for example `/v2.0.0`) now raises `ValueError`.
- `TeaClient` gains `spec_version` and `is_legacy`. `TeaClientProtocol` gains them too, plus `download_artifact_content` and the new `discover` signature, so test doubles that implement the protocol need updating.

**Discovery and TEIs**

- TEIs are now `tei://<domain>/<type>/<identifier>`. `parse_tei` and the CLI still accept the legacy `urn:tei:<type>:<domain>:<identifier>` form, and `TeaClient.discover` sends whatever TEI you give it verbatim; use the legacy form with 0.4.0 servers.
- `discover(tei=None, *, purl=None)` takes exactly one of the two, otherwise `TeaValidationError`. PURL lookup needs a 1.x server. On a 1.x server an empty discovery array also raises `TeaValidationError`; an unknown TEI is a 404.

**Pagination**

- `page_offset: int` is replaced by `page_token: str | None` on `list_*`, `search_*` and `get_product_releases`; the CLI's `--page-offset` is now `--page-token`. On 0.4.0 servers the token is the next offset as a string (`"100"`).
- `Paginated*Response` has `has_next` and `next_page_token`. `timestamp`, `page_start_index`, `page_size` and `total_results` are now optional and are `None` on 1.x servers, so code that reads them must handle `None`. `PaginatedCollectionResponse` is new.
- `page_size` is at most 100 on 1.x servers (10000 on 0.4.0), otherwise `TeaValidationError`.
- The `iter_*` iterators follow tokens and raise `TeaServerError` when a token repeats or after 10,000 pages. On 1.x servers `get_component_releases` and `get_*_release_collections` still return a list, but they now fetch every page.

**Models**

- `Collection.date` is now `Collection.created_date`. A 0.4.0 `date` is mapped to it.
- `get_product_release` returns `ProductReleaseWithCollection`, a `ProductRelease` subclass with `latest_collection` (`None` on 0.4.0 servers). Because of that, JSON output for a product release (`tea-cli --json get-release`, `tea-cli inspect`) now includes `latestCollection`: the collection on 1.x servers, `null` on 0.4.0 servers.
- `ComponentReleaseWithCollection` still exposes `.release` and `.latest_collection`, and now accepts the flattened 1.0.0 wire shape. Keyword construction with a dict, `ComponentReleaseWithCollection(release={...}, ...)`, now fails; pass a `Release` instance instead.
- Fields that both spec versions require are no longer optional: `Checksum.algorithm_type` and `algorithm_value`, `Artifact.uuid`, `type` and `formats`, and `ReleaseDistribution.distribution_id`. Building one without them now fails.
- Fields that only 1.0.0 requires (for example `Release.component`, `ProductRelease.product`, `Artifact.version` and `created_date`, `ArtifactFormat.media_type`, `Identifier.id_type` and `id_value`, and the `Collection` fields) keep their optional types, but a 1.x response that omits one raises `TeaValidationError`. 0.4.0 responses may omit them.
- Models you build in Python follow the 1.0.0 rules too: leaving out a field that only 1.0.0 requires raises pydantic `ValidationError`. That breaks test doubles such as `Collection()`, `Identifier(id_type="PURL")` and a `Paginated*Response` built without `has_next` or `results`. For 0.4.0-shaped data, pass the wire (camelCase) dict to `model_validate(..., context={"tea_legacy": True})`. Don't nest instances built that way into a model you build without that context; the outer model checks them against the 1.0.0 rules and fails.
- Removed: `ReleaseDistribution.distribution_type`, `Artifact.distribution_types`, and the `mimeType` alias for `ArtifactFormat.media_type`.
- `ComplianceDocumentType.FEDRAMP` is now `"FEDRAMP"` (was `"FedRAMP"`), and `EU_DECLARATION_OF_CONFORMITY` is new.

**Checksums**

MD5 is rejected in responses from 1.x servers and still accepted from 0.4.0 servers (and by the CLI's `--checksum`). To build an MD5 `Checksum` yourself, validate it in the legacy context; a plain `Checksum(...)` follows the 1.0.0 rules:

```python
from libtea import Checksum

md5 = Checksum.model_validate(
    {"algType": "MD5", "algValue": "d41d8cd98f00b204e9800998ecf8427e"},
    context={"tea_legacy": True},
)
```

**Downloads**

- `download_artifact` and `download_artifact_content` now refuse a redirect from HTTPS to HTTP and raise `TeaValidationError`; the partial file is deleted. HTTP-to-HTTP and HTTP-to-HTTPS redirects still work.

**Errors**

- `ErrorResponse.error` is a `str` (was `ErrorType`); compare it with `==`. `ErrorResponse.message` is new, and `ErrorType` has the 1.0.0 values.
- `TeaRequestError` now has `.error_type`, like `TeaNotFoundError`. libtea reads at most 4 KiB of a 4xx body to find it, and cuts the message snippet at 200 characters.

## Requirements

- Python >= 3.11
- [requests](https://requests.readthedocs.io/) >= 2.32.4 for HTTP
- [Pydantic](https://docs.pydantic.dev/) >= 2.1.0 for data models
- [semver](https://python-semver.readthedocs.io/) >= 3.0.4 for version selection

Optional:
- CLI: [click](https://click.palletsprojects.com/) >= 8.0, [rich](https://rich.readthedocs.io/) >= 13.0.0
- Conformance: [pytest](https://docs.pytest.org/) >= 8.0.0

## Not yet supported

- Publisher API (blocked on the TEA spec)
- Async client
- Some TEA 1.0.0 consumer features: the `/token` exchange, `ETag` revalidation, signature downloads, `sortField`/`sortOrder` and following `servers[].rootUrl`. See [docs/FUTURE.md](docs/FUTURE.md)

## Development

This project uses [uv](https://docs.astral.sh/uv/) for dependency management.

```bash
uv sync                        # Install dependencies
uv run pytest                  # Run tests (with coverage)
uv run ruff check .            # Lint
uv run ruff format --check .   # Format check
uv build                       # Build wheel and sdist
```

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.
