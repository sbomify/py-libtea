# libtea

[![CI](https://github.com/sbomify/py-libtea/actions/workflows/ci.yaml/badge.svg)](https://github.com/sbomify/py-libtea/actions/workflows/ci.yaml)
[![PyPI version](https://img.shields.io/pypi/v/libtea.svg)](https://pypi.org/project/libtea/)
[![Python](https://img.shields.io/pypi/pyversions/libtea.svg)](https://pypi.org/project/libtea/)
[![License](https://img.shields.io/github/license/sbomify/py-libtea.svg)](https://github.com/sbomify/py-libtea/blob/master/LICENSE)

Python client library for the [Transparency Exchange API (TEA)](https://transparency.exchange/) v0.3.0-beta.2.

TEA is an open standard for discovering and retrieving software transparency artifacts (SBOMs, VEX, build metadata) for any software product or component. A [TEI identifier](https://github.com/CycloneDX/transparency-exchange-api/blob/main/discovery/readme.md) resolves via DNS to the right endpoint, similar to how email uses MX records — so consumers can fetch artifacts without knowing which server hosts them.

**Specification:** [Ecma TC54-TG1](https://tc54.org/tea/) | [OpenAPI spec](https://github.com/CycloneDX/transparency-exchange-api)

> **Status**: Alpha — API is subject to change.

### Features

- Auto-discovery via `.well-known/tea` and TEI URNs
- Products, components, releases, and versioned collections
- Search by PURL, CPE, or TEI identifier
- Common Lifecycle Enumeration (CLE) — ECMA-428 lifecycle events
- Artifact download with on-the-fly checksum verification (MD5 through BLAKE2b)
- Endpoint failover with SemVer-compatible version selection
- Bearer token, HTTP basic auth, and mutual TLS (mTLS) authentication
- Bearer token isolation — tokens are never sent to artifact download hosts
- Typed Pydantic v2 models with full camelCase/snake_case conversion
- Structured exception hierarchy with error context
- CLI with rich-formatted output and JSON mode

## Installation

```bash
pip install libtea
```

To include the CLI (`tea-cli`):

```bash
pip install libtea[cli]
```

## Quick start

```python
from libtea import TeaClient

# Auto-discover the sbomify TEA server from its .well-known/tea
with TeaClient.from_well_known("trust.sbomify.com", token="your-bearer-token") as client:
    # Discover a product by TEI
    results = client.discover(
        "urn:tei:purl:trust.sbomify.com:pkg:github/sbomify/sbomify"
    )
    for info in results:
        print(info.product_release_uuid, info.servers)

    # Get a product release
    pr = client.get_product_release(results[0].product_release_uuid)
    print(pr.version, pr.product_name)
```

Or connect directly to a known endpoint:

```python
client = TeaClient(
    base_url="https://trust.sbomify.com/tea/v0.3.0-beta.2",
    token="your-bearer-token",
    timeout=30.0,
)
```

Using `from_well_known`, you can also override the spec version and timeout:

```python
client = TeaClient.from_well_known(
    "trust.sbomify.com",
    token="your-bearer-token",
    timeout=15.0,
    version="0.3.0-beta.2",  # default
)
```

## Usage

### Discovery

```python
from libtea import TeaClient

# Discover sbomify products via TEI
with TeaClient.from_well_known("trust.sbomify.com") as client:
    results = client.discover(
        "urn:tei:purl:trust.sbomify.com:pkg:github/sbomify/sbomify"
    )
    for info in results:
        print(info.product_release_uuid, info.servers)
```

Low-level discovery functions are also available:

```python
from libtea.discovery import parse_tei, fetch_well_known, select_endpoint

# Parse a TEI URN
tei_type, domain, identifier = parse_tei(
    "urn:tei:purl:trust.sbomify.com:pkg:github/sbomify/sbomify"
)

# Fetch and select an endpoint manually
well_known = fetch_well_known("trust.sbomify.com")
endpoint = select_endpoint(well_known, "0.3.0-beta.2")
print(endpoint.url, endpoint.priority)
```

Supported TEI types: `uuid`, `purl`, `hash`, `swid`, `eanupc`, `gtin`, `asin`, `udi`.

### Search

```python
with TeaClient.from_well_known("trust.sbomify.com") as client:
    # Search by PURL
    results = client.search_products("PURL", "pkg:github/sbomify/sbomify")
    for product in results.results:
        print(product.name, product.uuid)

    # Search product releases (with pagination)
    releases = client.search_product_releases(
        "PURL", "pkg:github/sbomify/sbomify",
        page_offset=0, page_size=100,
    )
    print(releases.total_results)
```

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

    # Product release collections
    latest = client.get_product_release_collection_latest("release-uuid")
    all_versions = client.get_product_release_collections("release-uuid")
    specific = client.get_product_release_collection("release-uuid", 3)
```

### Components

```python
with TeaClient.from_well_known("trust.sbomify.com") as client:
    component = client.get_component("component-uuid")
    releases = client.get_component_releases("component-uuid")

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
        verify_checksums=fmt.checksums,
    )
```

Supported checksum algorithms: MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, BLAKE2b-256, BLAKE2b-384, BLAKE2b-512. BLAKE3 is recognized in the model but not verifiable (Python's `hashlib` has no BLAKE3 support — a clear error is raised).

Artifact downloads use a separate unauthenticated HTTP session so the bearer token is never leaked to third-party hosts (CDNs, Maven Central, etc.). On checksum mismatch, the downloaded file is automatically deleted.

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
from libtea import TeaClient, MtlsConfig
from pathlib import Path

# Bearer token
client = TeaClient.from_well_known("trust.sbomify.com", token="your-token")

# HTTP basic auth
client = TeaClient.from_well_known("trust.sbomify.com", basic_auth=("user", "password"))

# Mutual TLS (mTLS)
client = TeaClient.from_well_known(
    "trust.sbomify.com",
    mtls=MtlsConfig(
        client_cert=Path("client.pem"),
        client_key=Path("client-key.pem"),
        ca_bundle=Path("ca-bundle.pem"),  # optional
    ),
)
```

## CLI

The `tea-cli` command provides a terminal interface for all TEA operations. Install with `pip install libtea[cli]`. See the [full CLI reference](docs/cli.md) for detailed documentation.

### Global options

```
--json       Output raw JSON instead of rich-formatted tables
--debug, -d  Show debug output (HTTP requests, timing)
--version    Show version
```

All commands accept connection options: `--base-url`, `--domain`, `--token`, `--auth`, `--use-http`, `--port`, `--client-cert`, `--client-key`, `--ca-bundle`.

### Discover

```bash
# Discover sbomify product releases via TEI
tea-cli discover "urn:tei:purl:trust.sbomify.com:pkg:github/sbomify/sbomify"

# UUIDs only (for scripting)
tea-cli discover -q "urn:tei:purl:trust.sbomify.com:pkg:github/sbomify/sbomify"

# JSON output
tea-cli --json discover "urn:tei:purl:trust.sbomify.com:pkg:github/sbomify/sbomify"
```

### Inspect (full flow)

```bash
# TEI -> discovery -> releases -> components -> artifacts in one shot
tea-cli inspect "urn:tei:purl:trust.sbomify.com:pkg:github/sbomify/sbomify"

# Limit component resolution
tea-cli inspect --max-components 10 "urn:tei:purl:trust.sbomify.com:pkg:github/sbomify/sbomify"
```

### Search

```bash
# Search products by PURL
tea-cli search-products --id-type PURL --id-value "pkg:github/sbomify/sbomify" \
    --domain trust.sbomify.com

# Search product releases
tea-cli search-releases --id-type PURL --id-value "pkg:github/sbomify/sbomify" \
    --domain trust.sbomify.com --page-size 50
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
```

### Lifecycle (CLE)

```bash
# Get lifecycle events for different entity types
tea-cli get-cle <uuid> --entity product-release --domain trust.sbomify.com
tea-cli get-cle <uuid> --entity product --domain trust.sbomify.com
tea-cli get-cle <uuid> --entity component --domain trust.sbomify.com
tea-cli get-cle <uuid> --entity component-release --domain trust.sbomify.com
```

### Environment variables

| Variable | Description |
|----------|-------------|
| `TEA_BASE_URL` | TEA server base URL (alternative to `--base-url`) |
| `TEA_TOKEN` | Bearer token (alternative to `--token`) |
| `TEA_AUTH` | Basic auth as `USER:PASSWORD` (alternative to `--auth`) |

### Shell completion

```bash
# Bash
tea-cli --install-completion bash

# Zsh
tea-cli --install-completion zsh

# Fish
tea-cli --install-completion fish
```

## Error handling

All exceptions inherit from `TeaError`:

```python
from libtea.exceptions import TeaError, TeaNotFoundError, TeaChecksumError

try:
    product = client.get_product("unknown-uuid")
except TeaNotFoundError as exc:
    print(exc.error_type)  # "OBJECT_UNKNOWN" or "OBJECT_NOT_SHAREABLE"
except TeaError:
    print("Something went wrong")
```

Exception hierarchy:

| Exception | When |
|-----------|------|
| `TeaConnectionError` | Network failure or timeout |
| `TeaAuthenticationError` | HTTP 401/403 |
| `TeaNotFoundError` | HTTP 404 (`.error_type` has the TEA error code) |
| `TeaRequestError` | Other HTTP 4xx |
| `TeaServerError` | HTTP 5xx |
| `TeaDiscoveryError` | Invalid TEI, `.well-known` failure, or no compatible endpoint |
| `TeaChecksumError` | Checksum mismatch (`.algorithm`, `.expected`, `.actual`) |
| `TeaValidationError` | Malformed server response |
| `TeaInsecureTransportWarning` | Warning emitted when using plaintext HTTP |

Using a bearer token over plaintext HTTP raises `ValueError` immediately — HTTPS is required for authenticated requests.

## Requirements

- Python >= 3.11
- [requests](https://requests.readthedocs.io/) >= 2.32.4 for HTTP
- [Pydantic](https://docs.pydantic.dev/) >= 2.1.0 for data models
- [semver](https://python-semver.readthedocs.io/) >= 3.0.4 for version selection

Optional (for CLI): [typer](https://typer.tiangolo.com/) >= 0.12.0, [rich](https://rich.readthedocs.io/) >= 13.0.0

## Not yet supported

- Publisher API (spec is consumer-only in beta.2)
- Async client (httpx migration)

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
