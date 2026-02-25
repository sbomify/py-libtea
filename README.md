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
- Artifact download with on-the-fly checksum verification
- Typed Pydantic v2 models with full camelCase/snake_case conversion
- Structured exception hierarchy with error context

## Installation

```bash
pip install libtea
```

## Quick start

```python
from libtea import TeaClient

# Auto-discover from a domain's .well-known/tea
with TeaClient.from_well_known("example.com", token="your-bearer-token") as client:
    # Browse a product
    product = client.get_product("product-uuid")
    print(product.name)

    # Get a component release with its latest collection
    cr = client.get_component_release("release-uuid")
    for artifact in cr.latest_collection.artifacts:
        print(artifact.name, artifact.type)
```

Or connect directly to a known endpoint:

```python
client = TeaClient(base_url="https://api.example.com/tea/v0.3.0-beta.2")
```

## Usage

### Search

```python
with TeaClient.from_well_known("example.com") as client:
    # Search by PURL
    results = client.search_products("PURL", "pkg:pypi/requests")
    for product in results.results:
        print(product.name, product.uuid)

    # Search product releases
    releases = client.search_product_releases("PURL", "pkg:pypi/requests@2.31.0")
    print(releases.total_results)
```

### Products and releases

```python
with TeaClient.from_well_known("example.com") as client:
    product = client.get_product("product-uuid")
    print(product.name, product.identifiers)

    releases = client.get_product_releases("product-uuid", page_size=25)
    for release in releases.results:
        print(release.version, release.created_date)
```

### Components

```python
with TeaClient(base_url="https://api.example.com/tea/v1") as client:
    component = client.get_component("component-uuid")
    releases = client.get_component_releases("component-uuid")

    # Get a component release with its latest collection
    cr = client.get_component_release("release-uuid")
    print(cr.release.version, len(cr.latest_collection.artifacts))
```

### Collections and artifacts

```python
with TeaClient(base_url="https://api.example.com/tea/v1") as client:
    collection = client.get_component_release_collection_latest("release-uuid")
    for artifact in collection.artifacts:
        print(artifact.name, artifact.type)

    # Specific collection version
    collection_v3 = client.get_component_release_collection("release-uuid", 3)
```

### Downloading artifacts with checksum verification

```python
from pathlib import Path

with TeaClient(base_url="https://api.example.com/tea/v1") as client:
    artifact = client.get_artifact("artifact-uuid")
    fmt = artifact.formats[0]

    # Downloads and verifies checksums on-the-fly
    client.download_artifact(
        fmt.url,
        Path("sbom.json"),
        verify_checksums=fmt.checksums,
    )
```

### Discovery

```python
from libtea.discovery import parse_tei

# Parse a TEI URN
tei_type, domain, identifier = parse_tei(
    "urn:tei:purl:cyclonedx.org:pkg:pypi/cyclonedx-python-lib@8.4.0"
)

# Discover product releases by TEI
with TeaClient(base_url="https://api.example.com/tea/v1") as client:
    results = client.discover("urn:tei:uuid:example.com:d4d9f54a-abcf-11ee-ac79-1a52914d44b")
    for info in results:
        print(info.product_release_uuid, info.servers)
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

## Requirements

- Python >= 3.11
- [requests](https://requests.readthedocs.io/) for HTTP
- [Pydantic](https://docs.pydantic.dev/) v2 for data models

## Not yet supported

- Publisher API (spec is consumer-only in beta.2)
- Async client
- CLE (Common Lifecycle Enumeration) endpoints
- Mutual TLS (mTLS) authentication
- Endpoint failover with retry

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
