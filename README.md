# libtea

Python client library for the [Transparency Exchange API (TEA)](https://transparency.exchange/) v0.3.0-beta.2.

> **Status**: Alpha — API is subject to change.

## Installation

```bash
pip install libtea
```

## Quick start

```python
from libtea import TeaClient

# Connect directly
client = TeaClient(base_url="https://api.example.com/tea/v0.3.0-beta.2")

# Or auto-discover from a domain's .well-known/tea
client = TeaClient.from_well_known("example.com")

# With authentication
client = TeaClient.from_well_known("example.com", token="your-bearer-token")
```

## Usage

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
    component = client.get_component("component-uuid")
    releases = client.get_component_releases("component-uuid")

    # Get a component release with its latest collection
    cr = client.get_component_release("release-uuid")
    print(cr.release.version, len(cr.latest_collection.artifacts))
```

### Collections and artifacts

```python
    collection = client.get_component_release_collection_latest("release-uuid")
    for artifact in collection.artifacts:
        print(artifact.name, artifact.type)

    # Specific collection version
    collection_v3 = client.get_component_release_collection("release-uuid", 3)
```

### Downloading artifacts with checksum verification

```python
from pathlib import Path

    artifact = client.get_artifact("artifact-uuid")
    fmt = artifact.formats[0]

    # Downloads and verifies checksums on-the-fly
    client.download_artifact(
        fmt.url,
        Path("sbom.json"),
        verify_checksums=fmt.checksums,
    )
```

### Discovery via TEI

```python
    results = client.discover("urn:tei:uuid:example.com:d4d9f54a-abcf-11ee-ac79-1a52914d44b")
    for info in results:
        print(info.product_release_uuid, info.servers)
```

## Error handling

All exceptions inherit from `TeaError`:

```python
from libtea.exceptions import (
    TeaError,              # Base exception
    TeaConnectionError,    # Network failure or timeout
    TeaAuthenticationError,# HTTP 401/403
    TeaNotFoundError,      # HTTP 404 (has .error_type: "OBJECT_UNKNOWN" or "OBJECT_NOT_SHAREABLE")
    TeaRequestError,       # HTTP 4xx (other)
    TeaServerError,        # HTTP 5xx
    TeaDiscoveryError,     # Invalid TEI, .well-known failure, or no compatible endpoint
    TeaChecksumError,      # Checksum mismatch (has .algorithm, .expected, .actual)
    TeaValidationError,    # Malformed server response
)
```

## Requirements

- Python >= 3.11
- [httpx](https://www.python-httpx.org/) for HTTP
- [Pydantic](https://docs.pydantic.dev/) v2 for data models

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
