# Conformance Test Suite

The `libtea.conformance` module validates that a TEA server correctly implements the [Transparency Exchange API specification](https://github.com/CycloneDX/transparency-exchange-api). It runs 26 checks covering discovery, products, releases, components, artifacts, CLE, and cross-cutting concerns.

## Installation

```bash
pip install libtea[conformance]
```

This installs `pytest` as a dependency. The conformance suite can also be used without pytest via the programmatic API.

## Usage

### Programmatic API

```python
from libtea.conformance import run_conformance

result = run_conformance(
    "https://tea.example.com/v1",
    tei="urn:tei:purl:example.com:pkg:pypi/mylib",
    token="your-bearer-token",
    timeout=30.0,
)

print(f"{result.passed} passed, {result.failed} failed, {result.skipped} skipped")

for check in result.checks:
    if check.status.value == "fail":
        print(f"  FAIL: {check.name} — {check.message}")
        if check.details:
            print(f"        {check.details}")
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `base_url` | `str` | TEA server base URL (required) |
| `tei` | `str \| None` | TEI URN for discovery-driven testing |
| `product_uuid` | `str \| None` | Explicit product UUID |
| `product_release_uuid` | `str \| None` | Explicit product release UUID |
| `component_uuid` | `str \| None` | Explicit component UUID |
| `component_release_uuid` | `str \| None` | Explicit component release UUID |
| `artifact_uuid` | `str \| None` | Explicit artifact UUID |
| `token` | `str \| None` | Bearer token |
| `basic_auth` | `tuple[str, str] \| None` | `(user, password)` tuple |
| `timeout` | `float` | Request timeout in seconds (default: 30) |
| `allow_private_ips` | `bool` | Allow private IPs in downloads (default: False) |

**Returns:** `ConformanceResult` with `.passed`, `.failed`, `.skipped` counts and `.checks` list.

### CLI

```bash
# Basic conformance run
tea-cli conformance --base-url https://tea.example.com/v1

# With TEI for discovery-driven testing
tea-cli conformance --base-url https://tea.example.com/v1 --tei "urn:tei:..."

# With explicit UUIDs
tea-cli conformance --base-url https://tea.example.com/v1 \
    --product-uuid "a1b2c3d4-..." \
    --release-uuid "b2c3d4e5-..."

# JSON output (for CI pipelines)
tea-cli conformance --base-url https://tea.example.com/v1 --json

# With authentication
tea-cli conformance --base-url https://tea.example.com/v1 --token "$TEA_TOKEN"

# Verbose output (show failure details)
tea-cli conformance --base-url https://tea.example.com/v1 -v
```

The CLI exits with code 0 if all checks pass, and code 1 if any check fails.

### pytest plugin

The conformance suite registers as a pytest plugin via the `pytest11` entry point. It generates one parametrized test per conformance check.

```bash
# Run conformance checks as pytest tests
pytest --tea-base-url https://tea.example.com/v1 --tea-tei "urn:tei:..."

# With authentication
pytest --tea-base-url https://tea.example.com/v1 --tea-token "$TEA_TOKEN"

# Verbose pytest output
pytest --tea-base-url https://tea.example.com/v1 -v
```

**pytest options:**

| Option | Description |
|--------|-------------|
| `--tea-base-url` | TEA server base URL (required to enable conformance tests) |
| `--tea-tei` | TEI URN for discovery-driven testing |
| `--tea-token` | Bearer token |
| `--tea-product-uuid` | Explicit product UUID |
| `--tea-release-uuid` | Explicit product release UUID |
| `--tea-component-uuid` | Explicit component UUID |
| `--tea-component-release-uuid` | Explicit component release UUID |
| `--tea-artifact-uuid` | Explicit artifact UUID |
| `--tea-timeout` | Request timeout in seconds (default: 30) |

When `--tea-base-url` is not provided, all conformance tests are automatically skipped.

**Fixtures:**

- `tea_client` — session-scoped `TeaClient` instance
- `tea_check_context` — session-scoped `CheckContext` populated from CLI options

## How checks work

Checks run sequentially in a defined order. Earlier checks discover UUIDs and populate a shared `CheckContext`, so later checks can reference them without requiring the caller to supply every UUID upfront.

For example:
1. `check_list_products` discovers `product_uuid`
2. `check_get_product` uses that `product_uuid`
3. `check_product_releases` uses it to find `product_release_uuid`
4. `check_get_product_release` uses that to find `component_uuid`
5. ...and so on down the resource tree

Providing a TEI or explicit UUIDs seeds the context, enabling checks that depend on those resources.

Each check returns one of three statuses:
- **PASS** — the server responded correctly
- **FAIL** — the server's response violates the spec
- **SKIP** — the check couldn't run (missing prerequisite UUID or no data on server)

## Check reference

### Discovery (2 checks)

| Check | Description |
|-------|-------------|
| `discovery` | Discover a TEI and verify the server returns results |
| `discovery_404` | Verify unknown TEI returns 404 or empty list |

### Products (5 checks)

| Check | Description |
|-------|-------------|
| `list_products` | List products and discover a product UUID |
| `search_products` | Search products by identifier from a known product |
| `get_product` | Get a product by UUID |
| `get_product_404` | Verify unknown product UUID returns 404 |
| `product_releases` | Get releases for a product |

### Product releases (6 checks)

| Check | Description |
|-------|-------------|
| `list_product_releases` | List product releases and discover a release UUID |
| `search_product_releases` | Search releases by identifier from a known release |
| `get_product_release` | Get a product release by UUID, discover component UUID |
| `product_release_collection_latest` | Get latest collection, discover artifact UUID |
| `product_release_collections` | Get all collection versions |
| `product_release_collection_version` | Get collection version 1 |

### Components (4 checks)

| Check | Description |
|-------|-------------|
| `get_component` | Get a component by UUID |
| `component_releases` | Get releases for a component |
| `component_release` | Get a component release with its latest collection |
| `component_release_collections` | Get all collection versions for a component release |

### Artifacts (1 check)

| Check | Description |
|-------|-------------|
| `get_artifact` | Get artifact metadata by UUID |

### CLE (5 checks)

| Check | Description |
|-------|-------------|
| `product_cle` | Get CLE data for a product |
| `product_release_cle` | Get CLE data for a product release |
| `component_cle` | Get CLE data for a component |
| `component_release_cle` | Get CLE data for a component release |
| `cle_event_ordering` | Verify CLE events are ordered by id descending |

### Cross-cutting (3 checks)

| Check | Description |
|-------|-------------|
| `uuid_format` | Validate all collected UUIDs match canonical lowercase format |
| `pagination_fields` | Verify paginated listing exposes valid pagination metadata fields |
| `camel_case_fields` | Confirm server uses camelCase field names |

## CI integration

Example GitHub Actions workflow:

```yaml
- name: TEA conformance
  run: |
    pip install libtea[conformance]
    tea-cli conformance \
      --base-url "${{ secrets.TEA_BASE_URL }}" \
      --token "${{ secrets.TEA_TOKEN }}" \
      --json > conformance-report.json
```

Or with pytest for richer reporting:

```yaml
- name: TEA conformance (pytest)
  run: |
    pip install libtea[conformance]
    pytest --tea-base-url "${{ secrets.TEA_BASE_URL }}" \
           --tea-token "${{ secrets.TEA_TOKEN }}" \
           -v --tb=short
```
