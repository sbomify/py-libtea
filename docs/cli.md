# tea-cli Reference

Command-line client for the Transparency Exchange API (TEA).

## Synopsis

```
tea-cli [GLOBAL OPTIONS] COMMAND [COMMAND OPTIONS]
```

## Description

`tea-cli` is a command-line interface for the Transparency Exchange API (TEA) v0.3.0-beta.2. It discovers, searches, and retrieves software transparency artifacts (SBOMs, VEX, build metadata) from TEA-compliant servers.

Output is rich-formatted by default (tables, panels) for interactive use. Use `--json` for machine-readable JSON output suitable for piping.

`tea-cli` is part of the [libtea](https://github.com/sbomify/py-libtea) Python library, maintained by sbomify.

## Installation

```bash
pip install libtea[cli]
```

## Global Options

| Option | Description |
|--------|-------------|
| `--json` | Output raw JSON instead of rich-formatted tables |
| `--debug`, `-d` | Show debug output (HTTP requests, timing) on stderr |
| `--version` | Show version and exit |
| `--help` | Show help message and exit |

## Connection Options

Every command accepts the following options for server selection and authentication.

| Option | Description |
|--------|-------------|
| `--base-url` *URL* | TEA server base URL (e.g. `https://trust.sbomify.com/tea/v0.3.0-beta.2`). Can also be set via the `TEA_BASE_URL` environment variable. Mutually exclusive with `--domain`. |
| `--domain` *DOMAIN* | Discover server from the domain's `.well-known/tea` endpoint. The domain can also be auto-extracted from a TEI URN argument. |
| `--token` *TOKEN* | Bearer token for authentication. Prefer the `TEA_TOKEN` environment variable to avoid exposing the token in shell history. |
| `--auth` *USER:PASSWORD* | HTTP basic authentication credentials. Prefer the `TEA_AUTH` environment variable to avoid exposing credentials in shell history. Mutually exclusive with `--token`. |
| `--client-cert` *PATH* | Path to client certificate for mutual TLS (mTLS). Must be used with `--client-key`. |
| `--client-key` *PATH* | Path to client private key for mTLS. Must be used with `--client-cert`. |
| `--ca-bundle` *PATH* | Path to CA bundle for mTLS server verification. |
| `--timeout` *SECONDS* | Request timeout in seconds (default: 30). |
| `--use-http` | Use HTTP instead of HTTPS for `.well-known/tea` discovery. Intended for local development only. |
| `--port` *PORT* | Port for well-known resolution (overrides the default for the scheme). |

## Commands

### discover

Resolve a TEI URN to product release UUID(s).

```
tea-cli discover [--quiet | -q] TEI
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| *TEI* | A TEI URN (e.g. `urn:tei:purl:trust.sbomify.com:pkg:github/sbomify/sbomify`). The domain is auto-extracted for server discovery when `--base-url` and `--domain` are omitted. |

**Options:**

| Option | Description |
|--------|-------------|
| `--quiet`, `-q` | Output only UUIDs, one per line. Useful for scripting. |

---

### inspect

Full flow: TEI -> discovery -> product releases -> components -> artifacts. Resolves a TEI and fetches the full object graph in one shot.

```
tea-cli inspect [--max-components N] TEI
```

**Options:**

| Option | Description |
|--------|-------------|
| `--max-components` *N* | Maximum number of components to fetch per release (default: 50). |

---

### search-products

Search for products by identifier.

```
tea-cli search-products --id-type TYPE --id-value VALUE [--page-offset N] [--page-size N]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--id-type` *TYPE* | Identifier type: `CPE`, `TEI`, or `PURL`. |
| `--id-value` *VALUE* | Identifier value to search for. |
| `--page-offset` *N* | Page offset for pagination (default: 0). |
| `--page-size` *N* | Page size for pagination (default: 100). |

---

### search-releases

Search for product releases by identifier.

```
tea-cli search-releases --id-type TYPE --id-value VALUE [--page-offset N] [--page-size N]
```

Options are the same as `search-products`.

---

### get-product

Get a product by UUID.

```
tea-cli get-product UUID
```

---

### get-product-releases

List releases for a product UUID.

```
tea-cli get-product-releases UUID [--page-offset N] [--page-size N]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--page-offset` *N* | Page offset for pagination (default: 0). |
| `--page-size` *N* | Page size for pagination (default: 100). |

---

### get-release

Get a product or component release by UUID.

```
tea-cli get-release [--component] UUID
```

**Options:**

| Option | Description |
|--------|-------------|
| `--component` | Get a component release instead of a product release. |

---

### get-component

Get a component by UUID.

```
tea-cli get-component UUID
```

---

### get-component-releases

List releases for a component UUID.

```
tea-cli get-component-releases UUID
```

---

### get-collection

Get a collection (latest or by version).

```
tea-cli get-collection [--version N] [--component] UUID
```

**Options:**

| Option | Description |
|--------|-------------|
| `--version` *N* | Collection version number. If omitted, returns the latest collection. |
| `--component` | Get from component release instead of product release. |

---

### list-collections

List all collection versions for a release UUID.

```
tea-cli list-collections [--component] UUID
```

**Options:**

| Option | Description |
|--------|-------------|
| `--component` | List collections for a component release instead of a product release. |

---

### get-artifact

Get artifact metadata by UUID.

```
tea-cli get-artifact UUID
```

---

### download

Download an artifact file with optional checksum verification.

```
tea-cli download URL DEST [--checksum ALG:VALUE]... [--max-download-bytes N]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| *URL* | Artifact download URL. |
| *DEST* | Local file path to save the downloaded artifact. |

**Options:**

| Option | Description |
|--------|-------------|
| `--checksum` *ALG:VALUE* | Checksum to verify, as `ALGORITHM:HEX_VALUE`. Can be specified multiple times. Supported algorithms: MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, BLAKE2b-256, BLAKE2b-384, BLAKE2b-512. |
| `--max-download-bytes` *N* | Maximum download size in bytes. The download is aborted if the response exceeds this limit. |

---

### get-cle

Get Common Lifecycle Enumeration (CLE) events for an entity.

```
tea-cli get-cle [--entity TYPE] UUID
```

**Options:**

| Option | Description |
|--------|-------------|
| `--entity` *TYPE* | Entity type: `product`, `product-release` (default), `component`, or `component-release`. |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `TEA_BASE_URL` | TEA server base URL. Equivalent to `--base-url`. |
| `TEA_TOKEN` | Bearer token. Equivalent to `--token`. Preferred over the command-line flag to avoid exposing the token in shell history. |
| `TEA_AUTH` | Basic auth credentials as `USER:PASSWORD`. Equivalent to `--auth`. |

## Authentication

`tea-cli` supports three authentication methods, all mutually exclusive:

**Bearer token** (most common): Pass via `--token` or `TEA_TOKEN`. Requires HTTPS. The token is never sent to artifact download URLs (CDNs) — only to the TEA API server.

**HTTP basic auth:** Pass via `--auth USER:PASSWORD` or `TEA_AUTH`. Requires HTTPS.

**Mutual TLS (mTLS):** Pass certificate and key via `--client-cert` and `--client-key`. Optionally provide a CA bundle with `--ca-bundle`.

Using credentials over plaintext HTTP raises an error. Use `--use-http` only for unauthenticated local development.

## Examples

Discover sbomify product releases:

```bash
tea-cli discover "urn:tei:purl:trust.sbomify.com:pkg:github/sbomify/sbomify"
```

Full inspection with JSON output:

```bash
tea-cli --json inspect "urn:tei:purl:trust.sbomify.com:pkg:github/sbomify/sbomify"
```

Search for a product by PURL:

```bash
tea-cli search-products \
    --id-type PURL \
    --id-value "pkg:github/sbomify/sbomify" \
    --domain trust.sbomify.com
```

Get lifecycle events for a product release:

```bash
tea-cli get-cle --entity product-release <uuid> \
    --domain trust.sbomify.com
```

Download an artifact with checksum verification:

```bash
tea-cli download "https://cdn.example.com/sbom.json" ./sbom.json \
    --checksum "SHA-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
    --domain trust.sbomify.com
```

Pipe UUIDs to another tool:

```bash
tea-cli discover -q "urn:tei:purl:trust.sbomify.com:pkg:github/sbomify/sbomify" | \
    xargs -I {} tea-cli --json get-release {} --domain trust.sbomify.com
```

Using environment variables to avoid repeating credentials:

```bash
export TEA_TOKEN="your-bearer-token"
export TEA_BASE_URL="https://trust.sbomify.com/tea/v0.3.0-beta.2"
tea-cli discover "urn:tei:purl:trust.sbomify.com:pkg:github/sbomify/sbomify"
tea-cli get-product <product-uuid>
```

Mutual TLS authentication:

```bash
tea-cli get-product <uuid> \
    --domain trust.sbomify.com \
    --client-cert client.pem \
    --client-key client-key.pem \
    --ca-bundle ca-bundle.pem
```

## Exit Status

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error (network failure, authentication error, not found, invalid input, etc.). The error message is printed to stderr. |

## See Also

- [Transparency Exchange API](https://transparency.exchange/)
- [py-libtea on GitHub](https://github.com/sbomify/py-libtea)
- [TEA specification](https://github.com/CycloneDX/transparency-exchange-api)
