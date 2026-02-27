# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**py-libtea** is a hand-crafted Python client library for the Transparency Exchange API (TEA) v0.3.0-beta.2. Consumer-focused (read-only); publisher API is not yet supported (blocked on TEA spec). Licensed Apache 2.0, maintained under sbomify.

## Build & Dev Commands

```bash
uv sync                                    # Install all dependencies
uv run pytest                              # Run full test suite with coverage
uv run pytest tests/client/test_client.py -v      # Run a single test file
uv run pytest tests/unit/test_security.py::TestSsrfProtection::test_rejects_cgnat_ip -v  # Single test
uv run mypy                                # Type check (strict mode)
uv run ruff check .                        # Lint
uv run ruff format --check .               # Format check
uv run ruff format .                       # Auto-format
uv build                                   # Build wheel and sdist
```

## Code Conventions

- **Layout**: src/ layout (`src/libtea/`), hatchling build backend
- **Python**: >=3.11 (enables `StrEnum`, `X | Y` union syntax)
- **Line length**: 120, ruff rules: E, F, I
- **Models**: Pydantic v2 with `frozen=True`, `extra="ignore"`, `alias_generator=to_camel`
- **HTTP mocking**: `responses` library (not `unittest.mock` for HTTP)
- **Coverage**: Branch coverage enabled, target ~97%

## Architecture

The library has a layered design with strict separation of concerns:

```
__init__.py          Public API re-exports (all models, exceptions, client, discovery)
client.py            TeaClient — high-level consumer API, checksum verification
  ↓ uses
_validation.py       Input validation helpers (path segments, page size/offset, Pydantic wrappers)
_http.py             TeaHttpClient — low-level requests wrapper, auth, streaming downloads
                     Also: probe_endpoint() for endpoint failover
_security.py         SSRF protection (_validate_download_url, DNS rebinding checks, internal IP detection)
_hashing.py          Checksum hash builders (SHA-*, BLAKE2b-*, MD5)
discovery.py         TEI parsing, .well-known/tea fetching, SemVer endpoint selection, redirect SSRF protection
models.py            Pydantic v2 models for all TEA domain objects (frozen, camelCase aliases)
exceptions.py        Exception hierarchy (all inherit from TeaError)
cli.py               typer CLI (optional dependency, thin wrapper over TeaClient)
_cli_fmt.py          Rich output formatters for all CLI commands (tables, panels, escape helpers)
_cli_entry.py        Entry point wrapper that handles missing typer gracefully
```

**Key design patterns:**

- `TeaClient` delegates all HTTP to `TeaHttpClient` — never calls `requests` directly
- Bearer tokens are NOT sent to artifact download URLs (separate unauthenticated session prevents token leakage to CDNs)
- Downloads follow redirects manually with SSRF validation at each hop
- Discovery redirects are validated against internal networks (SSRF protection via `_security._validate_download_url`)
- `_validation._validate()` wraps Pydantic `ValidationError` into `TeaValidationError` so all client errors are `TeaError` subclasses
- Endpoint failover: `from_well_known()` probes candidates in priority order, skipping unreachable ones
- `probe_endpoint()` lives in `_http.py` (not `client.py`) to maintain the HTTP layer boundary
- `_raise_for_status()` uses bounded reads (201 bytes) for error body snippets to avoid memory issues on streaming responses
- CLI formatters in `_cli_fmt.py` escape all server-controlled strings with `rich.markup.escape()` to prevent Rich markup injection

**Auth**: Bearer token, basic auth, and mTLS (via `MtlsConfig` dataclass) are mutually configurable. Token and basic_auth are mutually exclusive. HTTP (non-TLS) with credentials is rejected.

## Critical Implementation Rules

- **NEVER** use `from __future__ import annotations` in files containing Pydantic models — it breaks Pydantic v2 runtime type evaluation
- `pydantic >= 2.1.0` is the floor (for `pydantic.alias_generators.to_camel`)
- `requests` auto-encodes query params — do NOT pre-encode with `urllib.parse.quote()`
- When mocking with `responses` library, use `requests.ConnectionError` as the body exception (not Python's built-in `ConnectionError` — they are different classes)
- `ChecksumAlgorithm` values may arrive as `SHA_256` (underscore) or `SHA-256` (hyphen) from servers — the `@field_validator` in `Checksum` normalizes both
- BLAKE3 is in the enum for spec completeness but NOT supported at runtime (not in stdlib `hashlib`) — raises `TeaChecksumError`
- `Identifier.id_type` is typed as `str` (not `IdentifierType` enum) so unknown types from future spec versions pass through
- CGNAT range (100.64.0.0/10, RFC 6598) is checked separately in SSRF protection because `ipaddress.is_private` misses it on Python 3.11+

## TEA Spec Reference

The TEA spec repo should be cloned to `/tmp/transparency-exchange-api/` for cross-referencing:

```bash
git clone https://github.com/CycloneDX/transparency-exchange-api /tmp/transparency-exchange-api
```

Key spec files: `spec/openapi.yaml`, `discovery/readme.md`, `auth/readme.md`

## Design Docs

- `docs/plans/2025-02-25-tea-client-design.md` — v0.1.0 original design
- `docs/plans/2026-02-25-v0.2.0-design.md` — v0.2.0 (CLE, SemVer, failover, mTLS, CLI)
- `docs/plans/2026-02-26-v0.3.0-design.md` — v0.3.0 (httpx migration, async client)
- `docs/FUTURE.md` — Items blocked on external factors (Publisher API)
