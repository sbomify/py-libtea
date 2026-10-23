# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**py-libtea** is a hand-crafted Python client library for the Transparency Exchange API (TEA) 1.0.0 with 0.4.0 server compatibility. Consumer-focused (read-only); publisher API is not yet supported (blocked on TEA spec). Licensed Apache 2.0, maintained under sbomify.

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
- **Coverage**: Branch coverage enabled, target ~95%

## Architecture

The library has a layered design with strict separation of concerns:

```
__init__.py          Public API re-exports (all models, exceptions, client, discovery)
client.py            TeaClient — high-level consumer API, spec version resolution, checksum verification
  ↓ uses
_validation.py       Input validation helpers (path segments, page size, Pydantic wrappers)
_http.py             TeaHttpClient — low-level requests wrapper, auth, streaming downloads
                     Also: probe_endpoint() for endpoint failover
_security.py         SSRF protection (_validate_download_url, DNS rebinding checks, internal IP detection)
_hashing.py          Checksum hash builders (SHA-*, BLAKE2b-*, MD5)
discovery.py         TEI parsing, .well-known/tea fetching, SemVer endpoint selection, redirect SSRF protection
models.py            Pydantic v2 models for all TEA domain objects (frozen, camelCase aliases)
exceptions.py        Exception hierarchy (all inherit from TeaError)
server.py            Server-side helpers (tea_datetime_serializer)
cli.py               click CLI (optional dependency, thin wrapper over TeaClient)
_cli_fmt.py          Rich output formatters for all CLI commands (tables, panels, escape helpers)
_cli_entry.py        Entry point wrapper that handles missing CLI extras gracefully

conformance/         Conformance test suite (optional dependency: pytest)
  __init__.py        Public API: run_conformance, CheckResult, CheckStatus, ConformanceResult
  _checks.py         28 check functions organized by category, CheckContext shared state
  _runner.py         Orchestrates checks, collects results into ConformanceResult
  _types.py          CheckStatus (StrEnum), CheckResult (frozen dataclass), ConformanceResult
  plugin.py          pytest plugin — --tea-base-url options, parametrized test generation
```

**Key design patterns:**

- `TeaClient` delegates all HTTP to `TeaHttpClient` — never calls `requests` directly
- Bearer tokens are NOT sent to artifact download URLs (separate unauthenticated session prevents token leakage to CDNs)
- Downloads follow redirects manually with SSRF validation at each hop
- Discovery redirects are validated against internal networks (SSRF protection via `_security._validate_download_url`)
- `_validation._validate()` wraps Pydantic `ValidationError` into `TeaValidationError` so all client errors are `TeaError` subclasses
- Endpoint failover: `from_well_known()` probes candidates in priority order, skipping unreachable ones. With `version=None` it negotiates 1.0.0 first, then 0.4.0, and the candidates span both versions
- `download_artifact_content()` (server-hosted artifact bytes) sends the token only on the first hop, to the API base; every redirect hop goes through the unauthenticated session with SSRF validation
- `probe_endpoint()` lives in `_http.py` (not `client.py`) to maintain the HTTP layer boundary
- `_raise_for_status()` reads 4xx bodies once, bounded to 4 KiB, to parse the TEA `error` value (`_tea_error_type`); the message snippet is cut to 200 characters. This avoids memory issues on streaming responses
- CLI formatters in `_cli_fmt.py` escape all server-controlled strings with `rich.markup.escape()` to prevent Rich markup injection
- Conformance checks run sequentially; earlier checks populate `CheckContext` with discovered UUIDs for later checks
- `from __future__ import annotations` is safe in conformance modules (no Pydantic models, only dataclasses)

**Auth**: Bearer token and basic auth are supported. Token and basic_auth are mutually exclusive. HTTP (non-TLS) with credentials is rejected.

## Critical Implementation Rules

- **NEVER** use `from __future__ import annotations` in files containing Pydantic models — it breaks Pydantic v2 runtime type evaluation
- `pydantic >= 2.1.0` is the floor (for `pydantic.alias_generators.to_camel`)
- `requests` auto-encodes query params — do NOT pre-encode with `urllib.parse.quote()`
- When mocking with `responses` library, use `requests.ConnectionError` as the body exception (not Python's built-in `ConnectionError` — they are different classes)
- `ChecksumAlgorithm` values may arrive as `SHA_256` (underscore) or `SHA-256` (hyphen) from servers — the `@field_validator` in `Checksum` normalizes both
- BLAKE3 is in the enum for spec completeness but NOT supported at runtime (not in stdlib `hashlib`) — raises `TeaChecksumError`
- `Identifier.id_type` is typed as `str` (not `IdentifierType` enum) so unknown types from future spec versions pass through
- **Behaviour follows the negotiated version, never response-shape sniffing.** `TeaClient` resolves `spec_version` once (explicit argument, then the base URL's `/v<semver>` suffix, then `TEA_SPEC_VERSION` = 1.0.0) and exposes `is_legacy`. Pagination parameters, page-size limits, discovery by PURL and server-hosted downloads all branch on it. Never infer the version from what a response looks like
- **0.4.0 shims run only under the validation context `{"tea_legacy": True}`.** `_validation._validate(..., legacy=client.is_legacy)` supplies it; no context means 1.0.0 rules. Fields required by both versions are non-Optional model types; fields only 1.0.0 requires stay `X | None` and are rejected when missing outside the legacy context (`_v1_required` / `_v1_problems()` on `_TeaModel`). Building an MD5 `Checksum` by hand therefore needs `Checksum.model_validate({...}, context={"tea_legacy": True})`
- CGNAT range (100.64.0.0/10, RFC 6598) is checked separately in SSRF protection because `ipaddress.is_private` misses it on Python 3.11+

## TEA Spec Reference

The TEA spec repo should be cloned to `/tmp/transparency-exchange-api/` for cross-referencing:

```bash
git clone https://github.com/CycloneDX/transparency-exchange-api /tmp/transparency-exchange-api
```

Key spec files: `spec/openapi.yaml`, `discovery/readme.md`, `auth/readme.md`. The 0.4.0 baseline is `git -C /tmp/transparency-exchange-api show e0c986b:spec/openapi.yaml`.

## Design Docs

- `docs/conformance.md` — Conformance suite usage and check reference
- `docs/FUTURE.md` — Items blocked on external factors (Publisher API)
