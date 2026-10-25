# py-libtea Future Roadmap

Items that depend on external factors or are deferred indefinitely. These are **not** scheduled for any release — they move to a versioned plan when their blockers are resolved.

---

## Publisher API

**Blocked on:** TEA spec stability. The Publisher API is currently v0.0.2 draft with significant naming mismatches against the consumer API (`leaf` vs `release`, `tei_urn` vs `uuid`). Schema is not stable enough to build against.

**What we'll need when the spec stabilizes:**

| Item | Notes |
|------|-------|
| Publisher endpoints (POST/PUT/DELETE for products, releases, components, artifacts) | Mirror consumer API shape |
| Artifact upload with streaming + checksum | Reverse of `download_artifact` |
| Publisher-specific models | Likely share base types with consumer models |
| Publisher auth (token scoping, write permissions) | May differ from consumer bearer token |
| CLI `publish` / `upload` commands | Counterpart to existing `discover`, `get`, `download` |

**TEA spec tracking:** [CycloneDX/transparency-exchange-api](https://github.com/CycloneDX/transparency-exchange-api)

**Additional note for Publisher API:** When serializing models back to the server, use `model_dump(mode="json", by_alias=True, exclude_none=True)`. Serialization should also be gated by the negotiated spec version (`TeaClient.is_legacy`) so 0.4.0-only wire shapes (for example `Collection.date` instead of `createdDate`, offset pagination fields, MD5 checksums) are only sent to servers that expect them.

**Action:** When the Publisher API reaches beta (stable naming, stable schema), create a versioned design doc in `docs/plans/` and schedule for the next minor release.

---

## CLI Internal Cleanup

**Blocked on:** Nothing — these are low-priority tech debt items identified during the CLI UX review (PR #10). They are not user-facing and do not affect correctness.

| Item | Notes |
|------|-------|
| Consolidate repetitive 8-param command signatures | Every command repeats `base_url, token, auth, domain, timeout, use_http, port, allow_private_ips`. Could bundle into a connection config dataclass in `ctx.obj` and have `_build_client` read from it directly. |
| Unify wrapper parameter handling in `shared_options` | Older flags (`output_json`, `verbose`, `debug`) use explicit wrapper params; newer flags (`no_input`, `no_color`, `output_file`) use `kwargs.pop()`. Pick one pattern. |

**Action:** Address opportunistically during the next CLI feature addition.

---

## TEA 1.0.0 Deferred Items

**Blocked on:** Nothing — consumer-side parts of the TEA 1.0.0 spec that the 1.0.0 alignment left out on purpose. None is needed to read from a 1.x server.

| Item | Notes |
|------|-------|
| `/token` client-credentials exchange | `POST /token` with the `client_credentials` grant (see `auth/readme.md`). Today a caller supplies an already-issued bearer token or basic-auth credentials. |
| `ETag` / `If-None-Match` / `304` | Conditional requests and revalidation for the artifact download endpoints. Downloads currently always fetch the full body. |
| Signature download endpoints | `/artifact/{uuid}/latest/signature/download` and `/artifact/{uuid}/{artifactVersion}/signature/download`. `signatureUrl` on a format is exposed in the models but not fetched. |
| `sortField` / `sortOrder` | Sorting query parameters on `/products`, `/productReleases`, `/components` and `/componentReleases`, and on the per-parent child lists (a product's releases, a component's releases, and both collections lists). The client sends none of them. |
| Routing follow-up requests to the discovery `servers[].rootUrl` | `discover()` returns the servers that host a product release, but later calls keep using the client's own API base. Honouring `rootUrl` + `/v<version>` per release needs a client per server and token scoping (a token must go only to its own API base). |
| `purl` → `tei://<domain>/purl/<base64url>` builder | Helper that turns a PURL into the unpadded Base64URL TEI identifier. `parse_tei` already accepts such TEIs and passes the identifier through unchanged; callers must encode it themselves. |
| `--spec-version` override for the CLI, `run_conformance` and the pytest plugin | A base URL without a `/v<semver>` suffix now means TEA 1.0.0. `TeaClient(spec_version=...)` can force 0.4.0, but `tea-cli`, `run_conformance` and `--tea-base-url` cannot, so they treat a 0.4.0 server behind an unversioned base URL as 1.0.0. |
| Lowercase-hex checksum conformance check | The spec wants lowercase hexadecimal checksum values. Verification already lowercases both sides; a conformance check should flag servers that send uppercase. |

**Action:** Schedule individual items when a consumer needs them; each is independent.

---

## HTTP Layer Follow-ups

**Blocked on:** Nothing — a known gap in how `requests` handles redirects.

| Item | Notes |
|------|-------|
| Bound 3xx bodies during downloads | Even with `allow_redirects=False` and `stream=True`, `requests.Session.send` reads the whole 3xx response body (to release the connection) before libtea sees it, so `max_download_bytes` does not cap a redirect body. Fixing it needs a transport adapter (or a urllib3-level request) that skips that read. |

**Action:** Address if a server is found sending large redirect bodies.

---

## Conformance Follow-ups

**Blocked on:** Nothing — low-priority items from earlier alignment reviews.

| Item | Notes |
|------|-------|
| Component conformance checks | Add conformance checks for `/components` and `/componentReleases` endpoints (list, search) to match the product-level checks. |

**Action:** Address opportunistically.
