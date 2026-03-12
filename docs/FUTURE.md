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

**Additional note for Publisher API:** When serializing models back to the server, use `model_dump(mode="json", by_alias=True, exclude_none=True)` and explicitly exclude deprecated fields (`distribution_type`, `distribution_types`) — `exclude_none` alone won't help if they were populated from an older server response. Serialization should also be gated by the negotiated spec version so deprecated fields are only sent to servers that expect them.

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

## Spec v0.4.0 Follow-ups

**Blocked on:** Nothing — these are low-priority items from the v0.4.0 alignment review (PR #11).

| Item | Notes |
|------|-------|
| Deprecation warnings for legacy fields | `distribution_type` and `distribution_types` are spec-deprecated in v0.4.0. Consider adding `DeprecationWarning` via `@model_validator(mode="after")` when only old fields are populated. |
| Conformance checks for v0.4.0 required fields | `Artifact.uuid` and `ReleaseDistribution.distribution_id` are now required per spec. Add conformance checks that verify presence on v0.4.0 servers (gated behind version check). Note: `Artifact.formats` check is implemented as `check_artifact_formats_required` (WARN status). |
| Component conformance checks | Add conformance checks for `/components` and `/componentReleases` endpoints (list, search) to match the product-level checks. |

**Action:** Address when a v0.4.0 server is available for testing.
