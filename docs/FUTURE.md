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

**Action:** When the Publisher API reaches beta (stable naming, stable schema), create a versioned design doc in `docs/plans/` and schedule for the next minor release.
