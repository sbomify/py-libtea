"""Pydantic v2 data models for TEA API objects.

All models use camelCase aliases for JSON serialization (matching the TEA wire
format), are frozen (immutable after creation), and silently ignore unknown
fields for forward-compatibility with future TEA spec versions.

Fields required by both TEA 0.4.0 and 1.0.0 are non-optional types. Fields
required only by 1.0.0 are optional types that are rejected when missing,
unless the model is validated with ``context={"tea_legacy": True}``.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any, ClassVar, Generic, Literal, Self, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator
from pydantic.alias_generators import to_camel


def _is_legacy(info: ValidationInfo) -> bool:
    """Return ``True`` when validating in the TEA 0.4.0 compatibility context."""
    return bool(info.context and info.context.get("tea_legacy"))


class _TeaModel(BaseModel):
    """Base model for all TEA API objects.

    Configuration:
        - ``alias_generator=to_camel``: JSON keys use camelCase.
        - ``populate_by_name=True``: Fields can be set by Python name or alias.
        - ``extra="ignore"``: Unknown fields from newer spec versions are silently dropped.
        - ``frozen=True``: Instances are immutable (hashable, safe to cache).

    TEA 1.0.0 rules: fields named in ``_v1_required`` must not be ``None``.
    Subclasses add other 1.0.0-only checks by overriding :meth:`_v1_problems`
    and extending ``super()._v1_problems()``. The checks are skipped under the
    legacy validation context.
    """

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="ignore",  # forward-compat: silently drop unknown fields from future spec versions
        frozen=True,
    )

    _v1_required: ClassVar[tuple[str, ...]] = ()

    def _v1_problems(self) -> list[str]:
        return [f"missing required field {n!r}" for n in self._v1_required if getattr(self, n) is None]

    @model_validator(mode="after")
    def _enforce_v1(self, info: ValidationInfo) -> Self:
        if not _is_legacy(info) and (problems := self._v1_problems()):
            raise ValueError(f"{type(self).__name__}: {'; '.join(problems)} (TEA 1.0.0)")
        return self


# --- Enums ---


class IdentifierType(StrEnum):
    """Identifier type used in product and component identifiers.

    Note: ``Identifier.id_type`` is typed as ``str`` (not ``IdentifierType``)
    so unknown types from future spec versions pass through without error.
    """

    CPE = "CPE"
    TEI = "TEI"
    PURL = "PURL"
    COMPLIANCE_DOCUMENT = "COMPLIANCE_DOCUMENT"


class ComplianceDocumentType(StrEnum):
    """Compliance document types for the COMPLIANCE_DOCUMENT identifier type."""

    SOC_2_TYPE_I = "SOC_2_TYPE_I"
    SOC_2_TYPE_II = "SOC_2_TYPE_II"
    SOC_3 = "SOC_3"
    ISO_27001 = "ISO_27001"
    ISO_27017 = "ISO_27017"
    ISO_27018 = "ISO_27018"
    ISO_27701 = "ISO_27701"
    ISO_42001 = "ISO_42001"
    PCI_DSS = "PCI_DSS"
    HIPAA = "HIPAA"
    FEDRAMP = "FEDRAMP"
    GDPR = "GDPR"
    CSA_STAR = "CSA_STAR"
    NIST_800_53 = "NIST_800_53"
    NIST_800_171 = "NIST_800_171"
    CMMC = "CMMC"
    HITRUST = "HITRUST"
    TISAX = "TISAX"
    CYBER_ESSENTIALS = "CYBER_ESSENTIALS"
    CYBER_ESSENTIALS_PLUS = "CYBER_ESSENTIALS_PLUS"
    EU_DECLARATION_OF_CONFORMITY = "EU_DECLARATION_OF_CONFORMITY"


class TeiType(StrEnum):
    """TEI types per TEA discovery specification.

    These are the ``<type>`` values of a TEI. The 0.4.0 URN form
    (``urn:tei:<type>:<domain>:<identifier>``) accepts only these; the 1.0.0 URI form
    (``tei://<domain>/<type>/<identifier>``) also accepts other lowercase types.
    """

    UUID = "uuid"
    PURL = "purl"
    HASH = "hash"
    SWID = "swid"
    EANUPC = "eanupc"
    GTIN = "gtin"
    ASIN = "asin"
    UDI = "udi"


class ChecksumAlgorithm(StrEnum):
    """Checksum algorithm identifiers per TEA spec.

    Values use hyphen form (e.g. ``SHA-256``). The Checksum model's validator
    normalizes underscore form (``SHA_256``) to hyphen form automatically.

    ``MD5`` is 0.4.0 only: TEA 1.0.0 dropped it, so it is rejected unless the
    model is validated with the legacy context.
    """

    MD5 = "MD5"
    SHA_1 = "SHA-1"
    SHA_256 = "SHA-256"
    SHA_384 = "SHA-384"
    SHA_512 = "SHA-512"
    SHA3_256 = "SHA3-256"
    SHA3_384 = "SHA3-384"
    SHA3_512 = "SHA3-512"
    BLAKE2B_256 = "BLAKE2b-256"
    BLAKE2B_384 = "BLAKE2b-384"
    BLAKE2B_512 = "BLAKE2b-512"
    BLAKE3 = "BLAKE3"


_CHECKSUM_VALUES = frozenset(e.value for e in ChecksumAlgorithm)
_CHECKSUM_NAME_TO_VALUE = {e.name: e.value for e in ChecksumAlgorithm}


def normalize_algorithm_name(name: str) -> str:
    """Normalize a checksum algorithm name from underscore form to hyphen form.

    Maps enum member names (e.g. ``SHA_256``) to their values (``SHA-256``).
    Returns the input unchanged if it is already a valid value or unknown.
    """
    return _CHECKSUM_NAME_TO_VALUE.get(name, name)


class ArtifactType(StrEnum):
    """Type of a TEA artifact (e.g. BOM, VEX, attestation)."""

    ATTESTATION = "ATTESTATION"
    BOM = "BOM"
    BUILD_META = "BUILD_META"
    CERTIFICATION = "CERTIFICATION"
    FORMULATION = "FORMULATION"
    LICENSE = "LICENSE"
    RELEASE_NOTES = "RELEASE_NOTES"
    SECURITY_TXT = "SECURITY_TXT"
    THREAT_MODEL = "THREAT_MODEL"
    VULNERABILITIES = "VULNERABILITIES"
    OTHER = "OTHER"


class CollectionBelongsTo(StrEnum):
    """Whether a collection belongs to a component release or product release."""

    COMPONENT_RELEASE = "COMPONENT_RELEASE"
    PRODUCT_RELEASE = "PRODUCT_RELEASE"


class CollectionUpdateReasonType(StrEnum):
    """Reason for a collection version update."""

    INITIAL_RELEASE = "INITIAL_RELEASE"
    VEX_UPDATED = "VEX_UPDATED"
    ARTIFACT_UPDATED = "ARTIFACT_UPDATED"
    ARTIFACT_ADDED = "ARTIFACT_ADDED"
    ARTIFACT_REMOVED = "ARTIFACT_REMOVED"


class ErrorType(StrEnum):
    """TEA API error types carried in the ``error`` property of a 4xx response body.

    Servers may send values not listed here; clients must not reject them, so
    :attr:`ErrorResponse.error` is a plain ``str``. ``OBJECT_NOT_SHAREABLE`` is
    0.4.0 only.
    """

    OBJECT_UNKNOWN = "OBJECT_UNKNOWN"
    OBJECT_NOT_SHAREABLE = "OBJECT_NOT_SHAREABLE"  # 0.4.0 only
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    NO_ACCEPTABLE_FORMAT = "NO_ACCEPTABLE_FORMAT"
    SIGNATURE_NOT_FOUND = "SIGNATURE_NOT_FOUND"
    INVALID_REQUEST = "INVALID_REQUEST"
    INVALID_PAGE_TOKEN = "INVALID_PAGE_TOKEN"


class ErrorResponse(_TeaModel):
    """TEA API error response body.

    ``error`` is typically one of :class:`ErrorType` (compare with ``==``) but
    is kept as ``str``: the spec forbids rejecting a response over an
    ``error`` value the client does not know. ``message`` is an optional
    human-readable explanation for diagnostics only.
    """

    error: str
    message: str | None = None


# --- Shared types ---


class Identifier(_TeaModel):
    """An identifier with a specified type (e.g. PURL, CPE, TEI).

    The ``id_type`` field accepts any string for forward-compatibility with
    future TEA spec versions. Compare against :class:`IdentifierType` members
    for known types (e.g. ``ident.id_type == IdentifierType.PURL``).

    Both fields are required by TEA 1.0.0; 0.4.0 servers may omit either.
    """

    _v1_required = ("id_type", "id_value")

    id_type: str | None = None
    id_value: str | None = None


class Checksum(_TeaModel):
    """A checksum with algorithm type and hex value.

    The ``algorithm_type`` validator normalizes both hyphen form (``SHA-256``) and
    underscore form (``SHA_256``) to the canonical hyphen form. TEA 1.0.0 does not
    allow ``MD5``; 0.4.0 servers may still send it.
    """

    # Manual aliases because the TEA spec wire format uses abbreviated names
    # (algType/algValue) rather than the full algorithmType/algorithmValue
    # that to_camel would generate from the Python field names.
    algorithm_type: ChecksumAlgorithm = Field(alias="algType")
    algorithm_value: str = Field(alias="algValue")

    @field_validator("algorithm_type", mode="before")
    @classmethod
    def normalize_algorithm_type(cls, v: str) -> str:
        """Normalize underscore form (SHA_256) to hyphen form (SHA-256).

        Uses member-name lookup instead of blind replace to handle
        BLAKE2b casing correctly (BLAKE2B_256 -> BLAKE2b-256).
        """
        if isinstance(v, str) and v not in _CHECKSUM_VALUES:
            mapped = _CHECKSUM_NAME_TO_VALUE.get(v)
            if mapped is not None:
                return mapped
        return v

    def _v1_problems(self) -> list[str]:
        problems = super()._v1_problems()
        if self.algorithm_type is ChecksumAlgorithm.MD5:
            problems.append("MD5 is not a TEA 1.0.0 checksum algorithm")
        return problems


# --- Domain objects ---


class ReleaseDistribution(_TeaModel):
    """A distribution format for a component release (e.g. binary, source)."""

    distribution_id: str
    description: str | None = None
    identifiers: tuple[Identifier, ...] = ()
    url: str | None = None
    signature_url: str | None = None
    checksums: tuple[Checksum, ...] = ()


class ArtifactFormat(_TeaModel):
    """A TEA artifact in a specific format with download URL and checksums.

    TEA 1.0.0 requires ``media_type``, and at least one checksum when ``url`` is set.
    ``checksums`` may be omitted but, when present, must not be empty.
    """

    _v1_required = ("media_type",)

    media_type: str | None = None
    description: str | None = None
    url: str | None = None
    signature_url: str | None = None
    checksums: tuple[Checksum, ...] = ()

    def _v1_problems(self) -> list[str]:
        problems = super()._v1_problems()
        if not self.checksums and (self.url is not None or "checksums" in self.model_fields_set):
            problems.append("'checksums' must not be empty")
        return problems


class Artifact(_TeaModel):
    """A security-related artifact (e.g. SBOM, VEX, attestation) with available formats.

    TEA 1.0.0 also requires ``version``, ``created_date`` and at least one format.
    """

    _v1_required = ("version", "created_date")

    uuid: str
    name: str | None = None
    type: ArtifactType
    version: int | None = Field(default=None, ge=1)
    created_date: datetime | None = None
    distribution_ids: tuple[str, ...] | None = None
    formats: tuple[ArtifactFormat, ...]

    def _v1_problems(self) -> list[str]:
        problems = super()._v1_problems()
        if not self.formats:
            problems.append("'formats' must not be empty")
        return problems


class CollectionUpdateReason(_TeaModel):
    """Reason for a collection version update, with optional comment.

    TEA 1.0.0 requires ``type``.
    """

    _v1_required = ("type",)

    type: CollectionUpdateReasonType | None = None
    comment: str | None = None


class Collection(_TeaModel):
    """A versioned collection of artifacts belonging to a release.

    The UUID matches the owning component or product release. The version
    integer starts at 1 and increments on each content change.
    TEA 1.0.0 requires ``uuid``, ``version``, ``created_date``, ``belongs_to``,
    ``update_reason`` and the ``artifacts`` key (an empty list is valid); 0.4.0
    requires none and names the creation timestamp ``date``.

    Attributes:
        uuid: UUID of the owning component or product release.
        version: Collection version number (starts at 1, increments on change).
        created_date: Timestamp when this collection version was created.
        belongs_to: Whether this collection belongs to a component or product release.
        update_reason: Why this collection version was created.
        artifacts: The artifacts (SBOMs, VEX documents, etc.) in this collection.
    """

    _v1_required = ("uuid", "version", "created_date", "belongs_to", "update_reason")

    uuid: str | None = None
    version: int | None = Field(default=None, ge=1)
    created_date: datetime | None = None
    belongs_to: CollectionBelongsTo | None = None
    update_reason: CollectionUpdateReason | None = None
    artifacts: tuple[Artifact, ...] = ()

    def _v1_problems(self) -> list[str]:
        problems = super()._v1_problems()
        if "artifacts" not in self.model_fields_set:
            problems.append("missing required field 'artifacts'")
        return problems

    @model_validator(mode="before")
    @classmethod
    def _map_legacy_date(cls, data: Any, info: ValidationInfo) -> Any:
        """Map the 0.4.0 ``date`` key to ``createdDate`` (legacy context only)."""
        if _is_legacy(info) and isinstance(data, dict) and "date" in data:
            return {"createdDate": data["date"], **data}
        return data


class ComponentRef(_TeaModel):
    """Reference to a TEA component, optionally pinned to a specific release."""

    uuid: str
    release: str | None = None


class Component(_TeaModel):
    """A TEA component (software lineage/family, not a specific version)."""

    uuid: str
    name: str
    identifiers: tuple[Identifier, ...]


class Release(_TeaModel):
    """A specific version of a TEA component with distributions and identifiers.

    Attributes:
        uuid: Server-assigned UUID.
        component: UUID of the parent component (required by TEA 1.0.0).
        component_name: Human-readable name of the parent component.
        version: Version string (e.g. ``"1.2.3"``).
        created_date: When the release record was created on the TEA server.
        release_date: Actual release date (may differ from ``created_date``).
        pre_release: ``True`` if this is a pre-release / unstable version.
        identifiers: External identifiers (PURLs, CPEs, etc.).
        distributions: Available distribution formats (binary, source, etc.).
    """

    _v1_required = ("component",)

    uuid: str
    component: str | None = None
    component_name: str | None = None
    version: str
    created_date: datetime
    release_date: datetime | None = None
    pre_release: bool | None = None
    identifiers: tuple[Identifier, ...] = ()
    distributions: tuple[ReleaseDistribution, ...] = ()


class ComponentReleaseWithCollection(_TeaModel):
    """A component release bundled with its latest collection.

    Returned by ``GET /componentRelease/{uuid}``. TEA 1.0.0 flattens the release
    fields next to ``latestCollection``; TEA 0.4.0 nests them under ``release``.
    Both parse into the same ``release`` / ``latest_collection`` shape.
    """

    release: Release
    latest_collection: Collection

    @model_validator(mode="before")
    @classmethod
    def _unflatten(cls, data: Any, info: ValidationInfo) -> Any:
        """Wrap the 1.0.0 flattened wire object into ``release`` + ``latestCollection``.

        Skipped in the legacy context (already nested) and for Python-side
        construction from a ``Release`` instance.
        """
        if _is_legacy(info) or not isinstance(data, dict) or isinstance(data.get("release"), Release):
            return data
        return {
            "release": {k: v for k, v in data.items() if k != "latestCollection"},
            "latestCollection": data.get("latestCollection"),
        }


class Product(_TeaModel):
    """A TEA product (optional grouping of components)."""

    uuid: str
    name: str
    identifiers: tuple[Identifier, ...]


class ProductRelease(_TeaModel):
    """A specific version of a TEA product with its component references.

    This is the primary entry point from TEI discovery — resolving a TEI
    typically yields a product release UUID.

    Attributes:
        uuid: Server-assigned UUID.
        product: UUID of the parent product (required by TEA 1.0.0).
        product_name: Human-readable name of the parent product.
        version: Version string (e.g. ``"2.0.0"``).
        created_date: When the release record was created on the TEA server.
        release_date: Actual release date (may differ from ``created_date``).
        pre_release: ``True`` if this is a pre-release / unstable version.
        identifiers: External identifiers (PURLs, CPEs, etc.).
        components: References to the components included in this product release.
    """

    _v1_required: ClassVar[tuple[str, ...]] = ("product",)  # widened so subclasses can extend it

    uuid: str
    product: str | None = None
    product_name: str | None = None
    version: str
    created_date: datetime
    release_date: datetime | None = None
    pre_release: bool | None = None
    identifiers: tuple[Identifier, ...] = ()
    components: tuple[ComponentRef, ...]


class ProductReleaseWithCollection(ProductRelease):
    """A product release bundled with its latest collection.

    Returned by ``GET /productRelease/{uuid}``. TEA 1.0.0 requires
    ``latest_collection``; 0.4.0 servers omit it.

    Attributes:
        latest_collection: The latest collection for this product release.
    """

    _v1_required = ProductRelease._v1_required + ("latest_collection",)

    latest_collection: Collection | None = None


# --- CLE (Common Lifecycle Enumeration) ---


class CLEEventType(StrEnum):
    """CLE lifecycle event types per ECMA-428 TC54 TG3 CLE Specification v1.0.0."""

    RELEASED = "released"
    END_OF_DEVELOPMENT = "endOfDevelopment"
    END_OF_SUPPORT = "endOfSupport"
    END_OF_LIFE = "endOfLife"
    END_OF_DISTRIBUTION = "endOfDistribution"
    END_OF_MARKETING = "endOfMarketing"
    SUPERSEDED_BY = "supersededBy"
    COMPONENT_RENAMED = "componentRenamed"
    WITHDRAWN = "withdrawn"


class CLEVersionSpecifier(_TeaModel):
    """A version specifier: either a single version or a version range in vers format.

    At least one of ``version`` or ``range`` must be set.
    """

    version: str | None = None
    range: str | None = None

    @model_validator(mode="after")
    def _check_at_least_one_field(self) -> Self:
        if self.version is None and self.range is None:
            raise ValueError("CLEVersionSpecifier requires at least one of 'version' or 'range'")
        return self


class CLESupportDefinition(_TeaModel):
    """A support policy definition referenced by CLE events."""

    id: str
    description: str
    url: str | None = None


class CLEDefinitions(_TeaModel):
    """Container for reusable CLE policy definitions."""

    support: tuple[CLESupportDefinition, ...] | None = None


class CLEEvent(_TeaModel):
    """A discrete lifecycle event from the CLE specification.

    Required fields: ``id``, ``type``, ``effective``, ``published``.
    Other fields are event-type-specific.

    Attributes:
        id: Unique event identifier within the CLE document.
        type: Lifecycle event type (e.g. ``released``, ``endOfLife``).
        effective: When the event takes/took effect.
        published: When the event was published.
        version: Single version this event applies to (e.g. for ``released``).
        versions: Version range specifiers (e.g. for ``endOfSupport``).
        support_id: Reference to a :class:`CLESupportDefinition` id.
        license: SPDX license expression (for ``released`` events).
        superseded_by_version: Replacement version (for ``supersededBy`` events).
        identifiers: External identifiers associated with this event.
        event_id: Reference to another event id (for ``withdrawn`` events).
        reason: Human-readable reason for the event.
        description: Additional description or context.
        references: List of reference URLs.
    """

    id: int
    type: CLEEventType
    effective: datetime
    published: datetime
    version: str | None = None
    versions: tuple[CLEVersionSpecifier, ...] | None = None
    support_id: str | None = None
    license: str | None = None
    superseded_by_version: str | None = None
    identifiers: tuple[Identifier, ...] | None = None
    event_id: int | None = None
    reason: str | None = None
    description: str | None = None
    references: tuple[str, ...] | None = None


class CLE(_TeaModel):
    """Common Lifecycle Enumeration document per ECMA-428 TC54 TG3 v1.0.0.

    Contains lifecycle events and optional definitions. Per spec, events
    MUST be ordered by ``id`` in descending order (newest first).
    """

    events: tuple[CLEEvent, ...]
    definitions: CLEDefinitions | None = None


# --- Pagination ---

_R = TypeVar("_R")
_LEGACY_PAGE_KEYS = ("timestamp", "pageStartIndex", "pageSize", "totalResults")


class _PaginatedResponse(_TeaModel, Generic[_R]):
    """Common fields of a paginated TEA response.

    TEA 1.0.0 pages carry ``has_next`` and an opaque ``next_page_token``. 0.4.0
    pages carry offset metadata instead; under the legacy context ``has_next``
    and ``next_page_token`` are derived from it, the token being the next
    result offset as a string. Outside the legacy context the offset metadata
    is dropped, so ``total_results is None`` exactly on TEA 1.x pages.
    """

    has_next: bool
    next_page_token: str | None = None
    # TEA 0.4.0 only.
    timestamp: datetime | None = None
    page_start_index: int | None = None
    page_size: int | None = None
    total_results: int | None = None
    results: tuple[_R, ...] = ()

    def _v1_problems(self) -> list[str]:
        problems = super()._v1_problems()
        if "results" not in self.model_fields_set:
            problems.append("missing required field 'results'")
        if self.has_next and not self.next_page_token:
            problems.append("hasNext is true but nextPageToken is missing")
        return problems

    @model_validator(mode="before")
    @classmethod
    def _map_legacy_offsets(cls, data: Any, info: ValidationInfo) -> Any:
        """Derive ``hasNext``/``nextPageToken`` from 0.4.0 offsets; drop the offsets outside the legacy context."""
        if not isinstance(data, dict):
            return data
        if not _is_legacy(info):
            return {k: v for k, v in data.items() if k not in _LEGACY_PAGE_KEYS}
        if "totalResults" not in data:
            return data
        start, total, results = data.get("pageStartIndex"), data["totalResults"], data.get("results", [])
        if not (isinstance(start, int) and isinstance(total, int) and isinstance(results, list)):
            return data  # malformed offsets: leave hasNext missing so validation reports it
        next_offset = start + len(results)
        has_next = bool(results) and next_offset < total
        return {**data, "hasNext": has_next, **({"nextPageToken": str(next_offset)} if has_next else {})}


class PaginatedProductResponse(_PaginatedResponse[Product]):
    """Paginated response containing a list of products."""


class PaginatedProductReleaseResponse(_PaginatedResponse[ProductRelease]):
    """Paginated response containing a list of product releases."""


class PaginatedComponentResponse(_PaginatedResponse[Component]):
    """Paginated response containing a list of components."""


class PaginatedComponentReleaseResponse(_PaginatedResponse[Release]):
    """Paginated response containing a list of component releases."""


class PaginatedCollectionResponse(_PaginatedResponse[Collection]):
    """Paginated response containing a list of collections (TEA 1.0.0)."""


# --- Discovery types ---


class TeaEndpoint(_TeaModel):
    """A TEA server endpoint from the .well-known/tea discovery document.

    Attributes:
        url: Base URL of the endpoint (e.g. ``https://tea.example.com/api``).
        versions: SemVer version strings this endpoint supports (at least one).
        priority: Optional priority hint between 0.0 (lowest) and 1.0 (highest).
            Defaults to 1.0 per spec when not specified.
    """

    url: str
    versions: tuple[str, ...] = Field(min_length=1)
    priority: float | None = Field(default=None, ge=0, le=1)


class TeaWellKnown(_TeaModel):
    """The .well-known/tea discovery document listing available TEA endpoints."""

    schema_version: Literal[1]
    endpoints: tuple[TeaEndpoint, ...] = Field(min_length=1)


class TeaServerInfo(_TeaModel):
    """TEA server info returned from the discovery API endpoint."""

    root_url: str
    versions: tuple[str, ...] = Field(min_length=1)
    priority: float | None = Field(default=None, ge=0, le=1)


class DiscoveryInfo(_TeaModel):
    """Discovery result mapping a TEI to a product release and its servers.

    Returned by ``GET /discovery?tei=...``. Each result provides the UUID
    of the matching product release and the list of servers that host it.
    """

    product_release_uuid: str
    servers: tuple[TeaServerInfo, ...] = Field(min_length=1)


__all__ = [
    # Enums
    "ArtifactType",
    "ChecksumAlgorithm",
    "CLEEventType",
    "CollectionBelongsTo",
    "CollectionUpdateReasonType",
    "ComplianceDocumentType",
    "ErrorType",
    "IdentifierType",
    "TeiType",
    # Models
    "Artifact",
    "ArtifactFormat",
    "CLE",
    "CLEDefinitions",
    "CLEEvent",
    "CLESupportDefinition",
    "CLEVersionSpecifier",
    "Checksum",
    "Collection",
    "CollectionUpdateReason",
    "Component",
    "ComponentRef",
    "ComponentReleaseWithCollection",
    "DiscoveryInfo",
    "ErrorResponse",
    "Identifier",
    "PaginatedCollectionResponse",
    "PaginatedComponentReleaseResponse",
    "PaginatedComponentResponse",
    "PaginatedProductReleaseResponse",
    "PaginatedProductResponse",
    "Product",
    "ProductRelease",
    "ProductReleaseWithCollection",
    "Release",
    "ReleaseDistribution",
    "TeaEndpoint",
    "TeaServerInfo",
    "TeaWellKnown",
    # Helpers
    "normalize_algorithm_name",
]
