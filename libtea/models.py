"""Pydantic v2 data models for TEA API objects.

All models use camelCase aliases for JSON serialization (matching the TEA wire
format), are frozen (immutable after creation), and silently ignore unknown
fields for forward-compatibility with future TEA spec versions.
"""

from datetime import datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic.alias_generators import to_camel


class _TeaModel(BaseModel):
    """Base model for all TEA API objects.

    Configuration:
        - ``alias_generator=to_camel``: JSON keys use camelCase.
        - ``populate_by_name=True``: Fields can be set by Python name or alias.
        - ``extra="ignore"``: Unknown fields from newer spec versions are silently dropped.
        - ``frozen=True``: Instances are immutable (hashable, safe to cache).
    """

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="ignore",  # forward-compat: silently drop unknown fields from future spec versions
        frozen=True,
    )


# --- Enums ---


class IdentifierType(StrEnum):
    """Identifier type used in product and component identifiers.

    Note: ``Identifier.id_type`` is typed as ``str`` (not ``IdentifierType``)
    so unknown types from future spec versions pass through without error.
    """

    CPE = "CPE"
    TEI = "TEI"
    PURL = "PURL"


class TeiType(StrEnum):
    """TEI URN scheme types per TEA discovery specification.

    These are the valid ``<type>`` values in a TEI URN
    (``urn:tei:<type>:<domain>:<identifier>``).
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
    """TEA API error types returned in 404 responses."""

    OBJECT_UNKNOWN = "OBJECT_UNKNOWN"
    OBJECT_NOT_SHAREABLE = "OBJECT_NOT_SHAREABLE"


# --- Shared types ---


class Identifier(_TeaModel):
    """An identifier with a specified type (e.g. PURL, CPE, TEI).

    The ``id_type`` field accepts any string for forward-compatibility with
    future TEA spec versions. Compare against :class:`IdentifierType` members
    for known types (e.g. ``ident.id_type == IdentifierType.PURL``).
    """

    id_type: str
    id_value: str


class Checksum(_TeaModel):
    """A checksum with algorithm type and hex value.

    The ``algorithm_type`` validator normalizes both hyphen form (``SHA-256``) and
    underscore form (``SHA_256``) to the canonical hyphen form.
    """

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


# --- Domain objects ---


class ReleaseDistribution(_TeaModel):
    """A distribution format for a component release (e.g. binary, source)."""

    distribution_type: str
    description: str | None = None
    identifiers: list[Identifier] = []
    url: str | None = None
    signature_url: str | None = None
    checksums: list[Checksum] = []


class ArtifactFormat(_TeaModel):
    """A TEA artifact in a specific format with download URL and checksums."""

    media_type: str
    description: str | None = None
    url: str
    signature_url: str | None = None
    checksums: list[Checksum] = []


class Artifact(_TeaModel):
    """A security-related artifact (e.g. SBOM, VEX, attestation) with available formats."""

    uuid: str
    name: str
    type: ArtifactType
    distribution_types: list[str] | None = None
    formats: list[ArtifactFormat] = []


class CollectionUpdateReason(_TeaModel):
    """Reason for a collection version update, with optional comment."""

    type: CollectionUpdateReasonType
    comment: str | None = None


class Collection(_TeaModel):
    """A versioned collection of artifacts belonging to a release.

    The UUID matches the owning component or product release. The version
    integer starts at 1 and increments on each content change.
    Per spec, all fields are optional.

    Attributes:
        uuid: UUID of the owning component or product release.
        version: Collection version number (starts at 1, increments on change).
        date: Timestamp when this collection version was created.
        belongs_to: Whether this collection belongs to a component or product release.
        update_reason: Why this collection version was created.
        artifacts: The artifacts (SBOMs, VEX documents, etc.) in this collection.
    """

    uuid: str | None = None
    version: int | None = Field(default=None, ge=1)
    date: datetime | None = None
    belongs_to: CollectionBelongsTo | None = None
    update_reason: CollectionUpdateReason | None = None
    artifacts: list[Artifact] = []


class ComponentRef(_TeaModel):
    """Reference to a TEA component, optionally pinned to a specific release."""

    uuid: str
    release: str | None = None


class Component(_TeaModel):
    """A TEA component (software lineage/family, not a specific version)."""

    uuid: str
    name: str
    identifiers: list[Identifier]


class Release(_TeaModel):
    """A specific version of a TEA component with distributions and identifiers.

    Attributes:
        uuid: Server-assigned UUID.
        component: UUID of the parent component (set when returned in context).
        component_name: Human-readable name of the parent component.
        version: Version string (e.g. ``"1.2.3"``).
        created_date: When the release record was created on the TEA server.
        release_date: Actual release date (may differ from ``created_date``).
        pre_release: ``True`` if this is a pre-release / unstable version.
        identifiers: External identifiers (PURLs, CPEs, etc.).
        distributions: Available distribution formats (binary, source, etc.).
    """

    uuid: str
    component: str | None = None
    component_name: str | None = None
    version: str
    created_date: datetime
    release_date: datetime | None = None
    pre_release: bool | None = None
    identifiers: list[Identifier] = []
    distributions: list[ReleaseDistribution] = []


class ComponentReleaseWithCollection(_TeaModel):
    """A component release bundled with its latest collection.

    Returned by ``GET /componentRelease/{uuid}``.
    """

    release: Release
    latest_collection: Collection


class Product(_TeaModel):
    """A TEA product (optional grouping of components)."""

    uuid: str
    name: str
    identifiers: list[Identifier]


class ProductRelease(_TeaModel):
    """A specific version of a TEA product with its component references.

    This is the primary entry point from TEI discovery — resolving a TEI
    typically yields a product release UUID.

    Attributes:
        uuid: Server-assigned UUID.
        product: UUID of the parent product (set when returned in context).
        product_name: Human-readable name of the parent product.
        version: Version string (e.g. ``"2.0.0"``).
        created_date: When the release record was created on the TEA server.
        release_date: Actual release date (may differ from ``created_date``).
        pre_release: ``True`` if this is a pre-release / unstable version.
        identifiers: External identifiers (PURLs, CPEs, etc.).
        components: References to the components included in this product release.
    """

    uuid: str
    product: str | None = None
    product_name: str | None = None
    version: str
    created_date: datetime
    release_date: datetime | None = None
    pre_release: bool | None = None
    identifiers: list[Identifier] = []
    components: list[ComponentRef]


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

    support: list[CLESupportDefinition] | None = None


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
    versions: list[CLEVersionSpecifier] | None = None
    support_id: str | None = None
    license: str | None = None
    superseded_by_version: str | None = None
    identifiers: list[Identifier] | None = None
    event_id: int | None = None
    reason: str | None = None
    description: str | None = None
    references: list[str] | None = None


class CLE(_TeaModel):
    """Common Lifecycle Enumeration document per ECMA-428 TC54 TG3 v1.0.0.

    Contains lifecycle events and optional definitions. Event ordering is determined by the producer.
    """

    events: list[CLEEvent]
    definitions: CLEDefinitions | None = None


# --- Pagination ---


class PaginatedProductResponse(_TeaModel):
    """Paginated response containing a list of products."""

    timestamp: datetime
    page_start_index: int
    page_size: int
    total_results: int
    results: list[Product] = []


class PaginatedProductReleaseResponse(_TeaModel):
    """Paginated response containing a list of product releases."""

    timestamp: datetime
    page_start_index: int
    page_size: int
    total_results: int
    results: list[ProductRelease] = []


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
    versions: list[str] = Field(min_length=1)
    priority: float | None = Field(default=None, ge=0, le=1)


class TeaWellKnown(_TeaModel):
    """The .well-known/tea discovery document listing available TEA endpoints."""

    schema_version: Literal[1]
    endpoints: list[TeaEndpoint] = Field(min_length=1)


class TeaServerInfo(_TeaModel):
    """TEA server info returned from the discovery API endpoint."""

    root_url: str
    versions: list[str] = Field(min_length=1)
    priority: float | None = Field(default=None, ge=0, le=1)


class DiscoveryInfo(_TeaModel):
    """Discovery result mapping a TEI to a product release and its servers.

    Returned by ``GET /discovery?tei=...``. Each result provides the UUID
    of the matching product release and the list of servers that host it.
    """

    product_release_uuid: str
    servers: list[TeaServerInfo] = Field(min_length=1)
