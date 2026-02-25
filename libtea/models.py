"""Pydantic data models for TEA API objects."""

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator
from pydantic.alias_generators import to_camel


class _TeaModel(BaseModel):
    """Base model with camelCase alias support."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
    )


# --- Enums ---


class IdentifierType(StrEnum):
    CPE = "CPE"
    TEI = "TEI"
    PURL = "PURL"


class ChecksumAlgorithm(StrEnum):
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


class ArtifactType(StrEnum):
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
    COMPONENT_RELEASE = "COMPONENT_RELEASE"
    PRODUCT_RELEASE = "PRODUCT_RELEASE"


class CollectionUpdateReasonType(StrEnum):
    INITIAL_RELEASE = "INITIAL_RELEASE"
    VEX_UPDATED = "VEX_UPDATED"
    ARTIFACT_UPDATED = "ARTIFACT_UPDATED"
    ARTIFACT_ADDED = "ARTIFACT_ADDED"
    ARTIFACT_REMOVED = "ARTIFACT_REMOVED"


class ErrorType(StrEnum):
    OBJECT_UNKNOWN = "OBJECT_UNKNOWN"
    OBJECT_NOT_SHAREABLE = "OBJECT_NOT_SHAREABLE"


# --- Shared types ---


class Identifier(_TeaModel):
    id_type: IdentifierType
    id_value: str


class Checksum(_TeaModel):
    alg_type: ChecksumAlgorithm
    alg_value: str

    @field_validator("alg_type", mode="before")
    @classmethod
    def normalize_alg_type(cls, v: str) -> str:
        """Normalize underscore form (SHA_256) to hyphen form (SHA-256).

        Uses member-name lookup instead of blind replace to handle
        BLAKE2b casing correctly (BLAKE2B_256 -> BLAKE2b-256).
        """
        if isinstance(v, str) and v not in {e.value for e in ChecksumAlgorithm}:
            mapped = {e.name: e.value for e in ChecksumAlgorithm}.get(v)
            if mapped is not None:
                return mapped
        return v


# --- Domain objects ---


class ReleaseDistribution(_TeaModel):
    distribution_type: str
    description: str | None = None
    identifiers: list[Identifier] = []
    url: str | None = None
    signature_url: str | None = None
    checksums: list[Checksum] = []


class ArtifactFormat(_TeaModel):
    media_type: str
    description: str | None = None
    url: str
    signature_url: str | None = None
    checksums: list[Checksum] = []


class Artifact(_TeaModel):
    uuid: str
    name: str
    type: ArtifactType
    distribution_types: list[str] | None = None
    formats: list[ArtifactFormat] = []


class CollectionUpdateReason(_TeaModel):
    type: CollectionUpdateReasonType
    comment: str | None = None


class Collection(_TeaModel):
    uuid: str
    version: int
    date: datetime | None = None
    belongs_to: CollectionBelongsTo | None = None
    update_reason: CollectionUpdateReason | None = None
    artifacts: list[Artifact] = []


class ComponentRef(_TeaModel):
    uuid: str
    release: str | None = None


class Component(_TeaModel):
    uuid: str
    name: str
    identifiers: list[Identifier]


class Release(_TeaModel):
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
    release: Release
    latest_collection: Collection | None = None


class Product(_TeaModel):
    uuid: str
    name: str
    identifiers: list[Identifier]


class ProductRelease(_TeaModel):
    uuid: str
    product: str | None = None
    product_name: str | None = None
    version: str
    created_date: datetime
    release_date: datetime | None = None
    pre_release: bool | None = None
    identifiers: list[Identifier] = []
    components: list[ComponentRef]


class ErrorResponse(_TeaModel):
    error: ErrorType


# --- Pagination ---


class PaginatedProductResponse(_TeaModel):
    timestamp: datetime
    page_start_index: int
    page_size: int
    total_results: int
    results: list[Product] = []


class PaginatedProductReleaseResponse(_TeaModel):
    timestamp: datetime
    page_start_index: int
    page_size: int
    total_results: int
    results: list[ProductRelease] = []


# --- Discovery types ---


class TeaEndpoint(_TeaModel):
    url: str
    versions: list[str]
    priority: float | None = None


class TeaWellKnown(_TeaModel):
    schema_version: Literal[1]
    endpoints: list[TeaEndpoint]


class TeaServerInfo(_TeaModel):
    root_url: str
    versions: list[str]
    priority: float | None = None


class DiscoveryInfo(_TeaModel):
    product_release_uuid: str
    servers: list[TeaServerInfo]
