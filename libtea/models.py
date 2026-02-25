"""Pydantic data models for TEA API objects."""

from enum import StrEnum

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
