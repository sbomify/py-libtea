import pytest
from pydantic import ValidationError

from libtea.models import (
    ArtifactType,
    Checksum,
    ChecksumAlgorithm,
    CollectionBelongsTo,
    CollectionUpdateReasonType,
    ErrorType,
    Identifier,
    IdentifierType,
)


class TestEnums:
    def test_identifier_type_values(self):
        assert IdentifierType.CPE == "CPE"
        assert IdentifierType.TEI == "TEI"
        assert IdentifierType.PURL == "PURL"

    def test_checksum_algorithm_values(self):
        assert ChecksumAlgorithm.SHA_256 == "SHA-256"
        assert ChecksumAlgorithm.SHA3_512 == "SHA3-512"
        assert ChecksumAlgorithm.BLAKE3 == "BLAKE3"

    def test_artifact_type_values(self):
        assert ArtifactType.BOM == "BOM"
        assert ArtifactType.VULNERABILITIES == "VULNERABILITIES"
        assert ArtifactType.OTHER == "OTHER"

    def test_collection_belongs_to(self):
        assert CollectionBelongsTo.COMPONENT_RELEASE == "COMPONENT_RELEASE"
        assert CollectionBelongsTo.PRODUCT_RELEASE == "PRODUCT_RELEASE"

    def test_collection_update_reason_type(self):
        assert CollectionUpdateReasonType.INITIAL_RELEASE == "INITIAL_RELEASE"
        assert CollectionUpdateReasonType.VEX_UPDATED == "VEX_UPDATED"


class TestSharedTypes:
    def test_identifier_from_json(self):
        data = {"idType": "PURL", "idValue": "pkg:maven/org.apache/log4j"}
        ident = Identifier.model_validate(data)
        assert ident.id_type == IdentifierType.PURL
        assert ident.id_value == "pkg:maven/org.apache/log4j"

    def test_identifier_to_json(self):
        ident = Identifier(id_type=IdentifierType.CPE, id_value="cpe:2.3:a:apache:log4j")
        data = ident.model_dump(by_alias=True)
        assert data == {"idType": "CPE", "idValue": "cpe:2.3:a:apache:log4j"}

    def test_checksum_from_json(self):
        data = {"algType": "SHA-256", "algValue": "abcdef1234567890"}
        cs = Checksum.model_validate(data)
        assert cs.alg_type == ChecksumAlgorithm.SHA_256
        assert cs.alg_value == "abcdef1234567890"

    def test_checksum_underscore_normalization(self):
        """Servers may use SHA_256 (underscore) instead of SHA-256 (hyphen)."""
        data = {"algType": "SHA_256", "algValue": "abcdef1234567890"}
        cs = Checksum.model_validate(data)
        assert cs.alg_type == ChecksumAlgorithm.SHA_256

    def test_enum_is_strenum(self):
        assert isinstance(IdentifierType.CPE, str)
        assert isinstance(ChecksumAlgorithm.SHA_256, str)
        assert isinstance(ArtifactType.BOM, str)

    def test_checksum_to_json(self):
        cs = Checksum(alg_type=ChecksumAlgorithm.SHA_256, alg_value="abcdef1234567890")
        data = cs.model_dump(by_alias=True)
        assert data == {"algType": "SHA-256", "algValue": "abcdef1234567890"}

    def test_populate_by_name(self):
        ident = Identifier.model_validate({"id_type": "TEI", "id_value": "tei:example"})
        assert ident.id_type == IdentifierType.TEI

    def test_extra_fields_ignored(self):
        cs = Checksum.model_validate({"algType": "SHA-256", "algValue": "deadbeef", "extra": "ignored"})
        assert not hasattr(cs, "extra")


class TestChecksumNormalization:
    @pytest.mark.parametrize(
        "raw, expected_member",
        [
            ("SHA_1", ChecksumAlgorithm.SHA_1),
            ("SHA_256", ChecksumAlgorithm.SHA_256),
            ("SHA_384", ChecksumAlgorithm.SHA_384),
            ("SHA_512", ChecksumAlgorithm.SHA_512),
            ("SHA3_256", ChecksumAlgorithm.SHA3_256),
            ("SHA3_384", ChecksumAlgorithm.SHA3_384),
            ("SHA3_512", ChecksumAlgorithm.SHA3_512),
            ("BLAKE2B_256", ChecksumAlgorithm.BLAKE2B_256),
            ("BLAKE2B_384", ChecksumAlgorithm.BLAKE2B_384),
            ("BLAKE2B_512", ChecksumAlgorithm.BLAKE2B_512),
        ],
    )
    def test_underscore_to_value(self, raw, expected_member):
        cs = Checksum.model_validate({"algType": raw, "algValue": "aabbcc"})
        assert cs.alg_type == expected_member

    def test_valid_values_pass_through(self):
        for member in ChecksumAlgorithm:
            cs = Checksum.model_validate({"algType": member.value, "algValue": "aabbcc"})
            assert cs.alg_type == member


class TestValidationErrors:
    def test_checksum_rejects_unknown_algorithm(self):
        with pytest.raises(ValidationError):
            Checksum.model_validate({"algType": "CRC32", "algValue": "aabbcc"})

    def test_identifier_rejects_unknown_type(self):
        with pytest.raises(ValidationError):
            Identifier.model_validate({"idType": "SPDXID", "idValue": "some-value"})

    def test_checksum_rejects_missing_alg_value(self):
        with pytest.raises(ValidationError):
            Checksum.model_validate({"algType": "SHA-256"})

    def test_identifier_rejects_missing_id_value(self):
        with pytest.raises(ValidationError):
            Identifier.model_validate({"idType": "PURL"})


class TestEnumCompleteness:
    def test_checksum_algorithm_all_members(self):
        expected = {
            "MD5",
            "SHA-1",
            "SHA-256",
            "SHA-384",
            "SHA-512",
            "SHA3-256",
            "SHA3-384",
            "SHA3-512",
            "BLAKE2b-256",
            "BLAKE2b-384",
            "BLAKE2b-512",
            "BLAKE3",
        }
        assert {e.value for e in ChecksumAlgorithm} == expected

    def test_artifact_type_all_members(self):
        expected = {
            "ATTESTATION",
            "BOM",
            "BUILD_META",
            "CERTIFICATION",
            "FORMULATION",
            "LICENSE",
            "RELEASE_NOTES",
            "SECURITY_TXT",
            "THREAT_MODEL",
            "VULNERABILITIES",
            "OTHER",
        }
        assert {e.value for e in ArtifactType} == expected

    def test_collection_update_reason_all_members(self):
        expected = {
            "INITIAL_RELEASE",
            "VEX_UPDATED",
            "ARTIFACT_UPDATED",
            "ARTIFACT_ADDED",
            "ARTIFACT_REMOVED",
        }
        assert {e.value for e in CollectionUpdateReasonType} == expected

    def test_error_type_values(self):
        assert ErrorType.OBJECT_UNKNOWN == "OBJECT_UNKNOWN"
        assert ErrorType.OBJECT_NOT_SHAREABLE == "OBJECT_NOT_SHAREABLE"
        assert isinstance(ErrorType.OBJECT_UNKNOWN, str)
