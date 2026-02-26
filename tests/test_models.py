import pytest
from pydantic import ValidationError

from libtea.models import (
    ArtifactFormat,
    ArtifactType,
    Checksum,
    ChecksumAlgorithm,
    Collection,
    CollectionBelongsTo,
    CollectionUpdateReasonType,
    ErrorType,
    Identifier,
    IdentifierType,
    PaginatedProductResponse,
    Product,
    Release,
    TeiType,
)


class TestEnums:
    def test_identifier_type_values(self):
        assert IdentifierType.CPE == "CPE"
        assert IdentifierType.TEI == "TEI"
        assert IdentifierType.PURL == "PURL"
        assert IdentifierType.UDI == "UDI"

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


class TestTeiType:
    def test_all_members(self):
        expected = {"uuid", "purl", "hash", "swid", "eanupc", "gtin", "asin", "udi"}
        assert {e.value for e in TeiType} == expected

    def test_is_strenum(self):
        assert isinstance(TeiType.UUID, str)
        assert TeiType.UUID == "uuid"


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
        assert cs.algorithm_type == ChecksumAlgorithm.SHA_256
        assert cs.algorithm_value == "abcdef1234567890"

    def test_checksum_underscore_normalization(self):
        """Servers may use SHA_256 (underscore) instead of SHA-256 (hyphen)."""
        data = {"algType": "SHA_256", "algValue": "abcdef1234567890"}
        cs = Checksum.model_validate(data)
        assert cs.algorithm_type == ChecksumAlgorithm.SHA_256

    def test_enum_is_strenum(self):
        assert isinstance(IdentifierType.CPE, str)
        assert isinstance(ChecksumAlgorithm.SHA_256, str)
        assert isinstance(ArtifactType.BOM, str)

    def test_checksum_to_json(self):
        cs = Checksum(algorithm_type=ChecksumAlgorithm.SHA_256, algorithm_value="abcdef1234567890")
        data = cs.model_dump(by_alias=True)
        assert data == {"algType": "SHA-256", "algValue": "abcdef1234567890"}

    def test_checksum_json_round_trip(self):
        cs = Checksum(algorithm_type=ChecksumAlgorithm.SHA_256, algorithm_value="abcdef1234567890")
        json_str = cs.model_dump_json(by_alias=True)
        restored = Checksum.model_validate_json(json_str)
        assert restored == cs

    def test_populate_by_name(self):
        ident = Identifier.model_validate({"id_type": "TEI", "id_value": "tei:example"})
        assert ident.id_type == IdentifierType.TEI

    def test_checksum_populate_by_name(self):
        cs = Checksum.model_validate({"algorithm_type": "SHA-256", "algorithm_value": "abcdef"})
        assert cs.algorithm_type == ChecksumAlgorithm.SHA_256

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
        assert cs.algorithm_type == expected_member

    def test_valid_values_pass_through(self):
        for member in ChecksumAlgorithm:
            cs = Checksum.model_validate({"algType": member.value, "algValue": "aabbcc"})
            assert cs.algorithm_type == member


class TestValidationErrors:
    def test_checksum_rejects_unknown_algorithm(self):
        with pytest.raises(ValidationError):
            Checksum.model_validate({"algType": "CRC32", "algValue": "aabbcc"})

    def test_identifier_rejects_unknown_type(self):
        with pytest.raises(ValidationError):
            Identifier.model_validate({"idType": "SPDXID", "idValue": "some-value"})

    def test_checksum_rejects_missing_algorithm_type(self):
        with pytest.raises(ValidationError):
            Checksum.model_validate({"algValue": "abcdef1234567890"})

    def test_checksum_rejects_missing_algorithm_value(self):
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


class TestProduct:
    def test_product_from_json(self):
        data = {
            "uuid": "09e8c73b-ac45-4475-acac-33e6a7314e6d",
            "name": "Apache Log4j 2",
            "identifiers": [
                {"idType": "CPE", "idValue": "cpe:2.3:a:apache:log4j"},
                {"idType": "PURL", "idValue": "pkg:maven/org.apache.logging.log4j/log4j-api"},
            ],
        }
        product = Product.model_validate(data)
        assert product.uuid == "09e8c73b-ac45-4475-acac-33e6a7314e6d"
        assert product.name == "Apache Log4j 2"
        assert len(product.identifiers) == 2
        assert product.identifiers[0].id_type == IdentifierType.CPE

    def test_product_with_udi_identifier(self):
        data = {
            "uuid": "abc-123",
            "name": "Medical Device",
            "identifiers": [{"idType": "UDI", "idValue": "00123456789012"}],
        }
        product = Product.model_validate(data)
        assert product.identifiers[0].id_type == IdentifierType.UDI
        assert product.identifiers[0].id_value == "00123456789012"


class TestRelease:
    def test_release_from_json(self):
        data = {
            "uuid": "605d0ecb-1057-40e4-9abf-c400b10f0345",
            "version": "11.0.7",
            "createdDate": "2025-05-07T18:08:00Z",
            "releaseDate": "2025-05-12T18:08:00Z",
            "identifiers": [{"idType": "PURL", "idValue": "pkg:maven/org.apache.tomcat/tomcat@11.0.7"}],
            "distributions": [
                {
                    "distributionType": "zip",
                    "description": "Core binary distribution",
                    "checksums": [
                        {
                            "algType": "SHA-256",
                            "algValue": "9da736a1cdd27231e70187cbc67398d29ca0b714f885e7032da9f1fb247693c1",
                        }
                    ],
                    "url": "https://repo.maven.apache.org/maven2/tomcat-11.0.7.zip",
                }
            ],
        }
        release = Release.model_validate(data)
        assert release.version == "11.0.7"
        assert release.distributions[0].distribution_type == "zip"
        assert release.distributions[0].checksums[0].algorithm_type == ChecksumAlgorithm.SHA_256


class TestCollection:
    def test_collection_from_json(self):
        data = {
            "uuid": "4c72fe22-9d83-4c2f-8eba-d6db484f32c8",
            "version": 3,
            "date": "2024-12-13T00:00:00Z",
            "belongsTo": "COMPONENT_RELEASE",
            "updateReason": {"type": "ARTIFACT_UPDATED", "comment": "VDR file updated"},
            "artifacts": [
                {
                    "uuid": "1cb47b95-8bf8-3bad-a5a4-0d54d86e10ce",
                    "name": "Build SBOM",
                    "type": "BOM",
                    "formats": [
                        {
                            "mediaType": "application/vnd.cyclonedx+xml",
                            "description": "CycloneDX SBOM (XML)",
                            "url": "https://repo.maven.apache.org/maven2/log4j-core-2.24.3-cyclonedx.xml",
                            "checksums": [{"algType": "SHA-1", "algValue": "5a7d4caef63c5c5ccdf07c39337323529eb5a770"}],
                        }
                    ],
                }
            ],
        }
        collection = Collection.model_validate(data)
        assert collection.version == 3
        assert collection.belongs_to == CollectionBelongsTo.COMPONENT_RELEASE
        assert collection.update_reason.type == CollectionUpdateReasonType.ARTIFACT_UPDATED
        assert collection.artifacts[0].type == ArtifactType.BOM
        assert collection.artifacts[0].formats[0].media_type == "application/vnd.cyclonedx+xml"


class TestOptionalFields:
    def test_release_minimal_fields(self):
        data = {
            "uuid": "r-1",
            "version": "1.0.0",
            "createdDate": "2024-01-01T00:00:00Z",
        }
        release = Release.model_validate(data)
        assert release.release_date is None
        assert release.pre_release is None
        assert release.component is None
        assert release.distributions == []
        assert release.identifiers == []

    def test_collection_minimal_fields(self):
        data = {"uuid": "c-1", "version": 1}
        collection = Collection.model_validate(data)
        assert collection.date is None
        assert collection.belongs_to is None
        assert collection.update_reason is None
        assert collection.artifacts == []

    def test_artifact_format_minimal_fields(self):
        data = {
            "mediaType": "application/json",
            "url": "https://example.com/sbom.json",
        }
        fmt = ArtifactFormat.model_validate(data)
        assert fmt.description is None
        assert fmt.signature_url is None
        assert fmt.checksums == []

    def test_paginated_product_response_empty_results(self):
        data = {
            "timestamp": "2024-03-20T15:30:00Z",
            "pageStartIndex": 0,
            "pageSize": 100,
            "totalResults": 0,
            "results": [],
        }
        resp = PaginatedProductResponse.model_validate(data)
        assert resp.total_results == 0
        assert resp.results == []


class TestPaginatedResponse:
    def test_paginated_product_response(self):
        data = {
            "timestamp": "2024-03-20T15:30:00Z",
            "pageStartIndex": 0,
            "pageSize": 100,
            "totalResults": 1,
            "results": [
                {
                    "uuid": "09e8c73b-ac45-4475-acac-33e6a7314e6d",
                    "name": "Apache Log4j 2",
                    "identifiers": [{"idType": "PURL", "idValue": "pkg:maven/org.apache.logging.log4j/log4j-api"}],
                }
            ],
        }
        resp = PaginatedProductResponse.model_validate(data)
        assert resp.total_results == 1
        assert resp.results[0].name == "Apache Log4j 2"
