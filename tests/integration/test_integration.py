"""Integration tests using example data from the TEA OpenAPI spec."""

import responses

from libtea.client import TeaClient
from libtea.models import ArtifactType, ChecksumAlgorithm, IdentifierType

# Example JSON taken directly from the TEA OpenAPI spec
LOG4J_PRODUCT = {
    "uuid": "09e8c73b-ac45-4475-acac-33e6a7314e6d",
    "name": "Apache Log4j 2",
    "identifiers": [
        {"idType": "CPE", "idValue": "cpe:2.3:a:apache:log4j"},
        {"idType": "PURL", "idValue": "pkg:maven/org.apache.logging.log4j/log4j-api"},
    ],
}

TOMCAT_RELEASE = {
    "uuid": "605d0ecb-1057-40e4-9abf-c400b10f0345",
    "version": "11.0.7",
    "createdDate": "2025-05-07T18:08:00Z",
    "releaseDate": "2025-05-12T18:08:00Z",
    "identifiers": [{"idType": "PURL", "idValue": "pkg:maven/org.apache.tomcat/tomcat@11.0.7"}],
    "distributions": [
        {
            "distributionType": "zip",
            "description": "Core binary distribution, zip archive",
            "identifiers": [{"idType": "PURL", "idValue": "pkg:maven/org.apache.tomcat/tomcat@11.0.6?type=zip"}],
            "checksums": [
                {"algType": "SHA-256", "algValue": "9da736a1cdd27231e70187cbc67398d29ca0b714f885e7032da9f1fb247693c1"}
            ],
            "url": "https://repo.maven.apache.org/maven2/org/apache/tomcat/tomcat/11.0.7/tomcat-11.0.6.zip",
            "signatureUrl": "https://repo.maven.apache.org/maven2/org/apache/tomcat/tomcat/11.0.7/tomcat-11.0.6.zip.asc",
        }
    ],
}

LOG4J_COLLECTION = {
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
                    "signatureUrl": "https://repo.maven.apache.org/maven2/log4j-core-2.24.3-cyclonedx.xml.asc",
                    "checksums": [
                        {"algType": "MD5", "algValue": "2e1a525afc81b0a8ecff114b8b743de9"},
                        {"algType": "SHA-1", "algValue": "5a7d4caef63c5c5ccdf07c39337323529eb5a770"},
                    ],
                }
            ],
        },
        {
            "uuid": "dfa35519-9734-4259-bba1-3e825cf4be06",
            "name": "Vulnerability Disclosure Report",
            "type": "VULNERABILITIES",
            "formats": [
                {
                    "mediaType": "application/vnd.cyclonedx+xml",
                    "description": "CycloneDX VDR (XML)",
                    "url": "https://logging.apache.org/cyclonedx/vdr.xml",
                    "checksums": [
                        {
                            "algType": "SHA-256",
                            "algValue": "75b81020b3917cb682b1a7605ade431e062f7a4c01a412f0b87543b6e995ad2a",
                        }
                    ],
                }
            ],
        },
    ],
}


class TestSpecExamples:
    @responses.activate
    def test_full_consumer_flow(self, base_url):
        """Test the full consumer flow: product -> component releases -> collection -> artifacts."""
        product_uuid = LOG4J_PRODUCT["uuid"]
        release_uuid = TOMCAT_RELEASE["uuid"]

        responses.get(f"{base_url}/product/{product_uuid}", json=LOG4J_PRODUCT)
        responses.get(
            f"{base_url}/componentRelease/{release_uuid}",
            json={
                "release": TOMCAT_RELEASE,
                "latestCollection": LOG4J_COLLECTION,
            },
        )
        responses.get(f"{base_url}/componentRelease/{release_uuid}/collection/latest", json=LOG4J_COLLECTION)

        with TeaClient(base_url=base_url) as client:
            # Step 1: Get product
            product = client.get_product(product_uuid)
            assert product.name == "Apache Log4j 2"
            assert product.identifiers[0].id_type == IdentifierType.CPE

            # Step 2: Get component release with collection
            cr = client.get_component_release(release_uuid)
            assert cr.release.version == "11.0.7"
            assert cr.release.distributions[0].distribution_type == "zip"
            assert cr.release.distributions[0].checksums[0].algorithm_type == ChecksumAlgorithm.SHA_256

            # Step 3: Get latest collection
            collection = client.get_component_release_collection_latest(release_uuid)
            assert collection.version == 3
            assert len(collection.artifacts) == 2

            # Step 4: Inspect artifacts
            sbom = collection.artifacts[0]
            assert sbom.type == ArtifactType.BOM
            assert sbom.formats[0].media_type == "application/vnd.cyclonedx+xml"

            vdr = collection.artifacts[1]
            assert vdr.type == ArtifactType.VULNERABILITIES
