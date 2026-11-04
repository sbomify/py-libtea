LEGACY_BASE_URL = "https://api.example.com/tea/v0.4.0"
V1_BASE_URL = "https://api.example.com/tea/v1.0.0"
LEGACY = {"tea_legacy": True}

PRODUCT = "09e8c73b-ac45-4475-acac-33e6a7314e6d"
PRODUCT_RELEASE = "123e4567-e89b-12d3-a456-426614174000"
COMPONENT = "b844c9bd-55d6-478c-af59-954a932b6ad3"
COMPONENT_RELEASE = "da89e38e-95e7-44ca-aa7d-f3b6b34c7fab"
ARTIFACT = "1cb47b95-8bf8-3bad-a5a4-0d54d86e10ce"
SHA256_HEX = "e04c9d55986d7194822eaa4f8115a77f801844d807ad6e0d454ac31dd41861e5"
MD5_HEX = "d41d8cd98f00b204e9800998ecf8427e"

V1_ARTIFACT = {
    "uuid": ARTIFACT,
    "version": 2,
    "type": "BOM",
    "createdDate": "2024-12-13T00:00:00Z",
    "formats": [
        {
            "mediaType": "application/vnd.cyclonedx+xml",
            "url": "https://repo.example.com/sbom.xml",
            "checksums": [{"algType": "SHA-256", "algValue": SHA256_HEX}],
        }
    ],
}
V1_COLLECTION = {
    "uuid": COMPONENT_RELEASE,
    "version": 2,
    "createdDate": "2025-05-12T18:08:00Z",
    "belongsTo": "COMPONENT_RELEASE",
    "updateReason": {"type": "VEX_UPDATED"},
    "artifacts": [V1_ARTIFACT],
}
V1_RELEASE = {
    "uuid": COMPONENT_RELEASE,
    "version": "2.24.3",
    "createdDate": "2024-12-10T10:51:00Z",
    "component": COMPONENT,
}
V1_PRODUCT_RELEASE = {
    "uuid": PRODUCT_RELEASE,
    "version": "2.24.3",
    "createdDate": "2025-04-01T15:43:00Z",
    "product": PRODUCT,
    "components": [{"uuid": COMPONENT}],
}


def product(uuid: str, name: str) -> dict:
    return {"uuid": uuid, "name": name, "identifiers": []}
