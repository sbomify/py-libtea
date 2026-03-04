"""libtea — Python client library for the Transparency Exchange API (TEA).

Quick start::

    from libtea import TeaClient

    with TeaClient("https://tea.example.com/v1", token="...") as client:
        results = client.discover("urn:tei:purl:example.com:pkg:pypi/lib@1.0")

Or auto-discover the server from a domain's ``.well-known/tea``::

    client = TeaClient.from_well_known("tea.example.com", token="...")
"""

from importlib.metadata import version

from libtea.client import TEA_SPEC_VERSION, TeaClient
from libtea.discovery import (
    VersionedEndpoint,
    fetch_well_known,
    parse_tei,
    select_best_endpoint,
    select_endpoint,
    select_endpoints,
)
from libtea.exceptions import (
    TeaAuthenticationError,
    TeaChecksumError,
    TeaConnectionError,
    TeaDiscoveryError,
    TeaError,
    TeaInsecureTransportWarning,
    TeaNotFoundError,
    TeaRequestError,
    TeaServerError,
    TeaValidationError,
)
from libtea.models import (
    CLE,
    Artifact,
    ArtifactFormat,
    ArtifactType,
    Checksum,
    ChecksumAlgorithm,
    CLEDefinitions,
    CLEEvent,
    CLEEventType,
    CLESupportDefinition,
    CLEVersionSpecifier,
    Collection,
    CollectionBelongsTo,
    CollectionUpdateReason,
    CollectionUpdateReasonType,
    Component,
    ComponentRef,
    ComponentReleaseWithCollection,
    DiscoveryInfo,
    ErrorResponse,
    ErrorType,
    Identifier,
    IdentifierType,
    PaginatedProductReleaseResponse,
    PaginatedProductResponse,
    Product,
    ProductRelease,
    Release,
    ReleaseDistribution,
    TeaEndpoint,
    TeaServerInfo,
    TeaWellKnown,
    TeiType,
)
from libtea.protocols import TeaClientProtocol

__version__ = version("libtea")
__all__ = [
    # Client
    "TEA_SPEC_VERSION",
    "TeaClient",
    "TeaClientProtocol",
    # Discovery
    "VersionedEndpoint",
    "fetch_well_known",
    "parse_tei",
    "select_best_endpoint",
    "select_endpoint",
    "select_endpoints",
    # Exceptions
    "TeaError",
    "TeaAuthenticationError",
    "TeaChecksumError",
    "TeaConnectionError",
    "TeaDiscoveryError",
    "TeaInsecureTransportWarning",
    "TeaNotFoundError",
    "TeaRequestError",
    "TeaServerError",
    "TeaValidationError",
    # Models
    "Artifact",
    "ArtifactFormat",
    "ArtifactType",
    "CLE",
    "CLEDefinitions",
    "CLEEvent",
    "CLEEventType",
    "CLESupportDefinition",
    "CLEVersionSpecifier",
    "Checksum",
    "ChecksumAlgorithm",
    "Collection",
    "CollectionBelongsTo",
    "CollectionUpdateReason",
    "CollectionUpdateReasonType",
    "Component",
    "ComponentRef",
    "ComponentReleaseWithCollection",
    "DiscoveryInfo",
    "ErrorResponse",
    "ErrorType",
    "Identifier",
    "IdentifierType",
    "PaginatedProductReleaseResponse",
    "PaginatedProductResponse",
    "Product",
    "ProductRelease",
    "Release",
    "ReleaseDistribution",
    "TeaEndpoint",
    "TeaServerInfo",
    "TeaWellKnown",
    "TeiType",
    "__version__",
]
