"""libtea — Python client library for the Transparency Exchange API (TEA).

Quick start::

    from libtea import TeaClient

    with TeaClient("https://tea.example.com/v1", token="...") as client:
        results = client.discover("urn:tei:purl:example.com:pkg:pypi/lib@1.0")

Or auto-discover the server from a domain's ``.well-known/tea``::

    client = TeaClient.from_well_known("tea.example.com", token="...")
"""

from importlib.metadata import version
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libtea.client import TEA_SPEC_VERSION as TEA_SPEC_VERSION
    from libtea.client import TeaClient as TeaClient
    from libtea.discovery import (
        VersionedEndpoint as VersionedEndpoint,
    )
    from libtea.discovery import (
        fetch_well_known as fetch_well_known,
    )
    from libtea.discovery import (
        parse_tei as parse_tei,
    )
    from libtea.discovery import (
        select_best_endpoint as select_best_endpoint,
    )
    from libtea.discovery import (
        select_endpoint as select_endpoint,
    )
    from libtea.discovery import (
        select_endpoints as select_endpoints,
    )
    from libtea.exceptions import (
        TeaAuthenticationError as TeaAuthenticationError,
    )
    from libtea.exceptions import (
        TeaChecksumError as TeaChecksumError,
    )
    from libtea.exceptions import (
        TeaConnectionError as TeaConnectionError,
    )
    from libtea.exceptions import (
        TeaDiscoveryError as TeaDiscoveryError,
    )
    from libtea.exceptions import (
        TeaError as TeaError,
    )
    from libtea.exceptions import (
        TeaInsecureTransportWarning as TeaInsecureTransportWarning,
    )
    from libtea.exceptions import (
        TeaNotFoundError as TeaNotFoundError,
    )
    from libtea.exceptions import (
        TeaRequestError as TeaRequestError,
    )
    from libtea.exceptions import (
        TeaServerError as TeaServerError,
    )
    from libtea.exceptions import (
        TeaValidationError as TeaValidationError,
    )
    from libtea.models import (
        CLE as CLE,
    )
    from libtea.models import (
        Artifact as Artifact,
    )
    from libtea.models import (
        ArtifactFormat as ArtifactFormat,
    )
    from libtea.models import (
        ArtifactType as ArtifactType,
    )
    from libtea.models import (
        Checksum as Checksum,
    )
    from libtea.models import (
        ChecksumAlgorithm as ChecksumAlgorithm,
    )
    from libtea.models import (
        CLEDefinitions as CLEDefinitions,
    )
    from libtea.models import (
        CLEEvent as CLEEvent,
    )
    from libtea.models import (
        CLEEventType as CLEEventType,
    )
    from libtea.models import (
        CLESupportDefinition as CLESupportDefinition,
    )
    from libtea.models import (
        CLEVersionSpecifier as CLEVersionSpecifier,
    )
    from libtea.models import (
        Collection as Collection,
    )
    from libtea.models import (
        CollectionBelongsTo as CollectionBelongsTo,
    )
    from libtea.models import (
        CollectionUpdateReason as CollectionUpdateReason,
    )
    from libtea.models import (
        CollectionUpdateReasonType as CollectionUpdateReasonType,
    )
    from libtea.models import (
        Component as Component,
    )
    from libtea.models import (
        ComponentRef as ComponentRef,
    )
    from libtea.models import (
        ComponentReleaseWithCollection as ComponentReleaseWithCollection,
    )
    from libtea.models import (
        DiscoveryInfo as DiscoveryInfo,
    )
    from libtea.models import (
        ErrorResponse as ErrorResponse,
    )
    from libtea.models import (
        ErrorType as ErrorType,
    )
    from libtea.models import (
        Identifier as Identifier,
    )
    from libtea.models import (
        IdentifierType as IdentifierType,
    )
    from libtea.models import (
        PaginatedProductReleaseResponse as PaginatedProductReleaseResponse,
    )
    from libtea.models import (
        PaginatedProductResponse as PaginatedProductResponse,
    )
    from libtea.models import (
        Product as Product,
    )
    from libtea.models import (
        ProductRelease as ProductRelease,
    )
    from libtea.models import (
        Release as Release,
    )
    from libtea.models import (
        ReleaseDistribution as ReleaseDistribution,
    )
    from libtea.models import (
        TeaEndpoint as TeaEndpoint,
    )
    from libtea.models import (
        TeaServerInfo as TeaServerInfo,
    )
    from libtea.models import (
        TeaWellKnown as TeaWellKnown,
    )
    from libtea.models import (
        TeiType as TeiType,
    )
    from libtea.protocols import TeaClientProtocol as TeaClientProtocol

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

_LAZY_IMPORTS: dict[str, str] = {
    # client
    "TEA_SPEC_VERSION": "libtea.client",
    "TeaClient": "libtea.client",
    # discovery
    "VersionedEndpoint": "libtea.discovery",
    "fetch_well_known": "libtea.discovery",
    "parse_tei": "libtea.discovery",
    "select_best_endpoint": "libtea.discovery",
    "select_endpoint": "libtea.discovery",
    "select_endpoints": "libtea.discovery",
    # exceptions
    "TeaAuthenticationError": "libtea.exceptions",
    "TeaChecksumError": "libtea.exceptions",
    "TeaConnectionError": "libtea.exceptions",
    "TeaDiscoveryError": "libtea.exceptions",
    "TeaError": "libtea.exceptions",
    "TeaInsecureTransportWarning": "libtea.exceptions",
    "TeaNotFoundError": "libtea.exceptions",
    "TeaRequestError": "libtea.exceptions",
    "TeaServerError": "libtea.exceptions",
    "TeaValidationError": "libtea.exceptions",
    # models
    "Artifact": "libtea.models",
    "ArtifactFormat": "libtea.models",
    "ArtifactType": "libtea.models",
    "CLE": "libtea.models",
    "CLEDefinitions": "libtea.models",
    "CLEEvent": "libtea.models",
    "CLEEventType": "libtea.models",
    "CLESupportDefinition": "libtea.models",
    "CLEVersionSpecifier": "libtea.models",
    "Checksum": "libtea.models",
    "ChecksumAlgorithm": "libtea.models",
    "Collection": "libtea.models",
    "CollectionBelongsTo": "libtea.models",
    "CollectionUpdateReason": "libtea.models",
    "CollectionUpdateReasonType": "libtea.models",
    "Component": "libtea.models",
    "ComponentRef": "libtea.models",
    "ComponentReleaseWithCollection": "libtea.models",
    "DiscoveryInfo": "libtea.models",
    "ErrorResponse": "libtea.models",
    "ErrorType": "libtea.models",
    "Identifier": "libtea.models",
    "IdentifierType": "libtea.models",
    "PaginatedProductReleaseResponse": "libtea.models",
    "PaginatedProductResponse": "libtea.models",
    "Product": "libtea.models",
    "ProductRelease": "libtea.models",
    "Release": "libtea.models",
    "ReleaseDistribution": "libtea.models",
    "TeaEndpoint": "libtea.models",
    "TeaServerInfo": "libtea.models",
    "TeaWellKnown": "libtea.models",
    "TeiType": "libtea.models",
    # protocols
    "TeaClientProtocol": "libtea.protocols",
}


def __getattr__(name: str) -> object:
    if name in _LAZY_IMPORTS:
        import importlib

        module = importlib.import_module(_LAZY_IMPORTS[name])
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
