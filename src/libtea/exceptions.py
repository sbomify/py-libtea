"""Exception hierarchy for the TEA client library.

All library-specific exceptions inherit from :class:`TeaError`, making it
easy to catch any TEA-related failure with a single ``except TeaError`` clause.
:class:`TeaInsecureTransportWarning` is a :class:`UserWarning` (not an exception)
emitted when plaintext HTTP is used instead of HTTPS.
"""


class TeaError(Exception):
    """Base exception for all TEA client errors.

    Catch this to handle any error raised by the library.
    """


class TeaConnectionError(TeaError):
    """Network or connection failure (DNS, TCP, TLS, timeout)."""


class TeaAuthenticationError(TeaError):
    """HTTP 401 (Unauthorized) or 403 (Forbidden) response from the TEA server."""


class TeaNotFoundError(TeaError):
    """HTTP 404 response from the TEA server.

    Attributes:
        error_type: Optional TEA error type from the JSON response body
            (e.g. ``"OBJECT_UNKNOWN"`` or ``"OBJECT_NOT_SHAREABLE"``).
    """

    def __init__(self, message: str, *, error_type: str | None = None):
        super().__init__(message)
        self.error_type = error_type


class TeaRequestError(TeaError):
    """Unexpected HTTP redirect (3xx) or client error (4xx other than 401/403/404)."""


class TeaServerError(TeaError):
    """HTTP 5xx response indicating a server-side failure."""


class TeaDiscoveryError(TeaError):
    """Discovery-specific failure: invalid TEI, unreachable .well-known, or no compatible endpoint."""


class TeaChecksumError(TeaError):
    """Checksum verification failure on artifact download.

    Attributes:
        algorithm: Checksum algorithm name (e.g. ``"SHA-256"``), or ``None``
            if the failure is not algorithm-specific.
        expected: Expected hex digest from the server metadata, or ``None``.
        actual: Computed hex digest from the downloaded bytes, or ``None``.
    """

    def __init__(
        self,
        message: str,
        *,
        algorithm: str | None = None,
        expected: str | None = None,
        actual: str | None = None,
    ):
        super().__init__(message)
        self.algorithm = algorithm
        self.expected = expected
        self.actual = actual


class TeaValidationError(TeaError):
    """Malformed server response that fails Pydantic model validation."""


class TeaInsecureTransportWarning(UserWarning):
    """Warning emitted when using plaintext HTTP instead of HTTPS.

    Triggered by :class:`~libtea.client.TeaClient` or :func:`~libtea.discovery.fetch_well_known`
    when the ``scheme`` is ``"http"``.
    """


__all__ = [
    "TeaAuthenticationError",
    "TeaChecksumError",
    "TeaConnectionError",
    "TeaDiscoveryError",
    "TeaError",
    "TeaInsecureTransportWarning",
    "TeaNotFoundError",
    "TeaRequestError",
    "TeaServerError",
    "TeaValidationError",
]
