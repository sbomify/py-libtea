"""Exception hierarchy for the TEA client library."""


class TeaError(Exception):
    """Base exception for all TEA client errors."""


class TeaConnectionError(TeaError):
    """Network or connection failure."""


class TeaAuthenticationError(TeaError):
    """HTTP 401 or 403 response."""


class TeaNotFoundError(TeaError):
    """HTTP 404 response."""

    def __init__(self, message: str, *, error_type: str | None = None):
        super().__init__(message)
        self.error_type = error_type


class TeaRequestError(TeaError):
    """Unexpected HTTP redirect (3xx) or client error (4xx other than 401/403/404)."""


class TeaServerError(TeaError):
    """HTTP 5xx response."""


class TeaDiscoveryError(TeaError):
    """Discovery-specific failure (bad TEI, no .well-known, no compatible endpoint)."""


class TeaChecksumError(TeaError):
    """Checksum verification failure on artifact download."""

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
    """Malformed server response that fails Pydantic validation."""


class TeaInsecureTransportWarning(UserWarning):
    """Warning emitted when using plaintext HTTP instead of HTTPS."""
