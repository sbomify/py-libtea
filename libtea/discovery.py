"""TEI parsing, .well-known/tea fetching, and endpoint selection."""

import logging
import warnings
from typing import Any
from urllib.parse import urlparse

import requests
from pydantic import ValidationError
from semver import Version as _SemVer

from libtea._http import USER_AGENT, MtlsConfig
from libtea.exceptions import TeaDiscoveryError, TeaInsecureTransportWarning
from libtea.models import TeaEndpoint, TeaWellKnown, TeiType

logger = logging.getLogger("libtea")

_VALID_TEI_TYPES = frozenset(e.value for e in TeiType)
_DOMAIN_LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")


def _is_valid_domain(domain: str) -> bool:
    """Validate domain per RFC 952/1123: alnum labels, internal hyphens, max 63 chars per label, max 253 total."""
    if not domain or len(domain) > 253:
        return False
    for label in domain.split("."):
        if not label or len(label) > 63:
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        if not all(c in _DOMAIN_LABEL_CHARS for c in label):
            return False
    return True


def parse_tei(tei: str) -> tuple[str, str, str]:
    """Parse a TEI URN into (type, domain, identifier).

    TEI format: ``urn:tei:<type>:<domain>:<identifier>``

    Args:
        tei: TEI URN string.

    Returns:
        Tuple of (type, domain, identifier).

    Raises:
        TeaDiscoveryError: If the TEI format is invalid.
    """
    parts = tei.split(":")
    if len(parts) < 5 or parts[0] != "urn" or parts[1] != "tei":
        raise TeaDiscoveryError(f"Invalid TEI: {tei!r}. Expected format: urn:tei:<type>:<domain>:<identifier>")

    tei_type = parts[2]
    if tei_type not in _VALID_TEI_TYPES:
        raise TeaDiscoveryError(
            f"Invalid TEI type: {tei_type!r}. Must be one of: {', '.join(sorted(_VALID_TEI_TYPES))}"
        )
    domain = parts[3]
    if not domain or not _is_valid_domain(domain):
        raise TeaDiscoveryError(f"Invalid domain in TEI: {domain!r}")
    identifier = ":".join(parts[4:])
    return tei_type, domain, identifier


def fetch_well_known(
    domain: str,
    *,
    timeout: float = 10.0,
    scheme: str = "https",
    port: int | None = None,
    mtls: MtlsConfig | None = None,
) -> TeaWellKnown:
    """Fetch and parse the .well-known/tea discovery document from a domain.

    Args:
        domain: Domain name to resolve (e.g. ``tea.example.com``).
        timeout: HTTP request timeout in seconds.
        scheme: URL scheme, ``"https"`` (default) or ``"http"``.
        port: Optional port number. Default ports (443 for https, 80 for http)
            are omitted from the URL.
        mtls: Optional mutual TLS configuration.

    Returns:
        Parsed well-known document with endpoint list.

    Raises:
        TeaDiscoveryError: If the domain is invalid, unreachable, or returns
            an invalid document.
    """
    if scheme not in ("http", "https"):
        raise TeaDiscoveryError(f"Invalid scheme: {scheme!r}. Must be 'http' or 'https'.")
    if scheme == "http":
        warnings.warn(
            "Fetching .well-known/tea over plaintext HTTP. Use HTTPS in production.",
            TeaInsecureTransportWarning,
            stacklevel=2,
        )
    if port is not None and not (1 <= port <= 65535):
        raise TeaDiscoveryError(f"Invalid port: {port}. Must be between 1 and 65535.")
    if not domain or not _is_valid_domain(domain):
        raise TeaDiscoveryError(f"Invalid domain: {domain!r}")

    default_port = 80 if scheme == "http" else 443
    resolved_port = port if port is not None else default_port
    if resolved_port == default_port:
        url = f"{scheme}://{domain}/.well-known/tea"
    else:
        url = f"{scheme}://{domain}:{resolved_port}/.well-known/tea"

    kwargs: dict[str, Any] = {"timeout": timeout, "allow_redirects": True, "headers": {"user-agent": USER_AGENT}}
    if mtls:
        kwargs["cert"] = (str(mtls.client_cert), str(mtls.client_key))
        if mtls.ca_bundle:
            kwargs["verify"] = str(mtls.ca_bundle)

    try:
        response = requests.get(url, **kwargs)
        # Validate the final URL after any redirects (SSRF protection)
        final_parsed = urlparse(response.url)
        if final_parsed.scheme not in ("http", "https"):
            raise TeaDiscoveryError(f"Discovery redirected to unsupported scheme: {final_parsed.scheme!r}")
        if response.status_code >= 400:
            body_snippet = (response.text or "")[:200]
            if len(response.text or "") > 200:
                body_snippet += " (truncated)"
            msg = f"Failed to fetch {url}: HTTP {response.status_code}"
            if body_snippet:
                msg = f"{msg} — {body_snippet}"
            raise TeaDiscoveryError(msg)
    except requests.ConnectionError as exc:
        logger.warning("Discovery connection error for %s: %s", url, exc)
        raise TeaDiscoveryError(f"Failed to connect to {url}: {exc}") from exc
    except requests.Timeout as exc:
        logger.warning("Discovery timeout for %s: %s", url, exc)
        raise TeaDiscoveryError(f"Failed to connect to {url}: {exc}") from exc
    except requests.RequestException as exc:
        raise TeaDiscoveryError(f"HTTP error fetching {url}: {exc}") from exc

    try:
        data = response.json()
    except ValueError as exc:
        raise TeaDiscoveryError(f"Invalid JSON in .well-known/tea response from {domain}") from exc

    try:
        return TeaWellKnown.model_validate(data)
    except ValidationError as exc:
        raise TeaDiscoveryError(f"Invalid .well-known/tea document from {domain}: {exc}") from exc


def select_endpoints(well_known: TeaWellKnown, supported_version: str) -> list[TeaEndpoint]:
    """Select all endpoints that support the given version, sorted by priority.

    Per TEA spec: uses SemVer 2.0.0 comparison to match versions, then
    sorts by highest matching version with priority as tiebreaker.

    Args:
        well_known: Parsed .well-known/tea document.
        supported_version: SemVer version string the client supports.

    Returns:
        List of matching endpoints, best first.

    Raises:
        TeaDiscoveryError: If no endpoint supports the requested version.
    """
    target = _SemVer.parse(supported_version)

    candidates: list[tuple[_SemVer, TeaEndpoint]] = []
    for ep in well_known.endpoints:
        best_match: _SemVer | None = None
        for v_str in ep.versions:
            try:
                v = _SemVer.parse(v_str)
            except ValueError:
                continue
            if v == target and (best_match is None or v > best_match):
                best_match = v
        if best_match is not None:
            candidates.append((best_match, ep))

    if not candidates:
        available = {v for ep in well_known.endpoints for v in ep.versions}
        raise TeaDiscoveryError(
            f"No compatible endpoint found for version {supported_version!r}. Available versions: {sorted(available)}"
        )

    # Sort by: highest SemVer version desc, then priority desc (default 1.0 per spec)
    candidates.sort(
        key=lambda pair: (pair[0], pair[1].priority if pair[1].priority is not None else 1.0),
        reverse=True,
    )
    return [ep for _, ep in candidates]


def select_endpoint(well_known: TeaWellKnown, supported_version: str) -> TeaEndpoint:
    """Select the best endpoint that supports the given version.

    Convenience wrapper around :func:`select_endpoints` that returns only
    the top-priority candidate.

    Args:
        well_known: Parsed .well-known/tea document.
        supported_version: SemVer version string the client supports.

    Returns:
        The best matching endpoint.

    Raises:
        TeaDiscoveryError: If no endpoint supports the requested version.
    """
    return select_endpoints(well_known, supported_version)[0]
