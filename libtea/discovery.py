"""TEI parsing, .well-known/tea fetching, and endpoint selection."""

import requests

from libtea.exceptions import TeaDiscoveryError
from libtea.models import TeaEndpoint, TeaWellKnown


def parse_tei(tei: str) -> tuple[str, str, str]:
    """Parse a TEI URN into (type, domain, identifier).

    TEI format: urn:tei:<type>:<domain>:<identifier>
    The identifier may contain colons (e.g. hash type).
    """
    parts = tei.split(":")
    if len(parts) < 5 or parts[0] != "urn" or parts[1] != "tei":
        raise TeaDiscoveryError(f"Invalid TEI: {tei!r}. Expected format: urn:tei:<type>:<domain>:<identifier>")

    tei_type = parts[2]
    domain = parts[3]
    identifier = ":".join(parts[4:])
    return tei_type, domain, identifier


def fetch_well_known(domain: str, *, timeout: float = 10.0) -> TeaWellKnown:
    """Fetch and parse the .well-known/tea document from a domain via HTTPS."""
    url = f"https://{domain}/.well-known/tea"
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        if response.status_code >= 400:
            raise TeaDiscoveryError(f"Failed to fetch {url}: HTTP {response.status_code}")
    except requests.ConnectionError as exc:
        raise TeaDiscoveryError(f"Failed to connect to {url}: {exc}") from exc
    except requests.Timeout as exc:
        raise TeaDiscoveryError(f"Failed to connect to {url}: {exc}") from exc
    except TeaDiscoveryError:
        raise

    try:
        data = response.json()
    except ValueError as exc:
        raise TeaDiscoveryError(f"Invalid JSON in .well-known/tea response from {domain}") from exc

    try:
        return TeaWellKnown.model_validate(data)
    except Exception as exc:
        raise TeaDiscoveryError(f"Invalid .well-known/tea document from {domain}: {exc}") from exc


def select_endpoint(well_known: TeaWellKnown, supported_version: str) -> TeaEndpoint:
    """Select the best endpoint that supports the given version.

    Prefers endpoints with the requested version, then by highest priority.
    """
    candidates = [ep for ep in well_known.endpoints if supported_version in ep.versions]

    if not candidates:
        available = {v for ep in well_known.endpoints for v in ep.versions}
        raise TeaDiscoveryError(
            f"No compatible endpoint found for version {supported_version!r}. Available versions: {sorted(available)}"
        )

    candidates.sort(key=lambda ep: ep.priority if ep.priority is not None else 1.0, reverse=True)
    return candidates[0]
