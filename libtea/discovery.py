"""TEI parsing, .well-known/tea fetching, and endpoint selection."""

import logging
from functools import total_ordering

import requests
from pydantic import ValidationError

from libtea._http import USER_AGENT
from libtea.exceptions import TeaDiscoveryError
from libtea.models import TeaEndpoint, TeaWellKnown, TeiType


@total_ordering
class _SemVer:
    """Minimal SemVer 2.0.0 parser for version precedence comparison.

    Implements comparison per https://semver.org/#spec-item-11:
    - MAJOR.MINOR.PATCH compared numerically left-to-right
    - Pre-release versions have lower precedence than the normal version
    - Pre-release identifiers: numeric < alphanumeric, numeric compared as ints,
      alphanumeric compared lexically; shorter tuple has lower precedence
    """

    __slots__ = ("major", "minor", "patch", "pre", "_raw")

    def __init__(self, version_str: str) -> None:
        self._raw = version_str
        # Split pre-release: "1.2.3-beta.2" -> "1.2.3", "beta.2"
        if "-" in version_str:
            ver_part, pre_part = version_str.split("-", 1)
        else:
            ver_part, pre_part = version_str, None

        parts = ver_part.split(".")
        if len(parts) < 2 or len(parts) > 3:
            raise ValueError(f"Invalid SemVer string: {version_str!r}")
        if not all(p.isdigit() for p in parts):
            raise ValueError(f"Invalid SemVer string: {version_str!r}")

        self.major = int(parts[0])
        self.minor = int(parts[1])
        self.patch = int(parts[2]) if len(parts) == 3 else 0
        self.pre: tuple[int | str, ...] = tuple(_SemVer._parse_pre(pre_part)) if pre_part else ()

    @staticmethod
    def _parse_pre(pre_str: str) -> list[int | str]:
        parts: list[int | str] = []
        for part in pre_str.split("."):
            parts.append(int(part) if part.isdigit() else part)
        return parts

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _SemVer):
            return NotImplemented
        return (self.major, self.minor, self.patch, self.pre) == (other.major, other.minor, other.patch, other.pre)

    def __hash__(self) -> int:
        return hash((self.major, self.minor, self.patch, self.pre))

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, _SemVer):
            return NotImplemented
        if (self.major, self.minor, self.patch) != (other.major, other.minor, other.patch):
            return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)
        # Pre-release has lower precedence than no pre-release
        if self.pre and not other.pre:
            return True
        if not self.pre and other.pre:
            return False
        if not self.pre and not other.pre:
            return False
        # Compare pre-release identifiers per SemVer spec item 11.4
        return _SemVer._compare_pre(self.pre, other.pre) < 0

    @staticmethod
    def _compare_pre(a: tuple[int | str, ...], b: tuple[int | str, ...]) -> int:
        for ai, bi in zip(a, b):
            if type(ai) is type(bi):
                if ai < bi:  # type: ignore[operator]
                    return -1
                if ai > bi:  # type: ignore[operator]
                    return 1
            else:
                # Numeric identifiers always have lower precedence than alphanumeric
                return -1 if isinstance(ai, int) else 1
        # Shorter set has lower precedence
        if len(a) < len(b):
            return -1
        if len(a) > len(b):
            return 1
        return 0

    def __repr__(self) -> str:
        return f"_SemVer({self._raw!r})"

    def __str__(self) -> str:
        return self._raw


logger = logging.getLogger("libtea")

_VALID_TEI_TYPES = frozenset(e.value for e in TeiType)
_DOMAIN_LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")


def _is_valid_domain(domain: str) -> bool:
    """Validate domain per RFC 952/1123: alnum labels, internal hyphens, max 63 chars per label."""
    if not domain:
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


def fetch_well_known(domain: str, *, timeout: float = 10.0) -> TeaWellKnown:
    """Fetch and parse the .well-known/tea discovery document from a domain.

    Args:
        domain: Domain name to resolve (e.g. ``tea.example.com``).
        timeout: HTTP request timeout in seconds.

    Returns:
        Parsed well-known document with endpoint list.

    Raises:
        TeaDiscoveryError: If the domain is invalid, unreachable, or returns
            an invalid document.
    """
    if not domain or not _is_valid_domain(domain):
        raise TeaDiscoveryError(f"Invalid domain: {domain!r}")
    url = f"https://{domain}/.well-known/tea"
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True, headers={"user-agent": USER_AGENT})
        if 300 <= response.status_code < 400:
            raise TeaDiscoveryError(f"Unexpected redirect from {url}: HTTP {response.status_code}")
        if response.status_code >= 400:
            body_snippet = response.text[:200] if response.text else ""
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


def select_endpoint(well_known: TeaWellKnown, supported_version: str) -> TeaEndpoint:
    """Select the best endpoint that supports the given version.

    Per TEA spec: uses SemVer 2.0.0 comparison to match versions, then
    prioritizes by highest matching version, with priority as tiebreaker.

    Args:
        well_known: Parsed .well-known/tea document.
        supported_version: SemVer version string the client supports.

    Returns:
        The best matching endpoint.

    Raises:
        TeaDiscoveryError: If no endpoint supports the requested version.
    """
    target = _SemVer(supported_version)

    # For each endpoint, find the highest version matching the target via SemVer equality.
    # This handles cases like "1.0" matching "1.0.0" (patch defaults to 0).
    candidates: list[tuple[_SemVer, TeaEndpoint]] = []
    for ep in well_known.endpoints:
        best_match: _SemVer | None = None
        for v_str in ep.versions:
            try:
                v = _SemVer(v_str)
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
    return candidates[0][1]
