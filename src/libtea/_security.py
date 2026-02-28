"""SSRF protection for download URLs and discovery redirects.

Validates that URLs target public networks only, blocking private/internal
IPs, cloud metadata endpoints, and DNS-rebinding attempts. Used by both
:mod:`libtea._http` (artifact downloads) and :mod:`libtea.discovery`
(redirect validation).
"""

import ipaddress
import logging
import socket
from urllib.parse import urlparse

from libtea.exceptions import TeaValidationError

logger = logging.getLogger("libtea")

_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata.google.internal.",
    }
)

# RFC 6598 CGNAT range — ipaddress.is_private misses this on Python 3.11+.
_CGNAT_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")


def _is_internal_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if the IP address is non-global: private, loopback, link-local, reserved, unspecified, multicast, or CGNAT."""
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        return True
    if addr.is_unspecified or addr.is_multicast:
        return True
    # Extract embedded IPv4 from IPv4-mapped IPv6 (::ffff:x.x.x.x) before CGNAT check
    check_v4 = addr
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        check_v4 = addr.ipv4_mapped
    if isinstance(check_v4, ipaddress.IPv4Address) and check_v4 in _CGNAT_NETWORK:
        return True
    return False


def _validate_resolved_ips(hostname: str) -> None:
    """Resolve hostname via DNS and reject if any resolved IP is private/internal.

    Note: There is an inherent TOCTOU (time-of-check-time-of-use) gap between
    this DNS check and the actual HTTP request made by ``requests``.  A DNS
    rebinding attack could return a safe IP here and a malicious IP for the
    subsequent connection.  Fully closing this gap would require socket-level
    IP pinning, which ``requests`` does not support.  This check still raises
    the bar significantly against naive SSRF attempts.
    """
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        logger.warning("DNS resolution failed for %s during SSRF check; proceeding with request", hostname)
        return
    for _, _, _, _, sockaddr in addr_infos:
        resolved_ip = sockaddr[0]
        try:
            addr = ipaddress.ip_address(resolved_ip)
            if _is_internal_ip(addr):
                raise TeaValidationError(
                    f"Artifact download URL hostname {hostname!r} resolves to private/internal IP: {resolved_ip}"
                )
        except ValueError:
            pass


def _validate_download_url(url: str) -> None:
    """Reject download URLs that use non-HTTP schemes or target internal networks."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise TeaValidationError(f"Artifact download URL must use http or https scheme, got {parsed.scheme!r}")
    if not parsed.hostname:
        raise TeaValidationError(f"Artifact download URL must include a hostname: {url!r}")

    hostname = parsed.hostname.lower()
    if hostname in _BLOCKED_HOSTNAMES:
        raise TeaValidationError(f"Artifact download URL must not target internal hosts: {hostname!r}")

    try:
        addr = ipaddress.ip_address(hostname)
        if _is_internal_ip(addr):
            raise TeaValidationError(f"Artifact download URL must not target private/internal IP: {hostname!r}")
    except ValueError:
        # Not an IP literal — resolve hostname and check resolved IPs (DNS rebinding protection)
        _validate_resolved_ips(hostname)
