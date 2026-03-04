"""Conformance test runner — orchestrates checks and collects results."""

import logging

from libtea.client import TeaClient
from libtea.conformance._checks import ALL_CHECKS, CheckContext
from libtea.conformance._types import ConformanceResult

logger = logging.getLogger("libtea.conformance")


def run_conformance(
    base_url: str,
    *,
    tei: str | None = None,
    product_uuid: str | None = None,
    product_release_uuid: str | None = None,
    component_uuid: str | None = None,
    component_release_uuid: str | None = None,
    artifact_uuid: str | None = None,
    token: str | None = None,
    basic_auth: tuple[str, str] | None = None,
    timeout: float = 30.0,
    allow_private_ips: bool = False,
) -> ConformanceResult:
    """Run the full conformance suite against a TEA server.

    Args:
        base_url: TEA server base URL.
        tei: TEI for discovery-driven testing (auto-discovers UUIDs).
        product_uuid: Explicit product UUID.
        product_release_uuid: Explicit product release UUID.
        component_uuid: Explicit component UUID.
        component_release_uuid: Explicit component release UUID.
        artifact_uuid: Explicit artifact UUID.
        token: Optional bearer token.
        basic_auth: Optional ``(user, password)`` tuple.
        timeout: Request timeout in seconds.
        allow_private_ips: Allow private IPs in downloads.

    Returns:
        Aggregated conformance results.
    """
    ctx = CheckContext(
        tei=tei,
        product_uuid=product_uuid,
        product_release_uuid=product_release_uuid,
        component_uuid=component_uuid,
        component_release_uuid=component_release_uuid,
        artifact_uuid=artifact_uuid,
    )

    result = ConformanceResult(base_url=base_url)

    with TeaClient(
        base_url=base_url,
        token=token,
        basic_auth=basic_auth,
        timeout=timeout,
        allow_private_ips=allow_private_ips,
    ) as client:
        for check_fn in ALL_CHECKS:
            logger.debug("Running check: %s", check_fn.__name__)
            check_result = check_fn(client, ctx)
            result.checks.append(check_result)
            logger.info("  %s: %s — %s", check_result.status.value.upper(), check_result.name, check_result.message)

    return result
