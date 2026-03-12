"""pytest plugin for TEA server conformance testing.

Registers ``--tea-base-url`` and ``--tea-tei`` CLI options, provides
a ``tea_client`` fixture, and generates one pytest test item per check.

Usage::

    pytest --tea-base-url https://tea.example.com/v1 --tea-tei "urn:tei:..."

All conformance module imports are deferred to function bodies so that
``pytest-cov`` can track them.  The ``pytest11`` entry point causes this
file to be loaded before coverage starts — lazy imports avoid the
early-import coverage gap.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from libtea.client import TeaClient
    from libtea.conformance._checks import CheckContext
    from libtea.conformance._types import CheckResult


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("tea-conformance", "TEA server conformance testing")
    group.addoption("--tea-base-url", help="TEA server base URL for conformance tests")
    group.addoption("--tea-tei", default=None, help="TEI for discovery-driven conformance testing")
    group.addoption("--tea-token", default=None, help="Bearer token for TEA server")
    group.addoption("--tea-product-uuid", default=None, help="Product UUID")
    group.addoption("--tea-release-uuid", default=None, help="Product release UUID")
    group.addoption("--tea-component-uuid", default=None, help="Component UUID")
    group.addoption("--tea-component-release-uuid", default=None, help="Component release UUID")
    group.addoption("--tea-artifact-uuid", default=None, help="Artifact UUID")
    group.addoption("--tea-timeout", type=float, default=30.0, help="Request timeout")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "tea_conformance: TEA server conformance check")


@pytest.fixture(scope="session")
def tea_client(request: pytest.FixtureRequest) -> Iterator[TeaClient]:
    """Session-scoped TeaClient for conformance tests."""
    from libtea.client import TeaClient as _TeaClient

    base_url = request.config.getoption("--tea-base-url")
    if not base_url:
        pytest.skip("--tea-base-url not provided")
    token = request.config.getoption("--tea-token")
    timeout: float = request.config.getoption("--tea-timeout")
    client = _TeaClient(base_url=base_url, token=token, timeout=timeout)
    yield client
    client.close()


@pytest.fixture(scope="session")
def tea_check_context(request: pytest.FixtureRequest) -> CheckContext:
    """Session-scoped check context populated from CLI options."""
    from libtea.conformance._checks import CheckContext as _CheckContext

    return _CheckContext(
        tei=request.config.getoption("--tea-tei"),
        product_uuid=request.config.getoption("--tea-product-uuid"),
        product_release_uuid=request.config.getoption("--tea-release-uuid"),
        component_uuid=request.config.getoption("--tea-component-uuid"),
        component_release_uuid=request.config.getoption("--tea-component-release-uuid"),
        artifact_uuid=request.config.getoption("--tea-artifact-uuid"),
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip tea_conformance-marked tests when --tea-base-url is not provided."""
    if config.getoption("--tea-base-url", default=None):
        return
    skip = pytest.mark.skip(reason="--tea-base-url not provided")
    for item in items:
        if "tea_conformance" in item.keywords:
            item.add_marker(skip)


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Generate one test per conformance check when `tea_check_fn` is requested."""
    if "tea_check_fn" in metafunc.fixturenames:
        from libtea.conformance._checks import ALL_CHECKS

        metafunc.parametrize(
            "tea_check_fn",
            ALL_CHECKS,
            ids=[fn.__name__ for fn in ALL_CHECKS],
        )


@pytest.mark.tea_conformance
def test_tea_conformance(
    tea_client: TeaClient,
    tea_check_context: CheckContext,
    tea_check_fn: Callable[[TeaClient, CheckContext], CheckResult],
) -> None:
    """Run a single TEA conformance check."""
    from libtea.conformance._types import CheckStatus

    result = tea_check_fn(tea_client, tea_check_context)
    if result.status == CheckStatus.SKIP:
        pytest.skip(result.message)
    elif result.status == CheckStatus.WARN:
        import warnings

        warnings.warn(f"{result.name}: {result.message}", stacklevel=2)
    elif result.status == CheckStatus.FAIL:
        pytest.fail(f"{result.name}: {result.message}")
