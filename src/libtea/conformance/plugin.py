"""pytest plugin for TEA server conformance testing.

Registers ``--tea-base-url`` and ``--tea-tei`` CLI options, provides
a ``tea_client`` fixture, and generates one pytest test item per check.

Usage::

    pytest --tea-base-url https://tea.example.com/v1 --tea-tei "urn:tei:..."
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    pass


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("tea-conformance", "TEA server conformance testing")
    group.addoption("--tea-base-url", help="TEA server base URL for conformance tests")
    group.addoption("--tea-tei", default=None, help="TEI for discovery-driven conformance testing")
    group.addoption("--tea-token", default=None, help="Bearer token for TEA server")
    group.addoption("--tea-product-uuid", default=None, help="Product UUID")
    group.addoption("--tea-release-uuid", default=None, help="Product release UUID")
    group.addoption("--tea-component-uuid", default=None, help="Component UUID")
    group.addoption("--tea-artifact-uuid", default=None, help="Artifact UUID")
    group.addoption("--tea-timeout", type=float, default=30.0, help="Request timeout")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "tea_conformance: TEA server conformance check")
