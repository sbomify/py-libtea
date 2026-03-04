"""TEA server conformance test suite.

Usage (programmatic)::

    from libtea.conformance import run_conformance
    result = run_conformance(base_url="https://tea.example.com/v1", tei="urn:tei:...")
    print(f"{result.passed} passed, {result.failed} failed, {result.skipped} skipped")

Usage (CLI)::

    tea-cli conformance --base-url https://tea.example.com/v1 --tei "urn:tei:..."

Usage (pytest plugin)::

    pytest --tea-base-url https://tea.example.com/v1 --tea-tei "urn:tei:..."
"""

from libtea.conformance._types import CheckResult, CheckStatus, ConformanceResult

__all__ = ["CheckResult", "CheckStatus", "ConformanceResult", "run_conformance"]
