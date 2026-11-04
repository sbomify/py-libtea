"""TEA server conformance test suite.

Usage (programmatic)::

    from libtea.conformance import run_conformance
    result = run_conformance(
        base_url="https://tea.example.com/v1",
        tei="tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1",
    )
    print(f"{result.passed} passed, {result.failed} failed, {result.warned} warned, {result.skipped} skipped")

Usage (CLI)::

    tea-cli conformance --base-url https://tea.example.com/v1 \\
        --tei "tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1"

Usage (pytest plugin)::

    pytest --tea-base-url https://tea.example.com/v1 \\
        --tea-tei "tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libtea.conformance._runner import run_conformance as run_conformance
    from libtea.conformance._types import CheckResult as CheckResult
    from libtea.conformance._types import CheckStatus as CheckStatus
    from libtea.conformance._types import ConformanceResult as ConformanceResult

__all__ = ["CheckResult", "CheckStatus", "ConformanceResult", "run_conformance"]

_LAZY_IMPORTS = {
    "run_conformance": "libtea.conformance._runner",
    "CheckResult": "libtea.conformance._types",
    "CheckStatus": "libtea.conformance._types",
    "ConformanceResult": "libtea.conformance._types",
}


def __getattr__(name: str) -> object:
    if name in _LAZY_IMPORTS:
        import importlib

        module = importlib.import_module(_LAZY_IMPORTS[name])
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
