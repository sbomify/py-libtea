"""Data types for conformance check results."""

from dataclasses import dataclass, field
from enum import StrEnum


class CheckStatus(StrEnum):
    """Status of a conformance check."""

    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"


@dataclass(frozen=True)
class CheckResult:
    """Result of a single conformance check."""

    name: str
    status: CheckStatus
    message: str = ""
    details: str = ""


@dataclass
class ConformanceResult:
    """Aggregated results from a full conformance run."""

    base_url: str
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.FAIL)

    @property
    def skipped(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.SKIP)
