import pytest

from libtea.conformance._types import CheckResult, CheckStatus, ConformanceResult


class TestCheckResult:
    def test_pass_result(self):
        r = CheckResult(name="test_check", status=CheckStatus.PASS, message="OK")
        assert r.name == "test_check"
        assert r.status == CheckStatus.PASS

    def test_frozen(self):
        r = CheckResult(name="test", status=CheckStatus.PASS)
        with pytest.raises(AttributeError):
            r.name = "changed"  # type: ignore[misc]


class TestConformanceResult:
    def test_counts(self):
        result = ConformanceResult(
            base_url="https://example.com",
            checks=[
                CheckResult(name="a", status=CheckStatus.PASS),
                CheckResult(name="b", status=CheckStatus.FAIL, message="bad"),
                CheckResult(name="c", status=CheckStatus.SKIP, message="no data"),
                CheckResult(name="d", status=CheckStatus.PASS),
            ],
        )
        assert result.passed == 2
        assert result.failed == 1
        assert result.skipped == 1

    def test_empty(self):
        result = ConformanceResult(base_url="https://example.com")
        assert result.passed == 0
        assert result.failed == 0
        assert result.skipped == 0
