from datetime import datetime, timedelta, timezone

import pytest

from libtea.server import tea_datetime_serializer


class TestTeaDatetimeSerializer:
    def test_utc_datetime(self):
        dt = datetime(2024, 3, 20, 15, 30, 0, tzinfo=timezone.utc)
        assert tea_datetime_serializer(dt) == "2024-03-20T15:30:00Z"

    def test_strips_milliseconds(self):
        dt = datetime(2024, 3, 20, 15, 30, 0, 123456, tzinfo=timezone.utc)
        assert tea_datetime_serializer(dt) == "2024-03-20T15:30:00Z"

    def test_converts_non_utc_to_utc(self):
        est = timezone(timedelta(hours=-5))
        dt = datetime(2024, 3, 20, 10, 30, 0, tzinfo=est)
        # 10:30 EST = 15:30 UTC
        assert tea_datetime_serializer(dt) == "2024-03-20T15:30:00Z"

    def test_naive_datetime_raises(self):
        dt = datetime(2024, 3, 20, 15, 30, 0)
        with pytest.raises(ValueError, match="timezone-aware"):
            tea_datetime_serializer(dt)
