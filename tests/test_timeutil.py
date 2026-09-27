"""时间段：跨午夜、含起点不含终点、夏令时切换、保存时校验。"""
from datetime import datetime, timezone

import pytest

from policy_engine.errors import ValidationError
from policy_engine.timeutil import local_time_in_range, validate_time_range

UTC = timezone.utc


def dt(s):
    return datetime.fromisoformat(s).replace(tzinfo=UTC)


def test_cross_midnight():
    # 22:00-06:00 跨午夜
    assert local_time_in_range(dt("2026-03-10T23:30:00"), "UTC", "22:00", "06:00")
    assert local_time_in_range(dt("2026-03-11T05:59:00"), "UTC", "22:00", "06:00")
    assert not local_time_in_range(dt("2026-03-10T12:00:00"), "UTC", "22:00", "06:00")


def test_start_inclusive_end_exclusive():
    assert local_time_in_range(dt("2026-03-10T22:00:00"), "UTC", "22:00", "06:00")
    assert not local_time_in_range(dt("2026-03-11T06:00:00"), "UTC", "22:00", "06:00")


def test_normal_range():
    assert local_time_in_range(dt("2026-03-10T09:00:00"), "UTC", "09:00", "18:00")
    assert not local_time_in_range(dt("2026-03-10T18:00:00"), "UTC", "09:00", "18:00")


def test_dst_fallback_repeated_hours_count():
    # America/New_York 2025-11-02 01:30 出现两次：UTC 05:30(EDT) 与 06:30(EST)
    tz = "America/New_York"
    assert local_time_in_range(dt("2025-11-02T05:30:00"), tz, "01:00", "02:00")
    assert local_time_in_range(dt("2025-11-02T06:30:00"), tz, "01:00", "02:00")
    assert not local_time_in_range(dt("2025-11-02T07:30:00"), tz, "01:00", "02:00")


def test_dst_spring_forward_skipped_hours_never_match():
    # America/New_York 2025-03-09 02:00-03:00 不存在：UTC 07:30 已是 03:30
    tz = "America/New_York"
    assert not local_time_in_range(dt("2025-03-09T07:30:00"), tz, "02:00", "03:00")
    assert local_time_in_range(dt("2025-03-09T06:30:00"), tz, "01:00", "02:00")


def test_validate_time_range_rejects_equal_endpoints():
    with pytest.raises(ValidationError):
        validate_time_range("08:00", "08:00")


@pytest.mark.parametrize("bad", ["25:00", "8:60", "ab:cd", "0800"])
def test_validate_time_range_rejects_bad_format(bad):
    with pytest.raises(ValidationError):
        validate_time_range(bad, "09:00")
