"""Quiet hours: a child's defaults, a guardian's own, across midnight."""

from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from zoomriya_identity import quiet_hours

TORONTO = ZoneInfo("America/Toronto")


def at(day: int, hour: int, minute: int = 0) -> datetime:
    # 26 October 2026 is a Monday.
    return datetime(2026, 10, day, hour, minute, tzinfo=TORONTO)


def test_a_childs_default_bedtime_runs_past_midnight() -> None:
    setting = {"bedtime": {"from": "20:30", "to": "07:00"}, "school": None, "tz": "America/Toronto"}
    assert quiet_hours.quiet_until(setting, "child", at(26, 21)) == "07:00"
    assert quiet_hours.quiet_until(setting, "child", at(27, 6, 59)) == "07:00"
    assert quiet_hours.quiet_until(setting, "child", at(27, 7)) is None


def test_school_hours_are_weekdays_only() -> None:
    setting = {"bedtime": None, "school": {"from": "08:30", "to": "15:00"}, "tz": "America/Toronto"}
    assert quiet_hours.quiet_until(setting, "child", at(26, 10)) == "15:00"
    # Saturday 31 October.
    assert quiet_hours.quiet_until(setting, "child", at(31, 10)) is None


def test_defaults_by_level_and_none_for_adults() -> None:
    assert quiet_hours.for_level(None, "child")["bedtime"] == {"from": "20:30", "to": "07:00"}
    assert quiet_hours.for_level(None, "teen") == quiet_hours.NONE
    chosen = {"bedtime": {"from": "22:00", "to": "06:30"}, "school": None}
    assert quiet_hours.for_level(chosen, "adult") == quiet_hours.NONE
    assert quiet_hours.quiet_until(chosen, "adult", at(26, 23)) is None


def test_checked_refuses_nonsense() -> None:
    with pytest.raises(ValueError):
        quiet_hours.checked({"bedtime": {"from": "25:00", "to": "07:00"}})
    with pytest.raises(ValueError):
        quiet_hours.checked({"school": {"from": "15:00", "to": "08:30"}})
    with pytest.raises(ValueError):
        quiet_hours.checked({"tz": "Mars/Base"})
    assert quiet_hours.checked({"bedtime": None, "school": None}) == quiet_hours.NONE
