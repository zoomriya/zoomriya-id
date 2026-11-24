"""Quiet hours: when a child's apps go quiet (Hub-Design.md §1.3, decision H7).

Box-wide, per child, kept by ZOOMRIYA ID and passed in the family directory
(``quiet_hours``), so every app reads the same times. Each app decides what
quiet means for it; emergencies and "being hurt" are always answered.

The setting is a dict, or None for the level's default:

    {"bedtime": {"from": "20:30", "to": "07:00"} | None,
     "school": {"from": "08:30", "to": "15:00"} | None,
     "tz": "America/Toronto"}

Bedtime is every night (it may run past midnight); school is Monday to
Friday. ``tz`` is the guardian's browser's when they saved it; without one
the box's own clock is used. Children get both by default, teens neither.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime, time
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from zoomriya_identity import levels

DEFAULT_CHILD: dict[str, Any] = {
    "bedtime": {"from": "20:30", "to": "07:00"},
    "school": {"from": "08:30", "to": "15:00"},
}
NONE: dict[str, Any] = {"bedtime": None, "school": None}

_HHMM = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


def for_level(setting: Mapping[str, Any] | None, level: str) -> dict[str, Any]:
    """The quiet hours that apply: the guardians' own, else the level's
    default. An adult has none."""
    if level == levels.ADULT:
        return dict(NONE)
    if setting is None:
        return dict(DEFAULT_CHILD if level == levels.CHILD else NONE)
    return {
        "bedtime": setting.get("bedtime"),
        "school": setting.get("school"),
        **({"tz": setting["tz"]} if setting.get("tz") else {}),
    }


def checked(setting: Mapping[str, Any]) -> dict[str, Any]:
    """A guardian's setting, cleaned; ``ValueError`` when it doesn't make sense."""
    cleaned: dict[str, Any] = {}
    for name in ("bedtime", "school"):
        window = setting.get(name)
        if window is None:
            cleaned[name] = None
            continue
        start, end = str(window.get("from", "")), str(window.get("to", ""))
        if not _HHMM.match(start) or not _HHMM.match(end) or start == end:
            raise ValueError("Times are hours and minutes, like 20:30, and differ")
        if name == "school" and start > end:
            raise ValueError("School hours end after they start")
        cleaned[name] = {"from": start, "to": end}
    tz = setting.get("tz")
    if tz:
        try:
            ZoneInfo(str(tz))
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("Unknown time zone") from None
        cleaned["tz"] = str(tz)
    return cleaned


def _at(text: str) -> time:
    hours, minutes = text.split(":")
    return time(int(hours), int(minutes))


def _local(now: datetime | None, tz: str | None) -> datetime:
    moment = now or datetime.now().astimezone()
    if tz:
        try:
            return moment.astimezone(ZoneInfo(tz))
        except (ZoneInfoNotFoundError, ValueError):
            pass
    return moment.astimezone()


def quiet_until(
    setting: Mapping[str, Any] | None, level: str, now: datetime | None = None
) -> str | None:
    """"07:00" while it's quiet (when it ends), None otherwise."""
    applying = for_level(setting, level)
    local = _local(now, applying.get("tz"))
    clock = local.time().replace(second=0, microsecond=0)
    bedtime = applying.get("bedtime")
    if bedtime:
        start, end = _at(bedtime["from"]), _at(bedtime["to"])
        inside = start <= clock < end if start < end else (clock >= start or clock < end)
        if inside:
            return bedtime["to"]
    school = applying.get("school")
    if school and local.weekday() < 5:
        if _at(school["from"]) <= clock < _at(school["to"]):
            return school["to"]
    return None
