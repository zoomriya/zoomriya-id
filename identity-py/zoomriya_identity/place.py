"""Where the family lives: the box's country, then its province or state.

One box-wide setting, the admin's, chosen in Family Hub's System Settings and
kept by the box service (platform/zoomriya-box) in a small file every app may
read (``/var/lib/zoomriya-box/place.json``, 0644). Apps read it with
:func:`family_place`: the emergency number, who to call, units, holidays and
time zones are the household's, not one app's.

Not chosen yet: ``ZOOMRIYA_COUNTRY`` and ``ZOOMRIYA_REGION`` when set (tests,
development), else Canada, Ontario. Canada and the US for now (the first
markets); every province and territory, every state and DC.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

#: Where the box service keeps the admin's choice.
PLACE_FILE = Path("/var/lib/zoomriya-box/place.json")

COUNTRIES: dict[str, str] = {"CA": "Canada", "US": "United States"}

#: ISO 3166-2 codes (without the country), in English.
REGIONS: dict[str, dict[str, str]] = {
    "CA": {
        "AB": "Alberta",
        "BC": "British Columbia",
        "MB": "Manitoba",
        "NB": "New Brunswick",
        "NL": "Newfoundland and Labrador",
        "NS": "Nova Scotia",
        "NT": "Northwest Territories",
        "NU": "Nunavut",
        "ON": "Ontario",
        "PE": "Prince Edward Island",
        "QC": "Quebec",
        "SK": "Saskatchewan",
        "YT": "Yukon",
    },
    "US": {
        "AL": "Alabama",
        "AK": "Alaska",
        "AZ": "Arizona",
        "AR": "Arkansas",
        "CA": "California",
        "CO": "Colorado",
        "CT": "Connecticut",
        "DE": "Delaware",
        "DC": "District of Columbia",
        "FL": "Florida",
        "GA": "Georgia",
        "HI": "Hawaii",
        "ID": "Idaho",
        "IL": "Illinois",
        "IN": "Indiana",
        "IA": "Iowa",
        "KS": "Kansas",
        "KY": "Kentucky",
        "LA": "Louisiana",
        "ME": "Maine",
        "MD": "Maryland",
        "MA": "Massachusetts",
        "MI": "Michigan",
        "MN": "Minnesota",
        "MS": "Mississippi",
        "MO": "Missouri",
        "MT": "Montana",
        "NE": "Nebraska",
        "NV": "Nevada",
        "NH": "New Hampshire",
        "NJ": "New Jersey",
        "NM": "New Mexico",
        "NY": "New York",
        "NC": "North Carolina",
        "ND": "North Dakota",
        "OH": "Ohio",
        "OK": "Oklahoma",
        "OR": "Oregon",
        "PA": "Pennsylvania",
        "RI": "Rhode Island",
        "SC": "South Carolina",
        "SD": "South Dakota",
        "TN": "Tennessee",
        "TX": "Texas",
        "UT": "Utah",
        "VT": "Vermont",
        "VA": "Virginia",
        "WA": "Washington",
        "WV": "West Virginia",
        "WI": "Wisconsin",
        "WY": "Wyoming",
    },
}

DEFAULT_COUNTRY = "CA"
DEFAULT_REGION = "ON"


@dataclass(frozen=True)
class FamilyPlace:
    country: str
    region: str
    #: The admin chose it (False: the environment's, or the default).
    chosen: bool = False


def is_known(country: str, region: str) -> bool:
    return region in REGIONS.get(country, {})


def place_file() -> Path:
    return Path(os.getenv("ZOOMRIYA_PLACE_FILE", "") or PLACE_FILE)


_cache: tuple[Path, int, FamilyPlace | None] | None = None


def chosen_place(path: Path) -> FamilyPlace | None:
    """The admin's choice, read again only when the file changes."""
    global _cache
    try:
        stamp = path.stat().st_mtime_ns
    except OSError:
        return None
    if _cache is not None and _cache[0] == path and _cache[1] == stamp:
        return _cache[2]
    found = None
    try:
        saved = json.loads(path.read_text())
        country = str(saved.get("country", "")).upper()
        region = str(saved.get("region", "")).upper()
        if is_known(country, region):
            found = FamilyPlace(country, region, chosen=True)
    except (OSError, ValueError, AttributeError):
        pass
    _cache = (path, stamp, found)
    return found


def family_place() -> FamilyPlace:
    """Where the family lives: the admin's choice, else the environment's,
    else Canada, Ontario. Cheap enough to call for every request."""
    chosen = chosen_place(place_file())
    if chosen is not None:
        return chosen
    country = os.getenv("ZOOMRIYA_COUNTRY", "").upper()
    region = os.getenv("ZOOMRIYA_REGION", "").upper()
    if is_known(country, region):
        return FamilyPlace(country, region)
    return FamilyPlace(DEFAULT_COUNTRY, DEFAULT_REGION)


# --- a member's own place ------------------------------------------------------
#
# Each account may have its own place (ZOOMRIYA ID's ``place``, e.g. "CA-AB":
# a child at university in Alberta), set by the member, or a parent for a
# child. None: the family's. It reaches the apps with the member directory
# (the ``place`` field), so they never ask for it.


def code_of(country: str, region: str) -> str:
    """The code a member's place is kept and sent as ("CA-AB")."""
    return f"{country}-{region}"


def parse_code(code: object) -> FamilyPlace | None:
    """A member's own place from its code; None when empty or unknown."""
    if not isinstance(code, str):
        return None
    country, _, region = code.strip().upper().partition("-")
    return FamilyPlace(country, region, chosen=True) if is_known(country, region) else None


def member_place(own: object) -> FamilyPlace:
    """Where this member lives: their own place, else the family's."""
    return parse_code(own) or family_place()


def region_name(country: str, region: str) -> str:
    return REGIONS.get(country, {}).get(region, region)
