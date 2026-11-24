"""Child, teen or adult: the three levels every app answers for.

ZOOMRIYA ID passes each member's level in the family directory (``level``),
worked out here so no two apps count ages differently (Hub-Design.md §1.2).

* An account made as an adult is an adult.
* A child's account (the admin's choice, with a birth year) is a child under
  13 and a teen from 13 to 17. Only the year is known, so the age is the one
  they are sure to have all year (this year - birth year - 1), as Myira's
  kids mode counts it: they become an adult in the January after their 18th
  birthday, never early.
* A guardian may move a child one level within the under-18s: a ready
  12-year-old to teen early (``move="teen"``), or a 14-year-old kept a child
  longer (``move="child"``). Never to adult; a move that no longer applies
  falls away.
"""

from __future__ import annotations

from datetime import UTC, datetime

CHILD = "child"
TEEN = "teen"
ADULT = "adult"
LEVELS = (CHILD, TEEN, ADULT)

#: The moves a guardian may make (None: the birth year's level).
MOVES = (CHILD, TEEN)

TEEN_AGE = 13
ADULT_AGE = 18


def age_all_year(birth_year: int, year: int | None = None) -> int:
    """The age they are sure to have all year."""
    return max(0, (year or datetime.now(UTC).year) - birth_year - 1)


def level_by_age(birth_year: int, year: int | None = None) -> str:
    age = age_all_year(birth_year, year)
    if age >= ADULT_AGE:
        return ADULT
    return TEEN if age >= TEEN_AGE else CHILD


def level(
    *, is_child: bool, birth_year: int | None, move: str | None = None, year: int | None = None
) -> str:
    """The member's level now."""
    if not is_child:
        return ADULT
    if birth_year is None:
        # A child's account always has one; without it, the careful answer.
        return CHILD
    by_age = level_by_age(birth_year, year)
    if by_age == ADULT:
        return ADULT
    return move if move in MOVES else by_age


def move_allowed(move: str | None, birth_year: int, year: int | None = None) -> bool:
    """A guardian's move is one level from the birth year's, under 18."""
    by_age = level_by_age(birth_year, year)
    if move is None:
        return True
    return by_age != ADULT and move in MOVES and move != by_age
