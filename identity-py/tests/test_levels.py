"""Child, teen or adult, from the account and the birth year."""

from zoomriya_identity import levels

YEAR = 2026


def test_an_adult_account_is_an_adult_whatever_the_year() -> None:
    assert levels.level(is_child=False, birth_year=None, year=YEAR) == levels.ADULT
    assert levels.level(is_child=False, birth_year=1980, year=YEAR) == levels.ADULT


def test_a_childs_level_comes_from_the_age_they_have_all_year() -> None:
    # Born 2013: 12 all of 2026 (13 only after their birthday), so a child.
    assert levels.level(is_child=True, birth_year=2013, year=YEAR) == levels.CHILD
    assert levels.level(is_child=True, birth_year=2012, year=YEAR) == levels.TEEN
    assert levels.level(is_child=True, birth_year=2008, year=YEAR) == levels.TEEN
    # 18 all of 2026: an adult from January.
    assert levels.level(is_child=True, birth_year=2007, year=YEAR) == levels.ADULT


def test_a_guardian_moves_a_child_one_level_but_never_to_adult() -> None:
    assert levels.level(is_child=True, birth_year=2014, move="teen", year=YEAR) == levels.TEEN
    assert levels.level(is_child=True, birth_year=2011, move="child", year=YEAR) == levels.CHILD
    # At 18 the move falls away.
    assert levels.level(is_child=True, birth_year=2007, move="child", year=YEAR) == levels.ADULT
    assert levels.move_allowed("teen", 2014, YEAR)
    assert levels.move_allowed("child", 2011, YEAR)
    assert not levels.move_allowed("teen", 2011, YEAR)  # already a teen
    assert not levels.move_allowed("adult", 2011, YEAR)
    assert not levels.move_allowed("child", 2007, YEAR)


def test_a_childs_account_without_a_birth_year_stays_a_child() -> None:
    assert levels.level(is_child=True, birth_year=None, year=YEAR) == levels.CHILD
