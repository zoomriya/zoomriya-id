"""Where the family lives: the admin's choice, else the environment's, else Ontario."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from zoomriya_identity.place import FamilyPlace, family_place


@pytest.fixture
def chosen(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "place.json"
    monkeypatch.setenv("ZOOMRIYA_PLACE_FILE", str(path))
    monkeypatch.delenv("ZOOMRIYA_COUNTRY", raising=False)
    monkeypatch.delenv("ZOOMRIYA_REGION", raising=False)
    return path


def test_not_chosen_it_is_ontario(chosen: Path) -> None:
    assert family_place() == FamilyPlace("CA", "ON")


def test_the_environment_until_the_admin_chooses(
    chosen: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ZOOMRIYA_COUNTRY", "ca")
    monkeypatch.setenv("ZOOMRIYA_REGION", "qc")
    assert family_place() == FamilyPlace("CA", "QC")

    chosen.write_text(json.dumps({"country": "US", "region": "WA"}))
    assert family_place() == FamilyPlace("US", "WA", chosen=True)


def test_a_change_is_read_on_the_next_call(chosen: Path) -> None:
    chosen.write_text(json.dumps({"country": "CA", "region": "BC"}))
    assert family_place().region == "BC"
    chosen.write_text(json.dumps({"country": "US", "region": "TX"}))
    os.utime(chosen, ns=(1, 1))
    assert family_place() == FamilyPlace("US", "TX", chosen=True)


@pytest.mark.parametrize("saved", ["not json", "[]", '{"country": "CA", "region": "NY"}'])
def test_an_unreadable_or_unknown_choice_is_ontario(chosen: Path, saved: str) -> None:
    chosen.write_text(saved)
    assert family_place() == FamilyPlace("CA", "ON")
