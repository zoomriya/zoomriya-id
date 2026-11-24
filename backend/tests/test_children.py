"""Children's accounts, their guardians and their pages (Hub-Design.md §1)."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.db import SessionLocal
from app.main import app
from app.models import ROLE_FAMILY, User
from tests.helpers import API, auth_headers, build_user

client = TestClient(app)
YEAR = datetime.now(UTC).year
#: 9 all this year: a child.
CHILD_YEAR = YEAR - 10
#: 15 all this year: a teen.
TEEN_YEAR = YEAR - 16


@pytest.fixture
def family() -> Iterator[dict[str, Any]]:
    """An admin and two adult members. Users made through ``POST /users`` are
    recorded in ``created`` and removed too."""
    db = SessionLocal()
    users = [
        build_user(f"pytest-kids-{uuid.uuid4().hex[:8]}", role=role)
        for role in ("admin", ROLE_FAMILY, ROLE_FAMILY, ROLE_FAMILY)
    ]
    db.add_all(users)
    db.commit()
    created: list[str] = []
    try:
        yield {
            "db": db,
            "admin": users[0],
            "mum": users[1],
            "dad": users[2],
            "aunt": users[3],
            "created": created,
        }
    finally:
        db.rollback()
        db.execute(delete(User).where(User.username.in_(created)))
        db.execute(delete(User).where(User.id.in_([u.id for u in users])))
        db.commit()
        db.close()


def _make_child(family: dict[str, Any], guardians: list[User], **extra: Any) -> Any:
    username = f"pytest-kid-{uuid.uuid4().hex[:8]}"
    family["created"].append(username)
    return client.post(
        f"{API}/users",
        headers=auth_headers(family["admin"]),
        json={
            "username": username,
            "password": "temporary1",
            "kind": "child",
            "birth_year": CHILD_YEAR,
            "guardian_ids": [g.id for g in guardians],
        }
        | extra,
    )


def test_a_child_needs_a_birth_year_under_18_and_one_or_two_guardians(
    family: dict[str, Any],
) -> None:
    mum, dad, aunt = family["mum"], family["dad"], family["aunt"]
    assert _make_child(family, []).status_code == 400
    assert _make_child(family, [mum, dad, aunt]).status_code == 400
    assert _make_child(family, [mum], birth_year=None).status_code == 400
    assert _make_child(family, [mum], birth_year=YEAR - 30).status_code == 400

    made = _make_child(family, [mum, dad])
    assert made.status_code == 201
    body = made.json()
    assert (body["kind"], body["level"], body["needs_guardian"]) == ("child", "child", False)
    assert [g["id"] for g in body["guardians"]] == [mum.id, dad.id]

    # A child can't be another child's guardian.
    assert _make_child(family, [family["db"].get(User, body["id"])]).status_code == 400


def test_an_adult_account_cant_have_a_birth_year_under_18(family: dict[str, Any]) -> None:
    username = f"pytest-kid-{uuid.uuid4().hex[:8]}"
    family["created"].append(username)
    made = client.post(
        f"{API}/users",
        headers=auth_headers(family["admin"]),
        json={"username": username, "password": "temporary1", "birth_year": TEEN_YEAR},
    )
    assert made.status_code == 400


def test_the_directory_carries_the_level_and_the_guardians(family: dict[str, Any]) -> None:
    child = _make_child(family, [family["mum"]], birth_year=TEEN_YEAR).json()
    directory = client.get(f"{API}/users/directory", headers=auth_headers(family["dad"])).json()
    row = next(r for r in directory if r["id"] == child["id"])
    assert (row["level"], row["guardian_ids"]) == ("teen", [family["mum"].id])
    adult = next(r for r in directory if r["id"] == family["dad"].id)
    assert (adult["level"], adult["guardian_ids"]) == ("adult", [])


def test_only_guardians_see_the_childs_page_not_the_admin(family: dict[str, Any]) -> None:
    child = _make_child(family, [family["mum"]]).json()

    mine = client.get(f"{API}/users/children", headers=auth_headers(family["mum"])).json()
    assert [c["id"] for c in mine] == [child["id"]]
    me = client.get(f"{API}/auth/me", headers=auth_headers(family["mum"])).json()
    assert [c["id"] for c in me["children"]] == [child["id"]]
    assert me["level"] == "adult"

    page = client.get(f"{API}/users/children/{child['id']}", headers=auth_headers(family["mum"]))
    assert page.status_code == 200
    assert page.json()["level_by_age"] == "child"

    for outsider in (family["admin"], family["dad"]):
        seen = client.get(f"{API}/users/children/{child['id']}", headers=auth_headers(outsider))
        assert seen.status_code == 404
        assert client.get(f"{API}/users/children", headers=auth_headers(outsider)).json() == []


def test_a_guardian_moves_a_child_one_level_and_switches_apps(family: dict[str, Any]) -> None:
    child = _make_child(family, [family["mum"]]).json()
    headers = auth_headers(family["mum"])
    url = f"{API}/users/children/{child['id']}"

    moved = client.patch(url, headers=headers, json={"level_move": "teen"})
    assert (moved.status_code, moved.json()["level"]) == (200, "teen")
    # A child (by age) can't be moved to "child", nor anyone to adult.
    assert client.patch(url, headers=headers, json={"level_move": "child"}).status_code == 400
    assert client.patch(url, headers=headers, json={"level_move": "adult"}).status_code == 422
    back = client.patch(url, headers=headers, json={"level_move": None})
    assert back.json()["level"] == "child"

    apps = back.json()["app_access"]
    if apps:
        app_id = apps[0]["app"]
        off = client.put(f"{url}/apps", headers=headers, json={"app": app_id, "enabled": False})
        assert off.status_code == 200
        assert {a["app"]: a["enabled"] for a in off.json()["app_access"]}[app_id] is False

    other = client.patch(url, headers=auth_headers(family["dad"]), json={"level_move": "teen"})
    assert other.status_code == 404


def test_a_guardian_turned_off_leaves_the_child_needing_one(family: dict[str, Any]) -> None:
    child = _make_child(family, [family["mum"]]).json()
    admin = auth_headers(family["admin"])
    client.patch(f"{API}/users/{family['mum'].id}", headers=admin, json={"is_active": False})

    listed = client.get(f"{API}/users", headers=admin).json()
    row = next(u for u in listed if u["id"] == child["id"])
    assert row["needs_guardian"] is True

    fixed = client.patch(
        f"{API}/users/{child['id']}", headers=admin, json={"guardian_ids": [family["dad"].id]}
    )
    assert fixed.status_code == 200
    assert fixed.json()["needs_guardian"] is False
    assert [g["id"] for g in fixed.json()["guardians"]] == [family["dad"].id]


def test_a_guardian_cant_become_a_child_and_a_child_can_become_an_adult(
    family: dict[str, Any],
) -> None:
    child = _make_child(family, [family["mum"]]).json()
    admin = auth_headers(family["admin"])

    mum_to_child = client.patch(
        f"{API}/users/{family['mum'].id}",
        headers=admin,
        json={"kind": "child", "birth_year": CHILD_YEAR, "guardian_ids": [family["dad"].id]},
    )
    assert mum_to_child.status_code == 400

    grown = client.patch(
        f"{API}/users/{child['id']}", headers=admin, json={"kind": "adult", "birth_year": None}
    )
    assert grown.status_code == 200
    assert (grown.json()["level"], grown.json()["guardians"]) == ("adult", [])
    assert client.get(f"{API}/users/children", headers=auth_headers(family["mum"])).json() == []


def test_quiet_hours_default_by_level_and_a_guardians_own(family: dict[str, Any]) -> None:
    child = _make_child(family, [family["mum"], family["dad"]]).json()
    url = f"{API}/users/children/{child['id']}"
    page = client.get(url, headers=auth_headers(family["mum"])).json()
    assert page["quiet_hours"]["bedtime"] == {"from": "20:30", "to": "07:00"}
    assert page["quiet_hours_chosen"] is False

    chosen = {"bedtime": {"from": "21:00", "to": "07:00"}, "school": None, "tz": "America/Toronto"}
    changed = client.patch(url, headers=auth_headers(family["mum"]), json={"quiet_hours": chosen})
    assert changed.status_code == 200
    assert changed.json()["quiet_hours"] == chosen
    wrong = {"bedtime": {"from": "9pm", "to": "7am"}}
    assert (
        client.patch(
            url, headers=auth_headers(family["mum"]), json={"quiet_hours": wrong}
        ).status_code
        == 400
    )

    directory = client.get(f"{API}/users/directory", headers=auth_headers(family["dad"])).json()
    assert next(r for r in directory if r["id"] == child["id"])["quiet_hours"] == chosen


def test_changes_are_logged_and_the_other_guardian_sees_a_dot(family: dict[str, Any]) -> None:
    child = _make_child(family, [family["mum"], family["dad"]]).json()
    url = f"{API}/users/children/{child['id']}"
    mum, dad = auth_headers(family["mum"]), auth_headers(family["dad"])

    client.patch(url, headers=mum, json={"level_move": "teen"})
    client.post(f"{url}/changes", headers=mum, json={"what": "Myira: Stories off"})

    page = client.get(url, headers=dad).json()
    assert [c["what"] for c in page["changes"]][:2] == ["Myira: Stories off", "Level: teen (moved)"]
    assert page["changes"][0]["by"] == family["mum"].shown_name

    dads = client.get(f"{API}/users/children", headers=dad).json()
    assert dads[0]["unseen"] == 2
    # Mum made them: no dot for her.
    assert client.get(f"{API}/users/children", headers=mum).json()[0]["unseen"] == 0
    assert client.post(f"{url}/seen", headers=dad).status_code == 204
    assert client.get(f"{API}/users/children", headers=dad).json()[0]["unseen"] == 0

    # Someone who isn't a guardian can't write the log.
    outsider = client.post(
        f"{url}/changes", headers=auth_headers(family["aunt"]), json={"what": "x"}
    )
    assert outsider.status_code == 404


def test_the_child_is_told_who_their_guardians_are_and_what_changed(
    family: dict[str, Any],
) -> None:
    made = _make_child(family, [family["mum"]])
    child = family["db"].get(User, made.json()["id"])
    client.post(
        f"{API}/users/children/{child.id}/changes",
        headers=auth_headers(family["mum"]),
        json={"what": "Myira: Stories off"},
    )
    me = client.get(f"{API}/auth/me", headers=auth_headers(child)).json()
    assert me["level"] == "child"
    assert me["guardians"] == [family["mum"].shown_name]
    assert me["guardian_changes"][0]["what"] == "Myira: Stories off"
    adult = client.get(f"{API}/auth/me", headers=auth_headers(family["mum"])).json()
    assert "guardian_changes" not in adult


def test_a_parent_sets_where_a_child_lives_and_the_child_cant(family: dict[str, Any]) -> None:
    child = _make_child(family, [family["mum"]]).json()
    url = f"{API}/users/children/{child['id']}"
    assert client.get(url, headers=auth_headers(family["mum"])).json()["place"]["own"] is False

    changed = client.patch(url, headers=auth_headers(family["mum"]), json={"place": "CA-BC"})
    assert changed.status_code == 200
    assert changed.json()["place"]["name"] == "British Columbia"
    assert "Where they live: British Columbia" in [c["what"] for c in changed.json()["changes"]]
    assert (
        client.patch(url, headers=auth_headers(family["mum"]), json={"place": "XX"}).status_code
        == 400
    )

    # The child doesn't set it themselves; a teen does.
    kid = family["db"].get(User, child["id"])
    refused = client.put(f"{API}/auth/me/place", headers=auth_headers(kid), json={"place": "CA-AB"})
    assert refused.status_code == 403
    teen = _make_child(family, [family["mum"]], birth_year=TEEN_YEAR).json()
    teen_user = family["db"].get(User, teen["id"])
    ok = client.put(
        f"{API}/auth/me/place", headers=auth_headers(teen_user), json={"place": "CA-AB"}
    )
    assert ok.status_code == 200
