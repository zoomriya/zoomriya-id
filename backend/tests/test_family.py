"""Family accounts, managed by the admin (Settings -> Family)."""

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
from tests.helpers import API, TEST_PASSWORD, auth_headers, build_user

client = TestClient(app)


@pytest.fixture
def family() -> Iterator[dict[str, Any]]:
    """An admin and a family member. Users created through ``POST /users``
    during a test are recorded in ``created_usernames`` and removed too."""
    db = SessionLocal()
    users = [
        build_user(f"pytest-family-{uuid.uuid4().hex[:8]}", role=role)
        for role in ("admin", ROLE_FAMILY)
    ]
    db.add_all(users)
    db.commit()
    created_usernames: list[str] = []
    try:
        yield {
            "db": db,
            "admin": users[0],
            "member": users[1],
            "created_usernames": created_usernames,
        }
    finally:
        db.rollback()
        db.execute(delete(User).where(User.id.in_([u.id for u in users])))
        if created_usernames:
            db.execute(delete(User).where(User.username.in_(created_usernames)))
        db.commit()
        db.close()


# --- /users (admin only) ------------------------------------------------------


def test_admin_creates_a_family_member_who_can_sign_in(family: dict[str, Any]) -> None:
    username = f"pytest-family-new-{uuid.uuid4().hex[:8]}"
    family["created_usernames"].append(username)

    created = client.post(
        f"{API}/users",
        headers=auth_headers(family["admin"]),
        json={"username": username, "display_name": "Amma", "password": "temporary1"},
    )
    assert created.status_code == 201
    body = created.json()
    assert body["role"] == ROLE_FAMILY
    assert body["display_name"] == "Amma"
    assert body["password_temporary"] is True

    # The admin's password is temporary: no token until they choose their own.
    first = client.post(f"{API}/auth/login", json={"username": username, "password": "temporary1"})
    assert first.status_code == 403
    assert first.json()["code"] == "new_password_needed"
    login = client.post(
        f"{API}/auth/login/new-password",
        json={"username": username, "password": "temporary1", "new_password": "my-own-one"},
    )
    assert login.status_code == 200
    again = client.post(f"{API}/auth/login", json={"username": username, "password": "my-own-one"})
    assert again.status_code == 200
    me = client.get(
        f"{API}/auth/me", headers={"Authorization": f"Bearer {login.json()['access_token']}"}
    )
    assert me.json()["display_name"] == "Amma"
    assert me.json()["role"] == ROLE_FAMILY

    listed = client.get(f"{API}/users", headers=auth_headers(family["admin"]))
    assert username in {user["username"] for user in listed.json()}


def test_admin_sets_a_childs_birth_year_and_the_apps_see_it(family: dict[str, Any]) -> None:
    """Myira's kids mode comes from it, through the directory."""
    username = f"pytest-family-kid-{uuid.uuid4().hex[:8]}"
    family["created_usernames"].append(username)
    headers = auth_headers(family["admin"])

    created = client.post(
        f"{API}/users",
        headers=headers,
        json={
            "username": username,
            "password": "temporary1",
            "birth_year": 2017,
            "kind": "child",
            "guardian_ids": [family["admin"].id],
        },
    )
    assert created.status_code == 201
    assert created.json()["birth_year"] == 2017

    directory = client.get(f"{API}/users/directory", headers=auth_headers(family["member"]))
    row = next(row for row in directory.json() if row["username"] == username)
    assert row["birth_year"] == 2017

    changed = client.patch(
        f"{API}/users/{created.json()['id']}", headers=headers, json={"birth_year": 2016}
    )
    assert changed.json()["birth_year"] == 2016

    for year in (1850, 3000, None):
        wrong = client.patch(
            f"{API}/users/{created.json()['id']}", headers=headers, json={"birth_year": year}
        )
        assert wrong.status_code == 400


def test_usernames_are_unique_and_passwords_have_a_minimum(family: dict[str, Any]) -> None:
    headers = auth_headers(family["admin"])
    taken = client.post(
        f"{API}/users",
        headers=headers,
        json={"username": family["member"].username.upper(), "password": "temporary1"},
    )
    assert taken.status_code == 409

    short = client.post(
        f"{API}/users", headers=headers, json={"username": "pytest-family-x", "password": "short"}
    )
    assert short.status_code == 422


def test_family_members_cannot_manage_users(family: dict[str, Any]) -> None:
    headers = auth_headers(family["member"])
    assert client.get(f"{API}/users", headers=headers).status_code == 403
    assert (
        client.post(
            f"{API}/users",
            headers=headers,
            json={"username": "pytest-nope", "password": "temporary1"},
        ).status_code
        == 403
    )


def test_resetting_a_password_signs_the_member_out(family: dict[str, Any]) -> None:
    member = family["member"]
    old_headers = auth_headers(member)
    assert client.get(f"{API}/auth/me", headers=old_headers).status_code == 200

    reset = client.patch(
        f"{API}/users/{member.id}",
        headers=auth_headers(family["admin"]),
        json={"password": "brand-new-pass"},
    )
    assert reset.status_code == 200
    assert client.get(f"{API}/auth/me", headers=old_headers).status_code == 401
    login = client.post(
        f"{API}/auth/login", json={"username": member.username, "password": "brand-new-pass"}
    )
    assert login.status_code == 403


def test_a_password_the_person_typed_at_the_box_is_theirs(family: dict[str, Any]) -> None:
    """Box Desktop: the person types it themselves, so it isn't temporary."""
    admin_headers = auth_headers(family["admin"])
    username = f"pytest-family-box-{uuid.uuid4().hex[:8]}"
    family["created_usernames"].append(username)
    created = client.post(
        f"{API}/users",
        headers=admin_headers,
        json={"username": username, "password": "typed-by-me", "temporary": False},
    )
    assert created.json()["password_temporary"] is False
    login = client.post(f"{API}/auth/login", json={"username": username, "password": "typed-by-me"})
    assert login.status_code == 200

    member = family["member"]
    client.patch(
        f"{API}/users/{member.id}",
        headers=admin_headers,
        json={"password": "typed-again", "temporary": False},
    )
    login = client.post(
        f"{API}/auth/login", json={"username": member.username, "password": "typed-again"}
    )
    assert login.status_code == 200


def test_choosing_your_own_password_is_checked(family: dict[str, Any]) -> None:
    member = family["member"]
    client.patch(
        f"{API}/users/{member.id}",
        headers=auth_headers(family["admin"]),
        json={"password": "temporary2"},
    )

    def new_password(password: str, new: str) -> int:
        return client.post(
            f"{API}/auth/login/new-password",
            json={"username": member.username, "password": password, "new_password": new},
        ).status_code

    assert new_password("not-the-one", "my-own-one") == 401
    assert new_password("temporary2", "temporary2") == 400
    assert new_password("temporary2", "short") == 422
    assert new_password("temporary2", "my-own-one") == 200
    # Done once: their password is theirs now.
    assert new_password("my-own-one", "another-one") == 400


def test_deactivating_blocks_sign_in_and_admin_cannot_deactivate_self(
    family: dict[str, Any],
) -> None:
    admin_headers = auth_headers(family["admin"])
    member = family["member"]

    off = client.patch(f"{API}/users/{member.id}", headers=admin_headers, json={"is_active": False})
    assert off.status_code == 200
    assert off.json()["is_active"] is False
    login = client.post(
        f"{API}/auth/login", json={"username": member.username, "password": TEST_PASSWORD}
    )
    assert login.status_code == 401

    self_off = client.patch(
        f"{API}/users/{family['admin'].id}", headers=admin_headers, json={"is_active": False}
    )
    assert self_off.status_code == 400


def test_admin_makes_a_member_admin_and_takes_it_away(family: dict[str, Any]) -> None:
    admin_headers = auth_headers(family["admin"])
    member = family["member"]
    old_headers = auth_headers(member)

    made = client.patch(f"{API}/users/{member.id}", headers=admin_headers, json={"role": "admin"})
    assert made.status_code == 200
    assert made.json()["role"] == "admin"
    # Their old token carries the old role: it no longer works.
    assert client.get(f"{API}/auth/me", headers=old_headers).status_code == 401
    family["db"].refresh(member)
    assert client.get(f"{API}/users", headers=auth_headers(member)).status_code == 200

    taken = client.patch(f"{API}/users/{member.id}", headers=admin_headers, json={"role": "family"})
    assert taken.status_code == 200
    assert taken.json()["role"] == ROLE_FAMILY
    family["db"].refresh(member)
    assert client.get(f"{API}/users", headers=auth_headers(member)).status_code == 403


def test_an_admin_cannot_remove_their_own_admin_role(family: dict[str, Any]) -> None:
    admin = family["admin"]
    refused = client.patch(
        f"{API}/users/{admin.id}", headers=auth_headers(admin), json={"role": "family"}
    )
    assert refused.status_code == 400
    family["db"].refresh(admin)
    assert admin.role == "admin"


def test_a_turned_off_account_is_turned_on_before_becoming_admin(
    family: dict[str, Any],
) -> None:
    admin_headers = auth_headers(family["admin"])
    member = family["member"]
    client.patch(f"{API}/users/{member.id}", headers=admin_headers, json={"is_active": False})
    refused = client.patch(
        f"{API}/users/{member.id}", headers=admin_headers, json={"role": "admin"}
    )
    assert refused.status_code == 400


def test_a_child_is_never_an_admin(family: dict[str, Any]) -> None:
    admin_headers = auth_headers(family["admin"])
    username = f"pytest-family-child-{uuid.uuid4().hex[:8]}"
    family["created_usernames"].append(username)
    child = client.post(
        f"{API}/users",
        headers=admin_headers,
        json={
            "username": username,
            "password": "temporary1",
            "kind": "child",
            "birth_year": datetime.now(UTC).year - 8,
            "guardian_ids": [family["admin"].id],
        },
    ).json()
    refused = client.patch(
        f"{API}/users/{child['id']}", headers=admin_headers, json={"role": "admin"}
    )
    assert refused.status_code == 400

    member = family["member"]
    client.patch(f"{API}/users/{member.id}", headers=admin_headers, json={"role": "admin"})
    as_child = client.patch(
        f"{API}/users/{member.id}",
        headers=admin_headers,
        json={
            "kind": "child",
            "birth_year": datetime.now(UTC).year - 10,
            "guardian_ids": [family["admin"].id],
        },
    )
    assert as_child.status_code == 400
