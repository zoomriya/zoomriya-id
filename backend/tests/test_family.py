"""Family accounts, managed by the admin (Settings -> Family)."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
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

    login = client.post(f"{API}/auth/login", json={"username": username, "password": "temporary1"})
    assert login.status_code == 200
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
    assert login.status_code == 200


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
