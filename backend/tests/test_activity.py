"""The family's activity, for admins (decision 28): what ZOOMRIYA ID writes
down itself, what apps report, and who may read it."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import closing

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.db import SessionLocal
from app.main import app
from app.models import Activity, User
from tests.helpers import API, TEST_PASSWORD, auth_headers, build_user


@pytest.fixture
def make_user() -> Iterator:
    created: list[int] = []

    def _make(*, role: str = "family") -> User:
        with SessionLocal() as db:
            user = build_user(f"pytest-act-{uuid.uuid4().hex[:12]}", role=role)
            db.add(user)
            db.commit()
            db.refresh(user)
            created.append(int(user.id))
            db.expunge(user)
            return user

    yield _make
    with SessionLocal() as db:
        db.execute(delete(Activity).where(Activity.member_id.in_(created)))
        db.execute(delete(User).where(User.id.in_(created)))
        db.commit()


def _lines(client: TestClient, admin: User, **query: object) -> list[dict]:
    answer = client.get(f"{API}/users/activity", params=query, headers=auth_headers(admin))
    assert answer.status_code == 200, answer.text
    return answer.json()["activity"]


def test_sign_ins_and_wrong_passwords_are_written_down(make_user) -> None:
    admin, member = make_user(role="admin"), make_user()
    with closing(TestClient(app)) as client:
        login = {"username": member.username, "password": TEST_PASSWORD}
        assert client.post(f"{API}/auth/login", json=login).status_code == 200
        wrong = {"username": member.username, "password": "not it at all"}
        assert client.post(f"{API}/auth/login", json=wrong).status_code == 401
        # A name that isn't a member's is never written down.
        nobody = {"username": "nobody-" + uuid.uuid4().hex, "password": "x"}
        assert client.post(f"{API}/auth/login", json=nobody).status_code == 401
        mine = _lines(client, admin, member=member.id)
        everyone = _lines(client, admin)
    assert [(line["kind"], line["what"]) for line in mine] == [
        ("sign-in-failed", "Wrong password"),
        ("sign-in", "Signed in"),
    ]
    assert mine[0]["member"] == member.username and mine[0]["source"] == "ZOOMRIYA ID"
    assert all(nobody["username"] not in line["what"] for line in everyone)


def test_account_changes_name_the_admin(make_user) -> None:
    admin, member = make_user(role="admin"), make_user()
    with closing(TestClient(app)) as client:
        headers = auth_headers(admin)
        client.patch(f"{API}/users/{member.id}", json={"role": "admin"}, headers=headers)
        client.patch(
            f"{API}/users/{member.id}",
            json={"password": "a temporary one", "temporary": True},
            headers=headers,
        )
        lines = _lines(client, admin, member=member.id)
    whats = [(line["kind"], line["what"], line["by"]) for line in lines]
    assert ("account", "Made an admin", admin.username) in whats
    assert ("password", "Password reset by an admin", admin.username) in whats


def test_apps_report_devices_and_share_links_only(make_user) -> None:
    admin, member = make_user(role="admin"), make_user()
    with closing(TestClient(app)) as client:
        headers = auth_headers(member)
        made = client.post(
            f"{API}/auth/me/activity",
            json={"kind": "share-link", "what": "Shared the album Trip", "app": "Family Photos"},
            headers=headers,
        )
        assert made.status_code == 204
        forged = client.post(
            f"{API}/auth/me/activity",
            json={"kind": "sign-in", "what": "Signed in", "app": "Family Photos"},
            headers=headers,
        )
        assert forged.status_code == 400
        [line] = _lines(client, admin, member=member.id, kind="share-link")
    assert (line["what"], line["source"]) == ("Shared the album Trip", "Family Photos")


def test_only_admins_read_it(make_user) -> None:
    member = make_user()
    with closing(TestClient(app)) as client:
        answer = client.get(f"{API}/users/activity", headers=auth_headers(member))
    assert answer.status_code == 403
