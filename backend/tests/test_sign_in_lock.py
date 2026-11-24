"""A person's sign-in locks for 15 minutes after 5 wrong passwords
(app.sign_in_lock), and an admin or the box can lift it."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from app.config import settings
from app.db import SessionLocal
from app.main import app
from app.models import Activity, User
from app.recover_admin import recover_admin
from tests.helpers import API, TEST_PASSWORD, auth_headers, build_user

WRONG = "not-the-password"


@pytest.fixture
def make_user() -> Iterator:
    created: list[int] = []

    def _make(*, role: str = "family") -> User:
        db = SessionLocal()
        try:
            user = build_user(f"pytest-lock-{uuid.uuid4().hex[:12]}", role=role)
            db.add(user)
            db.commit()
            db.refresh(user)
            created.append(int(user.id))
            db.expunge(user)
            return user
        finally:
            db.close()

    yield _make
    db = SessionLocal()
    try:
        db.execute(delete(Activity).where(Activity.member_id.in_(created)))
        db.execute(delete(Activity).where(Activity.by_id.in_(created)))
        db.execute(delete(User).where(User.id.in_(created)))
        db.commit()
    finally:
        db.close()


def _login(client: TestClient, user: User, password: str):
    return client.post(f"{API}/auth/login", json={"username": user.username, "password": password})


def _set(user: User, **values) -> None:
    db = SessionLocal()
    try:
        row = db.get(User, user.id)
        for name, value in values.items():
            setattr(row, name, value)
        db.commit()
    finally:
        db.close()


def _row(user: User) -> User:
    db = SessionLocal()
    try:
        row = db.get(User, user.id)
        db.expunge(row)
        return row
    finally:
        db.close()


def test_the_defaults_are_five_tries_and_fifteen_minutes() -> None:
    assert settings.SIGN_IN_LOCK_TRIES == 5
    assert settings.SIGN_IN_LOCK_MINUTES == 15


def test_four_wrong_then_the_right_password_signs_in_and_forgets_them(make_user) -> None:
    user = make_user()
    client = TestClient(app)
    for _ in range(4):
        assert _login(client, user, WRONG).status_code == 401
    assert _login(client, user, TEST_PASSWORD).status_code == 200
    assert _row(user).failed_sign_ins == 0


def test_the_fifth_wrong_password_locks_even_the_right_one_out(make_user) -> None:
    user = make_user()
    client = TestClient(app)
    for _ in range(4):
        assert _login(client, user, WRONG).status_code == 401
    fifth = _login(client, user, WRONG)
    assert fifth.status_code == 429
    assert "Try again in 15 minutes" in fifth.json()["detail"]
    assert 0 < int(fifth.headers["Retry-After"]) <= 15 * 60
    refused = _login(client, user, TEST_PASSWORD)
    assert refused.status_code == 429


def test_the_lock_counts_tries_from_every_device(make_user) -> None:
    user = make_user()
    for _ in range(4):
        assert _login(TestClient(app), user, WRONG).status_code == 401
    assert _login(TestClient(app), user, WRONG).status_code == 429


def test_the_lock_ends_after_its_time(make_user) -> None:
    user = make_user()
    _set(user, sign_in_locked_until=datetime.now(UTC) - timedelta(seconds=1))
    assert _login(TestClient(app), user, TEST_PASSWORD).status_code == 200
    assert _row(user).sign_in_locked_until is None


def test_old_wrong_passwords_are_forgotten(make_user) -> None:
    user = make_user()
    _set(
        user,
        failed_sign_ins=4,
        last_failed_sign_in=datetime.now(UTC) - timedelta(minutes=16),
    )
    assert _login(TestClient(app), user, WRONG).status_code == 401
    assert _row(user).failed_sign_ins == 1


def test_the_lock_is_written_in_the_familys_activity(make_user) -> None:
    user = make_user()
    client = TestClient(app)
    for _ in range(5):
        _login(client, user, WRONG)
    db = SessionLocal()
    try:
        lines = (
            db.execute(select(Activity.what).where(Activity.member_id == user.id)).scalars().all()
        )
    finally:
        db.close()
    assert "Sign-in locked for 15 minutes after 5 wrong passwords" in lines


def test_a_name_that_isnt_a_member_never_locks() -> None:
    client = TestClient(app)
    for _ in range(6):
        response = client.post(
            f"{API}/auth/login", json={"username": "pytest-nobody", "password": WRONG}
        )
        assert response.status_code == 401


def test_an_admin_setting_a_new_password_lifts_the_lock(make_user) -> None:
    admin = make_user(role="admin")
    member = make_user()
    _set(member, sign_in_locked_until=datetime.now(UTC) + timedelta(minutes=10))
    client = TestClient(app)
    changed = client.patch(
        f"{API}/users/{member.id}",
        json={"password": "new-pass-5678"},
        headers=auth_headers(admin),
    )
    assert changed.status_code == 200, changed.text
    assert _row(member).sign_in_locked_until is None
    # A password set by an admin is temporary: the member chooses their own.
    assert _login(client, member, "new-pass-5678").status_code == 403


def test_letting_an_admin_back_in_at_the_box_lifts_the_lock(make_user) -> None:
    admin = make_user(role="admin")
    _set(
        admin,
        failed_sign_ins=3,
        sign_in_locked_until=datetime.now(UTC) + timedelta(minutes=10),
    )
    assert recover_admin(admin.username, "back-in-5678")
    row = _row(admin)
    assert row.sign_in_locked_until is None
    assert row.failed_sign_ins == 0
