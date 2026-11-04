"""The service around the routes: the first account, sign-in limits, health."""

from __future__ import annotations

import io
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from app import first_admin
from app.config import settings
from app.db import SessionLocal
from app.main import app
from app.models import User
from tests.helpers import API


@pytest.fixture
def no_accounts() -> Iterator[None]:
    """A new ZOOMRIYA ID: no accounts before, none left after (the test database)."""
    with SessionLocal() as db:
        db.execute(delete(User))
        db.commit()
    yield
    with SessionLocal() as db:
        db.execute(delete(User))
        db.commit()


def test_a_new_id_starts_with_no_accounts(no_accounts) -> None:
    """No default account and no default password: starting makes nobody."""
    with TestClient(app) as client:
        assert client.get(f"{API}/health").status_code == 200
        login = {"username": "admin", "password": "admin123"}
        assert client.post(f"{API}/auth/login", json=login).status_code == 401
    with SessionLocal() as db:
        assert db.execute(select(User.id).limit(1)).first() is None


def test_the_first_admin_is_made_once_and_signs_in(no_accounts) -> None:
    assert first_admin.create_first_admin(" amma ", "a long passphrase")
    assert not first_admin.create_first_admin("appa", "another passphrase")
    with SessionLocal() as db:
        users = db.execute(select(User)).scalars().all()
    assert [(u.username, u.role) for u in users] == [("amma", "admin")]
    client = TestClient(app)
    login = {"username": "amma", "password": "a long passphrase"}
    assert client.post(f"{API}/auth/login", json=login).status_code == 200


def test_the_first_admin_needs_a_real_password(no_accounts) -> None:
    with pytest.raises(first_admin.FirstAdminRefused):
        first_admin.create_first_admin("amma", "short")
    with pytest.raises(first_admin.FirstAdminRefused):
        first_admin.create_first_admin("  ", "a long passphrase")
    with SessionLocal() as db:
        assert db.execute(select(User.id).limit(1)).first() is None


def test_the_command_reads_the_password_and_says_when_accounts_exist(
    no_accounts, monkeypatch
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("a long passphrase\n"))
    assert first_admin.main(["amma"]) == 0
    monkeypatch.setattr("sys.stdin", io.StringIO("another passphrase\n"))
    assert first_admin.main(["appa"]) == first_admin.EXISTS
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    assert first_admin.main(["appa"]) == 2


def test_sign_in_attempts_are_limited_per_address() -> None:
    client = TestClient(app)
    wrong = {"username": "pytest-nobody", "password": "not-it"}
    statuses = [
        client.post(f"{API}/auth/login", json=wrong).status_code
        for _ in range(settings.RATE_LIMIT_AUTH_REQUESTS + 1)
    ]
    assert statuses[:-1] == [401] * settings.RATE_LIMIT_AUTH_REQUESTS
    assert statuses[-1] == 429
    # Everything else keeps working.
    assert client.get(f"{API}/auth/jwks.json").status_code == 200


def test_health() -> None:
    assert TestClient(app).get(f"{API}/health").json() == {"status": "ok"}
