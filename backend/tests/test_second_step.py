"""The second sign-in step: required for admins, a choice for others; codes
from an authenticator app, backup codes, tickets, and the admin's reset."""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterator
from contextlib import closing

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from app import second_step
from app.db import SessionLocal
from app.main import app
from app.models import User
from tests.helpers import API, TEST_PASSWORD, auth_headers, build_user


def _client() -> closing[TestClient]:
    return closing(TestClient(app))


@pytest.fixture
def make_user() -> Iterator:
    created: list[int] = []

    def _make(*, role: str = "family") -> User:
        db = SessionLocal()
        try:
            user = build_user(f"pytest-2nd-{uuid.uuid4().hex[:12]}", role=role)
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
        db.execute(delete(User).where(User.id.in_(created)))
        db.commit()
    finally:
        db.close()


def _login(client: TestClient, user: User):
    return client.post(
        f"{API}/auth/login", json={"username": user.username, "password": TEST_PASSWORD}
    )


def _secret_from(key: str) -> str:
    return key.replace(" ", "")


def _set_up(client: TestClient, user: User) -> tuple[str, list[str], dict]:
    """A family member turns it on from Account: (secret, backup codes, token answer)."""
    headers = auth_headers(user)
    start = client.post(
        f"{API}/auth/second-step/setup", json={"password": TEST_PASSWORD}, headers=headers
    )
    assert start.status_code == 200, start.text
    secret = _secret_from(start.json()["key"])
    done = client.post(
        f"{API}/auth/second-step/setup/finish",
        json={"code": second_step.code_now(secret)},
        headers=headers,
    )
    assert done.status_code == 200, done.text
    return secret, done.json()["backup_codes"], done.json()


def test_codes_follow_rfc_6238() -> None:
    # RFC 6238's test secret, SHA-1, at 59 s: 94287082 (8 digits), so 287082.
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert second_step.code_now(secret, at=59) == "287082"
    assert second_step.matching_step(secret, "287 082", None, at=59) == 1
    assert second_step.matching_step(secret, "287082", 1, at=59) is None  # used already
    assert second_step.matching_step(secret, "000000", None, at=59) is None


def test_a_family_member_signs_in_with_a_code(make_user) -> None:
    user = make_user()
    with _client() as client:
        assert _login(client, user).status_code == 200  # nothing asked until it's on
        secret, backup, answer = _set_up(client, user)
        assert len(backup) == 10 and "access_token" not in answer

        first = _login(client, user)
        assert first.status_code == 403 and first.json()["code"] == "second_step_needed"
        ticket = first.json()["ticket"]
        assert "access_token" not in first.json()

        wrong = client.post(
            f"{API}/auth/login/second-step", json={"ticket": ticket, "code": "000000"}
        )
        assert wrong.status_code == 400

        # The code used to set it up can't be used again; the next one can.
        next_step = int(time.time() // 30) + 1
        code = second_step._code_at(secret, next_step)
        good = client.post(f"{API}/auth/login/second-step", json={"ticket": ticket, "code": code})
        assert good.status_code == 200 and good.json()["access_token"]
        again = client.post(f"{API}/auth/login/second-step", json={"ticket": ticket, "code": code})
        assert again.status_code == 400

        # A backup code works once.
        ticket = _login(client, user).json()["ticket"]
        ok = client.post(
            f"{API}/auth/login/second-step", json={"ticket": ticket, "code": backup[0].lower()}
        )
        assert ok.status_code == 200
        ticket = _login(client, user).json()["ticket"]
        assert (
            client.post(
                f"{API}/auth/login/second-step", json={"ticket": ticket, "code": backup[0]}
            ).status_code
            == 400
        )

        me = client.get(f"{API}/auth/me", headers=auth_headers(user)).json()["second_step"]
        assert me == {"on": True, "required": False, "backup_codes_left": 9}


def test_an_admin_sets_it_up_before_signing_in(make_user) -> None:
    admin = make_user(role="admin")
    with _client() as client:
        first = _login(client, admin)
        assert first.status_code == 403 and first.json()["code"] == "second_step_setup_needed"
        ticket = first.json()["ticket"]
        # The ticket can't be used to sign in with a code.
        assert (
            client.post(
                f"{API}/auth/login/second-step", json={"ticket": ticket, "code": "123456"}
            ).status_code
            == 401
        )

        start = client.post(f"{API}/auth/second-step/setup", json={"ticket": ticket})
        assert start.status_code == 200
        body = start.json()
        assert body["qr_svg"].lstrip().startswith("<svg") and body["uri"].startswith(
            "otpauth://totp/ZOOMRIYA:"
        )
        secret = _secret_from(body["key"])

        done = client.post(
            f"{API}/auth/second-step/setup/finish",
            json={"ticket": ticket, "code": second_step.code_now(secret)},
        )
        assert (
            done.status_code == 200
            and done.json()["access_token"]
            and len(done.json()["backup_codes"]) == 10
        )

        # Spent: the ticket can't set up another app now.
        assert (
            client.post(f"{API}/auth/second-step/setup", json={"ticket": ticket}).status_code == 401
        )
        assert _login(client, admin).json()["code"] == "second_step_needed"

        # Admins keep it on.
        off = client.post(
            f"{API}/auth/me/second-step/off",
            json={"password": TEST_PASSWORD, "code": done.json()["backup_codes"][0]},
            headers=auth_headers(admin),
        )
        assert off.status_code == 400


def test_the_secret_is_kept_encrypted(make_user) -> None:
    user = make_user()
    with _client() as client:
        secret, _backup, _ = _set_up(client, user)
    db = SessionLocal()
    try:
        stored = db.get(User, user.id)
        assert secret not in (stored.second_step_secret or "")
        assert second_step.unseal(stored.second_step_secret, user.id) == secret
        assert all(len(h) == 64 for h in stored.second_step_backup)
    finally:
        db.close()


def test_changing_the_app_needs_the_password(make_user) -> None:
    user = make_user()
    with _client() as client:
        refused = client.post(f"{API}/auth/second-step/setup", json={}, headers=auth_headers(user))
        assert refused.status_code == 400


def test_turning_it_off_and_new_backup_codes(make_user) -> None:
    user = make_user()
    with _client() as client:
        secret, backup, _ = _set_up(client, user)
        headers = auth_headers(user)
        fresh = client.post(
            f"{API}/auth/me/second-step/backup-codes",
            json={"password": TEST_PASSWORD},
            headers=headers,
        )
        assert fresh.status_code == 200 and set(fresh.json()["backup_codes"]).isdisjoint(backup)
        # The old ones stop working.
        off = client.post(
            f"{API}/auth/me/second-step/off",
            json={"password": TEST_PASSWORD, "code": backup[1]},
            headers=headers,
        )
        assert off.status_code == 400
        off = client.post(
            f"{API}/auth/me/second-step/off",
            json={"password": TEST_PASSWORD, "code": fresh.json()["backup_codes"][0]},
            headers=headers,
        )
        assert off.status_code == 204
        assert _login(client, user).status_code == 200


def test_an_admin_resets_someone_elses(make_user) -> None:
    admin = make_user(role="admin")
    member = make_user()
    with _client() as client:
        _set_up(client, member)
        assert (
            client.post(
                f"{API}/users/{admin.id}/second-step/reset", headers=auth_headers(admin)
            ).status_code
            == 400
        )
        assert (
            client.post(
                f"{API}/users/{member.id}/second-step/reset", headers=auth_headers(member)
            ).status_code
            == 403
        )
        assert (
            client.post(
                f"{API}/users/{member.id}/second-step/reset", headers=auth_headers(admin)
            ).status_code
            == 204
        )
        assert _login(client, member).status_code == 200


def test_confirm_password(make_user) -> None:
    user = make_user()
    with _client() as client:
        headers = auth_headers(user)
        assert (
            client.post(
                f"{API}/auth/me/confirm-password", json={"password": TEST_PASSWORD}, headers=headers
            ).status_code
            == 204
        )
        assert (
            client.post(
                f"{API}/auth/me/confirm-password", json={"password": "nope"}, headers=headers
            ).status_code
            == 401
        )


def test_an_admin_is_let_back_in_at_the_box(make_user) -> None:
    """The agent's recovery, after the setup code: a new password, the second
    step cleared, every session signed out; never for a family member."""
    from app import recover_admin

    admin = make_user(role="admin")
    member = make_user()
    with _client() as client:
        old = auth_headers(admin)
        assert recover_admin.recover_admin(admin.username, "a new long one") is True
        assert recover_admin.recover_admin(member.username, "a new long one") is False
        assert recover_admin.recover_admin("nobody-at-all", "a new long one") is False
        with pytest.raises(recover_admin.RecoverRefused):
            recover_admin.recover_admin(admin.username, "short")
        # The old session is out; the new password works, and asks for a new second step.
        assert client.get(f"{API}/auth/me", headers=old).status_code == 401
        answer = client.post(
            f"{API}/auth/login", json={"username": admin.username, "password": "a new long one"}
        )
        assert answer.json()["code"] == "second_step_setup_needed"
