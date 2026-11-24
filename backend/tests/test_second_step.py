"""The second sign-in step: a code sent by email through the family's own
email account, a choice for everyone (admins too); trusted devices, the
family's email settings, and the admin's reset."""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from app import mail, second_step
from app.db import SessionLocal
from app.main import app
from app.models import MailSettings, User
from tests.helpers import API, TEST_PASSWORD, auth_headers, build_user


def _client() -> closing[TestClient]:
    return closing(TestClient(app))


@pytest.fixture
def outbox(monkeypatch) -> Iterator[list[EmailMessage]]:
    """The family's email set up, with nothing really sent: messages land here."""
    sent: list[EmailMessage] = []
    monkeypatch.setattr(mail, "_deliver", lambda _account, message: sent.append(message))
    monkeypatch.setattr(mail, "check", lambda _account: None)
    with SessionLocal() as db:
        mail.save(
            db,
            mail.Account("smtp.example.org", 465, mail.SSL, "family@example.org", "pw", "family@example.org"),
        )
    yield sent
    with SessionLocal() as db:
        db.execute(delete(MailSettings))
        db.commit()


@pytest.fixture
def make_user() -> Iterator:
    created: list[int] = []

    def _make(*, role: str = "family", language: str | None = None) -> User:
        with SessionLocal() as db:
            user = build_user(f"pytest-2nd-{uuid.uuid4().hex[:12]}", role=role)
            user.language = language
            db.add(user)
            db.commit()
            db.refresh(user)
            created.append(int(user.id))
            db.expunge(user)
            return user

    yield _make
    with SessionLocal() as db:
        db.execute(delete(User).where(User.id.in_(created)))
        db.commit()


def _login(client: TestClient, user: User, **extra):
    return client.post(
        f"{API}/auth/login",
        json={"username": user.username, "password": TEST_PASSWORD, **extra},
    )


def _code_in(message: EmailMessage) -> str:
    return re.search(r"\b(\d{6})\b", message.get_content()).group(1)


def _allow_resend(user: User) -> None:
    with SessionLocal() as db:
        row = db.get(User, user.id)
        row.second_step_code_sent = datetime.now(UTC) - timedelta(minutes=1)
        db.commit()


def _turn_on(client: TestClient, user: User, outbox, address: str = "emma@example.org") -> None:
    headers = auth_headers(user)
    start = client.post(
        f"{API}/auth/second-step/setup",
        json={"password": TEST_PASSWORD, "email": address},
        headers=headers,
    )
    assert start.status_code == 200, start.text
    assert outbox[-1]["To"] == address
    done = client.post(
        f"{API}/auth/second-step/setup/finish",
        json={"code": _code_in(outbox[-1])},
        headers=headers,
    )
    assert done.status_code == 200, done.text
    assert done.json()["second_step"] == {"on": True, "email": address, "available": True}
    _allow_resend(user)


def _fresh_client() -> TestClient:
    """Another device: no trusted-device cookie."""
    return TestClient(app)


def test_off_until_turned_on_for_admins_too(make_user, outbox) -> None:
    admin = make_user(role="admin")
    with _client() as client:
        assert _login(client, admin).status_code == 200
        me = client.get(f"{API}/auth/me", headers=auth_headers(admin)).json()["second_step"]
        assert me == {"on": False, "email": None, "available": True}
    assert outbox == []


def test_signing_in_with_an_emailed_code(make_user, outbox) -> None:
    user = make_user()
    with _client() as client:
        _turn_on(client, user, outbox)
    client = _fresh_client()
    first = _login(client, user)
    assert first.status_code == 403 and first.json()["code"] == "second_step_needed"
    assert first.json()["sent_to"] == "e•••@example.org"
    assert "access_token" not in first.json()
    ticket = first.json()["ticket"]
    code = _code_in(outbox[-1])
    assert "sign in" in outbox[-1].get_content()

    wrong = "000000" if code != "000000" else "111111"
    assert client.post(f"{API}/auth/login/second-step", json={"ticket": ticket, "code": wrong}).status_code == 400
    good = client.post(f"{API}/auth/login/second-step", json={"ticket": ticket, "code": code})
    assert good.status_code == 200 and good.json()["access_token"] and good.json()["trusted_device"]
    # Used up.
    again = client.post(f"{API}/auth/login/second-step", json={"ticket": ticket, "code": code})
    assert again.status_code == 400


def test_a_trusted_device_skips_the_code(make_user, outbox) -> None:
    user = make_user()
    with _client() as client:
        _turn_on(client, user, outbox)
    browser = _fresh_client()
    ticket = _login(browser, user).json()["ticket"]
    answer = browser.post(
        f"{API}/auth/login/second-step", json={"ticket": ticket, "code": _code_in(outbox[-1])}
    ).json()
    sent = len(outbox)
    # The browser kept the cookie; a client of its own sends the token.
    assert _login(browser, user).status_code == 200
    assert _login(_fresh_client(), user, trusted_device=answer["trusted_device"]).status_code == 200
    assert len(outbox) == sent
    # Another device still gets a code.
    assert _login(_fresh_client(), user).status_code == 403

    # Signing out ends the trust everywhere.
    browser.post(f"{API}/auth/logout", headers=auth_headers(user))
    _allow_resend(user)
    assert _login(_fresh_client(), user, trusted_device=answer["trusted_device"]).status_code == 403


def test_not_remembered(make_user, outbox) -> None:
    user = make_user()
    with _client() as client:
        _turn_on(client, user, outbox)
    browser = _fresh_client()
    ticket = _login(browser, user).json()["ticket"]
    answer = browser.post(
        f"{API}/auth/login/second-step",
        json={"ticket": ticket, "code": _code_in(outbox[-1]), "remember": False},
    )
    assert answer.status_code == 200 and answer.json()["trusted_device"] is None
    _allow_resend(user)
    assert _login(browser, user).status_code == 403


def test_send_again_waits_a_little(make_user, outbox) -> None:
    user = make_user()
    with _client() as client:
        _turn_on(client, user, outbox)
    client = _fresh_client()
    ticket = _login(client, user).json()["ticket"]
    old = _code_in(outbox[-1])
    soon = client.post(f"{API}/auth/login/second-step/resend", json={"ticket": ticket})
    assert soon.status_code == 429 and int(soon.headers["Retry-After"]) > 0
    _allow_resend(user)
    assert client.post(f"{API}/auth/login/second-step/resend", json={"ticket": ticket}).status_code == 204
    new = _code_in(outbox[-1])
    if new != old:
        # Only the newest code works.
        assert client.post(f"{API}/auth/login/second-step", json={"ticket": ticket, "code": old}).status_code == 400
    assert client.post(f"{API}/auth/login/second-step", json={"ticket": ticket, "code": new}).status_code == 200


def test_an_old_code_runs_out(make_user, outbox) -> None:
    user = make_user()
    with _client() as client:
        _turn_on(client, user, outbox)
    client = _fresh_client()
    ticket = _login(client, user).json()["ticket"]
    with SessionLocal() as db:
        db.get(User, user.id).second_step_code_until = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    code = _code_in(outbox[-1])
    assert client.post(f"{API}/auth/login/second-step", json={"ticket": ticket, "code": code}).status_code == 400


def test_the_email_is_in_their_language(make_user, outbox) -> None:
    user = make_user(language="fr")
    with _client() as client:
        _turn_on(client, user, outbox)
    _login(_fresh_client(), user)
    assert outbox[-1]["Subject"].startswith("Votre code ZOOMRIYA")


def test_turning_on_needs_the_password_and_the_family_email(make_user, outbox) -> None:
    user = make_user()
    with _client() as client:
        headers = auth_headers(user)
        wrong = client.post(
            f"{API}/auth/second-step/setup", json={"password": "nope", "email": "a@b.org"}, headers=headers
        )
        assert wrong.status_code == 400
        bad = client.post(
            f"{API}/auth/second-step/setup", json={"password": TEST_PASSWORD, "email": "not an address"}, headers=headers
        )
        assert bad.status_code == 400
        # A code for turning it on doesn't sign anyone in, and the reverse.
        client.post(
            f"{API}/auth/second-step/setup", json={"password": TEST_PASSWORD, "email": "a@b.org"}, headers=headers
        )
        assert not second_step.take_code(_row(user), second_step.CHECK, _code_in(outbox[-1]))
    with SessionLocal() as db:
        db.execute(delete(MailSettings))
        db.commit()
    with _client() as client:
        _allow_resend(user)
        none = client.post(
            f"{API}/auth/second-step/setup",
            json={"password": TEST_PASSWORD, "email": "a@b.org"},
            headers=auth_headers(user),
        )
        assert none.status_code == 400 and "Box Desktop" in none.json()["detail"]


def _row(user: User) -> User:
    with SessionLocal() as db:
        row = db.get(User, user.id)
        db.expunge(row)
        return row


def test_turning_it_off_admins_too(make_user, outbox) -> None:
    admin = make_user(role="admin")
    with _client() as client:
        _turn_on(client, admin, outbox)
        off = client.post(
            f"{API}/auth/me/second-step/off", json={"password": TEST_PASSWORD}, headers=auth_headers(admin)
        )
        assert off.status_code == 204
        assert _login(_fresh_client(), admin).status_code == 200


def test_an_admin_resets_someone_elses(make_user, outbox) -> None:
    admin = make_user(role="admin")
    member = make_user()
    with _client() as client:
        _turn_on(client, member, outbox)
        assert client.post(f"{API}/users/{admin.id}/second-step/reset", headers=auth_headers(admin)).status_code == 400
        assert client.post(f"{API}/users/{member.id}/second-step/reset", headers=auth_headers(member)).status_code == 403
        assert client.post(f"{API}/users/{member.id}/second-step/reset", headers=auth_headers(admin)).status_code == 204
    assert _login(_fresh_client(), member).status_code == 200


def test_mail_that_fails_is_said_plainly(make_user, outbox, monkeypatch) -> None:
    user = make_user()
    with _client() as client:
        _turn_on(client, user, outbox)

    def broken(_account, _message):
        raise mail.MailError("down")

    monkeypatch.setattr(mail, "_deliver", broken)
    answer = _login(_fresh_client(), user)
    assert answer.status_code == 503 and "ask an admin" in answer.json()["detail"]


def test_the_codes_are_not_kept_in_plain(make_user, outbox) -> None:
    user = make_user()
    with _client() as client:
        _turn_on(client, user, outbox)
    _login(_fresh_client(), user)
    code = _code_in(outbox[-1])
    stored = _row(user).second_step_code
    assert stored and code not in stored and len(stored) == 64
    with SessionLocal() as db:
        assert "pw" not in db.get(MailSettings, 1).password_sealed


def test_confirm_password(make_user) -> None:
    user = make_user()
    with _client() as client:
        headers = auth_headers(user)
        assert client.post(f"{API}/auth/me/confirm-password", json={"password": TEST_PASSWORD}, headers=headers).status_code == 204
        assert client.post(f"{API}/auth/me/confirm-password", json={"password": "nope"}, headers=headers).status_code == 401


def test_an_admin_is_let_back_in_at_the_box(make_user, outbox) -> None:
    """The agent's recovery, after the setup code: a new password, codes by
    email off, every session signed out; never for a family member."""
    from app import recover_admin

    admin = make_user(role="admin")
    member = make_user()
    with _client() as client:
        _turn_on(client, admin, outbox)
        old = auth_headers(admin)
        assert recover_admin.recover_admin(admin.username, "a new long one") is True
        assert recover_admin.recover_admin(member.username, "a new long one") is False
        assert recover_admin.recover_admin("nobody-at-all", "a new long one") is False
        with pytest.raises(recover_admin.RecoverRefused):
            recover_admin.recover_admin(admin.username, "short")
        assert client.get(f"{API}/auth/me", headers=old).status_code == 401
        answer = client.post(
            f"{API}/auth/login", json={"username": admin.username, "password": "a new long one"}
        )
        assert answer.status_code == 200


# --- the family's email account -------------------------------------------------


def test_the_family_email_is_for_admins(make_user, outbox) -> None:
    admin = make_user(role="admin")
    member = make_user()
    with _client() as client:
        assert client.get(f"{API}/mail", headers=auth_headers(member)).status_code == 403
        seen = client.get(f"{API}/mail", headers=auth_headers(admin)).json()
        assert seen["set"] is True and seen["host"] == "smtp.example.org" and "password" not in seen

        changed = client.put(
            f"{API}/mail",
            json={"host": "smtp.other.org", "port": 587, "security": "starttls", "username": "fam@other.org"},
            headers=auth_headers(admin),
        )
        # The password kept stays when none is sent.
        assert changed.status_code == 200 and changed.json()["from_address"] == "fam@other.org"
        with SessionLocal() as db:
            assert mail.account(mail.stored(db)).password == "pw"

        assert client.post(f"{API}/mail/test", json={"to": "sam@example.org"}, headers=auth_headers(admin)).status_code == 204
        assert outbox[-1]["To"] == "sam@example.org"


def test_a_server_that_refuses_is_not_kept(make_user, outbox, monkeypatch) -> None:
    admin = make_user(role="admin")

    def refuses(_account):
        raise mail.MailError("The email server refused the username or password.")

    monkeypatch.setattr(mail, "check", refuses)
    with _client() as client:
        answer = client.put(
            f"{API}/mail",
            json={"host": "smtp.bad.org", "port": 465, "security": "ssl", "username": "x@bad.org", "password": "no"},
            headers=auth_headers(admin),
        )
        assert answer.status_code == 400 and "refused" in answer.json()["detail"]
        assert client.get(f"{API}/mail", headers=auth_headers(admin)).json()["host"] == "smtp.example.org"


def test_removing_the_family_email_turns_codes_off(make_user, outbox) -> None:
    admin = make_user(role="admin")
    member = make_user()
    with _client() as client:
        _turn_on(client, member, outbox)
        assert client.get(f"{API}/mail", headers=auth_headers(admin)).json()["in_use"] >= 1
        gone = client.delete(f"{API}/mail", headers=auth_headers(admin))
        assert gone.status_code == 200 and gone.json() == {"set": False, "in_use": 0}
    assert _login(_fresh_client(), member).status_code == 200


# --- wrong codes count toward the person's sign-in lock --------------------------


def _wrong(right: str) -> str:
    return "000000" if right != "000000" else "111111"


def _try_code(client: TestClient, ticket: str, code: str):
    return client.post(f"{API}/auth/login/second-step", json={"ticket": ticket, "code": code})


def test_five_wrong_codes_lock_the_sign_in(make_user, outbox) -> None:
    user = make_user()
    with _client() as client:
        _turn_on(client, user, outbox)
    client = _fresh_client()
    ticket = _login(client, user).json()["ticket"]
    right = _code_in(outbox[-1])
    for _ in range(4):
        assert _try_code(client, ticket, _wrong(right)).status_code == 400
    fifth = _try_code(client, ticket, _wrong(right))
    assert fifth.status_code == 429 and "Too many wrong codes" in fifth.json()["detail"]
    assert 0 < int(fifth.headers["Retry-After"]) <= 15 * 60
    assert _try_code(client, ticket, right).status_code == 429
    assert _login(client, user).status_code == 429


def test_the_password_again_does_not_forget_wrong_codes(make_user, outbox) -> None:
    user = make_user()
    with _client() as client:
        _turn_on(client, user, outbox)
    client = _fresh_client()
    for _ in range(4):
        ticket = _login(client, user).json()["ticket"]
        assert _try_code(client, ticket, _wrong(_code_in(outbox[-1]))).status_code == 400
    ticket = _login(client, user).json()["ticket"]
    assert _try_code(client, ticket, _wrong(_code_in(outbox[-1]))).status_code == 429


def test_the_right_code_forgets_wrong_ones(make_user, outbox) -> None:
    user = make_user()
    with _client() as client:
        _turn_on(client, user, outbox)
    client = _fresh_client()
    ticket = _login(client, user).json()["ticket"]
    right = _code_in(outbox[-1])
    for _ in range(4):
        assert _try_code(client, ticket, _wrong(right)).status_code == 400
    assert _try_code(client, ticket, right).status_code == 200
    row = _row(user)
    assert row.failed_sign_ins == 0 and row.sign_in_locked_until is None
