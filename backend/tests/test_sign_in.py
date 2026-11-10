"""Signing in: Ed25519 tokens, the public key, session renewal, the family
directory, per-app access and the identity events."""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Iterator
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import jwt
import pytest
import redis
from fastapi.testclient import TestClient
from sqlalchemy import delete
from zoomriya_identity import identity as id_format

from app import accounts as identity
from app import security
from app.config import settings
from app.db import SessionLocal
from app.main import app
from app.models import User
from tests.helpers import API, TEST_PASSWORD, bearer, build_user, finish_sign_in


def _client() -> closing[TestClient]:
    """A browser of its own (own cookies), without running the app's startup."""
    return closing(TestClient(app))


@pytest.fixture
def make_user() -> Iterator:
    """Create users with a known password; delete exactly those afterwards."""
    created: list[int] = []

    def _make(*, role: str = "family", is_active: bool = True) -> User:
        db = SessionLocal()
        try:
            user = build_user(f"pytest-zid-{uuid.uuid4().hex[:12]}", role=role)
            user.is_active = is_active
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


def _login(client: TestClient, user: User) -> dict:
    response = client.post(
        f"{API}/auth/login", json={"username": user.username, "password": TEST_PASSWORD}
    )
    return finish_sign_in(client, response)


def _set_cookie_headers(response) -> dict[str, str]:
    headers = response.headers.get_list("set-cookie")
    return {header.split("=", 1)[0]: header for header in headers}


@pytest.fixture
def installed_apps(monkeypatch: pytest.MonkeyPatch):
    """Pretend more apps are installed on the box."""

    def _install(*apps: str) -> None:
        patched = replace(settings, INSTALLED_APPS=("photos", *apps))
        monkeypatch.setattr(identity, "settings", patched)

    return _install


# --- tokens and keys ----------------------------------------------------------


def test_login_issues_an_ed25519_token_others_can_verify(make_user, installed_apps) -> None:
    installed_apps()  # Photos alone, whatever the local .env installs
    user = make_user()
    with _client() as client:
        body = _login(client, user)
        keys = id_format.keys_from_jwks(client.get(f"{API}/auth/jwks.json").json())

    claims = id_format.verify_token(body["access_token"], keys)
    assert jwt.get_unverified_header(body["access_token"])["alg"] == "EdDSA"
    assert claims["iss"] == "zoomriya-id" and claims["aud"] == "zoomriya"
    assert claims["sub"] == str(user.id) and claims["ver"] == 0
    assert claims["role"] == "family" and claims["apps"] == ["photos"]
    assert claims["exp"] - claims["iat"] == settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    assert body["expires_in"] == settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60


def test_login_cookies_are_httponly_and_site_wide(make_user) -> None:
    with _client() as client:
        response = client.post(
            f"{API}/auth/login", json={"username": make_user().username, "password": TEST_PASSWORD}
        )
    cookies = _set_cookie_headers(response)
    for name in (id_format.AUTH_COOKIE_NAME, id_format.SESSION_COOKIE_NAME):
        header = cookies[name].lower()
        assert "httponly" in header and "path=/" in header and "samesite=lax" in header
        # Plain HTTP (a developer's machine): not Secure, or the browser drops it.
        assert "secure" not in header


def test_login_cookies_over_https_are_secure(make_user) -> None:
    """The gateway says HTTPS: every cookie is Secure, with nothing set."""
    with _client() as client:
        response = client.post(
            f"{API}/auth/login",
            json={"username": make_user().username, "password": TEST_PASSWORD},
            headers={"X-Forwarded-Proto": "https"},
        )
        out = client.post(f"{API}/auth/logout", headers={"X-Forwarded-Proto": "https"})
    for headers in (_set_cookie_headers(response), _set_cookie_headers(out)):
        for name in (id_format.AUTH_COOKIE_NAME, id_format.SESSION_COOKIE_NAME):
            assert "; secure" in headers[name].lower()


def test_jwks_is_public_and_names_the_signing_key() -> None:
    with _client() as client:
        response = client.get(f"{API}/auth/jwks.json")
    assert response.status_code == 200
    [key] = response.json()["keys"]
    assert key["kty"] == "OKP" and key["crv"] == "Ed25519" and key["alg"] == "EdDSA"
    assert key["kid"] == security.signing_key()[0]
    assert "d" not in key  # never the private part


def test_a_session_token_is_not_an_access_token(make_user) -> None:
    user = make_user()
    session = security.create_session_token(int(user.id), 0)
    with _client() as client:
        assert client.get(f"{API}/auth/me", headers=bearer(session)).status_code == 401


def test_an_expired_access_token_is_refused(make_user) -> None:
    user = make_user()
    kid, key = security.signing_key()
    past = datetime.now(UTC) - timedelta(minutes=30)
    token = jwt.encode(
        {
            "iss": "zoomriya-id",
            "aud": "zoomriya",
            "sub": str(user.id),
            "ver": 0,
            "iat": past,
            "exp": past + timedelta(minutes=15),
        },
        key,
        algorithm="EdDSA",
        headers={"kid": kid},
    )
    with _client() as client:
        assert client.get(f"{API}/auth/me", headers=bearer(token)).status_code == 401


# --- renewal ------------------------------------------------------------------


def test_refresh_renews_from_the_session_cookie(make_user) -> None:
    user = make_user()
    with _client() as client:
        _login(client, user)
        client.cookies.delete(id_format.AUTH_COOKIE_NAME)
        response = client.post(f"{API}/auth/refresh")
        assert response.status_code == 200
        token = response.json()["access_token"]
        assert client.get(f"{API}/auth/me", headers=bearer(token)).json()["id"] == user.id


def test_refresh_without_a_session_is_refused() -> None:
    with _client() as client:
        response = client.post(f"{API}/auth/refresh")
    assert response.status_code == 401


def test_a_dead_session_cookie_is_deleted_on_refresh(make_user) -> None:
    """Left behind, it makes /login send the browser back to / in a loop."""
    user = make_user()
    with _client() as client:
        _login(client, user)
        db = SessionLocal()
        try:
            member = db.get(User, user.id)
            assert member is not None
            member.token_version += 1  # signed out elsewhere
            db.commit()
        finally:
            db.close()
        response = client.post(f"{API}/auth/refresh")
        assert response.status_code == 401
        assert response.json() == {"detail": "Session expired"}
        assert id_format.SESSION_COOKIE_NAME not in client.cookies
        assert id_format.AUTH_COOKIE_NAME not in client.cookies


def test_logout_ends_the_session_everywhere(make_user) -> None:
    user = make_user()
    with _client() as browser, _client() as other_device:
        token = _login(browser, user)["access_token"]
        _login(other_device, user)
        assert browser.post(f"{API}/auth/logout", headers=bearer(token)).status_code == 200
        # The other device's session carries the old version now.
        assert other_device.post(f"{API}/auth/refresh").status_code == 401


def test_logout_with_an_expired_token_still_clears_the_cookies() -> None:
    with _client() as client:
        response = client.post(f"{API}/auth/logout", headers=bearer("not-a-token"))
    assert response.status_code == 200
    cookies = _set_cookie_headers(response)
    assert id_format.SESSION_COOKIE_NAME in cookies and id_format.AUTH_COOKIE_NAME in cookies


def test_a_password_change_keeps_this_session(make_user) -> None:
    user = make_user()
    with _client() as client:
        token = _login(client, user)["access_token"]
        response = client.post(
            f"{API}/auth/me/password",
            headers=bearer(token),
            json={"current_password": TEST_PASSWORD, "new_password": "another-pass-123"},
        )
        assert response.status_code == 200
        assert client.post(f"{API}/auth/refresh").status_code == 200


# --- the old HS256 tokens -----------------------------------------------------


def test_refresh_rejects_legacy_hs256(make_user) -> None:
    """A self-signed HS256 token, even without exp, never becomes a session (SEC-05)."""
    user = make_user()
    forged = jwt.encode(
        {"sub": str(user.id), "ver": user.token_version},
        "any-secret-anyone-could-have-at-least-32-chars",
        algorithm="HS256",
    )
    with _client() as client:
        for _ in range(2):
            assert client.post(f"{API}/auth/refresh", headers=bearer(forged)).status_code == 401
        client.cookies.set(id_format.SESSION_COOKIE_NAME, forged)
        assert client.post(f"{API}/auth/refresh").status_code == 401


def test_refresh_rate_limited(monkeypatch) -> None:
    from app import main

    rule = next(r for r in main.app.user_middleware if r.cls is main.RateLimitMiddleware)
    limit = next(c for c in rule.kwargs["rules"] if c.prefix.endswith("/auth/refresh"))
    with _client() as client:
        codes = [client.post(f"{API}/auth/refresh").status_code for _ in range(limit.requests + 1)]
    assert codes[:-1] == [401] * limit.requests
    assert codes[-1] == 429


# --- password hashes ----------------------------------------------------------


def test_hash_parameters() -> None:
    hashed = security.hash_password("a-password")
    assert hashed.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert security.verify_password("a-password", hashed)
    assert not security.verify_password("another", hashed)
    assert not security.needs_rehash(hashed)
    assert not security.verify_password("a-password", "not-a-hash")


def test_old_pbkdf2_hash_is_replaced_at_sign_in(make_user) -> None:
    user = make_user()
    old = security._legacy_context.hash(TEST_PASSWORD)
    with SessionLocal() as db:
        db.get(User, user.id).hashed_password = old
        db.commit()
    assert security.needs_rehash(old)
    with _client() as client:
        _login(client, user)
    with SessionLocal() as db:
        stored = db.get(User, user.id).hashed_password
    assert stored.startswith("$argon2id$")
    assert security.verify_password(TEST_PASSWORD, stored)


# --- family directory ---------------------------------------------------------


def test_directory_lists_active_members_for_any_member(make_user) -> None:
    member, inactive = make_user(), make_user(is_active=False)
    with _client() as client:
        token = _login(client, member)["access_token"]
        rows = client.get(f"{API}/users/directory", headers=bearer(token)).json()
    with _client() as signed_out:
        assert signed_out.get(f"{API}/users/directory").status_code == 401

    by_id = {row["id"]: row for row in rows}
    assert inactive.id not in by_id
    assert by_id[member.id] == {
        "id": member.id,
        "username": member.username,
        "display_name": member.username,
        "avatar_version": None,
        "role": "family",
        "birth_year": None,
        "level": "adult",
        "guardian_ids": [],
        "quiet_hours": {"bedtime": None, "school": None},
        "place": None,
        "ver": 0,
    }


# --- app access ---------------------------------------------------------------


def test_every_member_gets_every_installed_app(make_user, installed_apps) -> None:
    installed_apps("vault", "chat")
    user = make_user()
    with _client() as client:
        body = _login(client, user)
        me = client.get(f"{API}/auth/me", headers=bearer(body["access_token"])).json()
    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["apps"] == ["photos", "vault", "chat"] == me["apps"]


def test_admin_switches_an_app_off_for_one_member(make_user, installed_apps) -> None:
    installed_apps("vault", "chat")
    admin, member = make_user(role="admin"), make_user()
    with _client() as client:
        admin_token = _login(client, admin)["access_token"]
        response = client.put(
            f"{API}/users/{member.id}/apps",
            headers=bearer(admin_token),
            json={"app": "chat", "enabled": False},
        )
        assert response.json() == [
            {"app": "photos", "enabled": True},
            {"app": "vault", "enabled": True},
            {"app": "chat", "enabled": False},
        ]
        assert client.get(f"{API}/users/{member.id}/apps", headers=bearer(admin_token)).json() == (
            response.json()
        )
    with _client() as member_client:
        claims = jwt.decode(
            _login(member_client, member)["access_token"], options={"verify_signature": False}
        )
    assert claims["apps"] == ["photos", "vault"]


def test_apps_not_on_the_box_cannot_be_switched(make_user, installed_apps) -> None:
    installed_apps("vault")
    admin, member = make_user(role="admin"), make_user()
    with _client() as client:
        token = _login(client, admin)["access_token"]
        response = client.put(
            f"{API}/users/{member.id}/apps",
            headers=bearer(token),
            json={"app": "tracker", "enabled": False},
        )
        assert response.status_code == 400


def test_photos_is_an_app_like_any_other(make_user, installed_apps) -> None:
    installed_apps("vault")
    admin, member = make_user(role="admin"), make_user()
    with _client() as client:
        token = _login(client, admin)["access_token"]
        response = client.put(
            f"{API}/users/{member.id}/apps",
            headers=bearer(token),
            json={"app": "photos", "enabled": False},
        )
        assert response.status_code == 200
    with _client() as member_client:
        claims = jwt.decode(
            _login(member_client, member)["access_token"], options={"verify_signature": False}
        )
    assert claims["apps"] == ["vault"]


def test_a_box_without_photos_never_lists_it(make_user, monkeypatch) -> None:
    monkeypatch.setattr(identity, "settings", replace(settings, INSTALLED_APPS=("vault",)))
    user = make_user()
    with _client() as client:
        body = _login(client, user)
    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["apps"] == ["vault"]


def test_only_the_admin_sets_app_access(make_user, installed_apps) -> None:
    installed_apps("vault")
    member, other = make_user(), make_user()
    with _client() as client:
        token = _login(client, member)["access_token"]
        response = client.put(
            f"{API}/users/{other.id}/apps",
            headers=bearer(token),
            json={"app": "vault", "enabled": False},
        )
    assert response.status_code == 403


# --- identity events ----------------------------------------------------------


@pytest.fixture
def identity_events() -> Iterator:
    """Collect what is published on zoomriya:identity during the test."""
    client = redis.Redis.from_url(settings.REDIS_URL)
    pubsub = client.pubsub(ignore_subscribe_messages=True)
    try:
        pubsub.subscribe(id_format.IDENTITY_CHANNEL)
        pubsub.get_message(timeout=1.0)
    except redis.ConnectionError:
        pytest.skip("Redis is not running")

    def _collect(*, signed: bool = False) -> list[dict]:
        """The events, opened with ZOOMRIYA ID's public key (or, ``signed``,
        the messages as published)."""
        events, deadline = [], time.monotonic() + 1.0
        while time.monotonic() < deadline:
            message = pubsub.get_message(timeout=0.1)
            if message is not None:
                events.append(json.loads(message["data"]))
        if signed:
            return events
        keys = id_format.keys_from_jwks(security.public_keys())
        return [
            id_format.open_member_event(
                message,
                lambda token, audience: id_format.verify_token(token, keys, audience=audience),
            )
            for message in events
        ]

    yield _collect
    pubsub.close()
    client.close()


def test_account_changes_publish_identity_events(make_user, identity_events) -> None:
    admin = make_user(role="admin")
    with _client() as client:
        token = _login(client, admin)["access_token"]
        created = client.post(
            f"{API}/users",
            headers=bearer(token),
            json={"username": f"pytest-zid-{uuid.uuid4().hex[:12]}", "password": TEST_PASSWORD},
        ).json()
        try:
            client.patch(
                f"{API}/users/{created['id']}", headers=bearer(token), json={"display_name": "Amma"}
            )
            client.patch(
                f"{API}/users/{created['id']}",
                headers=bearer(token),
                json={"password": "a-new-password-1"},
            )
            client.patch(
                f"{API}/users/{created['id']}", headers=bearer(token), json={"is_active": False}
            )
            events = [e for e in identity_events() if e["audience"] == [created["id"]]]
        finally:
            db = SessionLocal()
            db.execute(delete(User).where(User.id == created["id"]))
            db.commit()
            db.close()

    assert [event["type"] for event in events] == [
        "user:created",
        "user:updated",
        "user:revoked",
        "user:deactivated",
    ]
    assert all(event["app"] == "identity" for event in events)
    assert events[1]["data"]["display_name"] == "Amma"
    assert events[2]["data"]["ver"] == 1
    assert events[3]["data"]["active"] is False


def test_logout_publishes_a_revocation(make_user, identity_events) -> None:
    user = make_user()
    with _client() as client:
        token = _login(client, user)["access_token"]
        client.post(f"{API}/auth/logout", headers=bearer(token))
    [event] = [e for e in identity_events() if e["audience"] == [user.id]]
    assert event["type"] == "user:revoked" and event["data"]["ver"] == 1


def test_a_redis_outage_never_fails_an_account_change(make_user, monkeypatch) -> None:
    def broken():
        raise redis.ConnectionError("down")

    monkeypatch.setattr(identity, "_redis", broken)
    user = make_user()
    with _client() as client:
        token = _login(client, user)["access_token"]
        response = client.patch(
            f"{API}/auth/me", headers=bearer(token), json={"display_name": "Appa"}
        )
    assert response.status_code == 200


# --- an app signing in with ZOOMRIYA ID ------------------------------------------


def test_another_app_signs_in_and_drops_a_revoked_member(
    make_user, installed_apps, identity_events
) -> None:
    """The Phase 0 gate in miniature: an app using only zoomriya_common and
    ZOOMRIYA ID's public contracts (JWKS, directory, identity events).

    zoomriya_common is the apps' shared package (zoomriya-apps, private), so
    this runs only where it's installed beside ZOOMRIYA ID."""
    pytest.importorskip("zoomriya_common.members")
    from fastapi import Depends, FastAPI
    from sqlalchemy import create_engine
    from sqlalchemy.orm import DeclarativeBase, sessionmaker
    from sqlalchemy.pool import StaticPool
    from zoomriya_common.members import (
        MemberMixin,
        MemberStore,
        SessionEnded,
        current_member_dependency,
        handle_identity_message,
    )

    class HelloBase(DeclarativeBase):
        pass

    class HelloMember(MemberMixin, HelloBase):
        __tablename__ = "members"

    installed_apps("hello")
    user = make_user()

    with _client() as zoomriya_id:
        keys = id_format.keys_from_jwks(zoomriya_id.get(f"{API}/auth/jwks.json").json())

        def directory(token: str) -> list[dict]:
            response = zoomriya_id.get(f"{API}/users/directory", headers=bearer(token))
            if response.status_code in (401, 403):
                raise SessionEnded(response.text)
            return response.json()

        engine = create_engine(
            "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
        )
        HelloBase.metadata.create_all(engine)
        sessions = sessionmaker(bind=engine, expire_on_commit=False)
        store = MemberStore(HelloMember, fetch_directory=directory)

        def get_db():
            db = sessions()
            try:
                yield db
            finally:
                db.close()

        current = current_member_dependency(
            app="hello",
            verify=lambda token: id_format.verify_token(token, keys),
            store=store,
            get_db=get_db,
        )
        hello = FastAPI()

        @hello.get("/hello/")
        def greet(member: HelloMember = Depends(current)) -> dict[str, str]:
            return {"hello": member.display_name}

        hello_client = TestClient(hello)
        token = _login(zoomriya_id, user)["access_token"]
        assert hello_client.get("/hello/", headers=bearer(token)).json() == {"hello": user.username}

        # Signing out reaches the app as an event.
        zoomriya_id.post(f"{API}/auth/logout", headers=bearer(token))
        for message in identity_events(signed=True):
            handle_identity_message(
                store,
                sessions,
                json.dumps(message),
                verify=lambda token, audience: id_format.verify_token(
                    token, keys, audience=audience
                ),
            )
        assert hello_client.get("/hello/", headers=bearer(token)).status_code == 401
        engine.dispose()


def test_identity_events_also_wait_on_the_stream(make_user, identity_events) -> None:
    """An app that was down when a member changed still hears it (the stream)."""
    stream = f"zoomriya:stream:{id_format.IDENTITY_STREAM}"
    client = redis.Redis.from_url(settings.REDIS_URL)
    before = client.xlen(stream)
    user = make_user()
    with closing(SessionLocal()) as db:
        identity.publish(db, id_format.USER_UPDATED, db.merge(user))
    assert client.xlen(stream) == before + 1
    [(_, fields)] = client.xrevrange(stream, count=1)
    assert json.loads(fields[b"data"]) == identity_events(signed=True)[-1]
