"""Shared test helpers (plain functions; fixtures belong in conftest.py)."""

from __future__ import annotations

from app.models import User
from app.security import create_access_token, hash_password

API = "/id/api/v1"
TEST_PASSWORD = "pass1234"


def build_user(username: str, *, role: str = "admin", password: str = TEST_PASSWORD) -> User:
    """An unsaved ``User``; the caller adds, commits and deletes it."""
    return User(
        username=username,
        hashed_password=hash_password(password),
        role=role,
        is_active=True,
        token_version=0,
    )


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def auth_headers(user: User) -> dict[str, str]:
    """Bearer headers carrying a fresh access token for ``user``."""
    return bearer(create_access_token(int(user.id), user.token_version))


def finish_sign_in(client, response):
    """A login's answer, through the second step when it asks for one (an
    admin sets one up at their first sign-in). Returns the token answer."""
    from app import second_step

    if response.status_code == 403 and response.json().get("code") == "second_step_setup_needed":
        ticket = response.json()["ticket"]
        key = client.post(f"{API}/auth/second-step/setup", json={"ticket": ticket}).json()["key"]
        response = client.post(
            f"{API}/auth/second-step/setup/finish",
            json={"ticket": ticket, "code": second_step.code_now(key.replace(" ", ""))},
        )
    assert response.status_code == 200, response.text
    return response.json()
