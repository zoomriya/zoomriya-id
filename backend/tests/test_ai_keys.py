"""Keys for a member's own AI apps (``mcp``) and the MCP service's trade."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from app import accounts as identity
from app.config import settings
from app.db import SessionLocal
from app.main import app
from app.models import ROLE_FAMILY, AiKey, User
from app.routes import ai_keys
from app.security import decode_access_token
from tests.helpers import API, auth_headers, build_user

client = TestClient(app)
SECRET = "s" * 40


@pytest.fixture
def box(monkeypatch, tmp_path) -> Iterator[dict[str, User]]:
    """A box with Vault and MCP installed, the service's secret, an adult and a child."""
    secret = tmp_path / "mcp-service.key"
    secret.write_text(SECRET)
    patched = replace(settings, INSTALLED_APPS=("vault", "mcp"), MCP_SERVICE_KEY_FILE=str(secret))
    monkeypatch.setattr(identity, "settings", patched)
    monkeypatch.setattr(ai_keys, "settings", patched)
    made = {}
    with SessionLocal() as db:
        for name, is_child in (("adult", False), ("child", True)):
            user = build_user(f"pytest-ai-{uuid.uuid4().hex[:10]}", role=ROLE_FAMILY)
            user.is_child = is_child
            if is_child:
                user.birth_year = datetime.now(UTC).year - 10
            db.add(user)
            db.commit()
            db.refresh(user)
            db.expunge(user)
            made[name] = user
    yield made
    with SessionLocal() as db:
        ids = [u.id for u in made.values()]
        db.execute(delete(AiKey).where(AiKey.user_id.in_(ids)))
        db.execute(delete(User).where(User.id.in_(ids)))
        db.commit()


def _switch(user: User, on: bool) -> None:
    with SessionLocal() as db:
        identity.set_app_access(db, db.get(User, user.id), "mcp", on)
        db.commit()


def test_ai_apps_are_off_until_an_admin_turns_them_on(box) -> None:
    adult = box["adult"]
    with SessionLocal() as db:
        assert identity.apps_for(db, db.get(User, adult.id)) == ["vault"]
    refused = client.post(
        f"{API}/auth/me/ai-keys", json={"name": "Laptop"}, headers=auth_headers(adult)
    )
    assert refused.status_code == 403
    _switch(adult, True)
    with SessionLocal() as db:
        assert identity.apps_for(db, db.get(User, adult.id)) == ["vault", "mcp"]


def test_never_for_a_child(box) -> None:
    child = box["child"]
    with pytest.raises(ValueError):
        _switch(child, True)
    with SessionLocal() as db:
        row = db.get(User, child.id)
        assert "mcp" not in identity.apps_for(db, row)
        assert "mcp" not in [a["app"] for a in identity.app_access(db, row)]


def test_a_key_is_shown_once_and_traded_only_by_the_service(box) -> None:
    adult = box["adult"]
    _switch(adult, True)
    made = client.post(
        f"{API}/auth/me/ai-keys", json={"name": " Claude  on laptop "}, headers=auth_headers(adult)
    )
    assert made.status_code == 201, made.text
    key = made.json()["key"]
    assert key.startswith("zr_ai_") and made.json()["name"] == "Claude on laptop"
    listed = client.get(f"{API}/auth/me/ai-keys", headers=auth_headers(adult)).json()["keys"]
    assert len(listed) == 1 and "key" not in listed[0] and listed[0]["last_used_at"] is None

    # Without the service's secret, the key alone gets nothing.
    alone = client.post(f"{API}/auth/ai-keys/token", headers={"Authorization": f"Bearer {key}"})
    assert alone.status_code == 403
    service = {"Authorization": f"Bearer {key}", "X-Zoomriya-Service": SECRET}
    traded = client.post(f"{API}/auth/ai-keys/token", headers=service)
    assert traded.status_code == 200, traded.text
    claims = decode_access_token(traded.json()["access_token"])
    assert claims["sub"] == str(adult.id) and claims["apps"] == ["vault", "mcp"]
    assert client.get(f"{API}/auth/me/ai-keys", headers=auth_headers(adult)).json()["keys"][0][
        "last_used_at"
    ]

    # Switched off again: the key stops working at once.
    _switch(adult, False)
    assert client.post(f"{API}/auth/ai-keys/token", headers=service).status_code == 403
    _switch(adult, True)
    # Removed: gone for good.
    key_id = listed[0]["id"]
    assert (
        client.delete(f"{API}/auth/me/ai-keys/{key_id}", headers=auth_headers(adult)).status_code
        == 204
    )
    assert client.post(f"{API}/auth/ai-keys/token", headers=service).status_code == 401


def test_a_wrong_key_or_no_secret_file(box, monkeypatch) -> None:
    service = {"Authorization": "Bearer zr_ai_nope", "X-Zoomriya-Service": SECRET}
    assert client.post(f"{API}/auth/ai-keys/token", headers=service).status_code == 401
    monkeypatch.setattr(
        ai_keys, "settings", replace(ai_keys.settings, MCP_SERVICE_KEY_FILE="/nonexistent")
    )
    assert client.post(f"{API}/auth/ai-keys/token", headers=service).status_code == 403
