"""Your own account: profile, password, profile photo and preferences."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from app import avatars
from app.db import SessionLocal
from app.main import app
from app.models import ROLE_FAMILY, User
from tests.helpers import API, TEST_PASSWORD, auth_headers, build_user

client = TestClient(app)


@pytest.fixture
def account() -> Iterator[dict[str, Any]]:
    """An admin and a family member; both removed (with their photos) on exit."""
    db = SessionLocal()
    users = [
        build_user(f"pytest-account-{uuid.uuid4().hex[:8]}", role=role)
        for role in ("admin", ROLE_FAMILY)
    ]
    db.add_all(users)
    db.commit()
    try:
        yield {"db": db, "admin": users[0], "member": users[1]}
    finally:
        db.rollback()
        ids = [u.id for u in users]
        for path in db.execute(select(User.avatar_path).where(User.id.in_(ids))).scalars():
            avatars.delete_avatar_file(path)
        db.execute(delete(User).where(User.id.in_(ids)))
        db.commit()
        db.close()


def test_me_includes_member_since(account: dict[str, Any]) -> None:
    body = client.get(f"{API}/auth/me", headers=auth_headers(account["member"])).json()
    assert body["role"] == ROLE_FAMILY
    assert body["created_at"]


def test_update_own_display_name(account: dict[str, Any]) -> None:
    headers = auth_headers(account["member"])
    changed = client.patch(f"{API}/auth/me", headers=headers, json={"display_name": "  Amma  "})
    assert changed.status_code == 200
    assert changed.json()["display_name"] == "Amma"

    cleared = client.patch(f"{API}/auth/me", headers=headers, json={"display_name": ""})
    assert cleared.json()["display_name"] == account["member"].username


def test_change_password_keeps_this_session_and_ends_others(account: dict[str, Any]) -> None:
    member = account["member"]
    old_headers = auth_headers(member)

    wrong = client.post(
        f"{API}/auth/me/password",
        headers=old_headers,
        json={"current_password": "not-it", "new_password": "a-new-password"},
    )
    assert wrong.status_code == 400

    changed = client.post(
        f"{API}/auth/me/password",
        headers=old_headers,
        json={"current_password": TEST_PASSWORD, "new_password": "a-new-password"},
    )
    assert changed.status_code == 200
    new_token = changed.json()["access_token"]

    # Other sessions (the old token) are signed out; this one continues.
    assert client.get(f"{API}/auth/me", headers=old_headers).status_code == 401
    assert (
        client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {new_token}"}).status_code
        == 200
    )
    login = client.post(
        f"{API}/auth/login", json={"username": member.username, "password": "a-new-password"}
    )
    assert login.status_code == 200


def test_change_password_rejects_short_or_same(account: dict[str, Any]) -> None:
    headers = auth_headers(account["member"])
    short = client.post(
        f"{API}/auth/me/password",
        headers=headers,
        json={"current_password": TEST_PASSWORD, "new_password": "short"},
    )
    assert short.status_code == 422
    same = client.post(
        f"{API}/auth/me/password",
        headers=headers,
        json={"current_password": TEST_PASSWORD, "new_password": TEST_PASSWORD},
    )
    assert same.status_code == 400


# --- profile photos -----------------------------------------------------------


def _png(size: tuple[int, int] = (640, 480), exif_gps: bool = False) -> bytes:
    import io

    from PIL import Image

    image = Image.new("RGB", size, (200, 80, 40))
    out = io.BytesIO()
    if exif_gps:
        exif = Image.Exif()
        exif[0x010F] = "SecretCam"  # Make
        image.save(out, "JPEG", exif=exif)
    else:
        image.save(out, "PNG")
    return out.getvalue()


def test_upload_and_remove_avatar(account: dict[str, Any]) -> None:
    import io

    from PIL import Image

    member, admin = account["member"], account["admin"]
    headers = auth_headers(member)

    uploaded = client.post(
        f"{API}/auth/me/avatar",
        headers=headers,
        files={"file": ("me.jpg", _png(exif_gps=True), "image/jpeg")},
    )
    assert uploaded.status_code == 200
    version = uploaded.json()["avatar_version"]
    assert version is not None

    # Another family member can see it; it's a clean 256px WebP.
    image = client.get(f"{API}/users/{member.id}/avatar?v={version}", headers=auth_headers(admin))
    assert image.status_code == 200
    assert image.headers["content-type"] == "image/webp"
    decoded = Image.open(io.BytesIO(image.content))
    assert decoded.size == (avatars.AVATAR_SIZE, avatars.AVATAR_SIZE)
    assert not decoded.getexif()

    # The directory carries the version, so every app shows the new photo.
    people = client.get(f"{API}/users/directory", headers=auth_headers(admin)).json()
    assert next(p for p in people if p["id"] == member.id)["avatar_version"] == version

    db = account["db"]
    db.refresh(member)
    stored = avatars.avatar_file(member.avatar_path)
    assert stored.is_file()

    # Replacing keeps one file; removing deletes it and goes back to initials.
    replaced = client.post(
        f"{API}/auth/me/avatar", headers=headers, files={"file": ("again.png", _png(), "image/png")}
    )
    assert replaced.json()["avatar_version"] != version
    assert not stored.exists()
    db.refresh(member)
    newer = avatars.avatar_file(member.avatar_path)

    removed = client.delete(f"{API}/auth/me/avatar", headers=headers)
    assert removed.json()["avatar_version"] is None
    assert not newer.exists()
    assert client.get(f"{API}/users/{member.id}/avatar", headers=headers).status_code == 404


def test_avatar_rejects_non_images_and_needs_sign_in(account: dict[str, Any]) -> None:
    headers = auth_headers(account["member"])
    bad = client.post(
        f"{API}/auth/me/avatar",
        headers=headers,
        files={"file": ("x.png", b"not an image", "image/png")},
    )
    assert bad.status_code == 400
    assert client.get(f"{API}/users/{account['member'].id}/avatar").status_code == 401


def test_avatar_accepts_only_jpeg_and_png(account: dict[str, Any]) -> None:
    import io

    from PIL import Image

    headers = auth_headers(account["member"])
    for fmt in ("WEBP", "GIF", "BMP", "TIFF"):
        out = io.BytesIO()
        Image.new("RGB", (64, 64), (10, 20, 30)).save(out, fmt)
        # Even when it claims to be a JPEG, the contents decide.
        response = client.post(
            f"{API}/auth/me/avatar",
            headers=headers,
            files={"file": ("sneaky.jpg", out.getvalue(), "image/jpeg")},
        )
        assert response.status_code == 400, fmt
        assert "JPEG or PNG" in response.json()["detail"]

    for fmt, mime in (("JPEG", "image/jpeg"), ("PNG", "image/png")):
        out = io.BytesIO()
        Image.new("RGB", (64, 64), (10, 20, 30)).save(out, fmt)
        ok = client.post(
            f"{API}/auth/me/avatar", headers=headers, files={"file": ("me", out.getvalue(), mime)}
        )
        assert ok.status_code == 200, fmt


# --- preferences (theme, language) ------------------------------------------------


def test_preferences_default_then_follow_the_account(account: dict[str, Any]) -> None:
    headers = auth_headers(account["member"])
    assert client.get(f"{API}/auth/me", headers=headers).json()["preferences"] == {
        "theme": None,
        "language": "en",
    }

    saved = client.patch(f"{API}/auth/me/preferences", headers=headers, json={"theme": "fjord"})
    assert saved.status_code == 200
    assert saved.json()["preferences"]["theme"] == "fjord"
    # Any other session (another device) sees the same choice.
    assert client.get(f"{API}/auth/me", headers=headers).json()["preferences"]["theme"] == "fjord"
    # Other people keep their own.
    admin = client.get(f"{API}/auth/me", headers=auth_headers(account["admin"])).json()
    assert admin["preferences"]["theme"] is None

    # Leaving a field out keeps it; null goes back to the default.
    kept = client.patch(f"{API}/auth/me/preferences", headers=headers, json={"language": "en"})
    assert kept.json()["preferences"] == {"theme": "fjord", "language": "en"}
    cleared = client.patch(f"{API}/auth/me/preferences", headers=headers, json={"theme": None})
    assert cleared.json()["preferences"]["theme"] is None


def test_preferences_reject_unknown_values(account: dict[str, Any]) -> None:
    headers = auth_headers(account["member"])
    bad_theme = client.patch(
        f"{API}/auth/me/preferences", headers=headers, json={"theme": "obsidian"}
    )
    assert bad_theme.status_code == 400
    bad_language = client.patch(
        f"{API}/auth/me/preferences", headers=headers, json={"language": "xx"}
    )
    assert bad_language.status_code == 400
    assert client.patch(f"{API}/auth/me/preferences", json={"theme": "skylight"}).status_code == 401


# --- where you live -----------------------------------------------------------


@pytest.fixture
def family_in_ontario(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """The family's place not chosen on this machine: Canada, Ontario."""
    monkeypatch.setenv("ZOOMRIYA_PLACE_FILE", str(tmp_path / "place.json"))
    monkeypatch.delenv("ZOOMRIYA_COUNTRY", raising=False)
    monkeypatch.delenv("ZOOMRIYA_REGION", raising=False)


def test_you_live_with_the_family_until_you_choose(
    account: dict[str, Any], family_in_ontario: None
) -> None:
    headers = auth_headers(account["member"])
    shown = client.get(f"{API}/auth/me", headers=headers).json()["place"]
    assert (shown["country"], shown["region"], shown["own"]) == ("CA", "ON", False)
    assert shown["family"]["name"] == "Ontario"

    # At university in Alberta.
    moved = client.put(f"{API}/auth/me/place", headers=headers, json={"place": "ca-ab"})
    assert moved.status_code == 200
    assert (moved.json()["place"]["name"], moved.json()["place"]["own"]) == ("Alberta", True)
    directory = client.get(f"{API}/users/directory", headers=headers).json()
    assert next(r for r in directory if r["id"] == account["member"].id)["place"] == "CA-AB"
    # Others keep the family's.
    assert next(r for r in directory if r["id"] == account["admin"].id)["place"] is None

    back = client.put(f"{API}/auth/me/place", headers=headers, json={"place": None})
    assert back.json()["place"]["own"] is False


def test_only_known_places(account: dict[str, Any]) -> None:
    headers = auth_headers(account["member"])
    for code in ("CA-ZZ", "FR-IDF", "Alberta"):
        assert (
            client.put(f"{API}/auth/me/place", headers=headers, json={"place": code}).status_code
            == 400
        )
    assert client.put(f"{API}/auth/me/place", json={"place": "CA-AB"}).status_code == 401


def test_the_places_to_choose_from(account: dict[str, Any]) -> None:
    shown = client.get(f"{API}/auth/places", headers=auth_headers(account["member"])).json()
    canada = shown["countries"][0]
    assert (canada["code"], canada["regions"][0]) == ("CA", {"code": "CA-AB", "name": "Alberta"})
    assert len(shown["countries"][1]["regions"]) == 51
