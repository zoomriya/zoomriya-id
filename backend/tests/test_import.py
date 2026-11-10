"""Moving the accounts out of Photos: nobody is signed out, nothing is lost."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, delete, select, text
from zoomriya_identity import identity

from app import security
from app.config import settings
from app.db import SessionLocal
from app.import_from_photos import ImportRefused, import_accounts
from app.main import app
from app.models import User, UserAppAccess
from app.security import hash_password
from tests.helpers import API, bearer, finish_sign_in

PHOTOS_SCHEMA = "pytest_photos"

# Photos' tables after its migration 0007 (only the columns the import reads).
PHOTOS_TABLES = """
CREATE TABLE users (
    id BIGINT PRIMARY KEY, username VARCHAR(128) UNIQUE NOT NULL,
    display_name VARCHAR(128), avatar_path VARCHAR(255),
    avatar_version INTEGER, theme VARCHAR(32), language VARCHAR(16),
    hashed_password VARCHAR(255), role VARCHAR(32) NOT NULL,
    is_active BOOLEAN NOT NULL, token_version INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE user_app_access (
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE, app VARCHAR(32),
    enabled BOOLEAN NOT NULL, PRIMARY KEY (user_id, app)
);
CREATE TABLE system_settings (key VARCHAR(64) PRIMARY KEY, value VARCHAR(255) NOT NULL);
"""


def _in_schema(url: str, schema: str) -> str:
    """The test database's URL, with ``schema`` as the only search path."""
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query) if k != "options"]
    query.append(("options", f"-csearch_path={schema}"))
    return urlunsplit(parts._replace(query=urlencode(query)))


@pytest.fixture
def photos(tmp_path: Path) -> Iterator[dict[str, Any]]:
    """Photos' accounts in a schema of their own, its library and its signing key."""
    with SessionLocal() as db:
        if db.execute(select(User.id).limit(1)).first() is not None:
            pytest.skip("The test database has accounts left over from another run")

    url = _in_schema(settings.DATABASE_URL, PHOTOS_SCHEMA)
    admin_engine = create_engine(settings.DATABASE_URL)
    with admin_engine.begin() as conn:
        conn.execute(text(f"DROP SCHEMA IF EXISTS {PHOTOS_SCHEMA} CASCADE"))
        conn.execute(text(f"CREATE SCHEMA {PHOTOS_SCHEMA}"))
    photos_engine = create_engine(url)
    base = 900_000 + uuid.uuid4().int % 10_000
    ids = {"amma": base + 1, "appa": base + 2, "paati": base + 3}
    library = tmp_path / "library"
    with photos_engine.begin() as conn:
        for statement in PHOTOS_TABLES.split(";"):
            if statement.strip():
                conn.execute(text(statement))
        conn.execute(
            text(
                "INSERT INTO users (id, username, display_name, avatar_path, avatar_version,"
                " theme, hashed_password, role, is_active, token_version) VALUES"
                " (:amma, 'amma', 'Amma', 'avatars/amma.webp', 3, 'fjord', :pw, 'admin', true, 2),"
                " (:appa, 'appa', NULL, 'avatars/gone.webp', 1, NULL, :pw, 'family', false, 0),"
                # As Photos' migration 0007 leaves a member who joined after it:
                # no password there, and no photo is NULL.
                " (:paati, 'paati', 'Paati', NULL, NULL, NULL, NULL, 'family', true, 0)"
            ),
            {**ids, "pw": hash_password("amma-password")},
        )
        conn.execute(
            text("INSERT INTO user_app_access VALUES (:appa, 'vault', false)"), ids
        )
        conn.execute(
            text("INSERT INTO system_settings VALUES ('storage.library_root', :library)"),
            {"library": str(library)},
        )
    photos_engine.dispose()

    (library / "avatars").mkdir(parents=True)
    (library / "avatars" / "amma.webp").write_bytes(b"amma's photo")
    photos_key = Ed25519PrivateKey.generate()
    key_file = tmp_path / "photos-key.pem"
    key_file.write_bytes(
        photos_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    security.signing_key()  # made on first use; this test may be the first
    our_key = settings.signing_key_path.read_bytes()

    yield {"url": url, "key_file": key_file, "key": photos_key, "ids": ids}

    # Put the tests' own key back, and remove what was imported.
    settings.signing_key_path.write_bytes(our_key)
    security._signing_key = None
    with SessionLocal() as db:
        db.execute(delete(User))
        db.commit()
    with admin_engine.begin() as conn:
        conn.execute(text(f"DROP SCHEMA {PHOTOS_SCHEMA} CASCADE"))
    admin_engine.dispose()


def _import(photos: dict[str, Any]):
    # The library is found where Photos keeps it (its storage setting).
    report = import_accounts(photos["url"], None, photos["key_file"])
    security._signing_key = None  # the service is restarted after an import
    return report


def test_accounts_move_with_their_ids_passwords_and_switches(photos) -> None:
    report = _import(photos)
    assert (
        report.users,
        report.app_switches,
        report.avatars,
        report.missing_avatars,
        report.skipped,
    ) == (2, 1, 1, 1, 1)
    ids = photos["ids"]
    with SessionLocal() as db:
        amma = db.get(User, ids["amma"])
        appa = db.get(User, ids["appa"])
        assert amma is not None and appa is not None
        assert (amma.display_name, amma.role, amma.token_version, amma.theme) == (
            "Amma",
            "admin",
            2,
            "fjord",
        )
        assert amma.avatar_ref == 3
        assert appa.is_active is False and appa.avatar_path is None
        assert db.get(User, ids["paati"]) is None
        assert db.get(UserAppAccess, (ids["appa"], "vault")).enabled is False

    assert (Path(settings.DATA_DIR) / "avatars" / "amma.webp").read_bytes() == b"amma's photo"
    client = TestClient(app)
    # The imported password still works; an admin then sets up the second step.
    login = finish_sign_in(
        client,
        client.post(f"{API}/auth/login", json={"username": "amma", "password": "amma-password"}),
    )
    # New accounts continue after Photos' ids.
    created = client.post(
        f"{API}/users",
        headers=bearer(login["access_token"]),
        json={"username": "pytest-after-import", "password": "temporary1"},
    )
    assert created.json()["id"] > ids["appa"]


def test_a_session_photos_signed_keeps_renewing(photos) -> None:
    _import(photos)
    now = datetime.now(UTC)
    key = photos["key"]
    session = jwt.encode(
        {
            "iss": identity.ISSUER,
            "aud": identity.SESSION_AUDIENCE,
            "sub": str(photos["ids"]["amma"]),
            "ver": 2,
            "iat": now,
            "exp": now + timedelta(days=30),
        },
        key,
        algorithm=identity.ALGORITHM,
        headers={"kid": identity.key_id(key.public_key())},
    )
    client = TestClient(app)
    client.cookies.set(identity.SESSION_COOKIE_NAME, session)
    assert client.post(f"{API}/auth/refresh").status_code == 200
    [jwk] = client.get(f"{API}/auth/jwks.json").json()["keys"]
    assert jwk["kid"] == identity.key_id(key.public_key())


def test_it_runs_once(photos) -> None:
    _import(photos)
    with pytest.raises(ImportRefused):
        _import(photos)


def test_a_photos_database_after_migration_0009_is_refused(photos) -> None:
    """Photos' 0009 drops the old account columns: nothing to import, said plainly."""
    engine = create_engine(photos["url"])
    with engine.begin() as conn:
        for column in ("hashed_password", "theme", "language", "avatar_path"):
            conn.execute(text(f"ALTER TABLE users DROP COLUMN {column}"))
    engine.dispose()
    with pytest.raises(ImportRefused, match="migration 0009"):
        _import(photos)
    with SessionLocal() as db:
        assert db.execute(select(User.id).limit(1)).first() is None
