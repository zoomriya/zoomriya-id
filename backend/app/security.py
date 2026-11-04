"""Passwords, and signing ZOOMRIYA ID tokens.

Only this service holds the Ed25519 private key. The token format and the
checks every app shares live in ``zoomriya_identity.identity``.
"""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from passlib.context import CryptContext
from zoomriya_identity import identity

from app.config import settings

logger = logging.getLogger(__name__)

# Passwords are hashed with Argon2id (RFC 9106's second recommended setting:
# 64 MiB, 3 passes, 4 lanes). Hashes from before (PBKDF2-SHA256 at 29,000
# rounds, Photos' and this service's first format) still verify, and are
# replaced at the member's next sign-in (needs_rehash).
_ARGON2_MEMORY_KIB = 64 * 1024
_ARGON2_ITERATIONS = 3
_ARGON2_LANES = 4
_ARGON2_PREFIX = f"$argon2id$v=19$m={_ARGON2_MEMORY_KIB},t={_ARGON2_ITERATIONS},p={_ARGON2_LANES}$"
# Each hash holds 64 MiB for ~50 ms; the service has 512 MiB. Two at a time
# keeps a burst of sign-ins well inside it.
_hashing = threading.BoundedSemaphore(2)

_legacy_context = CryptContext(schemes=["pbkdf2_sha256"])


def hash_password(password: str) -> str:
    kdf = Argon2id(
        salt=os.urandom(16),
        length=32,
        iterations=_ARGON2_ITERATIONS,
        lanes=_ARGON2_LANES,
        memory_cost=_ARGON2_MEMORY_KIB,
    )
    with _hashing:
        return kdf.derive_phc_encoded(password.encode())


def verify_password(plain_password: str, hashed_password: str) -> bool:
    if hashed_password.startswith("$argon2id$"):
        try:
            with _hashing:
                Argon2id.verify_phc_encoded(plain_password.encode(), hashed_password)
        except (InvalidKey, ValueError):
            return False
        return True
    try:
        return _legacy_context.verify(plain_password, hashed_password)
    except (ValueError, TypeError):
        return False


def needs_rehash(hashed_password: str) -> bool:
    """True for a hash in an older format or with weaker settings than today's."""
    return not hashed_password.startswith(_ARGON2_PREFIX)


# --- the signing key ----------------------------------------------------------

_key_lock = threading.Lock()
_signing_key: tuple[str, Ed25519PrivateKey] | None = None


def _load_or_create_key(path: Path) -> Ed25519PrivateKey:
    """Read the key, or create it on first start (readable by this user only).

    ``O_EXCL`` makes concurrent API workers agree on one key: whoever loses
    the race reads the winner's file.
    """
    try:
        key = load_pem_private_key(path.read_bytes(), password=None)
    except FileNotFoundError:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        new_key = Ed25519PrivateKey.generate()
        pem = new_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return _load_or_create_key(path)
        with os.fdopen(fd, "wb") as handle:
            handle.write(pem)
            handle.flush()
            os.fsync(handle.fileno())
        logger.info("Created the ZOOMRIYA ID signing key at %s", path)
        return new_key
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def signing_key() -> tuple[str, Ed25519PrivateKey]:
    """``(kid, private key)``, loaded once per process."""
    global _signing_key
    if _signing_key is None:
        with _key_lock:
            if _signing_key is None:
                key = _load_or_create_key(settings.signing_key_path)
                _signing_key = (identity.key_id(key.public_key()), key)
    return _signing_key


def public_keys() -> dict[str, Any]:
    """The JWKS document the other apps verify tokens with."""
    return identity.jwks_document([signing_key()[1].public_key()])


# --- tokens -------------------------------------------------------------------


def _sign(claims: dict[str, Any]) -> str:
    kid, key = signing_key()
    return jwt.encode(claims, key, algorithm=identity.ALGORITHM, headers={"kid": kid})


def sign_event(claims: dict[str, Any]) -> str:
    """Sign an identity event (``identity.signed_member_event`` builds the claims)."""
    return _sign(claims)


def create_access_token(
    user_id: int,
    token_version: int,
    *,
    role: str | None = None,
    apps: Iterable[str] | None = None,
) -> str:
    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "iss": identity.ISSUER,
        "aud": identity.AUDIENCE,
        "sub": str(user_id),
        "ver": token_version,
        "iat": now,
        "exp": now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    if role is not None:
        claims["role"] = role
    if apps is not None:
        claims["apps"] = list(apps)
    return _sign(claims)


def create_session_token(user_id: int, token_version: int) -> str:
    """The long-lived cookie that renews access tokens; useless anywhere else."""
    now = datetime.now(UTC)
    return _sign(
        {
            "iss": identity.ISSUER,
            "aud": identity.SESSION_AUDIENCE,
            "sub": str(user_id),
            "ver": token_version,
            "iat": now,
            "exp": now + timedelta(days=settings.JWT_SESSION_EXPIRE_DAYS),
        }
    )


def _our_keys() -> dict[str, Any]:
    kid, key = signing_key()
    return {kid: key.public_key()}


def decode_access_token(token: str) -> dict[str, Any]:
    """Check an access token. Claims are untyped JSON values, hence ``Any``."""
    return identity.verify_token(token, _our_keys())


def decode_session_token(token: str) -> dict[str, Any]:
    return identity.verify_token(token, _our_keys(), audience=identity.SESSION_AUDIENCE)
