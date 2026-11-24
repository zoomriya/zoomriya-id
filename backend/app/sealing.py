"""ZOOMRIYA ID's own key for what it keeps secret in its database: the family
email account's password, and the second step's codes (as keyed hashes). It
sits beside the signing key, so a copy of the database alone gives neither
away."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings


def _key_path() -> Path:
    return settings.signing_key_path.parent / "second-step.key"


def key() -> bytes:
    """The key, made on first use (this user only)."""
    path = _key_path()
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return key()
        data = AESGCM.generate_key(bit_length=256)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    if len(data) != 32:
        raise ValueError(f"{path} isn't a 256-bit key")
    return data


def seal(text: str, label: str) -> str:
    """Encrypted (AES-GCM), bound to ``label`` so it can't be moved elsewhere."""
    nonce = secrets.token_bytes(12)
    sealed = AESGCM(key()).encrypt(nonce, text.encode(), label.encode())
    return base64.b64encode(nonce + sealed).decode()


def unseal(sealed: str, label: str) -> str:
    raw = base64.b64decode(sealed)
    return AESGCM(key()).decrypt(raw[:12], raw[12:], label.encode()).decode()


def keyed_hash(text: str) -> str:
    return hmac.new(key(), text.encode(), hashlib.sha256).hexdigest()
