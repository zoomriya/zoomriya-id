"""The second sign-in step: a code from an authenticator app (RFC 6238), or one
of ten backup codes, after the password. Required for admins, a choice for
everyone else (Solutions Design, decision 27).

- **The app's secret** is kept encrypted (AES-GCM) with a key of ZOOMRIYA ID's
  own beside its signing key, so a copy of the database alone can't make
  codes. A code's time step is remembered, so the same code can't be used
  twice.
- **Backup codes** are ten random codes shown once; only their hashes are kept,
  and each works once.
- **Tickets** carry a sign-in from the password to the second step: signed by
  ZOOMRIYA ID, for five minutes, useless anywhere else. ``check`` asks for a
  code; ``setup`` lets an admin who has no second step yet set one up first.
- **The QR code** is drawn here (SVG), so Family Hub, Box Desktop and the box's
  setup show the same one.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import os
import secrets
import struct
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

import segno
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from zoomriya_identity import identity

from app.config import settings

ISSUER_NAME = "ZOOMRIYA"
DIGITS = 6
PERIOD = 30
#: Codes one step either side are accepted, for a phone's clock a little off.
DRIFT = 1
BACKUP_CODES = 10
#: Easy to read aloud and type: no 0/O, 1/I/L.
_BACKUP_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
TICKET_AUDIENCE = "zoomriya-id:second-step"
TICKET_MINUTES = 5
CHECK = "check"
SETUP = "setup"


# --- the app's secret, kept encrypted -----------------------------------------


def _key_path() -> Path:
    return settings.signing_key_path.parent / "second-step.key"


def _key() -> bytes:
    """ZOOMRIYA ID's own key for the secrets, made on first use (this user only)."""
    path = _key_path()
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return _key()
        data = AESGCM.generate_key(bit_length=256)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    if len(data) != 32:
        raise ValueError(f"{path} isn't a 256-bit key")
    return data


def new_secret() -> str:
    """A new secret for an authenticator app, in base32 (what people can type)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def seal(secret: str, user_id: int) -> str:
    nonce = secrets.token_bytes(12)
    sealed = AESGCM(_key()).encrypt(nonce, secret.encode(), str(user_id).encode())
    return base64.b64encode(nonce + sealed).decode()


def unseal(sealed: str, user_id: int) -> str:
    raw = base64.b64decode(sealed)
    return AESGCM(_key()).decrypt(raw[:12], raw[12:], str(user_id).encode()).decode()


# --- codes --------------------------------------------------------------------


def _code_at(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10**DIGITS).zfill(DIGITS)


def code_now(secret: str, at: float | None = None) -> str:
    return _code_at(secret, int((time.time() if at is None else at) // PERIOD))


def matching_step(secret: str, code: str, after: int | None, at: float | None = None) -> int | None:
    """The time step this code belongs to, if it's right and newer than ``after``
    (the step used last, so a code can't be used twice)."""
    code = "".join(code.split())
    if len(code) != DIGITS or not code.isdigit():
        return None
    now = int((time.time() if at is None else at) // PERIOD)
    for step in range(now - DRIFT, now + DRIFT + 1):
        if (after is None or step > after) and hmac.compare_digest(_code_at(secret, step), code):
            return step
    return None


def setup_uri(secret: str, username: str) -> str:
    """What the QR code holds: authenticator apps add the account from it."""
    label = quote(f"{ISSUER_NAME}:{username}", safe=":@")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={ISSUER_NAME}"
        f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}"
    )


def qr_svg(text: str) -> str:
    """The QR code as SVG: dark on white with a quiet border, which every
    camera reads, in light and dark themes alike."""
    out = io.BytesIO()
    segno.make(text, error="m").save(
        out, kind="svg", scale=6, border=4, dark="#000", light="#fff", xmldecl=False, svgns=True
    )
    return out.getvalue().decode()


# --- backup codes -------------------------------------------------------------


def _hash_backup(code: str) -> str:
    return hashlib.sha256(_normal_backup(code).encode()).hexdigest()


def _normal_backup(code: str) -> str:
    return "".join(c for c in code.upper() if c.isalnum())


def new_backup_codes() -> tuple[list[str], list[str]]:
    """Ten codes to show once (``ABCDE-FGHJK``), and the hashes to keep."""
    shown = []
    for _ in range(BACKUP_CODES):
        raw = "".join(secrets.choice(_BACKUP_ALPHABET) for _ in range(10))
        shown.append(f"{raw[:5]}-{raw[5:]}")
    return shown, [_hash_backup(code) for code in shown]


def use_backup_code(kept: list[str] | None, code: str) -> list[str] | None:
    """The hashes left once this code is used, or None if it isn't one of them."""
    if not kept or len(_normal_backup(code)) != 10:
        return None
    wanted = _hash_backup(code)
    for i, hashed in enumerate(kept):
        if hmac.compare_digest(hashed, wanted):
            return kept[:i] + kept[i + 1 :]
    return None


# --- tickets ------------------------------------------------------------------


def create_ticket(user_id: int, token_version: int, purpose: str) -> str:
    from app.security import _sign

    now = datetime.now(UTC)
    return _sign(
        {
            "iss": identity.ISSUER,
            "aud": TICKET_AUDIENCE,
            "sub": str(user_id),
            "ver": token_version,
            "use": purpose,
            "iat": now,
            "exp": now + timedelta(minutes=TICKET_MINUTES),
        }
    )


def read_ticket(ticket: str) -> dict[str, Any]:
    """The ticket's claims; ``jwt.InvalidTokenError`` when it isn't a good one."""
    from app.security import _our_keys

    return identity.verify_token(ticket, _our_keys(), audience=TICKET_AUDIENCE)
