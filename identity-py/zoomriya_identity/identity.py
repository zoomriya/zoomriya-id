"""ZOOMRIYA ID: the one login every ZOOMRIYA app shares.

ZOOMRIYA ID is its own small service (``backend/`` in this repository). It alone
holds the Ed25519 private key and signs the access tokens; every app checks
them with the public key it publishes at ``GET /id/api/v1/auth/jwks.json``,
so no app holds a shared secret.

This module is the shared format, so two apps can't drift apart:

* the token claims (``iss``, ``aud``, ``sub``, ``ver``, ``role``, ``apps``),
* the public key as a JWKS document, and a cached client that fetches it,
* the identity events on the ``zoomriya:identity`` Redis channel.

Revocation: a token carries ``ver``. Each app compares it with its own copy of
the user, which ``user:revoked`` events keep current, so a removed member is
locked out within seconds rather than when the token expires.

Identity events are signed: ZOOMRIYA ID publishes each one as a short-lived
token of its own audience (``signed_member_event``), and apps open it with the
same public key (``open_member_event``). Anything else that can reach Redis
can't make a member an admin or sign one out.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

#: Who signs every access token.
ISSUER = "zoomriya-id"
#: Who an access token is for: every ZOOMRIYA app.
AUDIENCE = "zoomriya"
#: Who a session (refresh) token is for: only ZOOMRIYA ID's ``/auth/refresh``.
#: A different audience keeps a session token from working as an access token.
SESSION_AUDIENCE = "zoomriya-id-session"
ALGORITHM = "EdDSA"

#: Short-lived access token. HttpOnly, ``Path=/``, so it reaches every app
#: behind the gateway. ``Authorization: Bearer`` works too.
AUTH_COOKIE_NAME = "zoomriya.auth.token"
#: Long-lived session that renews the access token. HttpOnly.
SESSION_COOKIE_NAME = "zoomriya.auth.session"

#: Redis channel for changes to family members.
IDENTITY_CHANNEL = "zoomriya:identity"
#: The same events on a stream (``zoomriya:stream:identity``), read by each
#: app as its own consumer group, so one sent while an app was down arrives.
IDENTITY_STREAM = "identity"
IDENTITY_APP = "identity"
USER_CREATED = "user:created"
USER_UPDATED = "user:updated"
USER_DEACTIVATED = "user:deactivated"
#: ``token_version`` went up: every token the member holds stops working.
USER_REVOKED = "user:revoked"
USER_EVENT_TYPES = frozenset({USER_CREATED, USER_UPDATED, USER_DEACTIVATED, USER_REVOKED})
#: Who a signed identity event is for. Its own audience, so an event can never
#: pass as an access or session token, nor a token as an event.
EVENT_AUDIENCE = "zoomriya-identity-event"
#: How long a signed event stays valid: Redis delivers in milliseconds, and a
#: copy someone captured can't be replayed later than this.
EVENT_LIFETIME_SECONDS = 120


class UnknownKeyError(jwt.InvalidTokenError):
    """The token names a signing key this app doesn't have."""


# --- keys ---------------------------------------------------------------------


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def key_id(public_key: Ed25519PublicKey) -> str:
    """The key's RFC 7638 thumbprint, so the same key always gets the same id."""
    x = _b64url(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
    canonical = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x}, separators=(",", ":"))
    return _b64url(hashlib.sha256(canonical.encode("ascii")).digest())


def public_jwk(public_key: Ed25519PublicKey) -> dict[str, str]:
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)),
        "kid": key_id(public_key),
        "alg": ALGORITHM,
        "use": "sig",
    }


def jwks_document(public_keys: Iterable[Ed25519PublicKey]) -> dict[str, list[dict[str, str]]]:
    return {"keys": [public_jwk(key) for key in public_keys]}


def keys_from_jwks(document: Mapping[str, Any]) -> dict[str, Ed25519PublicKey]:
    """The Ed25519 keys in a JWKS document, by ``kid``. Other key types are skipped."""
    keys: dict[str, Ed25519PublicKey] = {}
    for entry in document.get("keys") or []:
        if not isinstance(entry, Mapping):
            continue
        if entry.get("kty") != "OKP" or entry.get("crv") != "Ed25519":
            continue
        x, kid = entry.get("x"), entry.get("kid")
        if not isinstance(x, str) or not isinstance(kid, str):
            continue
        try:
            key = Ed25519PublicKey.from_public_bytes(_b64url_decode(x))
        except ValueError:
            continue
        keys[kid] = key
    return keys


# --- tokens -------------------------------------------------------------------


def verify_token(
    token: str,
    keys: Mapping[str, Ed25519PublicKey],
    *,
    audience: str = AUDIENCE,
) -> dict[str, Any]:
    """Check a ZOOMRIYA ID token and return its claims.

    Raises ``jwt.InvalidTokenError`` (or a subclass) when the token isn't
    EdDSA, names an unknown key, is expired, or has the wrong issuer or
    audience. Claims are untyped JSON values, hence ``Any``.
    """
    header = jwt.get_unverified_header(token)
    if header.get("alg") != ALGORITHM:
        raise jwt.InvalidAlgorithmError("Not a ZOOMRIYA ID token")
    key = keys.get(str(header.get("kid")))
    if key is None:
        raise UnknownKeyError("Unknown signing key")
    return jwt.decode(
        token,
        key,
        algorithms=[ALGORITHM],
        audience=audience,
        issuer=ISSUER,
        options={"require": ["exp", "iat", "iss", "aud", "sub"]},
    )


class JWKSClient:
    """ZOOMRIYA ID's public keys, fetched once and cached.

    An unknown ``kid`` triggers a refetch (the key was rotated), at most once
    per ``min_refetch_seconds`` so a stream of bad tokens can't hammer ZOOMRIYA ID.
    Uses only the standard library, so it works offline on the box.
    """

    def __init__(
        self,
        url: str,
        *,
        timeout_seconds: float = 5.0,
        min_refetch_seconds: float = 30.0,
    ) -> None:
        self.url = url
        self.timeout_seconds = timeout_seconds
        self.min_refetch_seconds = min_refetch_seconds
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._fetched_at: float | None = None
        self._lock = threading.Lock()

    def _fetch(self) -> dict[str, Ed25519PublicKey]:
        with urllib.request.urlopen(self.url, timeout=self.timeout_seconds) as response:
            return keys_from_jwks(json.load(response))

    def keys(self, *, wanted_kid: str | None = None) -> dict[str, Ed25519PublicKey]:
        with self._lock:
            stale = self._fetched_at is None or (
                wanted_kid is not None
                and wanted_kid not in self._keys
                and time.monotonic() - self._fetched_at >= self.min_refetch_seconds
            )
            if stale:
                self._keys = self._fetch()
                self._fetched_at = time.monotonic()
            return dict(self._keys)

    def verify(self, token: str, *, audience: str = AUDIENCE) -> dict[str, Any]:
        kid = jwt.get_unverified_header(token).get("kid")
        return verify_token(token, self.keys(wanted_kid=str(kid)), audience=audience)


# --- events -------------------------------------------------------------------


def build_event(
    event_type: str,
    *,
    app: str,
    audience: Iterable[int],
    data: Mapping[str, Any],
    at: datetime | None = None,
) -> dict[str, Any]:
    """The envelope every app's events use (design doc, Shared contracts 3)."""
    return {
        "type": event_type,
        "app": app,
        "audience": [int(user_id) for user_id in audience],
        "at": (at or datetime.now(UTC)).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "data": dict(data),
    }


def member_event(event_type: str, member: Mapping[str, Any]) -> dict[str, Any]:
    """An identity event. ``member`` is the full directory row, so another
    app's member list can apply any event on its own."""
    if event_type not in USER_EVENT_TYPES:
        raise ValueError(f"Not an identity event: {event_type}")
    return build_event(event_type, app=IDENTITY_APP, audience=[member["id"]], data=member)


def signed_member_event(
    event_type: str,
    member: Mapping[str, Any],
    sign: Callable[[dict[str, Any]], str],
) -> dict[str, str]:
    """What ZOOMRIYA ID publishes: the event inside a token ``sign`` signs
    with its private key. ``{"token": ...}`` on the wire."""
    envelope = member_event(event_type, member)
    now = datetime.now(UTC)
    token = sign(
        {
            "iss": ISSUER,
            "aud": EVENT_AUDIENCE,
            "sub": str(member["id"]),
            "iat": now,
            "exp": now + timedelta(seconds=EVENT_LIFETIME_SECONDS),
            "event": envelope,
        }
    )
    return {"token": token}


def open_member_event(
    message: Mapping[str, Any],
    verify: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    """The event inside a signed identity message, once its signature checks.

    ``verify(token, audience=...)`` is ``JWKSClient.verify`` (or the same
    check with fixed keys). Raises ``jwt.InvalidTokenError`` for an unsigned,
    forged, expired or mismatched event.
    """
    token = message.get("token")
    if not isinstance(token, str):
        raise jwt.InvalidTokenError("Unsigned identity event")
    claims = verify(token, audience=EVENT_AUDIENCE)
    envelope = claims.get("event")
    data = envelope.get("data") if isinstance(envelope, Mapping) else None
    if not isinstance(data, Mapping) or str(data.get("id")) != str(claims.get("sub")):
        raise jwt.InvalidTokenError("The event is not about the member it was signed for")
    return dict(envelope)
