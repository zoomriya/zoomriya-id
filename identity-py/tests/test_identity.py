"""ZOOMRIYA ID's shared token, key and event formats."""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zoomriya_identity import identity


def _token(private_key: Ed25519PrivateKey, **overrides: object) -> str:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "iss": identity.ISSUER,
        "aud": identity.AUDIENCE,
        "sub": "7",
        "ver": 3,
        "iat": now,
        "exp": now + timedelta(minutes=15),
    }
    claims.update(overrides)
    kid = overrides.pop("kid", None) or identity.key_id(private_key.public_key())
    claims.pop("kid", None)
    return jwt.encode(claims, private_key, algorithm=identity.ALGORITHM, headers={"kid": kid})


def test_jwks_round_trip_and_verify() -> None:
    private_key = Ed25519PrivateKey.generate()
    document = identity.jwks_document([private_key.public_key()])
    keys = identity.keys_from_jwks(json.loads(json.dumps(document)))

    claims = identity.verify_token(_token(private_key), keys)

    assert claims["sub"] == "7" and claims["ver"] == 3
    assert list(keys) == [identity.key_id(private_key.public_key())]


def test_key_id_is_stable() -> None:
    public_key = Ed25519PrivateKey.generate().public_key()
    assert identity.key_id(public_key) == identity.key_id(public_key)
    assert identity.public_jwk(public_key)["kid"] == identity.key_id(public_key)


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "someone-else"},
        {"aud": identity.SESSION_AUDIENCE},
        {"iss": "not-zoomriya"},
        {"exp": datetime.now(UTC) - timedelta(seconds=1)},
    ],
)
def test_wrong_claims_are_refused(overrides: dict[str, object]) -> None:
    private_key = Ed25519PrivateKey.generate()
    keys = {identity.key_id(private_key.public_key()): private_key.public_key()}
    with pytest.raises(jwt.InvalidTokenError):
        identity.verify_token(_token(private_key, **overrides), keys)


def test_other_signers_and_algorithms_are_refused() -> None:
    ours, theirs = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    keys = {identity.key_id(ours.public_key()): ours.public_key()}

    # Signed by another key that claims our kid.
    forged = _token(theirs, kid=identity.key_id(ours.public_key()))
    with pytest.raises(jwt.InvalidSignatureError):
        identity.verify_token(forged, keys)

    with pytest.raises(identity.UnknownKeyError):
        identity.verify_token(_token(theirs), keys)

    hs256 = jwt.encode({"sub": "7"}, "x" * 32, algorithm="HS256")
    with pytest.raises(jwt.InvalidAlgorithmError):
        identity.verify_token(hs256, keys)


def test_session_tokens_need_the_session_audience() -> None:
    private_key = Ed25519PrivateKey.generate()
    keys = {identity.key_id(private_key.public_key()): private_key.public_key()}
    session = _token(private_key, aud=identity.SESSION_AUDIENCE)
    claims = identity.verify_token(session, keys, audience=identity.SESSION_AUDIENCE)
    assert claims["aud"] == identity.SESSION_AUDIENCE


def test_keys_from_jwks_skips_what_it_cannot_use() -> None:
    good = Ed25519PrivateKey.generate().public_key()
    document = {
        "keys": [
            {"kty": "RSA", "kid": "rsa", "n": "x", "e": "AQAB"},
            {"kty": "OKP", "crv": "Ed25519", "kid": "short", "x": "AAAA"},
            "not a key",
            identity.public_jwk(good),
        ]
    }
    assert list(identity.keys_from_jwks(document)) == [identity.key_id(good)]


class _JwksServer:
    """A tiny local server for the JWKS client: counts fetches."""

    def __init__(self, document: Mapping[str, object]) -> None:
        self.document = document
        self.fetches = 0
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                owner.fetches += 1
                body = json.dumps(owner.document).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/api/v1/auth/jwks.json"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def test_jwks_client_caches_and_refetches_for_a_new_key() -> None:
    first, second = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    server = _JwksServer(identity.jwks_document([first.public_key()]))
    try:
        client = identity.JWKSClient(server.url, min_refetch_seconds=0)
        assert client.verify(_token(first))["sub"] == "7"
        assert client.verify(_token(first))["sub"] == "7"
        assert server.fetches == 1

        # Rotation: Photos now publishes the new key too.
        server.document = identity.jwks_document([first.public_key(), second.public_key()])
        assert client.verify(_token(second))["sub"] == "7"
        assert server.fetches == 2
    finally:
        server.close()


def test_jwks_client_limits_refetches_for_unknown_keys() -> None:
    known, stranger = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    server = _JwksServer(identity.jwks_document([known.public_key()]))
    try:
        client = identity.JWKSClient(server.url, min_refetch_seconds=60)
        client.keys()
        for _ in range(5):
            with pytest.raises(identity.UnknownKeyError):
                client.verify(_token(stranger))
        assert server.fetches == 1
    finally:
        server.close()


def test_member_event_envelope() -> None:
    member = {"id": 7, "display_name": "Amma", "avatar_version": None, "role": "family"}
    at = datetime(2026, 10, 4, 9, 12, tzinfo=UTC)
    event = identity.member_event(identity.USER_REVOKED, member) | {"at": "fixed"}

    assert event == {
        "type": "user:revoked",
        "app": "identity",
        "audience": [7],
        "at": "fixed",
        "data": member,
    }
    assert identity.build_event("x", app="a", audience=[], data={}, at=at)["at"] == (
        "2026-10-04T09:12:00Z"
    )
    with pytest.raises(ValueError):
        identity.member_event("chat:message", member)
