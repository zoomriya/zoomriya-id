"""Sign-in cookies over HTTPS are Secure, with nothing to set.

The gateway serves the box over HTTPS (ZOOMRIYA OS makes its certificate at
the first start) and says so in ``X-Forwarded-Proto``. On a response to such a
request every cookie is marked ``Secure``, so a browser never sends it over
plain HTTP. ``AUTH_COOKIE_SECURE`` still forces it; plain HTTP (a developer's
machine) is left as it is. A forged header can only make a cookie stricter.
"""

from __future__ import annotations

from typing import Any


def _over_https(scope: dict[str, Any]) -> bool:
    if scope.get("scheme") == "https":
        return True
    for key, value in scope.get("headers") or []:
        if key.lower() == b"x-forwarded-proto":
            return value.split(b",")[0].strip().lower() == b"https"
    return False


def _secure(value: bytes) -> bytes:
    parts = [p.strip().lower() for p in value.split(b";")]
    return value if b"secure" in parts else value + b"; Secure"


class SecureCookiesMiddleware:
    """Mark every cookie Secure on a response to an HTTPS request."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http" or not _over_https(scope):
            await self.app(scope, receive, send)
            return

        async def send_secure(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = [
                    (key, _secure(value) if key.lower() == b"set-cookie" else value)
                    for key, value in message.get("headers") or []
                ]
            await send(message)

        await self.app(scope, receive, send_secure)
