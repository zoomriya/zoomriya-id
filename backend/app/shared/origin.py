"""Only the box's own pages may change anything (audit SEC-07).

Every app sits behind the gateway at one origin, and its access token can be
read by any script on that origin, so a request that changes something
(POST, PUT, PATCH, DELETE) is refused when a browser says it came from a page
on another origin. The check compares the request's ``Origin`` with the
address it was sent to (``Host``, or ``X-Forwarded-Host`` from the gateway).

No ``Origin`` is allowed: browsers always send one with a cross-origin
request that changes something, so a request without one comes from a
program (a script, the phone app), which the token check covers. ``null``
(a sandboxed frame, a file) is refused.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlsplit

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def origin_allowed(
    headers: Mapping[str, str],
    *,
    also: Callable[[str], bool] | None = None,
) -> bool:
    """Whether a request with these headers may come from its page.

    ``also(origin)`` lets an app allow more origins (Photos' dev servers on
    other ports, from its CORS settings).
    """
    origin = headers.get("origin")
    if not origin:
        return True
    if origin != "null":
        host = headers.get("x-forwarded-host") or headers.get("host") or ""
        if urlsplit(origin).netloc.lower() == host.split(",")[0].strip().lower():
            return True
    return bool(also and origin != "null" and also(origin))


class OriginCheckMiddleware:
    """Refuse (403) a browser's request that changes something from another origin."""

    def __init__(self, app: Any, *, also: Callable[[str], bool] | None = None) -> None:
        self.app = app
        self.also = also

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http" and scope.get("method") in UNSAFE_METHODS:
            headers = {
                key.decode("latin-1").lower(): value.decode("latin-1")
                for key, value in scope.get("headers") or []
            }
            if not origin_allowed(headers, also=self.also):
                body = b'{"detail":"This request didn\'t come from the box\'s own pages"}'
                await send(
                    {
                        "type": "http.response.start",
                        "status": 403,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode()),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)
