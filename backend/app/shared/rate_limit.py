"""In-memory sliding-window rate limiting.

Suitable for single-instance deployments (the default for ZOOMRIYA). For
multi-instance setups, swap the store for Redis without changing the
middleware interface.
"""

import time
from collections import defaultdict
from collections.abc import Sequence
from threading import Lock

from fastapi import Request
from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class RateLimitConfig:
    """Rate limit rule for a set of endpoints."""

    def __init__(self, requests: int, window_seconds: int, prefix: str):
        self.requests = requests
        self.window_seconds = window_seconds
        self.prefix = prefix


class RateLimiter:
    """Timestamps per key (``<client>:<prefix>`` or any caller-chosen key)."""

    def __init__(self) -> None:
        self.buckets: dict[str, list[float]] = defaultdict(list)
        self.lock = Lock()

    def is_rate_limited(self, key: str, config: RateLimitConfig) -> bool:
        """Count this request and say whether ``key`` is over ``config``'s limit."""
        now = time.time()
        window_start = now - config.window_seconds

        with self.lock:
            # Only the requests still inside the window count. The bucket is
            # replaced, not trimmed in place, so a key whose old requests all
            # expired doesn't keep them in memory.
            timestamps = [t for t in self.buckets.get(key, ()) if t > window_start]
            if len(timestamps) >= config.requests:
                self.buckets[key] = timestamps
                return True
            timestamps.append(now)
            self.buckets[key] = timestamps
            return False

    def is_blocked(self, key: str, *, requests: int, window_seconds: int) -> bool:
        """Whether ``key`` has had ``requests`` failures (see ``record_failure``)
        within the window; for limits that count only wrong attempts."""
        window_start = time.time() - window_seconds
        with self.lock:
            timestamps = self.buckets.get(key)
            if not timestamps:
                return False
            timestamps[:] = [t for t in timestamps if t > window_start]
            if not timestamps:
                del self.buckets[key]
                return False
            return len(timestamps) >= requests

    def record_failure(self, key: str) -> None:
        with self.lock:
            self.buckets[key].append(time.time())


def client_key(request: Request) -> str:
    """Identify the client by IP + a forwarded header if behind a proxy."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Apply rate limiting based on URL prefix."""

    def __init__(
        self, app, rules: Sequence[RateLimitConfig], limiter: RateLimiter  # noqa: ANN001
    ) -> None:
        super().__init__(app)
        self.rules = rules
        self.limiter = limiter

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        client = client_key(request)

        for rule in self.rules:
            if path.startswith(rule.prefix):
                key = f"{client}:{rule.prefix}"
                if self.limiter.is_rate_limited(key, rule):
                    return JSONResponse(
                        status_code=429,
                        content={"detail": "Too many requests. Please slow down."},
                        # Headers (not a bare dict): Pylance stub for this
                        # Response types ``headers`` as ``Headers | None``.
                        headers=Headers(
                            {"Retry-After": str(rule.window_seconds)}
                        ),
                    )

        return await call_next(request)
