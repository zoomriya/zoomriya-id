"""ZOOMRIYA ID: the one sign-in every ZOOMRIYA app shares.

Its own small service, so no app's restart, update or crash stops anyone
signing in. It holds the accounts (passwords, roles, profile photos,
preferences), the sessions and the Ed25519 signing key; it serves the public
key, the family directory and per-app access, and announces every change to
a member on ``zoomriya:identity``. Its screens are Family Hub's (the sign-in page,
Account, Manage Family). Every route sits under ``/id/api/v1``, where the
gateway sends it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI

from app.config import settings
from app.routes.activity import router as activity_router
from app.routes.activity import users_router as activity_users_router
from app.routes.ai_keys import router as ai_keys_router
from app.routes.auth import router as auth_router
from app.routes.second_step import router as second_step_router
from app.routes.second_step import users_router as second_step_users_router
from app.routes.users import router as users_router
from app.security import signing_key
from app.shared.errors import register_exception_handlers
from app.shared.origin import OriginCheckMiddleware
from app.shared.rate_limit import RateLimitConfig, RateLimiter, RateLimitMiddleware
from app.shared.secure_cookies import SecureCookiesMiddleware


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    # No accounts are made here: the first admin is whoever set ZOOMRIYA ID up
    # (app.first_admin). Created on first start. Sign-in can't work without it, so a key that
    # can't be read stops startup.
    signing_key()
    yield


app = FastAPI(
    title="ZOOMRIYA ID",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
register_exception_handlers(app)
# Only the box's own pages may change anything (app.shared.origin).
app.add_middleware(OriginCheckMiddleware)
# Cookies over HTTPS are Secure (app.shared.secure_cookies).
app.add_middleware(SecureCookiesMiddleware)

# Brute-force protection: sign-in and password changes, per address; token
# renewal too, with a far higher limit (every open app renews).
limiter = RateLimiter()
app.add_middleware(
    RateLimitMiddleware,
    rules=[
        *(
            RateLimitConfig(
                requests=settings.RATE_LIMIT_AUTH_REQUESTS,
                window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
                prefix=f"{settings.api_prefix}{path}",
            )
            for path in (
                "/auth/login",
                "/auth/me/password",
                "/auth/me/confirm-password",
                "/auth/second-step",
                "/auth/me/second-step",
            )
        ),
        RateLimitConfig(
            requests=settings.RATE_LIMIT_REFRESH_REQUESTS,
            window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
            prefix=f"{settings.api_prefix}/auth/refresh",
        ),
    ],
    limiter=limiter,
)

api = APIRouter(prefix=settings.api_prefix)
api.include_router(auth_router, prefix="/auth", tags=["auth"])
api.include_router(ai_keys_router, prefix="/auth", tags=["ai keys"])
api.include_router(second_step_router, prefix="/auth", tags=["second step"])
api.include_router(activity_router, prefix="/auth", tags=["activity"])
api.include_router(activity_users_router, prefix="/users", tags=["activity"])
api.include_router(users_router, prefix="/users", tags=["users"])
api.include_router(second_step_users_router, prefix="/users", tags=["second step"])


@api.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(api)
