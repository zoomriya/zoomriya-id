"""ZOOMRIYA ID's settings, from the environment (and ``backend/.env`` in development).

On the box the service reads ``/etc/zoomriya/id.env`` (systemd's
``EnvironmentFile``); nothing here is shared with an app's settings.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BACKEND_DIR / ".env")

#: The box's own folder for ZOOMRIYA ID: the signing key and profile photos.
#: Outside /data/zoomriya on purpose: the apps' containers bind that folder,
#: and none of them may read the private key.
BOX_DATA_DIR = Path("/data/zoomriya-id")


def _default_data_dir() -> str:
    if BOX_DATA_DIR.is_dir():
        return str(BOX_DATA_DIR)
    return str(BACKEND_DIR.parent / "data")


def _flag(name: str, default: str) -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _installed_apps() -> tuple[str, ...]:
    # Only what the box has: no app is added on its own (a box may have no Photos).
    listed = [app.strip().lower() for app in os.getenv("INSTALLED_APPS", "photos").split(",")]
    return tuple(dict.fromkeys(app for app in listed if app))


@dataclass(frozen=True)
class Settings:
    #: Where the gateway serves the service; every route sits under it.
    BASE_PATH: str = "/id"
    DATABASE_URL: str = field(
        default_factory=lambda: os.getenv(
            "DATABASE_URL", "postgresql+psycopg://zoomriya:root@localhost:5432/zoomriya_id"
        )
    )
    REDIS_URL: str = field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    #: The signing key (``keys/``) and profile photos (``avatars/``).
    DATA_DIR: str = field(
        default_factory=lambda: os.getenv("ZOOMRIYA_ID_DATA_DIR", "") or _default_data_dir()
    )
    #: Defaults to ``<DATA_DIR>/keys/zoomriya-id-ed25519.pem``; created on first start.
    JWT_PRIVATE_KEY_PATH: str = field(default_factory=lambda: os.getenv("JWT_PRIVATE_KEY_PATH", ""))
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = field(
        default_factory=lambda: int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
    )
    #: The HttpOnly session cookie that renews access tokens (POST /auth/refresh).
    JWT_SESSION_EXPIRE_DAYS: int = field(
        default_factory=lambda: int(os.getenv("JWT_SESSION_EXPIRE_DAYS", "30"))
    )
    #: Always mark the login cookies Secure. Not needed on the box: cookies on
    #: a response to an HTTPS request are Secure anyway (app.shared.secure_cookies).
    AUTH_COOKIE_SECURE: bool = field(default_factory=lambda: _flag("AUTH_COOKIE_SECURE", "false"))
    #: The ZOOMRIYA apps on this box. Every member gets every installed app
    #: unless the admin switches one off (user_app_access).
    INSTALLED_APPS: tuple[str, ...] = field(default_factory=_installed_apps)
    #: The box's MCP service's own secret: only it may trade a member's AI app
    #: key for an access token (``POST /auth/ai-keys/token``). Missing: no one may.
    MCP_SERVICE_KEY_FILE: str = field(
        default_factory=lambda: os.getenv("MCP_SERVICE_KEY_FILE", "/etc/zoomriya/mcp-service.key")
    )
    #: Sign-in and password attempts one address may make per window
    #: (the gateway passes the address on in X-Forwarded-For).
    RATE_LIMIT_AUTH_REQUESTS: int = field(
        default_factory=lambda: int(os.getenv("RATE_LIMIT_AUTH_REQUESTS", "10"))
    )
    #: Token renewals one address may make per window. Every open app renews
    #: on load and every 15 minutes, so this is far above sign-in's limit; it
    #: only stops a client hammering the session check.
    RATE_LIMIT_REFRESH_REQUESTS: int = field(
        default_factory=lambda: int(os.getenv("RATE_LIMIT_REFRESH_REQUESTS", "60"))
    )
    RATE_LIMIT_WINDOW_SECONDS: int = field(
        default_factory=lambda: int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
    )

    def __post_init__(self) -> None:
        if self.JWT_ACCESS_TOKEN_EXPIRE_MINUTES < 1 or self.JWT_SESSION_EXPIRE_DAYS < 1:
            raise ValueError("Token lifetimes must be positive")

    @property
    def api_prefix(self) -> str:
        return f"{self.BASE_PATH}/api/v1"

    @property
    def signing_key_path(self) -> Path:
        if self.JWT_PRIVATE_KEY_PATH:
            return Path(self.JWT_PRIVATE_KEY_PATH)
        return Path(self.DATA_DIR) / "keys" / "zoomriya-id-ed25519.pem"


settings = Settings()
