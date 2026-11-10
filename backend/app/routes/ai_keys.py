"""Keys for a member's own AI apps (``mcp``), and the MCP service's trade.

A member the admin gave ``mcp`` (off by default, never for a child) makes a
key for one AI app ("Claude on my laptop") and pastes it into that app; they
see it once. The box's MCP service trades it, with its own secret, for a
15-minute access token as the member, and calls the family's apps with it,
under each app's rules. Anyone else holding the key without the service's
secret gets nothing: they can't skip the service, which keeps other people's
words and whereabouts on the box.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import accounts as identity
from app.config import settings
from app.db import get_db
from app.deps import get_current_user
from app.models import AiKey, User
from app.security import create_access_token

router = APIRouter()

APP = "mcp"
#: What every key starts with, so it's recognised if pasted somewhere it shouldn't be.
KEY_START = "zr_ai_"
MOST_KEYS = 10


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _may_use(db: Session, user: User) -> None:
    if APP not in identity.apps_for(db, user):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, detail="An admin hasn't turned on AI apps for you"
        )


def _view(key: AiKey) -> dict[str, object]:
    return {
        "id": key.id,
        "name": key.name,
        "prefix": key.prefix,
        "created_at": key.created_at.isoformat(),
        "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None,
    }


@router.get("/me/ai-keys")
def my_keys(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    _may_use(db, user)
    rows = db.scalars(select(AiKey).where(AiKey.user_id == user.id).order_by(AiKey.id))
    return {"keys": [_view(row) for row in rows]}


class NewKey(BaseModel):
    name: str = Field(min_length=1, max_length=60)


@router.post("/me/ai-keys", status_code=201)
def make_key(
    body: NewKey, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> dict:
    """A new key, shown this once."""
    _may_use(db, user)
    count = db.scalar(select(func.count()).select_from(AiKey).where(AiKey.user_id == user.id))
    if (count or 0) >= MOST_KEYS:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"{MOST_KEYS} keys at most")
    key = KEY_START + secrets.token_urlsafe(32)
    row = AiKey(
        user_id=user.id,
        name=" ".join(body.name.split()),
        key_hash=_hash(key),
        prefix=key[: len(KEY_START) + 4],
        created_at=datetime.now(UTC),
    )
    db.add(row)
    db.commit()
    return _view(row) | {"key": key}


@router.delete("/me/ai-keys/{key_id}", status_code=204)
def remove_key(
    key_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> Response:
    row = db.get(AiKey, key_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Key not found")
    db.delete(row)
    db.commit()
    return Response(status_code=204)


def _service_secret() -> str | None:
    try:
        secret = Path(settings.MCP_SERVICE_KEY_FILE).read_text().strip()
    except OSError:
        return None
    return secret if len(secret) >= 32 else None


class Traded(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    member_id: int


@router.post("/ai-keys/token", response_model=Traded)
def trade(
    authorization: str = Header(default=""),
    x_zoomriya_service: str = Header(default=""),
    db: Session = Depends(get_db),
) -> Traded:
    """The MCP service's trade: its secret, and the member's key, for a
    15-minute token as the member. Refused when ``mcp`` is off for them."""
    secret = _service_secret()
    if secret is None or not hmac.compare_digest(x_zoomriya_service, secret):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Only the box's MCP service")
    key = authorization.removeprefix("Bearer ").strip()
    row = (
        db.scalar(select(AiKey).where(AiKey.key_hash == _hash(key)))
        if key.startswith(KEY_START)
        else None
    )
    user = db.get(User, row.user_id) if row else None
    if row is None or user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Unknown key")
    apps = identity.apps_for(db, user)
    if APP not in apps:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, detail="An admin hasn't turned on AI apps for this member"
        )
    row.last_used_at = datetime.now(UTC)
    db.commit()
    token = create_access_token(
        user_id=user.id, token_version=user.token_version, role=user.role, apps=apps
    )
    return Traded(
        access_token=token,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        member_id=user.id,
    )
