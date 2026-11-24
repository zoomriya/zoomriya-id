"""The family's activity, for admins (Solutions Design decision 28): who
signed in, and when a password was wrong; second steps, passwords, accounts and
their apps, AI keys; and what apps report: new devices, share links and
setting changes. Admins read it in Family Hub's Activity and Box Desktop's Log
Center. Kept 90 days.

Recording never fails what it records: a problem writing it is logged and
dropped.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from fastapi import Request
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.models import Activity, User

logger = logging.getLogger(__name__)

SIGN_IN = "sign-in"
SIGN_IN_FAILED = "sign-in-failed"
SECOND_STEP = "second-step"
PASSWORD = "password"
ACCOUNT = "account"
AI_KEY = "ai-key"
# Reported by apps (POST /auth/me/activity).
DEVICE = "device"
SHARE_LINK = "share-link"
SETTING = "setting"
KINDS = (
    SIGN_IN,
    SIGN_IN_FAILED,
    SECOND_STEP,
    PASSWORD,
    ACCOUNT,
    AI_KEY,
    DEVICE,
    SHARE_LINK,
    SETTING,
)
APP_KINDS = (DEVICE, SHARE_LINK, SETTING)

KEPT = timedelta(days=90)
SOURCE = "ZOOMRIYA ID"


def address_of(request: Request | None) -> str | None:
    """The device's address: the gateway's X-Forwarded-For, else the peer."""
    if request is None:
        return None
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return request.client.host[:64] if request.client else None


def record(
    db: Session,
    kind: str,
    what: str,
    *,
    member: User | None = None,
    by: User | None = None,
    source: str = SOURCE,
    request: Request | None = None,
) -> None:
    """Add a line, and forget lines older than 90 days. Commits on its own."""
    try:
        now = datetime.now(UTC)
        db.add(
            Activity(
                at=now,
                kind=kind,
                member_id=member.id if member is not None else None,
                by_id=by.id if by is not None and (member is None or by.id != member.id) else None,
                what=what[:300],
                source=source[:64],
                address=address_of(request),
            )
        )
        db.execute(delete(Activity).where(Activity.at < now - KEPT))
        db.commit()
    except Exception:  # noqa: BLE001 - the activity list never fails the action
        db.rollback()
        logger.exception("Couldn't record activity: %s", kind)
