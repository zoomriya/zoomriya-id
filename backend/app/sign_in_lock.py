"""A person's sign-in locks after too many wrong passwords.

Five wrong passwords in a row for one person (SIGN_IN_LOCK_TRIES) lock their
sign-in for fifteen minutes (SIGN_IN_LOCK_MINUTES), wherever the tries come
from. While locked, even the right password is refused, so guessing stays
slow from any number of devices. This sits beside the limit per address in
app.main: that one stops one device trying many people; this one stops many
devices trying one person.

Wrong codes at the second step count the same way, toward the same lock:
someone who has the password can't keep guessing six-digit codes either.

A wrong try older than the lock's length is forgotten, so a slip now and
then never adds up. Signing in clears the count: the right password, and for
someone with a second step, the right code after it (the password alone
doesn't, or it would wipe the count of wrong codes each time). An admin
setting a new password, or letting an admin back in at the box, clears the lock.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from app import activity
from app.config import settings
from app.models import User


def _length() -> timedelta:
    return timedelta(minutes=settings.SIGN_IN_LOCK_MINUTES)


def _aware(moment: datetime | None) -> datetime | None:
    if moment is not None and moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment


def refuse_if_locked(user: User, now: datetime | None = None, *, what: str = "passwords") -> None:
    """429 with Retry-After while the person's sign-in is locked. ``what``
    names what was wrong, for the message ("passwords", "codes")."""
    now = now or datetime.now(UTC)
    until = _aware(user.sign_in_locked_until)
    if until is None or until <= now:
        return
    seconds = math.ceil((until - now).total_seconds())
    minutes = max(1, math.ceil(seconds / 60))
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=(
            f"Too many wrong {what}. "
            f"Try again in {minutes} minute{'s' if minutes != 1 else ''}, "
            "or ask an admin to set a new password."
        ),
        headers={"Retry-After": str(seconds)},
    )


def wrong_password(
    db: Session, user: User, request: Request | None = None, *, what: str = "passwords"
) -> bool:
    """Count a wrong password (or second-step code: ``what="codes"``); True
    when this one locked the sign-in."""
    now = datetime.now(UTC)
    last = _aware(user.last_failed_sign_in)
    if last is None or now - last > _length():
        user.failed_sign_ins = 0
    user.failed_sign_ins += 1
    user.last_failed_sign_in = now
    locked = user.failed_sign_ins >= settings.SIGN_IN_LOCK_TRIES
    if locked:
        user.sign_in_locked_until = now + _length()
        user.failed_sign_ins = 0
    db.add(user)
    db.commit()
    if locked:
        activity.record(
            db,
            activity.SIGN_IN_FAILED,
            f"Sign-in locked for {settings.SIGN_IN_LOCK_MINUTES} minutes after "
            f"{settings.SIGN_IN_LOCK_TRIES} wrong {what}",
            member=user,
            request=request,
        )
    return locked


def clear(user: User) -> None:
    """Forget wrong passwords and lift the lock (the caller commits)."""
    user.failed_sign_ins = 0
    user.last_failed_sign_in = None
    user.sign_in_locked_until = None


def right_password(db: Session, user: User) -> None:
    """The right password: forget earlier wrong ones."""
    if user.failed_sign_ins or user.last_failed_sign_in or user.sign_in_locked_until:
        clear(user)
        db.add(user)
        db.commit()
