"""The family's email account (app.mail), for admins: ``/mail``. Box Desktop
shows and sets it.

- ``GET /mail``: what's set (never the password), and how many members use
  sign-in codes by email.
- ``PUT /mail``: the account; ZOOMRIYA ID signs in to it first, and keeps it
  only when that works. Without ``password``, the one kept stays.
- ``POST /mail/test``: a test email to an address.
- ``DELETE /mail``: removed; everyone's sign-in codes by email go off with
  it (they couldn't get a code any more).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app import activity, mail
from app.db import get_db
from app.deps import require_admin
from app.models import User

router = APIRouter()


class MailRequest(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    security: str
    username: str = Field(min_length=1, max_length=254)
    # None: keep the password already set.
    password: str | None = Field(default=None, max_length=512)
    # None: the username (most providers send only from the account's own address).
    from_address: str | None = Field(default=None, max_length=254)


class TestRequest(BaseModel):
    to: str = Field(min_length=3, max_length=254)


def _in_use(db: Session) -> int:
    return db.execute(
        select(func.count()).select_from(User).where(User.second_step_email.is_not(None))
    ).scalar_one()


def _view(db: Session) -> dict[str, object]:
    return {**mail.view(mail.stored(db)), "in_use": _in_use(db)}


@router.get("")
def get_mail(db: Session = Depends(get_db), _: User = Depends(require_admin)) -> dict[str, object]:
    return _view(db)


@router.put("")
def set_mail(
    payload: MailRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> dict[str, object]:
    if payload.security not in mail.SECURITY:
        raise HTTPException(status_code=400, detail="Security is ssl or starttls")
    old = mail.stored(db)
    password = payload.password
    if not password:
        if old is None:
            raise HTTPException(status_code=400, detail="Enter the email account's password.")
        password = mail.account(old).password
    sender = (payload.from_address or payload.username).strip()
    if not mail.is_address(sender):
        raise HTTPException(
            status_code=400, detail="The address emails come from isn't an email address."
        )
    chosen = mail.Account(
        host=payload.host.strip(),
        port=payload.port,
        security=payload.security,
        username=payload.username.strip(),
        password=password,
        from_address=sender,
    )
    try:
        mail.check(chosen)
    except mail.MailError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    mail.save(db, chosen)
    activity.record(
        db,
        activity.SETTING,
        "Set the family's email account" if old is None else "Changed the family's email account",
        member=admin,
        request=request,
    )
    return _view(db)


@router.post("/test", status_code=204)
def test_mail(
    payload: TestRequest,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> None:
    to = payload.to.strip()
    if not mail.is_address(to):
        raise HTTPException(status_code=400, detail="That doesn't look like an email address.")
    try:
        mail.send(
            db,
            to,
            "ZOOMRIYA test email",
            "This is a test from your ZOOMRIYA Box. Sign-in codes will come from this address.",
        )
    except mail.MailError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("")
def remove_mail(
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> dict[str, object]:
    row = mail.stored(db)
    if row is None:
        return _view(db)
    turned_off = _in_use(db)
    db.execute(
        update(User).values(
            second_step_email=None,
            second_step_email_pending=None,
            second_step_code=None,
            second_step_code_use=None,
            second_step_code_until=None,
            second_step_code_sent=None,
        )
    )
    db.delete(row)
    db.commit()
    activity.record(
        db,
        activity.SETTING,
        f"Removed the family's email account; sign-in codes by email turned off for {turned_off}"
        if turned_off
        else "Removed the family's email account",
        member=admin,
        request=request,
    )
    return _view(db)
