"""The second sign-in step's routes (app.second_step), under ``/auth``:

- ``POST /login/second-step``: the ticket from login and the emailed code;
  signed in. ``remember`` (on unless sent false) trusts this device for
  thirty days.
- ``POST /login/second-step/resend``: a new code to the same address.
- ``POST /second-step/setup``: signed in, with the password and an address; a
  code goes there. ``POST /second-step/setup/finish`` with that code turns
  it on (or moves it to the new address).
- ``POST /me/second-step/off``: with the password; for anyone, admins too.
- ``POST /me/confirm-password``: "your password again" (Box Desktop), without
  signing in again.
- ``POST /users/{id}/second-step/reset``: an admin turns off someone else's,
  when their email is gone; their own they turn off from their account.
"""

from __future__ import annotations

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import activity, mail, second_step, sign_in_lock
from app.db import get_db
from app.deps import get_current_user, require_admin
from app.models import User
from app.routes.auth import TokenResponse, _issue_token, set_trust_cookie
from app.security import verify_password

router = APIRouter()
users_router = APIRouter()

WRONG_CODE = "That code isn't right, or it's too old. Check the newest email, or send a new code."
TICKET_GONE = "Signing in took too long. Start again with your password."
NOT_SENT = "We couldn't send the code. Try again in a few minutes, or ask an admin."
NO_FAMILY_EMAIL = "The family's email isn't set up yet. An admin sets it up in Box Desktop."


class CodeRequest(BaseModel):
    ticket: str = Field(min_length=1)
    code: str = Field(min_length=1, max_length=32)
    # Trust this device for thirty days (no code there until then).
    remember: bool = True


class TicketRequest(BaseModel):
    ticket: str = Field(min_length=1)


class SetupRequest(BaseModel):
    password: str = Field(min_length=1)
    email: str = Field(min_length=3, max_length=254)


class SetupFinishRequest(BaseModel):
    code: str = Field(min_length=1, max_length=32)


class PasswordRequest(BaseModel):
    password: str = Field(min_length=1)


class SignedInWithCode(TokenResponse):
    # The trusted-device token, for a client that keeps its own (Box Desktop);
    # browsers get it as a cookie too. None when not remembered.
    trusted_device: str | None = None


def too_soon(exc: second_step.TooSoon) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=f"A code was just sent. You can send another in {exc.seconds} seconds.",
        headers={"Retry-After": str(exc.seconds)},
    )


def _ticket_user(db: Session, ticket: str) -> User:
    try:
        claims = second_step.read_ticket(ticket)
        user = db.get(User, int(claims["sub"]))
    except (jwt.InvalidTokenError, KeyError, ValueError, TypeError):
        user, claims = None, {}
    if (
        user is None
        or not user.is_active
        or not user.has_second_step
        or claims.get("use") != second_step.CHECK
        or int(claims.get("ver", -1)) != user.token_version
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=TICKET_GONE)
    return user


@router.post("/login/second-step", response_model=SignedInWithCode)
def login_second_step(
    payload: CodeRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> SignedInWithCode:
    """The code after the password. Rate-limited with ``/auth/login`` per
    address, and wrong codes count toward the person's sign-in lock
    (app.sign_in_lock), so codes can't be guessed from many addresses."""
    user = _ticket_user(db, payload.ticket)
    sign_in_lock.refuse_if_locked(user, what="codes")
    if not second_step.take_code(user, second_step.CHECK, payload.code):
        activity.record(
            db, activity.SIGN_IN_FAILED, "Wrong sign-in code", member=user, request=request
        )
        if sign_in_lock.wrong_password(db, user, request, what="codes"):
            sign_in_lock.refuse_if_locked(user, what="codes")
        # 400, not 401: the page keeps the ticket and asks again; 401 means
        # the ticket ran out and signing in starts again.
        raise HTTPException(status_code=400, detail=WRONG_CODE)
    sign_in_lock.clear(user)
    db.add(user)
    db.commit()
    db.refresh(user)
    activity.record(db, activity.SIGN_IN, "Signed in", member=user, request=request)
    answer = _issue_token(response, user, db, new_session=True)
    trusted = None
    if payload.remember:
        trusted = second_step.create_trust(user)
        set_trust_cookie(response, trusted)
    return SignedInWithCode(**answer.model_dump(), trusted_device=trusted)


@router.post("/login/second-step/resend", status_code=204)
def resend_code(payload: TicketRequest, db: Session = Depends(get_db)) -> Response:
    user = _ticket_user(db, payload.ticket)
    sign_in_lock.refuse_if_locked(user, what="codes")
    try:
        second_step.send_code(db, user, second_step.CHECK, user.second_step_email or "")
    except second_step.TooSoon as exc:
        raise too_soon(exc) from exc
    except mail.MailError as exc:
        raise HTTPException(status_code=503, detail=NOT_SENT) from exc
    return Response(status_code=204)


@router.post("/second-step/setup")
def setup_start(
    payload: SetupRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """A code to the address the member chose; nothing changes until it's
    entered. The password too, so a session left open can't move it."""
    if not verify_password(payload.password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Your password is not correct")
    address = payload.email.strip()
    if not mail.is_address(address):
        raise HTTPException(status_code=400, detail="That doesn't look like an email address.")
    if not mail.is_set(db):
        raise HTTPException(status_code=400, detail=NO_FAMILY_EMAIL)
    current_user.second_step_email_pending = address
    try:
        second_step.send_code(db, current_user, second_step.SETUP, address)
    except second_step.TooSoon as exc:
        raise too_soon(exc) from exc
    except mail.MailError as exc:
        raise HTTPException(status_code=503, detail=NOT_SENT) from exc
    return {"sent_to": address}


@router.post("/second-step/setup/finish")
def setup_finish(
    payload: SetupFinishRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, object]:
    """The code from the email: the step is on, at that address."""
    address = current_user.second_step_email_pending
    if address is None:
        raise HTTPException(status_code=400, detail="Start again: send a code first.")
    if not second_step.take_code(current_user, second_step.SETUP, payload.code):
        raise HTTPException(status_code=400, detail=WRONG_CODE)
    moved = current_user.has_second_step
    current_user.second_step_email = address
    current_user.second_step_email_pending = None
    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    activity.record(
        db,
        activity.SECOND_STEP,
        "Moved sign-in codes to a new email address"
        if moved
        else "Turned on sign-in codes by email",
        member=current_user,
        request=request,
    )
    return {"second_step": second_step.view(db, current_user)}


@router.post("/me/second-step/off", status_code=204)
def turn_off(
    payload: PasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    if not verify_password(payload.password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Your password is not correct")
    second_step.clear(current_user)
    db.add(current_user)
    db.commit()
    activity.record(
        db,
        activity.SECOND_STEP,
        "Turned off sign-in codes by email",
        member=current_user,
        request=request,
    )
    return Response(status_code=204)


@router.post("/me/confirm-password", status_code=204)
def confirm_password(
    payload: PasswordRequest,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Your password again, for something that matters (Box Desktop's restart,
    reset, install...). Rate-limited with ``/auth/login``."""
    if not verify_password(payload.password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return Response(status_code=204)


@users_router.post("/{user_id}/second-step/reset", status_code=204)
def reset_for(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> Response:
    """For someone who can't get to their email any more. Your own: turn it
    off from your account."""
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Turn off your own from your account.")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="No such member")
    second_step.clear(user)
    db.add(user)
    db.commit()
    activity.record(
        db,
        activity.SECOND_STEP,
        "Sign-in codes by email turned off by an admin",
        member=user,
        by=admin,
        request=request,
    )
    return Response(status_code=204)
