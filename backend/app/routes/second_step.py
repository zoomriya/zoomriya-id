"""The second sign-in step's routes (app.second_step), under ``/auth``:

- ``POST /login/second-step``: the ticket from login and a code (or a backup
  code); signed in.
- ``POST /second-step/setup``: a new secret, its QR code and the key to type;
  with the setup ticket (an admin's first sign-in since it became required) or
  signed in (Account). ``POST /second-step/setup/finish`` with the first code
  turns it on and shows the backup codes, once.
- ``POST /me/second-step/backup-codes``: ten new ones (the old stop working).
- ``POST /me/second-step/off``: with the password and a code; not for admins.
- ``POST /me/confirm-password``: "your password again" (Box Desktop), without
  signing in again.
- ``POST /users/{id}/second-step/reset``: an admin turns off someone else's,
  for a lost phone with no backup codes; an admin sets one up again at their
  next sign-in.
"""

from __future__ import annotations

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import second_step
from app.db import get_db
from app.deps import bearer_scheme, get_current_user, require_admin
from app.models import ROLE_ADMIN, User
from app.routes.auth import TokenResponse, _issue_token
from app.security import verify_password

router = APIRouter()
users_router = APIRouter()

WRONG_CODE = "That code isn't right. Check the time on your phone, or use a backup code."
TICKET_GONE = "Signing in took too long. Start again with your password."


class CodeRequest(BaseModel):
    ticket: str = Field(min_length=1)
    code: str = Field(min_length=1, max_length=32)


class SetupRequest(BaseModel):
    ticket: str | None = None
    # Signed in (Account): the password too, so a session left open can't
    # swap in someone else's app.
    password: str | None = None


class SetupFinishRequest(BaseModel):
    ticket: str | None = None
    code: str = Field(min_length=1, max_length=32)


class PasswordRequest(BaseModel):
    password: str = Field(min_length=1)


class OffRequest(BaseModel):
    password: str = Field(min_length=1)
    code: str = Field(min_length=1, max_length=32)


def _ticket_user(db: Session, ticket: str, purpose: str) -> User:
    try:
        claims = second_step.read_ticket(ticket)
        user = db.get(User, int(claims["sub"]))
    except (jwt.InvalidTokenError, KeyError, ValueError, TypeError):
        user, claims = None, {}
    if (
        user is None
        or not user.is_active
        or claims.get("use") != purpose
        or int(claims.get("ver", -1)) != user.token_version
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=TICKET_GONE)
    return user


def _who(
    db: Session,
    request: Request,
    credentials: HTTPAuthorizationCredentials | None,
    ticket: str | None,
) -> tuple[User, bool]:
    """The member setting up their second step, and whether it's from a setup
    ticket (then finishing signs them in)."""
    if ticket:
        user = _ticket_user(db, ticket, second_step.SETUP)
        if user.has_second_step:
            # Already set up with this ticket: it's spent.
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=TICKET_GONE)
        return user, True
    return get_current_user(request, credentials, db), False


def _code_ok(user: User, code: str) -> bool:
    """A code from the app, or a backup code (used up). Changes ``user``."""
    if user.second_step_secret is None:
        return False
    secret = second_step.unseal(user.second_step_secret, user.id)
    step = second_step.matching_step(secret, code, user.second_step_last)
    if step is not None:
        user.second_step_last = step
        return True
    left = second_step.use_backup_code(user.second_step_backup, code)
    if left is not None:
        user.second_step_backup = left
        return True
    return False


@router.post("/login/second-step", response_model=TokenResponse)
def login_second_step(
    payload: CodeRequest, response: Response, db: Session = Depends(get_db)
) -> TokenResponse:
    """The second step after the password. Rate-limited with ``/auth/login``."""
    user = _ticket_user(db, payload.ticket, second_step.CHECK)
    if not _code_ok(user, payload.code):
        # 400, not 401: the page keeps the ticket and asks again; 401 means
        # the ticket ran out and signing in starts again.
        raise HTTPException(status_code=400, detail=WRONG_CODE)
    db.add(user)
    db.commit()
    db.refresh(user)
    return _issue_token(response, user, db, new_session=True)


@router.post("/second-step/setup")
def setup_start(
    payload: SetupRequest,
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """A new secret for an authenticator app: the QR code to scan, and the key
    to type instead. Nothing changes until the first code is checked."""
    user, from_ticket = _who(db, request, credentials, payload.ticket)
    if not from_ticket and not verify_password(payload.password or "", user.hashed_password):
        raise HTTPException(status_code=400, detail="Your password is not correct")
    secret = second_step.new_secret()
    user.second_step_pending = second_step.seal(secret, user.id)
    db.add(user)
    db.commit()
    uri = second_step.setup_uri(secret, user.username)
    return {
        "qr_svg": second_step.qr_svg(uri),
        "uri": uri,
        # Groups of four, as authenticator apps show a typed key.
        "key": " ".join(secret[i : i + 4] for i in range(0, len(secret), 4)),
    }


@router.post("/second-step/setup/finish")
def setup_finish(
    payload: SetupFinishRequest,
    request: Request,
    response: Response,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """The first code from the app: the second step is on. The backup codes are
    in the answer, and nowhere else, ever."""
    user, from_ticket = _who(db, request, credentials, payload.ticket)
    if user.second_step_pending is None:
        raise HTTPException(status_code=400, detail="Start again: scan the new QR code first.")
    secret = second_step.unseal(user.second_step_pending, user.id)
    step = second_step.matching_step(secret, payload.code, None)
    if step is None:
        raise HTTPException(
            status_code=400,
            detail="That code isn't right. Enter the code your app shows now for ZOOMRIYA.",
        )
    shown, kept = second_step.new_backup_codes()
    # Re-sealed under its own name, so a setup secret can't be swapped in.
    user.second_step_secret = second_step.seal(secret, user.id)
    user.second_step_pending = None
    user.second_step_last = step
    user.second_step_backup = kept
    db.add(user)
    db.commit()
    db.refresh(user)
    answer: dict[str, object] = {"backup_codes": shown}
    if from_ticket:
        answer.update(_issue_token(response, user, db, new_session=True).model_dump())
    return answer


@router.post("/me/second-step/backup-codes")
def new_backup_codes(
    payload: PasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, list[str]]:
    if not verify_password(payload.password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Your password is not correct")
    if not current_user.has_second_step:
        raise HTTPException(status_code=400, detail="Turn on the second step first.")
    shown, kept = second_step.new_backup_codes()
    current_user.second_step_backup = kept
    db.add(current_user)
    db.commit()
    return {"backup_codes": shown}


@router.post("/me/second-step/off", status_code=204)
def turn_off(
    payload: OffRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    if current_user.role == ROLE_ADMIN:
        raise HTTPException(status_code=400, detail="Admins keep the second step on.")
    if not verify_password(payload.password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Your password is not correct")
    if not _code_ok(current_user, payload.code):
        raise HTTPException(status_code=400, detail=WRONG_CODE)
    _clear(current_user)
    db.add(current_user)
    db.commit()
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
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> Response:
    """For someone who lost their phone and their backup codes. Not your own:
    another admin does that, so a stolen session can't remove it."""
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Another admin resets yours.")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="No such member")
    _clear(user)
    db.add(user)
    db.commit()
    return Response(status_code=204)


def _clear(user: User) -> None:
    user.second_step_secret = None
    user.second_step_pending = None
    user.second_step_last = None
    user.second_step_backup = None
