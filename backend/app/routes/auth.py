"""Signing in and out, and your own account: ``/id/api/v1/auth/...``."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from zoomriya_identity import identity as id_format
from zoomriya_identity import levels

from app import accounts as identity
from app import activity, avatars, second_step
from app.config import settings
from app.db import get_db
from app.deps import (
    AUTH_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    get_current_user,
    get_optional_user,
)
from app.models import ROLE_ADMIN, User
from app.security import (
    create_access_token,
    create_session_token,
    decode_session_token,
    hash_password,
    needs_rehash,
    public_keys,
    verify_password,
)

MIN_PASSWORD_LENGTH = 8

# Must match the themes the apps offer (packages/ui/src/types/theme.ts).
THEMES = frozenset({"daylight", "midnight", "nightshade", "fjord", "graphite", "skylight", "linen"})
LANGUAGES = frozenset({"en"})
DEFAULT_LANGUAGE = "en"

router = APIRouter()


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1)


class NewPasswordRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=256)


#: Login's answer when the password is temporary: the sign-in page asks for a
#: new one and sends both to ``/auth/login/new-password``.
NEW_PASSWORD_NEEDED = "new_password_needed"
#: Login's answers once the password is right but a second step comes first
#: (app.second_step): a code (``/auth/login/second-step``), or, for an admin
#: who has none yet, setting one up (``/auth/second-step/setup``). Each comes
#: with a ticket for those calls.
SECOND_STEP_NEEDED = "second_step_needed"
SECOND_STEP_SETUP_NEEDED = "second_step_setup_needed"


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    # Seconds until the access token expires; renew it with POST /auth/refresh.
    expires_in: int


def _checked_login(db: Session, username: str, password: str, request: Request) -> User:
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if user is None or not verify_password(password, user.hashed_password) or not user.is_active:
        # Admins see wrong passwords for a member; a name that isn't one is
        # left out (never write down what someone typed by mistake).
        if user is not None:
            activity.record(
                db,
                activity.SIGN_IN_FAILED,
                "Wrong password" if user.is_active else "Tried to sign in to a turned-off account",
                member=user,
                request=request,
            )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return user


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse | JSONResponse:
    user = _checked_login(db, payload.username, payload.password, request)
    if user.password_temporary:
        # No token for a temporary password: they choose their own first.
        return JSONResponse(
            {
                "detail": "Choose your own password to finish signing in",
                "code": NEW_PASSWORD_NEEDED,
            },
            status_code=status.HTTP_403_FORBIDDEN,
        )

    # An older hash is replaced now, while the password is at hand.
    if needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(payload.password)
        db.add(user)
        db.commit()
    return _after_password(response, user, db, request)


@router.post("/login/new-password", response_model=TokenResponse)
def login_with_new_password(
    payload: NewPasswordRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """The first sign-in after an admin set a temporary password: the
    temporary one, and the member's own, which replaces it. Rate-limited
    with ``/auth/login``."""
    user = _checked_login(db, payload.username, payload.password, request)
    if not user.password_temporary:
        raise HTTPException(status_code=400, detail="Sign in with your password")
    if payload.new_password == payload.password:
        raise HTTPException(status_code=400, detail="Choose a password you are not using now")
    user.hashed_password = hash_password(payload.new_password)
    user.password_temporary = False
    db.add(user)
    db.commit()
    db.refresh(user)
    activity.record(db, activity.PASSWORD, "Chose their own password", member=user, request=request)
    return _after_password(response, user, db, request)


def _after_password(
    response: Response, user: User, db: Session, request: Request
) -> TokenResponse | JSONResponse:
    """The password was right: signed in, or the second step first."""
    if user.has_second_step:
        return _second_step_answer(
            "Enter the code from your authenticator app",
            SECOND_STEP_NEEDED,
            user,
            second_step.CHECK,
        )
    if user.role == ROLE_ADMIN:
        return _second_step_answer(
            "Admins set up a second sign-in step first",
            SECOND_STEP_SETUP_NEEDED,
            user,
            second_step.SETUP,
        )
    activity.record(db, activity.SIGN_IN, "Signed in", member=user, request=request)
    return _issue_token(response, user, db, new_session=True)


def _second_step_answer(detail: str, code: str, user: User, purpose: str) -> JSONResponse:
    return JSONResponse(
        {
            "detail": detail,
            "code": code,
            "ticket": second_step.create_ticket(user.id, user.token_version, purpose),
        },
        status_code=status.HTTP_403_FORBIDDEN,
    )


def _issue_token(
    response: Response, user: User, db: Session, *, new_session: bool = False
) -> TokenResponse:
    """A fresh access token, in the body and in the shared cookie.

    Both cookies are HttpOnly with ``Path=/``, so they reach every app behind
    the gateway while page scripts can't read them. The page keeps the body's
    token and sends it as ``Authorization: Bearer``.
    """
    lifetime = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    token = create_access_token(
        user_id=user.id,
        token_version=user.token_version,
        role=user.role,
        apps=identity.apps_for(db, user),
    )
    _set_cookie(response, AUTH_COOKIE_NAME, token, lifetime)
    if new_session:
        session = create_session_token(user.id, user.token_version)
        _set_cookie(
            response, SESSION_COOKIE_NAME, session, settings.JWT_SESSION_EXPIRE_DAYS * 86400
        )
    return TokenResponse(access_token=token, expires_in=lifetime)


def _set_cookie(response: Response, name: str, value: str, max_age: int) -> None:
    response.set_cookie(
        key=name,
        value=value,
        max_age=max_age,
        httponly=True,
        secure=settings.AUTH_COOKIE_SECURE,
        samesite="lax",
        path="/",
    )


def _clear_cookies(response: Response) -> None:
    for name in (AUTH_COOKIE_NAME, SESSION_COOKIE_NAME):
        response.delete_cookie(
            key=name, path="/", secure=settings.AUTH_COOKIE_SECURE, httponly=True, samesite="lax"
        )


def _session_user(db: Session, token: str) -> User | None:
    """The member a still-valid session belongs to."""
    try:
        claims = decode_session_token(token)
        user = db.get(User, int(claims["sub"]))
        version = int(claims.get("ver", 0))
    except (jwt.InvalidTokenError, KeyError, ValueError, TypeError):
        return None
    if user is None or not user.is_active or user.token_version != version:
        return None
    return user


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse | JSONResponse:
    """Renew the 15-minute access token from the session cookie.

    Only the session cookie ZOOMRIYA ID signed renews a token. The old HS256
    tokens from before ZOOMRIYA ID are no longer traded for a session: anyone
    holding Photos' old shared secret could have signed one for any member.
    """
    session = request.cookies.get(SESSION_COOKIE_NAME)
    if session:
        user = _session_user(db, session)
        if user is not None:
            return _issue_token(response, user, db)

    # Returned, not raised: a raised error drops the injected response, and
    # its cookie deletions with it. A dead cookie left behind makes the web
    # app's /login send the browser back to / forever.
    expired = JSONResponse({"detail": "Session expired"}, status_code=status.HTTP_401_UNAUTHORIZED)
    _clear_cookies(expired)
    return expired


@router.get("/jwks.json")
def jwks(response: Response) -> dict[str, object]:
    """The public key every app checks ZOOMRIYA ID tokens with. Public by design."""
    response.headers["Cache-Control"] = "public, max-age=300"
    return public_keys()


@router.post("/logout")
def logout(
    response: Response,
    current_user: User | None = Depends(get_optional_user),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Sign out everywhere. Works with an expired token too, so the cookies
    are always cleared."""
    if current_user is not None:
        current_user.token_version += 1
        db.add(current_user)
        db.commit()
        identity.publish(db, id_format.USER_REVOKED, current_user)
    _clear_cookies(response)
    return {"message": "Logged out"}


class ProfileUpdateRequest(BaseModel):
    display_name: str | None = Field(default=None, max_length=128)


class PreferencesUpdateRequest(BaseModel):
    # Send a field to change it; null goes back to the app default.
    theme: str | None = Field(default=None, max_length=32)
    language: str | None = Field(default=None, max_length=16)


class PlaceRequest(BaseModel):
    # "CA-AB"; None: the family's again.
    place: str | None = Field(default=None, max_length=8)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=256)


#: How far back a child's dashboard shows their guardians' changes.
CHANGES_SHOWN_DAYS = 14


def _as_child(user: User, db: Session) -> dict[str, object]:
    if identity.level_of(user) == levels.ADULT:
        return {}
    since = datetime.now(UTC) - timedelta(days=CHANGES_SHOWN_DAYS)
    return {
        "guardians": [g.shown_name for g in identity.guardians_of(db, user)],
        "guardian_changes": [
            change
            for change in identity.recent_changes(db, user, limit=5)
            if datetime.fromisoformat(change["at"]) >= since
        ],
    }


def _serialize_me(user: User, db: Session) -> dict[str, object]:
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.shown_name,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "avatar_version": user.avatar_ref,
        # The apps this member may open (the app switcher reads this).
        "apps": identity.apps_for(db, user),
        # Child, teen or adult; and the children whose pages Family Hub's
        # sidebar lists for a guardian.
        "level": identity.level_of(user),
        "children": [
            {
                "id": child.id,
                "display_name": child.shown_name,
                "avatar_version": child.avatar_ref,
                "unseen": identity.unseen_changes(db, user, child),
            }
            for child in identity.children_of(db, user)
        ],
        # A child's or teen's own: who their guardians are, and what they
        # changed lately (they're told, decision H6).
        **_as_child(user, db),
        # Their province or state (Myira, holidays, time zone), and the family's.
        "place": identity.place_view(user),
        # The second sign-in step: on or not, and backup codes left.
        "second_step": {
            "on": user.has_second_step,
            "required": user.role == ROLE_ADMIN,
            "backup_codes_left": len(user.second_step_backup or []),
        },
        "preferences": {
            # None: the app default, or what this browser last used.
            "theme": user.theme,
            "language": user.language or DEFAULT_LANGUAGE,
        },
    }


@router.get("/me")
def me(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
) -> dict[str, object]:
    return _serialize_me(current_user, db)


@router.patch("/me")
def update_me(
    payload: ProfileUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, object]:
    """Change your own display name (empty falls back to the username)."""
    current_user.display_name = (payload.display_name or "").strip() or None
    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    identity.publish(db, id_format.USER_UPDATED, current_user)
    return _serialize_me(current_user, db)


@router.patch("/me/preferences")
def update_my_preferences(
    payload: PreferencesUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, object]:
    """Save your theme and language on your account (they follow you to every device)."""
    sent = payload.model_fields_set
    if "theme" in sent:
        if payload.theme is not None and payload.theme not in THEMES:
            raise HTTPException(status_code=400, detail="Unknown theme")
        current_user.theme = payload.theme
    if "language" in sent:
        if payload.language is not None and payload.language not in LANGUAGES:
            raise HTTPException(status_code=400, detail="Unsupported language")
        current_user.language = payload.language
    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    return _serialize_me(current_user, db)


@router.get("/places")
def place_choices(_: User = Depends(get_current_user)) -> dict[str, object]:
    """The countries and their provinces or states a member may choose."""
    return identity.place_choices()


@router.put("/me/place")
def set_my_place(
    payload: PlaceRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, object]:
    """Where you live, when not with the family (at university elsewhere);
    null: the family's again. A child's is set by a parent, on their page."""
    if identity.level_of(current_user) == levels.CHILD:
        raise HTTPException(status_code=403, detail="A parent sets where a child lives")
    try:
        current_user.place = identity.checked_place(payload.place)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    # Every app's member list hears it (Myira, Family Planner).
    identity.publish(db, id_format.USER_UPDATED, current_user)
    return _serialize_me(current_user, db)


@router.post("/me/password", response_model=TokenResponse)
def change_my_password(
    payload: PasswordChangeRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TokenResponse:
    """Change your own password. Every other session is signed out; this one
    gets a fresh token so it stays signed in."""
    if not verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Your current password is not correct")
    if payload.new_password == payload.current_password:
        raise HTTPException(status_code=400, detail="Choose a password you are not using now")
    current_user.hashed_password = hash_password(payload.new_password)
    current_user.password_temporary = False
    current_user.token_version += 1
    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    identity.publish(db, id_format.USER_REVOKED, current_user)
    activity.record(
        db, activity.PASSWORD, "Changed their password", member=current_user, request=request
    )
    # The old session cookie carries the old version, so this one gets a new one.
    return _issue_token(response, current_user, db, new_session=True)


@router.post("/me/avatar")
async def upload_my_avatar(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, object]:
    """Set your profile photo (the browser sends the square you cropped)."""
    data = await file.read(avatars.MAX_UPLOAD_BYTES + 1)
    try:
        webp = avatars.render_avatar(data)
    except avatars.AvatarError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    old_path = current_user.avatar_path
    current_user.avatar_path = avatars.save_avatar(int(current_user.id), webp)
    current_user.avatar_version += 1
    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    avatars.delete_avatar_file(old_path)
    identity.publish(db, id_format.USER_UPDATED, current_user)
    return _serialize_me(current_user, db)


@router.delete("/me/avatar")
def remove_my_avatar(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
) -> dict[str, object]:
    """Go back to initials."""
    old_path = current_user.avatar_path
    current_user.avatar_path = None
    current_user.avatar_version += 1
    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    avatars.delete_avatar_file(old_path)
    identity.publish(db, id_format.USER_UPDATED, current_user)
    return _serialize_me(current_user, db)
