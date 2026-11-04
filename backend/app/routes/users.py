"""Family accounts, managed by the admin (Settings -> Family).

There is no self-signup: the admin creates each family member with a
temporary password, can reset it (which signs them out everywhere) and can
deactivate or reactivate the account.

A child's account has a birth year under 18 and one or two guardians, chosen
by the admin from the family's adults. Its guardians (and only they, admins
included) see its page in Family Hub: ``/users/children`` (Hub-Design.md §1).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from zoomriya_identity import identity as id_format
from zoomriya_identity import levels, quiet_hours

from app import accounts as identity
from app import avatars
from app.db import get_db
from app.deps import get_current_user, require_admin
from app.models import ROLE_FAMILY, User
from app.security import hash_password

router = APIRouter()

MIN_PASSWORD_LENGTH = 8
#: The oldest birth year an account can have.
EARLIEST_BIRTH_YEAR = 1900


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    display_name: str | None = Field(default=None, max_length=128)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=256)
    # A child's birth year turns on Myira's kids mode for them.
    birth_year: int | None = None
    kind: Literal["adult", "child"] = "adult"
    # A child's one or two guardians: adult members' ids.
    guardian_ids: list[int] = Field(default_factory=list)


class AppAccessUpdate(BaseModel):
    app: str = Field(min_length=1, max_length=32)
    enabled: bool


class UserUpdateRequest(BaseModel):
    display_name: str | None = Field(default=None, max_length=128)
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=MIN_PASSWORD_LENGTH, max_length=256)
    birth_year: int | None = None
    kind: Literal["adult", "child"] | None = None
    guardian_ids: list[int] | None = None


def _checked_birth_year(year: int | None) -> int | None:
    if year is None:
        return None
    if not EARLIEST_BIRTH_YEAR <= year <= datetime.now(UTC).year:
        raise HTTPException(status_code=400, detail="That birth year doesn't look right")
    return year


def _bad(detail: str) -> HTTPException:
    return HTTPException(status_code=400, detail=detail)


def _checked_family(
    db: Session,
    user: User | None,
    *,
    is_child: bool,
    birth_year: int | None,
    guardian_ids: list[int],
) -> list[int]:
    """Check a member's kind, birth year and guardians together; the
    guardians to keep (none for an adult)."""
    if not is_child:
        if birth_year is not None and levels.level_by_age(birth_year) != levels.ADULT:
            raise _bad("They're under 18: make it a child's account, with a parent or guardian")
        return []
    if birth_year is None:
        raise _bad("A child's account needs a birth year")
    if levels.level_by_age(birth_year) == levels.ADULT:
        raise _bad("That birth year makes them 18 or older: make it an adult's account")
    if user is not None:
        guarded = identity.children_of(db, user)
        if guarded:
            raise _bad(
                f"{user.shown_name} is a parent or guardian of {guarded[0].shown_name}. "
                "Choose someone else for them first"
            )
    chosen = list(dict.fromkeys(guardian_ids))
    if not chosen:
        raise _bad("Choose a parent or guardian for a child")
    if len(chosen) > identity.MAX_GUARDIANS:
        raise _bad(f"A child can have at most {identity.MAX_GUARDIANS} parents or guardians")
    for gid in chosen:
        guardian = db.get(User, gid)
        if guardian is None or (user is not None and guardian.id == user.id):
            raise _bad("Choose a parent or guardian from the family")
        if not guardian.is_active or identity.level_of(guardian) != levels.ADULT:
            raise _bad(
                f"{guardian.shown_name} can't be a guardian: choose an adult whose account is on"
            )
    return chosen


def _guardian_brief(guardian: User) -> dict[str, object]:
    return {
        "id": guardian.id,
        "display_name": guardian.shown_name,
        "avatar_version": guardian.avatar_ref,
        "is_active": guardian.is_active,
    }


def serialize_user(
    user: User, db: Session, guardians: list[User] | None = None
) -> dict[str, object]:
    if guardians is None:
        guardians = identity.guardian_rows(db, [int(user.id)]).get(int(user.id), [])
    level = identity.level_of(user)
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.shown_name,
        "role": user.role,
        "birth_year": user.birth_year,
        "kind": "child" if user.is_child else "adult",
        "level": level,
        # Every guardian chosen, turned off or not; ``needs_guardian`` when none
        # can act, so Family Hub asks the admin to choose one.
        "guardians": [_guardian_brief(g) for g in guardians] if user.is_child else [],
        "needs_guardian": bool(
            user.is_child and level != levels.ADULT and not any(g.is_active for g in guardians)
        ),
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "avatar_version": user.avatar_ref,
        # The admin's per-app switches; empty while Photos is the only app.
        "app_access": identity.app_access(db, user),
    }


def _get_user(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def _username_taken(db: Session, username: str) -> bool:
    return (
        db.execute(
            select(User.id).where(func.lower(User.username) == username.lower()).limit(1)
        ).scalar_one_or_none()
        is not None
    )


@router.get("")
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> list[dict[str, object]]:
    users = db.execute(select(User).order_by(User.id)).scalars().all()
    guardians = identity.guardian_rows(db)
    return [serialize_user(user, db, guardians.get(int(user.id), [])) for user in users]


@router.get("/directory")
def family_directory(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[dict[str, object]]:
    """Every active family member, for any signed-in member and for every
    app's member list. Avatars load from ``/users/{id}/avatar?v=<avatar_version>``."""
    users = db.execute(select(User).where(User.is_active.is_(True)).order_by(User.id)).scalars()
    guardians = identity.guardian_rows(db)
    return [
        identity.directory_row(
            user, [int(g.id) for g in guardians.get(int(user.id), []) if g.is_active]
        )
        for user in users
    ]


# --- a guardian's children (Family Hub's child pages) ---------------------------

#: The names the family sees, for the log of changes.
APP_NAMES = {
    "photos": "Family Photos",
    "vault": "Family Vault",
    "chat": "Family Chat",
    "tracker": "Family Tracker",
    "planner": "Family Planner",
    "inbox": "Family Inbox",
    "myira": "Myira",
}


def _child_brief(child: User) -> dict[str, object]:
    return {
        "id": child.id,
        "display_name": child.shown_name,
        "avatar_version": child.avatar_ref,
        "level": identity.level_of(child),
    }


def _guarded_child(db: Session, guardian: User, child_id: int) -> User:
    """The child, if this member is their guardian; not found otherwise, for
    admins too (being admin doesn't make someone a guardian)."""
    child = db.get(User, child_id)
    if child is None or not child.is_active or not identity.is_guardian_of(db, guardian, child):
        raise HTTPException(status_code=404, detail="Child not found")
    return child


def _child_view(db: Session, child: User) -> dict[str, object]:
    by_age = levels.level_by_age(child.birth_year) if child.birth_year else levels.CHILD
    return _child_brief(child) | {
        "username": child.username,
        "birth_year": child.birth_year,
        # What the birth year makes them, and the guardian's move, if any.
        "level_by_age": by_age,
        "level_move": child.level_move,
        "guardians": [_guardian_brief(g) for g in identity.guardians_of(db, child)],
        "app_access": identity.app_access(db, child),
        # The quiet hours that apply, and whether the guardians chose them
        # (False: the level's default).
        "quiet_hours": identity.quiet_hours_of(child),
        "quiet_hours_chosen": child.quiet_hours is not None,
        # Where they live: their own place (a parent sets it), or the family's.
        "place": identity.place_view(child),
        "changes": identity.recent_changes(db, child),
    }


def _window(window: dict[str, str] | None) -> str:
    return f"{window['from']}–{window['to']}" if window else "off"


class ChildControlsRequest(BaseModel):
    # "child" or "teen", one level from the birth year's; None follows it.
    level_move: Literal["child", "teen"] | None = None
    # {"bedtime": {"from", "to"} | None, "school": … | None, "tz"}; None: the default.
    quiet_hours: dict | None = None
    # "CA-AB" when they live elsewhere; None: the family's.
    place: str | None = Field(default=None, max_length=8)


class ChangeNote(BaseModel):
    # What changed, in the app's words ("Myira: Stories off").
    what: str = Field(min_length=1, max_length=200)


@router.get("/children")
def my_children(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[dict[str, object]]:
    """The children and teens you're a parent or guardian of, each with how
    many changes someone else made since you last opened their page."""
    return [
        _child_brief(child) | {"unseen": identity.unseen_changes(db, current_user, child)}
        for child in identity.children_of(db, current_user)
    ]


@router.get("/children/{child_id}")
def get_child(
    child_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, object]:
    return _child_view(db, _guarded_child(db, current_user, child_id))


@router.post("/children/{child_id}/seen", status_code=status.HTTP_204_NO_CONTENT)
def child_seen(
    child_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    """The guardian opened the page: the sidebar's dot goes."""
    identity.mark_seen(db, current_user, _guarded_child(db, current_user, child_id))
    db.commit()


@router.patch("/children/{child_id}")
def change_child_controls(
    child_id: int,
    payload: ChildControlsRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, object]:
    """A guardian moves a child one level (within the under-18s) or sets
    their quiet hours. Either guardian may; each change is logged."""
    child = _guarded_child(db, current_user, child_id)
    provided = payload.model_fields_set
    if "level_move" in provided and payload.level_move != child.level_move:
        if child.birth_year is None or not levels.move_allowed(
            payload.level_move, child.birth_year
        ):
            raise _bad("A child can move one level, child or teen, never to adult")
        child.level_move = payload.level_move
        identity.log_change(
            db,
            child,
            current_user,
            f"Level: {identity.level_of(child)}"
            + (" (moved)" if payload.level_move else " (from the birth year)"),
        )
    if "quiet_hours" in provided:
        try:
            chosen = (
                None if payload.quiet_hours is None else quiet_hours.checked(payload.quiet_hours)
            )
        except ValueError as exc:
            raise _bad(str(exc)) from exc
        child.quiet_hours = chosen
        now_applying = identity.quiet_hours_of(child)
        identity.log_change(
            db,
            child,
            current_user,
            "Quiet hours: "
            + ("the default, " if chosen is None else "")
            + f"bedtime {_window(now_applying['bedtime'])}, "
            + f"school days {_window(now_applying['school'])}",
        )
    if "place" in provided:
        try:
            chosen_place = identity.checked_place(payload.place)
        except ValueError as exc:
            raise _bad(str(exc)) from exc
        if chosen_place != child.place:
            child.place = chosen_place
            shown = identity.place_view(child)
            identity.log_change(
                db,
                child,
                current_user,
                f"Where they live: {shown['name']}" + ("" if shown["own"] else " (the family's)"),
            )
    db.commit()
    db.refresh(child)
    identity.publish(db, id_format.USER_UPDATED, child)
    return _child_view(db, child)


@router.put("/children/{child_id}/apps")
def set_child_app(
    child_id: int,
    payload: AppAccessUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, object]:
    """A guardian switches an app on or off for their child, as the admin can."""
    child = _guarded_child(db, current_user, child_id)
    app = payload.app.strip().lower()
    try:
        identity.set_app_access(db, child, app, payload.enabled)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    identity.log_change(
        db, child, current_user, f"{APP_NAMES.get(app, app)} {'on' if payload.enabled else 'off'}"
    )
    db.commit()
    identity.publish(db, id_format.USER_UPDATED, child)
    return _child_view(db, child)


@router.post("/children/{child_id}/changes", status_code=status.HTTP_201_CREATED)
def note_child_change(
    child_id: int,
    payload: ChangeNote,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, object]:
    """Family Hub logs a change an app accepted to its own controls for the
    child (Myira's features, Memory), as the guardian who made it."""
    child = _guarded_child(db, current_user, child_id)
    identity.log_change(db, child, current_user, payload.what.strip())
    db.commit()
    return {"changes": identity.recent_changes(db, child)}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreateRequest,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> dict[str, object]:
    username = payload.username.strip()
    if not username or any(char.isspace() for char in username):
        raise HTTPException(status_code=400, detail="Username can't contain spaces")
    if _username_taken(db, username):
        raise HTTPException(status_code=409, detail="That username is already taken")
    birth_year = _checked_birth_year(payload.birth_year)
    is_child = payload.kind == "child"
    guardian_ids = _checked_family(
        db, None, is_child=is_child, birth_year=birth_year, guardian_ids=payload.guardian_ids
    )

    user = User(
        username=username,
        display_name=(payload.display_name or "").strip() or None,
        birth_year=birth_year,
        is_child=is_child,
        hashed_password=hash_password(payload.password),
        role=ROLE_FAMILY,
        is_active=True,
        token_version=0,
    )
    db.add(user)
    db.flush()
    identity.set_guardians(db, user, guardian_ids)
    db.commit()
    db.refresh(user)
    identity.publish(db, id_format.USER_CREATED, user)
    return serialize_user(user, db)


@router.patch("/{user_id}")
def update_user(
    user_id: int,
    payload: UserUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict[str, object]:
    user = _get_user(db, user_id)
    provided = payload.model_fields_set
    was_active, old_version = user.is_active, user.token_version

    if "display_name" in provided:
        user.display_name = (payload.display_name or "").strip() or None
    family_change = provided & {"birth_year", "kind", "guardian_ids"}
    if family_change:
        birth_year = (
            _checked_birth_year(payload.birth_year) if "birth_year" in provided else user.birth_year
        )
        is_child = (payload.kind == "child") if payload.kind is not None else bool(user.is_child)
        if payload.guardian_ids is not None:
            wanted = payload.guardian_ids
        elif is_child and user.is_child:
            wanted = [int(g.id) for g in identity.guardians_of(db, user)]
        else:
            wanted = []
        guardian_ids = _checked_family(
            db, user, is_child=is_child, birth_year=birth_year, guardian_ids=wanted
        )
        user.birth_year, user.is_child = birth_year, is_child
        if not is_child or (
            birth_year is not None and not levels.move_allowed(user.level_move, birth_year)
        ):
            user.level_move = None
        identity.set_guardians(db, user, guardian_ids)
    if "is_active" in provided and payload.is_active is not None:
        if user.id == current_user.id and not payload.is_active:
            raise HTTPException(status_code=400, detail="You can't deactivate your own account")
        if user.is_active and not payload.is_active:
            # Sign them out of every device now, not when their token expires.
            user.token_version += 1
        user.is_active = payload.is_active
    if "password" in provided and payload.password is not None:
        user.hashed_password = hash_password(payload.password)
        if user.id != current_user.id:
            user.token_version += 1

    db.add(user)
    db.commit()
    db.refresh(user)
    if was_active and not user.is_active:
        event = id_format.USER_DEACTIVATED
    elif user.token_version != old_version:
        event = id_format.USER_REVOKED
    else:
        event = id_format.USER_UPDATED
    identity.publish(db, event, user)
    if was_active != user.is_active:
        # A guardian turned off or on: their children's guardians changed.
        for child in identity.children_of(db, user):
            identity.publish(db, id_format.USER_UPDATED, child)
    return serialize_user(user, db)


@router.get("/{user_id}/apps")
def get_user_apps(
    user_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> list[dict[str, object]]:
    """Settings -> Family: which installed apps this member may open.

    Photos isn't listed: it stays on for everyone.
    """
    user = _get_user(db, user_id)
    return identity.app_access(db, user)


@router.put("/{user_id}/apps")
def set_user_app(
    user_id: int,
    payload: AppAccessUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> list[dict[str, object]]:
    user = _get_user(db, user_id)
    app = payload.app.strip().lower()
    try:
        identity.set_app_access(db, user, app, payload.enabled)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if user.is_child:
        identity.log_change(
            db, user, admin, f"{APP_NAMES.get(app, app)} {'on' if payload.enabled else 'off'}"
        )
    db.commit()
    identity.publish(db, id_format.USER_UPDATED, user)
    return identity.app_access(db, user)


@router.get("/{user_id}/avatar")
def get_user_avatar(
    user_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> FileResponse:
    """Anyone signed in may see a family member's photo (as with their name).

    The URL carries ?v=<avatar_version>, so the image can be cached for good.
    """
    user = db.get(User, user_id)
    if user is None or not user.avatar_path:
        raise HTTPException(status_code=404, detail="No profile photo")
    path = avatars.avatar_file(user.avatar_path)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="No profile photo")
    return FileResponse(
        path,
        media_type="image/webp",
        headers={"Cache-Control": "private, max-age=31536000, immutable"},
    )
