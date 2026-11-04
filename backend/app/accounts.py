"""The family members, as the apps see them.

* ``directory_row``: what ``GET /users/directory`` and every identity event
  carry for a member, so each app's member list stays current.
* ``level_of``, ``guardians_of``, ``children_of``: children's accounts and
  their one or two guardians (Hub-Design.md §1).
* ``apps_for`` / ``set_app_access``: which apps a member may open, built from
  the installed apps and the admin's switches (``user_app_access``).
* ``publish``: the ``user:*`` events on ``zoomriya:identity``, signed with
  ZOOMRIYA ID's key so the apps can tell them from forgeries. Best effort:
  a Redis outage must never fail a change to an account, and the apps
  re-read the directory instead of trusting that every event arrived. Call it
  after the change is committed.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import UTC, datetime
from typing import Any

import redis
from sqlalchemy import select
from sqlalchemy.orm import Session
from zoomriya_identity import identity, levels, quiet_hours
from zoomriya_identity import place as places

from app.config import settings
from app.models import ChildChange, Guardian, User, UserAppAccess
from app.security import sign_event

logger = logging.getLogger(__name__)


#: A child has one or two guardians (Hub-Design.md, decision H4).
MAX_GUARDIANS = 2


def level_of(user: User) -> str:
    """Child, teen or adult, now."""
    return levels.level(
        is_child=bool(user.is_child), birth_year=user.birth_year, move=user.level_move
    )


def guardian_rows(db: Session, child_ids: list[int] | None = None) -> dict[int, list[User]]:
    """Each child's guardians, active or not, in the order they were chosen."""
    query = (
        select(Guardian.child_id, User)
        .join(User, User.id == Guardian.guardian_id)
        .order_by(Guardian.created_at, Guardian.guardian_id)
    )
    if child_ids is not None:
        query = query.where(Guardian.child_id.in_(child_ids))
    found: dict[int, list[User]] = {}
    for child_id, guardian in db.execute(query).all():
        found.setdefault(int(child_id), []).append(guardian)
    return found


def guardians_of(db: Session, child: User) -> list[User]:
    """The child's guardians who can act: active accounts only."""
    return [g for g in guardian_rows(db, [int(child.id)]).get(int(child.id), []) if g.is_active]


def children_of(db: Session, guardian: User) -> list[User]:
    """The active children and teens this member is a guardian of."""
    children = db.execute(
        select(User)
        .join(Guardian, Guardian.child_id == User.id)
        .where(Guardian.guardian_id == guardian.id, User.is_active.is_(True))
        .order_by(User.id)
    ).scalars()
    return [child for child in children if level_of(child) != levels.ADULT]


def is_guardian_of(db: Session, guardian: User, child: User) -> bool:
    return (
        guardian.is_active
        and level_of(child) != levels.ADULT
        and db.get(Guardian, (int(child.id), int(guardian.id))) is not None
    )


def set_guardians(db: Session, child: User, guardian_ids: list[int]) -> None:
    """Replace the child's guardians. The caller checked them and commits."""
    for row in db.execute(select(Guardian).where(Guardian.child_id == child.id)).scalars():
        if int(row.guardian_id) not in guardian_ids:
            db.delete(row)
    have = {
        int(gid)
        for gid in db.execute(
            select(Guardian.guardian_id).where(Guardian.child_id == child.id)
        ).scalars()
    }
    for gid in guardian_ids:
        if gid not in have:
            db.add(Guardian(child_id=int(child.id), guardian_id=gid))


def quiet_hours_of(user: User) -> dict[str, Any]:
    """The quiet hours that apply now: the guardians' own, or the level's default."""
    return quiet_hours.for_level(user.quiet_hours, level_of(user))


def log_change(db: Session, child: User, by: User | None, what: str) -> None:
    """Record a change to a child's controls. The caller commits."""
    db.add(
        ChildChange(
            child_id=int(child.id),
            by_id=int(by.id) if by else None,
            what=what[:300],
            at=datetime.now(UTC),
        )
    )


def recent_changes(db: Session, child: User, limit: int = 20) -> list[dict[str, Any]]:
    rows = db.execute(
        select(ChildChange, User)
        .outerjoin(User, User.id == ChildChange.by_id)
        .where(ChildChange.child_id == child.id)
        .order_by(ChildChange.at.desc(), ChildChange.id.desc())
        .limit(limit)
    ).all()
    return [
        {
            "what": change.what,
            "by_id": change.by_id,
            "by": by.shown_name if by else None,
            "at": change.at.isoformat(),
        }
        for change, by in rows
    ]


def unseen_changes(db: Session, guardian: User, child: User) -> int:
    """Changes by someone else since this guardian last opened the page."""
    link = db.get(Guardian, (int(child.id), int(guardian.id)))
    query = select(ChildChange.id).where(
        ChildChange.child_id == child.id,
        (ChildChange.by_id.is_(None)) | (ChildChange.by_id != guardian.id),
    )
    if link is not None and link.seen_at is not None:
        query = query.where(ChildChange.at > link.seen_at)
    return len(db.execute(query.limit(100)).all())


def mark_seen(db: Session, guardian: User, child: User) -> None:
    link = db.get(Guardian, (int(child.id), int(guardian.id)))
    if link is not None:
        link.seen_at = datetime.now(UTC)


def directory_row(user: User, guardian_ids: list[int] | None = None) -> dict[str, Any]:
    """``guardian_ids``: the member's active guardians (none for an adult)."""
    level = level_of(user)
    return {
        "id": int(user.id),
        # Photos shows it beside the name when sharing.
        "username": user.username,
        "display_name": user.shown_name,
        "avatar_version": user.avatar_ref,
        "role": user.role,
        # Myira's kids mode and age band come from it (None: an adult).
        "birth_year": user.birth_year,
        # "child", "teen" or "adult" (zoomriya_identity.levels), and who may see
        # a child's parent controls; apps check guardians with it.
        "level": level,
        "guardian_ids": [] if level == levels.ADULT else list(guardian_ids or []),
        # When a child's apps go quiet (zoomriya_identity.quiet_hours); none for adults.
        "quiet_hours": quiet_hours.for_level(user.quiet_hours, level),
        # Their own province or state ("CA-AB"), when not the family's; None:
        # the family's. Myira and Family Planner use it for this member.
        "place": user.place,
        # The apps compare a token's ``ver`` with this to spot a revoked
        # token without asking ZOOMRIYA ID.
        "ver": int(user.token_version),
    }


def switchable_apps() -> tuple[str, ...]:
    """Installed apps the admin can switch off for a member: every one of them.

    No app is special: a box may have Family Hub and Family Vault alone.
    """
    return settings.INSTALLED_APPS


def _overrides(db: Session, user_id: int) -> dict[str, bool]:
    rows = db.execute(
        select(UserAppAccess.app, UserAppAccess.enabled).where(UserAppAccess.user_id == user_id)
    ).all()
    return {app: enabled for app, enabled in rows}


def apps_for(db: Session, user: User) -> list[str]:
    """The apps this member may open, in install order (the token's ``apps``)."""
    overrides = _overrides(db, int(user.id))
    return [app for app in settings.INSTALLED_APPS if overrides.get(app, True)]


def app_access(db: Session, user: User) -> list[dict[str, Any]]:
    """Settings -> Family: one switch per app the admin can turn off."""
    overrides = _overrides(db, int(user.id))
    return [{"app": app, "enabled": overrides.get(app, True)} for app in switchable_apps()]


def set_app_access(db: Session, user: User, app: str, enabled: bool) -> None:
    """Record the admin's switch. The caller commits.

    Takes effect when the member's access token is next renewed (within
    ``JWT_ACCESS_TOKEN_EXPIRE_MINUTES``); the ``user:updated`` event lets the
    apps act on it sooner.
    """
    if app not in switchable_apps():
        raise ValueError(f"{app} can't be switched on or off")
    row = db.get(UserAppAccess, (int(user.id), app))
    if row is None:
        db.add(UserAppAccess(user_id=int(user.id), app=app, enabled=enabled))
    else:
        row.enabled = enabled


def event_data(db: Session, user: User) -> dict[str, Any]:
    guardians = [int(g.id) for g in guardians_of(db, user)] if user.is_child else []
    return directory_row(user, guardians) | {
        "active": bool(user.is_active),
        "apps": apps_for(db, user),
    }


# --- publishing ---------------------------------------------------------------

_client_lock = threading.Lock()
_client: redis.Redis | None = None


def _redis() -> redis.Redis:
    global _client
    with _client_lock:
        if _client is None:
            _client = redis.Redis.from_url(
                settings.REDIS_URL, socket_timeout=1.0, socket_connect_timeout=1.0
            )
        return _client


def publish(db: Session, event_type: str, user: User) -> None:
    """Announce a change to a member. Never raises."""
    try:
        # Signed, so no other process that can reach Redis can pass as us.
        message = identity.signed_member_event(event_type, event_data(db, user), sign_event)
        _redis().publish(identity.IDENTITY_CHANNEL, json.dumps(message))
    except Exception:
        logger.warning(
            "Could not publish %s for user %s", event_type, getattr(user, "id", None), exc_info=True
        )


def place_view(user: User) -> dict[str, object]:
    """Where a member lives: their own place, or the family's (``own`` False)."""
    family = places.family_place()
    own = places.parse_code(user.place)
    shown = own or family
    return {
        "country": shown.country,
        "region": shown.region,
        "name": places.region_name(shown.country, shown.region),
        "own": own is not None,
        "family": {
            "country": family.country,
            "region": family.region,
            "name": places.region_name(family.country, family.region),
        },
    }


def checked_place(code: str | None) -> str | None:
    """A place code as kept ("CA-AB"), or None; ValueError when unknown."""
    if code is None or not code.strip():
        return None
    found = places.parse_code(code)
    if found is None:
        raise ValueError("Choose a province or state in Canada or the US")
    return places.code_of(found.country, found.region)


def place_choices() -> dict[str, object]:
    """Every country, then its provinces or states by name (Canada and the US)."""
    return {
        "countries": [
            {
                "code": code,
                "name": name,
                "regions": [
                    {"code": places.code_of(code, region), "name": region_name}
                    for region, region_name in sorted(
                        places.REGIONS[code].items(), key=lambda item: item[1]
                    )
                ],
            }
            for code, name in places.COUNTRIES.items()
        ]
    }
