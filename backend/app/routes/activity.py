"""The family's activity (app.activity): apps report what a member did there,
and admins read the list.

- ``POST /auth/me/activity``: an app, with the member's own token, reports a
  new device, a share link or a setting change, in plain words.
- ``GET /users/activity``: admins only; newest first, 50 at a time
  (``before`` an id for the next page), optionally one kind or one member.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import activity
from app.db import get_db
from app.deps import get_current_user, require_admin
from app.models import Activity, User

router = APIRouter()
users_router = APIRouter()

PAGE = 50


class Reported(BaseModel):
    kind: str
    what: str = Field(min_length=1, max_length=200)
    # The app reporting it, as people know it ("Family Photos").
    app: str = Field(min_length=1, max_length=48)


@router.post("/me/activity", status_code=204)
def report(
    payload: Reported,
    request: Request,
    db: Session = Depends(get_db),
    member: User = Depends(get_current_user),
) -> None:
    """What a member did in an app. Only about themselves, and only the app
    kinds: a member can't write sign-ins or someone else's lines."""
    if payload.kind not in activity.APP_KINDS:
        raise HTTPException(status_code=400, detail="Apps report devices, share links or settings")
    activity.record(
        db,
        payload.kind,
        payload.what.strip(),
        member=member,
        source=payload.app.strip(),
        request=request,
    )


@users_router.get("/activity")
def family_activity(
    kind: str | None = None,
    member: int | None = None,
    before: int | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> dict[str, object]:
    query = select(Activity).order_by(Activity.id.desc()).limit(PAGE + 1)
    if kind:
        if kind not in activity.KINDS:
            raise HTTPException(status_code=400, detail="No such kind")
        query = query.where(Activity.kind == kind)
    if member is not None:
        query = query.where(Activity.member_id == member)
    if before is not None:
        query = query.where(Activity.id < before)
    rows = list(db.execute(query).scalars())
    names = {
        user.id: user.shown_name
        for user in db.execute(
            select(User).where(
                User.id.in_(
                    {r.member_id for r in rows if r.member_id} | {r.by_id for r in rows if r.by_id}
                )
            )
        ).scalars()
    }
    return {
        "activity": [
            {
                "id": r.id,
                "at": r.at.isoformat(),
                "kind": r.kind,
                "what": r.what,
                "member_id": r.member_id,
                "member": names.get(r.member_id) if r.member_id else None,
                "by": names.get(r.by_id) if r.by_id else None,
                "source": r.source,
                "address": r.address,
            }
            for r in rows[:PAGE]
        ],
        "more": len(rows) > PAGE,
        "kinds": list(activity.KINDS),
    }
