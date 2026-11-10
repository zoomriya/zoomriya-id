"""An admin who can't sign in, back in at the box: a new password, and their
second sign-in step cleared, so they set up a new one at their next sign-in.

Only ZOOMRIYA OS's agent runs it, after the person at the box typed the box's
setup code (on its sticker, or written down at the first setup), so holding the
box is what proves it's theirs::

    printf '%s' "$PASSWORD" | python -m app.recover_admin <username>

The password comes on standard input, so it never shows in the process list.
Every session of theirs is signed out. Exit 3: no active admin of that name.
"""

from __future__ import annotations

import argparse
import sys

from sqlalchemy import select
from zoomriya_identity import identity as id_format

from app import accounts as identity
from app.db import SessionLocal
from app.models import ROLE_ADMIN, User
from app.routes.users import MIN_PASSWORD_LENGTH
from app.security import hash_password

#: Exit status when there's no active admin of that name.
NO_SUCH_ADMIN = 3


class RecoverRefused(ValueError):
    """The password isn't one ZOOMRIYA ID accepts."""


def recover_admin(username: str, password: str) -> bool:
    """True when the admin got the new password; False if there's no such admin."""
    if not MIN_PASSWORD_LENGTH <= len(password) <= 256:
        raise RecoverRefused(f"The password must be {MIN_PASSWORD_LENGTH} to 256 characters")
    with SessionLocal() as db:
        user = db.execute(
            select(User).where(User.username == username.strip())
        ).scalar_one_or_none()
        if user is None or user.role != ROLE_ADMIN or not user.is_active:
            return False
        user.hashed_password = hash_password(password)
        user.password_temporary = False
        user.second_step_secret = None
        user.second_step_pending = None
        user.second_step_last = None
        user.second_step_backup = None
        # Signed out everywhere: whoever had their old password or a session is out.
        user.token_version += 1
        db.add(user)
        db.commit()
        db.refresh(user)
        identity.publish(db, id_format.USER_REVOKED, user)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("username", help="The admin's username")
    args = parser.parse_args(argv)
    password = sys.stdin.readline().rstrip("\r\n")
    try:
        done = recover_admin(args.username, password)
    except RecoverRefused as exc:
        print(exc, file=sys.stderr)
        return 2
    if not done:
        print("There's no active admin with that username.", file=sys.stderr)
        return NO_SUCH_ADMIN
    print(f"{args.username.strip()} has a new password; their second step was cleared.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
