"""Make the first account, an admin, while ZOOMRIYA ID has no accounts at all.

There is no default account and no default password. Whoever sets ZOOMRIYA ID
up makes the first admin with a password the person chose: the first-boot
setup page on a ZOOMRIYA Box, the apps' installer elsewhere, and
``scripts/dev.sh`` in development::

    printf '%s' "$PASSWORD" | python -m app.first_admin <username>

The password comes on standard input, so it never shows in the process list.
Once any account exists it changes nothing and says so (exit 3), so every
caller can run it without checking first.
"""

from __future__ import annotations

import argparse
import sys

from sqlalchemy import select, text

from app.db import SessionLocal
from app.models import ROLE_ADMIN, User
from app.routes.users import MIN_PASSWORD_LENGTH
from app.security import hash_password

#: Held while checking and adding, so two callers at once (the box and an app's
#: installer) can't both make one.
_LOCK = 0x5A_49_44_01

#: Exit status when accounts already exist.
EXISTS = 3


class FirstAdminRefused(ValueError):
    """The username or password isn't one ZOOMRIYA ID accepts."""


def create_first_admin(username: str, password: str) -> bool:
    """The admin, if there are no accounts yet; False (nothing changed) otherwise."""
    username = username.strip()
    if not 1 <= len(username) <= 128:
        raise FirstAdminRefused("The username must be 1 to 128 characters")
    if not MIN_PASSWORD_LENGTH <= len(password) <= 256:
        raise FirstAdminRefused(
            f"The password must be {MIN_PASSWORD_LENGTH} to 256 characters"
        )
    with SessionLocal() as db:
        db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _LOCK})
        if db.execute(select(User.id).limit(1)).first() is not None:
            return False
        db.add(
            User(
                username=username,
                hashed_password=hash_password(password),
                role=ROLE_ADMIN,
                is_active=True,
                token_version=0,
            )
        )
        db.commit()
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("username", help="The admin's username")
    args = parser.parse_args(argv)
    password = sys.stdin.readline().rstrip("\r\n")
    try:
        created = create_first_admin(args.username, password)
    except FirstAdminRefused as exc:
        print(exc, file=sys.stderr)
        return 2
    if not created:
        print("ZOOMRIYA ID already has accounts; nothing was changed.", file=sys.stderr)
        return EXISTS
    print(f"Made {args.username.strip()}, the first admin.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
