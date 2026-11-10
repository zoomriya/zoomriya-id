"""Move the accounts out of Photos into ZOOMRIYA ID, once, so nobody is signed out.

Copies, with the same ids, password hashes and token versions:

* Photos' ``users`` and ``user_app_access`` rows,
* the profile photos (``<Photos library>/avatars/...`` to ``<DATA_DIR>/avatars/...``),
* the Ed25519 signing key, so tokens and sessions Photos signed keep working.

Run it with the service stopped, before the first admin is made on an upgraded
box::

    PHOTOS_DATABASE_URL=postgresql+psycopg://zoomriya:...@localhost/zoomriya \\
        python -m app.import_from_photos

Optional: ``PHOTOS_LIBRARY_ROOT`` (default: the library folder Photos has
saved, else /data/zoomriya/media) and ``PHOTOS_SIGNING_KEY`` (default
/data/zoomriya/keys/zoomriya-id-ed25519.pem).
It refuses to run once ZOOMRIYA ID has accounts of its own. This is the one
time anything reads Photos' database; it only reads.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import create_engine, func, inspect, select, text

from app.config import settings
from app.db import SessionLocal
from app.models import User, UserAppAccess

USER_COLUMNS = (
    "id",
    "username",
    "display_name",
    "avatar_path",
    "avatar_version",
    "theme",
    "language",
    "hashed_password",
    "role",
    "is_active",
    "token_version",
    "created_at",
    "updated_at",
)


#: Where Photos keeps its library when the admin moved it (Storage settings).
PHOTOS_LIBRARY_SETTING = "storage.library_root"
PHOTOS_DEFAULT_LIBRARY = Path("/data/zoomriya/media")


class ImportRefused(Exception):
    """ZOOMRIYA ID already has accounts of its own."""


@dataclass
class ImportReport:
    users: int = 0
    app_switches: int = 0
    avatars: int = 0
    missing_avatars: int = 0
    skipped: int = 0
    key_copied: bool = False


def _copy_key(photos_key: Path) -> bool:
    """Photos' signing key becomes ZOOMRIYA ID's (readable by this user only)."""
    if not photos_key.is_file():
        return False
    target = settings.signing_key_path
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.is_file() and target.read_bytes() == photos_key.read_bytes():
        return False
    tmp = target.with_suffix(".tmp")
    tmp.write_bytes(photos_key.read_bytes())
    tmp.chmod(0o600)
    os.replace(tmp, target)
    return True


def _copy_avatar(library: Path, relative: str) -> bool:
    source = library / relative
    if not source.is_file():
        return False
    target = Path(settings.DATA_DIR) / relative
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copy2(source, target)
    return True


def import_accounts(
    photos_database_url: str, photos_library: Path | None, photos_key: Path
) -> ImportReport:
    """``photos_library`` None: wherever Photos keeps it."""
    report = ImportReport()
    photos = create_engine(photos_database_url)
    try:
        with photos.connect() as source:
            if photos_library is None:
                photos_library = PHOTOS_DEFAULT_LIBRARY
                if inspect(source).has_table("system_settings"):
                    saved = source.execute(
                        text("SELECT value FROM system_settings WHERE key = :key"),
                        {"key": PHOTOS_LIBRARY_SETTING},
                    ).scalar()
                    if saved:
                        photos_library = Path(saved)
            have = {column["name"] for column in inspect(source).get_columns("users")}
            if "hashed_password" not in have:
                # Photos' migration 0009 dropped them once the move was done.
                raise ImportRefused(
                    "This Photos database no longer holds the accounts (migration 0009): "
                    "import from a backup of it taken before that release"
                )
            rows = [
                dict(row._mapping)
                for row in source.execute(
                    text(f"SELECT {', '.join(USER_COLUMNS)} FROM users ORDER BY id")
                )
            ]
            switches = []
            if inspect(source).has_table("user_app_access"):
                switches = [
                    dict(row._mapping)
                    for row in source.execute(
                        text("SELECT user_id, app, enabled FROM user_app_access")
                    )
                ]
    finally:
        photos.dispose()

    with SessionLocal() as db:
        if db.execute(select(User.id).limit(1)).first() is not None:
            raise ImportRefused("ZOOMRIYA ID already has accounts; nothing was imported")

        for row in rows:
            if not row["hashed_password"]:
                # Joined after the move began: Photos never had their password.
                report.skipped += 1
                continue
            # NULL in Photos once its migration 0007 has run; never NULL here.
            row["avatar_version"] = row["avatar_version"] or 0
            if row["avatar_path"]:
                if _copy_avatar(photos_library, row["avatar_path"]):
                    report.avatars += 1
                else:
                    report.missing_avatars += 1
                    row["avatar_path"] = None
            db.add(User(**row))
            report.users += 1
        db.flush()
        known = {row["id"] for row in rows if row["hashed_password"]}
        for switch in switches:
            if switch["user_id"] in known:
                db.add(UserAppAccess(**switch))
                report.app_switches += 1
        # New accounts continue after the highest id Photos used.
        highest = db.execute(select(func.max(User.id))).scalar()
        if highest is not None:
            db.execute(
                text("SELECT setval(pg_get_serial_sequence('users', 'id'), :highest)"),
                {"highest": highest},
            )
        db.commit()

    report.key_copied = _copy_key(photos_key)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--photos-database-url",
        default=os.getenv("PHOTOS_DATABASE_URL", ""),
        help="Photos' database (or PHOTOS_DATABASE_URL)",
    )
    parser.add_argument(
        "--photos-library",
        default=os.getenv("PHOTOS_LIBRARY_ROOT", ""),
        help="Photos' library folder, where avatars/ is (default: where Photos keeps it)",
    )
    parser.add_argument(
        "--photos-key",
        default=os.getenv("PHOTOS_SIGNING_KEY", "/data/zoomriya/keys/zoomriya-id-ed25519.pem"),
        help="The signing key Photos used",
    )
    args = parser.parse_args(argv)
    if not args.photos_database_url:
        parser.error("Give --photos-database-url or PHOTOS_DATABASE_URL")
    try:
        report = import_accounts(
            args.photos_database_url,
            Path(args.photos_library) if args.photos_library else None,
            Path(args.photos_key),
        )
    except ImportRefused as exc:
        print(exc, file=sys.stderr)
        return 1
    missing = (
        f" ({report.missing_avatars} photo files were missing)" if report.missing_avatars else ""
    )
    print(
        f"Imported {report.users} accounts, {report.app_switches} app switches and "
        f"{report.avatars} profile photos{missing}."
    )
    if report.skipped:
        print(f"Skipped {report.skipped} members without a password in Photos.")
    if report.key_copied:
        print(f"Copied Photos' signing key to {settings.signing_key_path}.")
    print("Start (or restart) zoomriya-id now.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
