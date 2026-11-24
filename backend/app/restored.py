"""The box was brought back from a backup: a line in the family's activity
(Box Desktop's Log Center, Family Hub's Activity), so the admins see who did
it and from when, whoever it was.

Only ZOOMRIYA OS's agent runs it, as ZOOMRIYA ID's own account, once the
accounts are back from the backup drive::

    python -m app.restored --date "14 November 2026" --by priya

Every account came back as it was: passwords, second steps and signed-in
devices. Nothing here changes them.
"""

from __future__ import annotations

import argparse
import sys

from app import activity
from app.db import SessionLocal


def record_restore(date: str, by: str) -> str:
    """Write the line, and give it back."""
    what = f"This box was restored from the backup of {date.strip()[:40]} by {by.strip()[:64]}"
    with SessionLocal() as db:
        activity.record(db, activity.ACCOUNT, what, source="The box")
    return what


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--date", required=True, help="The backup's date, as the admin reads it")
    parser.add_argument("--by", required=True, help="Who brought it back")
    args = parser.parse_args(argv)
    print(record_restore(args.date, args.by))
    return 0


if __name__ == "__main__":
    sys.exit(main())
