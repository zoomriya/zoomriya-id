"""ZOOMRIYA ID's own database (``zoomriya_id``): accounts and app access only."""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy.orm import Session

from app.config import settings
from app.shared.db.session import make_engine, make_session_factory

engine = make_engine(settings.DATABASE_URL)
SessionLocal = make_session_factory(engine)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
