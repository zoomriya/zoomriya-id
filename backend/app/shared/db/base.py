from datetime import datetime

from sqlalchemy import BigInteger, DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class IntPKMixin:
    """Standard BigInteger auto-incrementing primary key.

    Used by every model except ``User``, which declares its own ``id`` (also
    BIGINT) because it keeps an extra index on it.
    """

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)


class CreatedAtMixin:
    """``created_at`` timestamp, set once by the database on insert."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class TimestampMixin(CreatedAtMixin):
    """``created_at`` + ``updated_at``, both maintained by the database."""

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class VersionMixin:
    """Optimistic locking version column.

    Incremented on every UPDATE. Clients must send their expected version;
    if it mismatches, the update is rejected with 409 Conflict instead of
    silently overwriting concurrent changes.
    """

    version: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
