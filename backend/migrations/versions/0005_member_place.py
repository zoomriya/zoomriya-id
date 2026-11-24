"""A member's own place, when not with the family (a child at university
elsewhere): their province or state, for Myira, holidays and time zones."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_member_place"
down_revision: str | Sequence[str] | None = "0004_child_controls"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("place", sa.String(length=8), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "place")
