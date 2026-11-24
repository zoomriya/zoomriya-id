"""A member's birth year, set by the admin: Myira's kids mode comes from it."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_birth_year"
down_revision: str | Sequence[str] | None = "0001_accounts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("birth_year", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "birth_year")
