"""A password an admin set for someone else is temporary: they choose their
own at their first sign-in (Hub-Design.md, decision H13)."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_temporary_password"
down_revision: str | Sequence[str] | None = "0005_member_place"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("password_temporary", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("users", "password_temporary")
