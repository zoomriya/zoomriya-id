"""Children's accounts and their guardians (Hub-Design.md §1).

A member whose birth year makes them under 18 becomes a child's account, with
no guardian yet: Family Hub asks the admin to choose one.
"""

from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0003_children"
down_revision: str | Sequence[str] | None = "0002_birth_year"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("is_child", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("users", sa.Column("level_move", sa.String(length=16), nullable=True))
    op.create_table(
        "guardians",
        sa.Column(
            "child_id",
            sa.BigInteger(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "guardian_id",
            sa.BigInteger(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_guardians_guardian_id", "guardians", ["guardian_id"])
    # Under 18 all this year (this year - birth year - 1 < 18): a child.
    op.execute(
        sa.text(
            "UPDATE users SET is_child = true WHERE birth_year IS NOT NULL AND birth_year > :y"
        ).bindparams(y=datetime.now(UTC).year - 19)
    )


def downgrade() -> None:
    op.drop_index("ix_guardians_guardian_id", table_name="guardians")
    op.drop_table("guardians")
    op.drop_column("users", "level_move")
    op.drop_column("users", "is_child")
