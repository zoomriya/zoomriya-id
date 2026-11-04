"""Quiet hours, the log of changes to a child's controls, and when each
guardian last looked (Hub-Design.md §1, decisions H5, H6, H7)."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_child_controls"
down_revision: str | Sequence[str] | None = "0003_children"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("quiet_hours", sa.JSON(), nullable=True))
    op.add_column("guardians", sa.Column("seen_at", sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        "child_changes",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "child_id",
            sa.BigInteger(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "by_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("what", sa.String(length=300), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_child_changes_child_id", "child_changes", ["child_id"])


def downgrade() -> None:
    op.drop_index("ix_child_changes_child_id", table_name="child_changes")
    op.drop_table("child_changes")
    op.drop_column("guardians", "seen_at")
    op.drop_column("users", "quiet_hours")
