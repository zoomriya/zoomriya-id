"""The family's activity, for admins (decision 28; app.activity)."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_activity"
down_revision: str | Sequence[str] | None = "0008_second_step"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "activity",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column(
            "member_id",
            sa.BigInteger(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "by_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("what", sa.String(300), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("address", sa.String(64), nullable=True),
    )
    op.create_index("ix_activity_at", "activity", ["at"])
    op.create_index("ix_activity_kind", "activity", ["kind"])
    op.create_index("ix_activity_member_id", "activity", ["member_id"])


def downgrade() -> None:
    op.drop_table("activity")
