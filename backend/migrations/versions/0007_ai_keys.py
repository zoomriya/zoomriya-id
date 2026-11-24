"""Keys members make for their own AI apps, which the box's MCP service
trades for a short-lived token as them (Solutions Design: ZOOMRIYA MCP)."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_ai_keys"
down_revision: str | Sequence[str] | None = "0006_temporary_password"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ai_keys",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "user_id",
            sa.BigInteger(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(60), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("prefix", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_ai_keys_user_id", "ai_keys", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_ai_keys_user_id", table_name="ai_keys")
    op.drop_table("ai_keys")
