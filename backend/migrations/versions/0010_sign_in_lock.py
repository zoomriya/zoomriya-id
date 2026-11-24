"""A person's sign-in locks for a while after too many wrong passwords
(app.sign_in_lock)."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_sign_in_lock"
down_revision: str | Sequence[str] | None = "0009_activity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users", sa.Column("failed_sign_ins", sa.Integer(), nullable=False, server_default="0")
    )
    op.add_column(
        "users", sa.Column("last_failed_sign_in", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "users", sa.Column("sign_in_locked_until", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    for column in ("sign_in_locked_until", "last_failed_sign_in", "failed_sign_ins"):
        op.drop_column("users", column)
