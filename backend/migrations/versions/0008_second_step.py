"""The second sign-in step: an authenticator app's code or a backup code
(decision 27; app.second_step)."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_second_step"
down_revision: str | Sequence[str] | None = "0007_ai_keys"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("second_step_secret", sa.String(255), nullable=True))
    op.add_column("users", sa.Column("second_step_pending", sa.String(255), nullable=True))
    op.add_column("users", sa.Column("second_step_last", sa.BigInteger(), nullable=True))
    op.add_column("users", sa.Column("second_step_backup", sa.JSON(), nullable=True))


def downgrade() -> None:
    for column in ("second_step_backup", "second_step_last", "second_step_pending", "second_step_secret"):
        op.drop_column("users", column)
