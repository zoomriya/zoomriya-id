"""The second sign-in step: a code sent by email through the family's own email
account (decided 24 November 2026; app.second_step, app.mail).

Whatever an earlier version of the step kept is removed for good: its columns
on ``users`` and its lines in the family's activity. Nothing of it comes back
on a downgrade."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_email_second_step"
down_revision: str | Sequence[str] | None = "0010_sign_in_lock"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_EARLIER = ("second_step_secret", "second_step_pending", "second_step_last", "second_step_backup")


def upgrade() -> None:
    for column in _EARLIER:
        op.execute(f"ALTER TABLE users DROP COLUMN IF EXISTS {column}")
    # Its lines in the activity: everything about the step so far, and the
    # sign-ins and wrong tries that named it.
    op.execute(
        """
        DELETE FROM activity
        WHERE kind = 'second-step'
           OR what IN ('Signed in with a backup code', 'Wrong second-step code')
           OR what LIKE '%new second step%'
        """
    )
    op.add_column("users", sa.Column("second_step_email", sa.String(254), nullable=True))
    op.add_column("users", sa.Column("second_step_email_pending", sa.String(254), nullable=True))
    op.add_column("users", sa.Column("second_step_code", sa.String(128), nullable=True))
    op.add_column("users", sa.Column("second_step_code_use", sa.String(16), nullable=True))
    op.add_column(
        "users", sa.Column("second_step_code_until", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "users", sa.Column("second_step_code_sent", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_table(
        "mail_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("security", sa.String(16), nullable=False),
        sa.Column("username", sa.String(254), nullable=False),
        sa.Column("password_sealed", sa.String(1024), nullable=False),
        sa.Column("from_address", sa.String(254), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("mail_settings")
    for column in (
        "second_step_code_sent",
        "second_step_code_until",
        "second_step_code_use",
        "second_step_code",
        "second_step_email_pending",
        "second_step_email",
    ):
        op.drop_column("users", column)
