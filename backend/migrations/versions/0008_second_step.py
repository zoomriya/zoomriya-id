"""Kept as an empty step so databases already past it still line up; what it
added was taken out again (0011_email_second_step)."""

from collections.abc import Sequence

revision: str = "0008_second_step"
down_revision: str | Sequence[str] | None = "0007_ai_keys"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
