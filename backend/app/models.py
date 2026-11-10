"""The accounts: one row per family member, and the admin's per-app switches."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.shared.db.base import Base, TimestampMixin

ROLE_ADMIN = "admin"
# Family members use the apps; only admins manage the family and the box.
ROLE_FAMILY = "family"


class User(TimestampMixin, Base):
    __tablename__ = "users"

    # The id every app knows the member by (the token's ``sub``).
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    # Shown in every app ("From Amma"); falls back to the username when empty.
    display_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Profile photo: a 256px WebP under DATA_DIR (``avatars/<id>-<random>.webp``).
    # avatar_version changes on every upload so browsers refetch it.
    avatar_path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    avatar_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    # Personal preferences, so they follow the person to every device and app.
    # None means the default (Midnight, English).
    theme: Mapped[str | None] = mapped_column(String(32), nullable=True)
    language: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Set by the admin when making the account. A child's birth year puts
    # Myira in kids mode for them (and picks the age band); an adult's is
    # optional and never under 18.
    birth_year: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # A child's account (the admin's choice): a child or a teen by the birth
    # year until 18, with one or two guardians (``Guardian``). The level is
    # worked out with ``zoomriya_identity.levels``, never stored.
    is_child: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    # A guardian's move within the under-18s ("child" or "teen"); None follows
    # the birth year.
    level_move: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # A child's quiet hours as their guardians set them
    # (``zoomriya_identity.quiet_hours``); None: the level's default.
    quiet_hours: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Where this member lives, when not with the family ("CA-AB": a child at
    # university in Alberta; ``zoomriya_identity.place``). None: the family's.
    # Set by the member, or a guardian for a child.
    place: Mapped[str | None] = mapped_column(String(8), nullable=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    # An admin set it for them from afar (Family Hub): signing in with it is
    # refused until they choose their own (``/auth/login/new-password``).
    password_temporary: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    role: Mapped[str] = mapped_column(String(32), nullable=False, default=ROLE_FAMILY)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Goes up to sign the member out everywhere: tokens carry it as ``ver``.
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # The second sign-in step (app.second_step): the authenticator app's secret,
    # encrypted; while one is being set up, the new secret waits beside it.
    # None: no second step.
    second_step_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    second_step_pending: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # The time step of the last code used, so no code works twice.
    second_step_last: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # The hashes of the backup codes not used yet.
    second_step_backup: Mapped[list | None] = mapped_column(JSON, nullable=True)

    @property
    def has_second_step(self) -> bool:
        return self.second_step_secret is not None

    @property
    def avatar_ref(self) -> int | None:
        """The avatar version to request, or None when there's no photo."""
        return self.avatar_version if self.avatar_path else None

    @property
    def shown_name(self) -> str:
        return (self.display_name or "").strip() or self.username


class UserAppAccess(TimestampMixin, Base):
    """An app the admin switched off (or back on) for one family member.

    No row means the default: every member gets every installed app. Photos
    never has a row: it stays on for everyone (Settings -> Family).
    """

    __tablename__ = "user_app_access"

    user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    app: Mapped[str] = mapped_column(String(32), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)


class AiKey(Base):
    """A key a member made for one of their own AI apps (``mcp``): the box's
    MCP service trades it for a short-lived access token as that member.
    Only its hash is kept; the member sees the key once, when it's made."""

    __tablename__ = "ai_keys"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    #: The member's name for it ("Claude on my laptop").
    name: Mapped[str] = mapped_column(String(60), nullable=False)
    #: sha256 of the key, hex.
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    #: Its first characters, to tell keys apart in the list.
    prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Guardian(TimestampMixin, Base):
    """A parent or guardian of a child's account: one or two per child.

    Chosen by the admin from the family's adults. Being admin doesn't make
    someone a guardian.
    """

    __tablename__ = "guardians"

    child_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    guardian_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    # When this guardian last opened the child's page: changes since, by
    # someone else, put a dot beside the child in Family Hub's sidebar.
    seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ChildChange(Base):
    """One change to a child's controls: who made it, what, when (decision H5).

    The other guardian sees it on the child's page, and the child on their
    dashboard (decision H6). Apps' own controls are logged by Family Hub
    after the app accepts the change, as the guardian who made it.
    """

    __tablename__ = "child_changes"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    child_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    by_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    what: Mapped[str] = mapped_column(String(300), nullable=False)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Activity(Base):
    """The family's activity, for admins (decision 28): sign-ins (and wrong
    passwords), second steps, passwords, accounts and their apps, AI keys;
    and what apps report: new devices, share links, setting changes. Kept 90
    days (``app.activity``)."""

    __tablename__ = "activity"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    # sign-in, sign-in-failed, second-step, password, account, ai-key, device,
    # share-link, setting (app.activity.KINDS).
    kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    # Whose it is, and who did it (an admin, for an account change); either
    # may be gone since (None), and a wrong password names no member.
    member_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    by_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # Plain words: "Signed in", "Turned on the second step", "Added a device: Pixel 8".
    what: Mapped[str] = mapped_column(String(300), nullable=False)
    # ZOOMRIYA ID, or the app that reported it (Family Photos…).
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    # The device's address on the home network (or through ZOOMRIYA Connect).
    address: Mapped[str | None] = mapped_column(String(64), nullable=True)
