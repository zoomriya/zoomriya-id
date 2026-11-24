"""The second sign-in step: a six-digit code sent by email, after the password.
A choice for everyone, admins too (decided 24 November 2026).

- **The email** goes out through the family's own email account (app.mail),
  which an admin sets in Box Desktop. No text messages.
- **A code** works once, for ten minutes, for what it was sent for (signing
  in, or turning the step on). Only a keyed hash of it is kept (app.sealing).
  Wrong codes count toward the person's sign-in lock (app.sign_in_lock).
- **Tickets** carry a sign-in from the password to the code: signed by
  ZOOMRIYA ID, for ten minutes, useless anywhere else.
- **A trusted device** skips the code for thirty days: a signed token, kept in
  a cookie (and given to Box Desktop, which keeps its own). Signing out,
  changing the password or the step's address ends it.
"""

from __future__ import annotations

import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from sqlalchemy.orm import Session
from zoomriya_identity import identity

from app import mail, sealing
from app.models import User

DIGITS = 6
CODE_MINUTES = 10
#: "Send again" waits this long after the last code, so an inbox isn't flooded.
RESEND_SECONDS = 30
TRUST_DAYS = 30
TICKET_AUDIENCE = "zoomriya-id:second-step"
TRUST_AUDIENCE = "zoomriya-id:trusted-device"
TICKET_MINUTES = CODE_MINUTES
#: What a code is for.
CHECK = "check"
SETUP = "setup"

_WORDS = {
    "en": {
        "subject": "Your ZOOMRIYA code: {code}",
        CHECK: (
            "Your code to sign in to ZOOMRIYA is {code}\n\n"
            "It works for {minutes} minutes.\n\n"
            "If you did not just sign in, someone may know your password. "
            "Change it in your account, or ask an admin."
        ),
        SETUP: (
            "Your code to turn on sign-in codes by email is {code}\n\n"
            "It works for {minutes} minutes.\n\n"
            "If you did not ask for this, you can ignore this email."
        ),
    },
    "fr": {
        "subject": "Votre code ZOOMRIYA : {code}",
        CHECK: (
            "Votre code pour vous connecter à ZOOMRIYA est {code}\n\n"
            "Il est valable {minutes} minutes.\n\n"
            "Si vous ne venez pas de vous connecter, quelqu'un connaît peut-être "
            "votre mot de passe. Changez-le dans votre compte, ou prévenez un admin."
        ),
        SETUP: (
            "Votre code pour activer les codes par e-mail est {code}\n\n"
            "Il est valable {minutes} minutes.\n\n"
            "Si vous n'avez rien demandé, ignorez cet e-mail."
        ),
    },
}


class TooSoon(Exception):
    """A code was sent less than RESEND_SECONDS ago."""

    def __init__(self, seconds: int) -> None:
        super().__init__(seconds)
        self.seconds = seconds


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(moment: datetime | None) -> datetime | None:
    if moment is not None and moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment


def _hash(user_id: int, use: str, code: str) -> str:
    return sealing.keyed_hash(f"{user_id}:{use}:{code}")


def masked(address: str) -> str:
    """``e•••@gmail.com``: enough to tell which inbox, not the whole address."""
    name, _, domain = address.partition("@")
    return f"{name[:1]}•••@{domain}"


def send_code(db: Session, user: User, use: str, to: str) -> None:
    """A new code to ``to``, in the member's language. The one before stops
    working. TooSoon when one went out moments ago; mail.MailError when the
    email couldn't be sent (nothing is kept then)."""
    now = _now()
    sent = _aware(user.second_step_code_sent)
    if sent is not None and (now - sent).total_seconds() < RESEND_SECONDS:
        raise TooSoon(RESEND_SECONDS - int((now - sent).total_seconds()))
    code = str(secrets.randbelow(10**DIGITS)).zfill(DIGITS)
    words = _WORDS.get(user.language or "en", _WORDS["en"])
    mail.send(
        db,
        to,
        words["subject"].format(code=code),
        words[use].format(code=code, minutes=CODE_MINUTES),
    )
    user.second_step_code = _hash(user.id, use, code)
    user.second_step_code_use = use
    user.second_step_code_until = now + timedelta(minutes=CODE_MINUTES)
    user.second_step_code_sent = now
    db.add(user)
    db.commit()


def take_code(user: User, use: str, code: str) -> bool:
    """True when it's the code sent last, for this, still in time; it's used
    up then. Changes ``user``; the caller commits."""
    code = "".join(code.split())
    until = _aware(user.second_step_code_until)
    if (
        len(code) != DIGITS
        or not code.isdigit()
        or user.second_step_code is None
        or user.second_step_code_use != use
        or until is None
        or until < _now()
    ):
        return False
    if not hmac.compare_digest(user.second_step_code, _hash(user.id, use, code)):
        return False
    forget_code(user)
    return True


def forget_code(user: User) -> None:
    user.second_step_code = None
    user.second_step_code_use = None
    user.second_step_code_until = None
    user.second_step_code_sent = None


def view(db: Session, user: User) -> dict[str, object]:
    """For the member's own account page."""
    return {
        "on": user.has_second_step,
        "email": user.second_step_email,
        # The family's email is set up, so it can be turned on.
        "available": mail.is_set(db),
    }


def clear(user: User) -> None:
    """The step off: no address, no code waiting."""
    user.second_step_email = None
    user.second_step_email_pending = None
    forget_code(user)


# --- tickets and trusted devices ------------------------------------------------


def _sign(claims: dict[str, Any]) -> str:
    from app.security import _sign as sign

    return sign(claims)


def _verify(token: str, audience: str) -> dict[str, Any]:
    from app.security import _our_keys

    return identity.verify_token(token, _our_keys(), audience=audience)


def create_ticket(user_id: int, token_version: int) -> str:
    now = _now()
    return _sign(
        {
            "iss": identity.ISSUER,
            "aud": TICKET_AUDIENCE,
            "sub": str(user_id),
            "ver": token_version,
            "use": CHECK,
            "iat": now,
            "exp": now + timedelta(minutes=TICKET_MINUTES),
        }
    )


def read_ticket(ticket: str) -> dict[str, Any]:
    """The ticket's claims; ``jwt.InvalidTokenError`` when it isn't a good one."""
    return _verify(ticket, TICKET_AUDIENCE)


def _address_mark(user: User) -> str:
    # Changes with the step's address, so moving it ends every trust.
    return sealing.keyed_hash(f"trust:{user.id}:{user.second_step_email or ''}")[:16]


def create_trust(user: User) -> str:
    now = _now()
    return _sign(
        {
            "iss": identity.ISSUER,
            "aud": TRUST_AUDIENCE,
            "sub": str(user.id),
            "ver": user.token_version,
            "adr": _address_mark(user),
            "iat": now,
            "exp": now + timedelta(days=TRUST_DAYS),
        }
    )


def is_trusted(user: User, token: str | None) -> bool:
    """This device passed the code lately, as this member, since they last
    signed out or changed their password or address."""
    if not token:
        return False
    try:
        claims = _verify(token, TRUST_AUDIENCE)
    except jwt.InvalidTokenError:
        return False
    return (
        claims.get("sub") == str(user.id)
        and int(claims.get("ver", -1)) == user.token_version
        and hmac.compare_digest(str(claims.get("adr", "")), _address_mark(user))
    )
