"""The family's own email account, which sends the second step's codes.

An admin sets it in Box Desktop: the email provider's server, port, security
and the account's sign-in. ZOOMRIYA ID sends through it and nothing else:
nothing goes through ZOOMRIYA's servers, and there are no text messages (the
box has no SIM). The password is kept encrypted (app.sealing).
"""

from __future__ import annotations

import re
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr

from sqlalchemy.orm import Session

from app import sealing
from app.models import MailSettings

SSL = "ssl"
STARTTLS = "starttls"
SECURITY = (SSL, STARTTLS)
TIMEOUT_SECONDS = 15
SENDER_NAME = "ZOOMRIYA"
_PASSWORD_LABEL = "mail-settings"
_ADDRESS = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class MailError(Exception):
    """Sending (or signing in to the email account) didn't work. The words are
    for the admin: plain, without the server's own message."""


@dataclass(frozen=True)
class Account:
    host: str
    port: int
    security: str
    username: str
    password: str
    from_address: str


def is_address(text: str) -> bool:
    return len(text) <= 254 and bool(_ADDRESS.match(text))


def stored(db: Session) -> MailSettings | None:
    return db.get(MailSettings, 1)


def is_set(db: Session) -> bool:
    return stored(db) is not None


def view(row: MailSettings | None) -> dict[str, object]:
    """What Box Desktop shows; never the password."""
    if row is None:
        return {"set": False}
    return {
        "set": True,
        "host": row.host,
        "port": row.port,
        "security": row.security,
        "username": row.username,
        "from_address": row.from_address,
    }


def account(row: MailSettings) -> Account:
    return Account(
        host=row.host,
        port=row.port,
        security=row.security,
        username=row.username,
        password=sealing.unseal(row.password_sealed, _PASSWORD_LABEL),
        from_address=row.from_address,
    )


def save(db: Session, chosen: Account) -> MailSettings:
    row = stored(db) or MailSettings(id=1)
    row.host = chosen.host
    row.port = chosen.port
    row.security = chosen.security
    row.username = chosen.username
    row.password_sealed = sealing.seal(chosen.password, _PASSWORD_LABEL)
    row.from_address = chosen.from_address
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _connect(chosen: Account) -> smtplib.SMTP:
    context = ssl.create_default_context()
    try:
        if chosen.security == SSL:
            server: smtplib.SMTP = smtplib.SMTP_SSL(
                chosen.host, chosen.port, timeout=TIMEOUT_SECONDS, context=context
            )
        else:
            server = smtplib.SMTP(chosen.host, chosen.port, timeout=TIMEOUT_SECONDS)
            server.starttls(context=context)
    except (OSError, smtplib.SMTPException) as exc:
        raise MailError(
            "Couldn't reach the email server. Check the server name, port and security."
        ) from exc
    try:
        server.login(chosen.username, chosen.password)
    except smtplib.SMTPAuthenticationError as exc:
        server.close()
        raise MailError(
            "The email server refused the username or password. Some providers want an "
            "app password here."
        ) from exc
    except (OSError, smtplib.SMTPException) as exc:
        server.close()
        raise MailError("Couldn't sign in to the email server.") from exc
    return server


def check(chosen: Account) -> None:
    """Sign in to the account and out again; MailError when it doesn't work."""
    server = _connect(chosen)
    try:
        server.quit()
    except (OSError, smtplib.SMTPException):
        pass


def _deliver(chosen: Account, message: EmailMessage) -> None:
    """Sends one message (tests replace this)."""
    server = _connect(chosen)
    try:
        server.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise MailError("The email server didn't take the message.") from exc
    finally:
        try:
            server.quit()
        except (OSError, smtplib.SMTPException):
            pass


def send(db: Session, to: str, subject: str, body: str) -> None:
    """One plain-text email through the family's account; MailError when it
    isn't set up or doesn't work."""
    row = stored(db)
    if row is None:
        raise MailError("The family's email isn't set up.")
    chosen = account(row)
    message = EmailMessage()
    message["From"] = formataddr((SENDER_NAME, chosen.from_address))
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)
    _deliver(chosen, message)
