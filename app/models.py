"""
Two tables, intentionally minimal:

Secret  — the encrypted payload itself, one-time-view + TTL expiry
Session — server-side session record, referenced by an opaque cookie value
          (see auth.py for why we use this instead of a signed JWT cookie)
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, Boolean
from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    # SQLite stores DateTime columns without timezone info, so we use naive UTC
    # throughout to avoid offset-naive vs offset-aware comparison errors.
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Secret(Base):
    __tablename__ = "secrets"

    id = Column(String, primary_key=True, default=_uuid)
    # Encrypted with Fernet (see crypto.py) — never stored in plaintext, even though
    # this is a demo app, doing this properly is the point of the exercise.
    encrypted_payload = Column(String, nullable=False)
    created_at = Column(DateTime, default=_utcnow)
    expires_at = Column(DateTime, nullable=False)
    viewed = Column(Boolean, default=False)
    # Who actually viewed it — useful for the "evidence" / demo narrative,
    # shows the auth-gating is real, not decorative.
    viewed_by_sub = Column(String, nullable=True)
    viewed_at = Column(DateTime, nullable=True)
    # Comma-separated allowlist of Asgardeo-verified email addresses.
    # NULL means unrestricted (anyone authenticated can view).
    allowed_emails = Column(String, nullable=True)

    def is_expired(self) -> bool:
        return _utcnow() >= self.expires_at

    def is_available(self) -> bool:
        return not self.viewed and not self.is_expired()
    
    def is_allowed(self, email: str | None) -> bool:
        if not self.allowed_emails:
            return True     # no restriction set
        if not email:
            return False    # restriction set but viewer has no email claim
        allowed = {e.strip().lower() for e in self.allowed_emails.split(",")}
        return email.strip().lower() in allowed


class UserSession(Base):
    __tablename__ = "sessions"

    # This is the opaque value stored in the cookie. Random, unguessable,
    # carries no claims itself — it's just a lookup key into this table.
    session_id = Column(String, primary_key=True, default=_uuid)
    sub = Column(String, nullable=False)        # Asgardeo user's stable subject ID
    email = Column(String, nullable=True)        # for display / evidence only
    created_at = Column(DateTime, default=_utcnow)
    expires_at = Column(DateTime, nullable=False)

    def is_expired(self) -> bool:
        return _utcnow() >= self.expires_at
