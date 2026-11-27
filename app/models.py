"""
Two tables, intentionally minimal:

Secret      — an encrypted payload the server cannot read, with a TTL
UserSession — server-side session record, referenced by an opaque cookie value
              (see auth.py for why we use this instead of a signed JWT cookie)

Neither table stores a usable bearer credential. The session cookie's value
and the secret's claim token are both stored only as SHA-256 hashes, so a
leaked copy of the database cannot be replayed as a login or as a claim.
Plain SHA-256 (no salt, no slow hash) is correct here because both inputs are
256-bit random values: there is nothing to brute-force or look up in a table.
"""
import hashlib
import uuid
from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, String, Text

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    # SQLite stores DateTime columns without timezone info, so we use naive UTC
    # throughout to avoid offset-naive vs offset-aware comparison errors.
    return datetime.now(UTC).replace(tzinfo=None)


def sha256_hex(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


class Secret(Base):
    __tablename__ = "secrets"

    id = Column(String, primary_key=True, default=_uuid)
    # AES-256-GCM output from the sender's browser, base64url. The key never
    # reaches the server, so this column is opaque to us by construction —
    # there is no server-side encryption layer because there is nothing left
    # for one to protect.
    ciphertext = Column(Text, nullable=False)
    # The GCM nonce. Not secret; stored so the recipient's browser can decrypt.
    iv = Column(String, nullable=False)
    # SHA-256 of the claim token, a value the browser derives from the link's
    # key with HKDF. Whoever claims the secret must present the token, which
    # proves they hold the full link and not just this row's id.
    claim_token_hash = Column(String, nullable=False)
    # Comma-separated allowlist of verified email addresses.
    # NULL means unrestricted: the full link alone opens it, with no sign-in.
    allowed_emails = Column(String, nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)

    # No `viewed` flag: a claimed secret is deleted, not marked. A row that
    # exists is by definition unclaimed.

    def is_expired(self) -> bool:
        return _utcnow() >= self.expires_at

    def is_allowed(self, email: str | None) -> bool:
        if not self.allowed_emails:
            return True     # no restriction set
        if not email:
            return False    # restriction set but viewer has no verified email
        allowed = {e.strip().lower() for e in self.allowed_emails.split(",")}
        return email.strip().lower() in allowed


class UserSession(Base):
    __tablename__ = "sessions"

    # SHA-256 of the random token held in the browser's cookie. The token
    # itself is never stored.
    token_hash = Column(String, primary_key=True)
    sub = Column(String, nullable=False)        # the provider's stable subject ID
    # Only ever set when the provider asserted `email_verified: true`. An
    # unverified address is treated as no address at all, because the
    # allowlist is only as trustworthy as this column.
    email = Column(String, nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)

    def is_expired(self) -> bool:
        return _utcnow() >= self.expires_at
