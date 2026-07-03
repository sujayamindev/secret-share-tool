"""
Shared test fixtures.

Env vars must be set before the FIRST `import app...` anywhere in the test
session: app/config.py reads os.environ[...] at class-definition time, and
app/database.py builds its SQLAlchemy `engine` from settings.DATABASE_URL at
module-import time. So this file sets everything up top, before any app
import, and points DATABASE_URL at an isolated temp file rather than the
dev/prod app.db.
"""
import os
import tempfile

from cryptography.fernet import Fernet

_db_fd, _db_path = tempfile.mkstemp(suffix=".db")
os.close(_db_fd)

os.environ.setdefault("ASGARDEO_BASE_URL", "https://example.asgardeo.test/t/testorg")
os.environ.setdefault("ASGARDEO_CLIENT_ID", "test-client-id")
os.environ.setdefault("ASGARDEO_CLIENT_SECRET", "test-client-secret")
os.environ.setdefault("ASGARDEO_REDIRECT_URI", "http://localhost:8000/auth/callback")
os.environ.setdefault("FERNET_KEY", Fernet.generate_key().decode())
os.environ["DATABASE_URL"] = f"sqlite:///{_db_path}"
os.environ.setdefault("ENVIRONMENT", "development")

import pytest  # noqa: E402
from datetime import timedelta  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import Secret, UserSession, _utcnow  # noqa: E402
from app.crypto import encrypt  # noqa: E402

SESSION_COOKIE_NAME = "session_id"


@pytest.fixture
def db():
    """A plain SQLAlchemy session for setting up/inspecting rows directly."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    """Intentionally NOT `with TestClient(app) as client:` — that form reuses
    a single persistent portal (one background thread/event loop) across every
    call, which would serialize "concurrent" requests in the race-condition
    test below. Without the context manager, each call gets its own fresh
    portal (its own thread), so two threads calling this concurrently get
    genuine OS-thread-level concurrency."""
    return TestClient(app)


def make_secret(db, *, allowed_emails=None, expires_in_minutes=60, payload="the-plaintext-secret"):
    secret = Secret(
        encrypted_payload=encrypt(payload),
        expires_at=_utcnow() + timedelta(minutes=expires_in_minutes),
        allowed_emails=allowed_emails,
    )
    db.add(secret)
    db.commit()
    db.refresh(secret)
    return secret


def make_authenticated_cookie(db, *, email="viewer@example.com", sub="test-sub-1"):
    """Creates a UserSession row directly (bypassing the real Asgardeo OIDC
    flow entirely) and returns the cookie dict to attach to a request."""
    session_row = UserSession(
        sub=sub,
        email=email,
        expires_at=_utcnow() + timedelta(minutes=30),
    )
    db.add(session_row)
    db.commit()
    db.refresh(session_row)
    return {SESSION_COOKIE_NAME: session_row.session_id}
