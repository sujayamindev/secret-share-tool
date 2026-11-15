"""
Shared test fixtures.

Env vars must be set before the FIRST `import app...` anywhere in the test
session: app/config.py reads the environment when Settings() is first built,
and app/database.py builds its SQLAlchemy `engine` from settings.DATABASE_URL
at module-import time. So this file sets everything up top, before any app
import, and points DATABASE_URL at an isolated temp file rather than the
dev/prod app.db.

The identity provider is faked, but not hollowed out: `FakeProvider` holds a
real RSA key and signs real RS256 ID tokens, and the app verifies them with
its real code path (PyJWKClient key lookup + jwt.decode). Only the network is
replaced. That is what lets tests/test_auth.py hand the app forged, expired
and mis-addressed tokens and check that each one is refused.
"""
import base64
import hashlib
import hmac
import json
import os
import tempfile
import time
from urllib.parse import parse_qs, urlsplit

_db_dir = tempfile.mkdtemp(prefix="secret-share-tests-")
os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(_db_dir, "test.db").replace("\\", "/")
os.environ["OIDC_ISSUER"] = "https://idp.test/"
os.environ["OIDC_CLIENT_ID"] = "test-client-id"
os.environ["OIDC_CLIENT_SECRET"] = "test-client-secret"
os.environ["OIDC_REDIRECT_URI"] = "http://localhost:8000/auth/callback"
os.environ["ENVIRONMENT"] = "development"
os.environ.pop("OIDC_DISCOVERY_URL", None)
os.environ["TRUSTED_PROXY_HOPS"] = "0"

from datetime import timedelta  # noqa: E402

import httpx  # noqa: E402
import jwt  # noqa: E402
import pytest  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import auth, secrets_router  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Secret, UserSession, _utcnow, sha256_hex  # noqa: E402

APP_ORIGIN = "http://localhost:8000"
ISSUER = "https://idp.test/"
CLIENT_ID = "test-client-id"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# Generating an RSA key is slow, and nothing about a test depends on the key
# being new, so one signing key is shared by the whole run.
_PROVIDER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeProvider:
    """A stand-in identity provider: discovery document, JWKS, token endpoint."""

    def __init__(self):
        self.key = _PROVIDER_KEY
        self.kid = "test-key-1"
        self.discovery = {
            "issuer": ISSUER,
            "authorization_endpoint": "https://idp.test/authorize",
            "token_endpoint": "https://idp.test/oauth/token",
            "jwks_uri": "https://idp.test/.well-known/jwks.json",
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        }
        self.id_token: str | None = None       # what the token endpoint will return
        self.token_status = 200
        self.token_requests: list[httpx.Request] = []
        self.discovery_requests = 0

    def jwks(self) -> dict:
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    def public_pem(self) -> bytes:
        return self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def claims(self, **overrides) -> dict:
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "user-1",
            "iat": now,
            "exp": now + 300,
            "email": "viewer@example.com",
            "email_verified": True,
        }
        claims.update(overrides)
        # A value of None means "leave this claim out of the token".
        return {k: v for k, v in claims.items() if v is not None}

    def mint(self, *, key=None, kid=None, **overrides) -> str:
        return jwt.encode(
            self.claims(**overrides), key or self.key, algorithm="RS256",
            headers={"kid": kid or self.kid},
        )

    def mint_unsigned(self, **overrides) -> str:
        """`alg: none` — a token that claims it needs no signature at all."""
        header = b64url(json.dumps({"alg": "none", "typ": "JWT", "kid": self.kid}).encode())
        payload = b64url(json.dumps(self.claims(**overrides)).encode())
        return f"{header}.{payload}."

    def mint_hs256_with_public_key(self, **overrides) -> str:
        """Algorithm confusion: sign with HMAC, using the provider's PUBLIC key
        (which anyone can download) as the HMAC secret. A verifier that lets
        the token pick its algorithm would check this with that same public
        key and accept it. PyJWT refuses to build such a token, so it is
        assembled by hand here."""
        header = b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": self.kid}).encode())
        payload = b64url(json.dumps(self.claims(**overrides)).encode())
        signing_input = f"{header}.{payload}".encode()
        signature = hmac.new(self.public_pem(), signing_input, hashlib.sha256).digest()
        return f"{header}.{payload}.{b64url(signature)}"

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/openid-configuration":
            self.discovery_requests += 1
            return httpx.Response(200, json=self.discovery)
        if request.url.path == "/oauth/token":
            self.token_requests.append(request)
            if self.token_status != 200:
                return httpx.Response(self.token_status, json={"error": "invalid_grant"})
            return httpx.Response(200, json={
                "access_token": "unused", "token_type": "Bearer", "id_token": self.id_token,
            })
        return httpx.Response(404)


@pytest.fixture
def idp(monkeypatch, _isolate):
    provider = FakeProvider()
    auth.reset_provider_cache()
    monkeypatch.setattr(auth, "_transport", httpx.MockTransport(provider.handle))
    # PyJWKClient fetches keys with urllib rather than httpx, so its one
    # network method is replaced directly. Its key selection (match the
    # token's `kid` against the set) still runs for real.
    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", lambda _self: provider.jwks())
    yield provider
    auth.reset_provider_cache()


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Applied to every test: a clean rate limiter, and no real network. A
    test that does not ask for the `idp` fixture gets a provider that is
    simply down, instead of a ten-second DNS timeout against idp.test."""
    secrets_router.create_limiter.reset()
    auth.reset_provider_cache()
    monkeypatch.setattr(auth, "_transport", httpx.MockTransport(lambda _r: httpx.Response(503)))


@pytest.fixture
def db():
    """A plain SQLAlchemy session for setting up/inspecting rows directly."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def new_client() -> TestClient:
    """Intentionally NOT `with TestClient(app) as client:` — that form reuses
    a single persistent portal (one background thread/event loop) across every
    call, which would serialize "concurrent" requests in the race-condition
    test. Without the context manager, each call gets its own fresh portal
    (its own thread), so two threads calling this concurrently get genuine
    OS-thread-level concurrency.

    The Origin header is what a browser attaches to a same-origin fetch();
    tests of the cross-origin check override or remove it."""
    return TestClient(app, headers={"origin": APP_ORIGIN})


@pytest.fixture
def client():
    return new_client()


# --- OIDC flow helpers ------------------------------------------------------

def start_login(client, next_path="/"):
    """GET /auth/login. Returns the parameters the app sent to the provider."""
    response = client.get("/auth/login", params={"next": next_path}, follow_redirects=False)
    assert response.status_code == 302, response.text
    location = response.headers["location"]
    params = {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
    params["_location"] = location
    params["_response"] = response
    return params


def finish_login(client, state, code="good-code"):
    return client.get("/auth/callback", params={"code": code, "state": state},
                      follow_redirects=False)


def login(client, idp, next_path="/", **claims):
    """Complete a whole login as the fake provider's user. Returns the callback response."""
    params = start_login(client, next_path)
    idp.id_token = idp.mint(nonce=params["nonce"], **claims)
    return finish_login(client, params["state"])


# --- direct row helpers -----------------------------------------------------

CLAIM_TOKEN = b64url(bytes(range(32)))      # a fixed, valid-shaped claim token
OTHER_CLAIM_TOKEN = b64url(bytes(range(1, 33)))
CIPHERTEXT = b64url(b"\x01" * 40)           # opaque to the server; any bytes do
IV = b64url(b"\x02" * 12)


def make_secret(db, *, allowed_emails=None, expires_in_minutes=60,
                ciphertext=CIPHERTEXT, claim_token=CLAIM_TOKEN):
    secret = Secret(
        ciphertext=ciphertext,
        iv=IV,
        claim_token_hash=sha256_hex(base64.urlsafe_b64decode(claim_token + "=")),
        expires_at=_utcnow() + timedelta(minutes=expires_in_minutes),
        allowed_emails=allowed_emails,
    )
    db.add(secret)
    db.commit()
    db.refresh(secret)
    return secret


def sign_in(client, db, *, email="viewer@example.com", sub="test-sub-1", expires_in_minutes=30):
    """Give `client` a session by inserting the row directly, bypassing the
    OIDC flow (which tests/test_auth.py covers on its own). Returns the raw
    session token so tests can check it is not what the database stores."""
    token = f"test-session-{os.urandom(16).hex()}"
    db.add(UserSession(
        token_hash=sha256_hex(token), sub=sub, email=email,
        expires_at=_utcnow() + timedelta(minutes=expires_in_minutes),
    ))
    db.commit()
    client.cookies.set(auth.SESSION_COOKIE_NAME, token)
    return token


def claim(client, secret_id, claim_token=CLAIM_TOKEN, **kwargs):
    return client.post(f"/api/secrets/{secret_id}/claim",
                       json={"claim_token": claim_token}, **kwargs)
