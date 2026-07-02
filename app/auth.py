"""
OIDC Authorization Code flow against Asgardeo, plus our own server-side session.

Flow:
  1. GET /auth/login?next=<secret_id>  -> redirect to Asgardeo's authorize endpoint
     (with a `nonce` bound to this login attempt, to prevent ID token replay)
  2. User authenticates on Asgardeo's hosted login page (we never see their password)
  3. Asgardeo redirects back to /auth/callback?code=...&state=...
  4. We exchange the code for tokens (server-to-server, using client_secret)
  5. We cryptographically verify the ID token's signature against Asgardeo's
     published JWKS, check aud/exp/nonce, then extract `sub`/`email` directly
     from the verified claims — no further network call needed.
  6. We create OUR OWN session row + cookie, and redirect back to the secret.

`state` protects the OAuth redirect itself from CSRF. `nonce` is a separate,
narrower protection: it's embedded inside the signed ID token and prevents an
attacker from replaying a previously-issued, still-valid ID token into our
callback to impersonate a login.
"""
import secrets as pysecrets
from datetime import timedelta
from urllib.parse import urlencode

import httpx
import jwt
from jwt import PyJWKClient
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session as DBSession

from app.config import get_settings
from app.database import get_db
from app.models import UserSession, _utcnow

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()

SESSION_COOKIE_NAME = "session_id"
OAUTH_STATE_COOKIE = "oauth_state"
OAUTH_NONCE_COOKIE = "oauth_nonce"
OAUTH_NEXT_COOKIE = "oauth_next"

_discovery_cache: dict | None = None
_jwk_client: PyJWKClient | None = None


async def get_discovery_doc() -> dict:
    """Fetched once and cached — avoids hitting Asgardeo's discovery endpoint
    on every login. In a multi-worker prod deployment this just means each
    worker caches its own copy, which is fine for endpoints that essentially
    never change."""
    global _discovery_cache
    if _discovery_cache is None:
        async with httpx.AsyncClient() as client:
            resp = await client.get(settings.OIDC_DISCOVERY_URL)
            resp.raise_for_status()
            _discovery_cache = resp.json()
    return _discovery_cache


def get_jwk_client(jwks_uri: str) -> PyJWKClient:
    """PyJWKClient handles fetching + caching Asgardeo's public signing keys
    (and re-fetching automatically if a token references a key ID it hasn't
    seen, e.g. after Asgardeo rotates keys). Created once, reused across requests."""
    global _jwk_client
    if _jwk_client is None:
        _jwk_client = PyJWKClient(jwks_uri)
    return _jwk_client


def _safe_next(next: str) -> str:
    """Only allow same-origin relative paths as a post-login redirect target.
    `next` is attacker-controllable (it's a public query param), so without this
    check /auth/login?next=https://evil.com would send a just-authenticated user
    straight to an attacker's site — an open redirect."""
    if next.startswith("/") and not next.startswith("//") and "://" not in next:
        return next
    return "/"


@router.get("/login")
async def login(request: Request, next: str = "/"):
    next = _safe_next(next)
    discovery = await get_discovery_doc()
    state = pysecrets.token_urlsafe(24)
    nonce = pysecrets.token_urlsafe(24)

    params = {
        "response_type": "code",
        "client_id": settings.ASGARDEO_CLIENT_ID,
        "redirect_uri": settings.ASGARDEO_REDIRECT_URI,
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
    }
    auth_url = f"{discovery['authorization_endpoint']}?{urlencode(params)}"

    response = RedirectResponse(auth_url)
    # Short-lived cookies just to survive the round trip to Asgardeo and back.
    # 5 minutes is generous for a login redirect.
    response.set_cookie(OAUTH_STATE_COOKIE, state, max_age=300, httponly=True,
                         secure=settings.COOKIE_SECURE, samesite="lax")
    response.set_cookie(OAUTH_NONCE_COOKIE, nonce, max_age=300, httponly=True,
                         secure=settings.COOKIE_SECURE, samesite="lax")
    response.set_cookie(OAUTH_NEXT_COOKIE, next, max_age=300, httponly=True,
                         secure=settings.COOKIE_SECURE, samesite="lax")
    return response


@router.get("/callback")
async def callback(request: Request, code: str | None = None, state: str | None = None,
                    error: str | None = None, db: DBSession = Depends(get_db)):
    if error:
        raise HTTPException(400, f"Asgardeo returned an error: {error}")

    cookie_state = request.cookies.get(OAUTH_STATE_COOKIE)
    if not state or not cookie_state or state != cookie_state:
        # CSRF protection on the redirect itself: an attacker can trick a user
        # into hitting /auth/callback with a code they obtained themselves,
        # but they can't also forge the state cookie that only our redirect set.
        raise HTTPException(400, "Invalid OAuth state")

    expected_nonce = request.cookies.get(OAUTH_NONCE_COOKIE)
    if not expected_nonce:
        raise HTTPException(400, "Missing OAuth nonce")

    next_url = _safe_next(request.cookies.get(OAUTH_NEXT_COOKIE, "/"))
    discovery = await get_discovery_doc()

    # Exchange the authorization code for tokens. This call is server-to-server
    # and includes the client_secret — it never touches the browser.
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            discovery["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.ASGARDEO_REDIRECT_URI,
                "client_id": settings.ASGARDEO_CLIENT_ID,
                "client_secret": settings.ASGARDEO_CLIENT_SECRET,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if token_resp.status_code != 200:
            raise HTTPException(400, "Token exchange with Asgardeo failed")
        tokens = token_resp.json()

    id_token = tokens.get("id_token")
    if not id_token:
        raise HTTPException(400, "Asgardeo did not return an ID token")

    # Cryptographic verification: fetch (or reuse cached) Asgardeo public keys,
    # find the one matching this token's `kid` header, and verify the
    # signature + standard claims. If any of this fails, jwt raises and we 400.
    jwk_client = get_jwk_client(discovery["jwks_uri"])
    signing_key = jwk_client.get_signing_key_from_jwt(id_token)
    try:
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.ASGARDEO_CLIENT_ID,
            issuer=discovery["issuer"],
        )
    except jwt.PyJWTError as e:
        raise HTTPException(400, f"ID token verification failed: {e}")

    if claims.get("nonce") != expected_nonce:
        # The check that specifically defeats ID token replay: even a
        # perfectly valid, correctly-signed token is rejected if it wasn't
        # issued for *this* login attempt.
        raise HTTPException(400, "Invalid nonce — possible token replay")

    sub = claims["sub"]
    email = claims.get("email")

    # Create OUR session — the opaque, revocable record described in models.py.
    # The Asgardeo tokens are discarded after this point; we don't hold onto them.
    session_row = UserSession(
        sub=sub,
        email=email,
        expires_at=_utcnow() + timedelta(minutes=settings.SESSION_TTL_MINUTES),
    )
    db.add(session_row)
    db.commit()

    response = RedirectResponse(next_url)
    response.delete_cookie(OAUTH_STATE_COOKIE)
    response.delete_cookie(OAUTH_NONCE_COOKIE)
    response.delete_cookie(OAUTH_NEXT_COOKIE)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_row.session_id,
        max_age=settings.SESSION_TTL_MINUTES * 60,
        httponly=True,                      # JS can't read it — blocks XSS token theft
        secure=settings.COOKIE_SECURE,      # HTTPS-only in production
        samesite="lax",                     # CSRF mitigation for state-changing requests
    )
    return response


def get_current_session(request: Request, db: DBSession = Depends(get_db)) -> UserSession | None:
    """FastAPI dependency: resolves the cookie -> session row, or None if
    missing/expired. Routes decide what to do with None (usually: redirect to login)."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        return None
    session_row = db.get(UserSession, session_id)
    if not session_row or session_row.is_expired():
        return None
    return session_row
