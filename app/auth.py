"""
OpenID Connect Authorization Code flow against any standards-compliant
provider, plus our own server-side session.

Flow:
  1. GET /auth/login?next=/secret/<id>  -> redirect to the provider's authorize
     endpoint, carrying three per-attempt values (below)
  2. The user authenticates on the provider's hosted page (we never see a password)
  3. The provider redirects back to /auth/callback?code=...&state=...
  4. We exchange the code for tokens (server-to-server, using the client secret)
  5. We cryptographically verify the ID token's signature against the
     provider's published keys (JWKS), check its claims, then read `sub` and
     `email` straight from the verified token — no further network call.
  6. We create OUR OWN session row + cookie, and redirect back to the secret.

Three per-attempt values, each stopping a different attack:
  state          Ties the callback to a login this browser started. Without it
                 an attacker could make a victim's browser finish a login the
                 attacker began (login CSRF).
  nonce          Embedded by the provider inside the signed ID token. Stops a
                 previously issued, still-valid ID token being replayed.
  code_verifier  PKCE. We send its hash when starting, and the value itself
                 when redeeming the code, so a stolen authorization code is
                 useless to anyone who did not start this attempt.

Nothing in this module is specific to one provider: every endpoint comes from
the discovery document, and the only fixed inputs are the four OIDC_* settings.
"""
import base64
import hashlib
import hmac
import logging
import re
import secrets as pysecrets
import threading
from datetime import timedelta
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import delete
from sqlalchemy.orm import Session as DBSession

from app.config import get_settings
from app.database import get_db
from app.models import UserSession, _utcnow, sha256_hex
from app.security import require_same_origin_json
from app.web import error_page

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()
logger = logging.getLogger("secretshare.auth")

SESSION_COOKIE_NAME = f"{settings.COOKIE_PREFIX}session"
STATE_COOKIE = f"{settings.COOKIE_PREFIX}oidc_state"
NONCE_COOKIE = f"{settings.COOKIE_PREFIX}oidc_nonce"
VERIFIER_COOKIE = f"{settings.COOKIE_PREFIX}oidc_verifier"
NEXT_COOKIE = f"{settings.COOKIE_PREFIX}oidc_next"
LOGIN_COOKIES = (STATE_COOKIE, NONCE_COOKIE, VERIFIER_COOKIE, NEXT_COOKIE)
LOGIN_COOKIE_MAX_AGE = 600  # 10 minutes to complete a login, including sign-up

# Signature algorithms we accept. This list is fixed here and never taken from
# the token's own header: a token is not allowed to choose how it is checked.
# All three are asymmetric (the provider signs with a private key, we verify
# with the public one). No HS* — that would let anyone who knows the *public*
# key forge tokens — and no "none".
ALLOWED_ALGORITHMS = ["RS256", "PS256", "ES256"]

# Tolerance for the provider's clock and ours disagreeing slightly.
CLOCK_SKEW_SECONDS = 60

# The only place a login may send someone afterwards.
_NEXT_RE = re.compile(
    r"/secret/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)

# Tests replace this with an httpx.MockTransport standing in for the provider.
_transport: httpx.BaseTransport | None = None
_discovery_cache: dict | None = None
_jwk_client: jwt.PyJWKClient | None = None
_provider_lock = threading.Lock()


class AuthError(Exception):
    """Any reason a login attempt is refused. The message is for the server
    log only; the browser always gets the same generic page."""


def _http() -> httpx.Client:
    # follow_redirects is off (httpx's default, stated here on purpose): the
    # provider's endpoints are fixed URLs, and a redirect from one of them
    # would mean sending the client secret somewhere we did not choose.
    return httpx.Client(transport=_transport, timeout=10, follow_redirects=False)


def reset_provider_cache() -> None:
    global _discovery_cache, _jwk_client
    with _provider_lock:
        _discovery_cache = None
        _jwk_client = None


def get_discovery() -> dict:
    """Fetch the provider's discovery document once and cache it.

    The document tells us where the provider's endpoints and signing keys
    are. It also names the provider's issuer, and that must match the issuer
    we were configured with exactly (OIDC Discovery 1.0, section 4.3). Without
    this check, a wrong or tampered OIDC_DISCOVERY_URL would silently change
    whose tokens we accept, since everything else is read from the document."""
    global _discovery_cache
    with _provider_lock:
        if _discovery_cache is not None:
            return _discovery_cache
        try:
            with _http() as client:
                response = client.get(settings.OIDC_DISCOVERY_URL)
                response.raise_for_status()
                document = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise AuthError(f"could not load discovery document: {exc}") from exc

        if document.get("issuer") != settings.OIDC_ISSUER:
            raise AuthError(
                f"discovery issuer {document.get('issuer')!r} does not equal "
                f"OIDC_ISSUER {settings.OIDC_ISSUER!r} (they must match exactly, "
                "including any trailing slash)"
            )
        for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            value = document.get(field)
            if not isinstance(value, str):
                raise AuthError(f"discovery document has no {field}")
            if not settings.IS_DEVELOPMENT and not value.startswith("https://"):
                raise AuthError(f"discovery {field} is not https")
        _discovery_cache = document
        return document


def get_jwk_client() -> jwt.PyJWKClient:
    """PyJWKClient fetches and caches the provider's public signing keys, and
    re-fetches if a token names a key ID it has not seen (key rotation).
    Created once, reused across requests."""
    global _jwk_client
    discovery = get_discovery()
    with _provider_lock:
        if _jwk_client is None:
            _jwk_client = jwt.PyJWKClient(discovery["jwks_uri"], timeout=10)
        return _jwk_client


def safe_next(value: str | None) -> str:
    """Where to go after login. `next` is a public query parameter, so it is
    attacker-controlled; left unchecked, /auth/login?next=https://evil.example
    would bounce a freshly signed-in user to an attacker's site.

    This is an allow-list, not a filter. A login only ever happens on the way
    to a secret, so the one accepted shape is /secret/<uuid>. Everything else
    becomes "/". Trying to enumerate the dangerous shapes instead ("//host",
    "/\\host", "scheme://", control characters...) is a game the defender
    eventually loses."""
    if value and _NEXT_RE.fullmatch(value):
        return value
    return "/"


def _set_login_cookie(response, name: str, value: str) -> None:
    # HttpOnly: page script cannot read these. SameSite=Lax (not Strict): the
    # provider's redirect back to us is a cross-site navigation, and Strict
    # would withhold the cookies on exactly that request.
    response.set_cookie(name, value, max_age=LOGIN_COOKIE_MAX_AGE, httponly=True,
                        secure=settings.COOKIE_SECURE, samesite="lax", path="/")


def _clear_login_cookies(response) -> None:
    for name in LOGIN_COOKIES:
        response.delete_cookie(name, path="/", secure=settings.COOKIE_SECURE,
                               httponly=True, samesite="lax")


def _login_failed(request: Request, status_code: int = 400):
    response = error_page(
        request, status_code, "Sign-in failed",
        "We couldn't complete the sign-in. Open your link again to retry.",
    )
    _clear_login_cookies(response)
    return response


@router.get("/login", name="login")
def login(request: Request, next: str = "/"):
    try:
        discovery = get_discovery()
    except AuthError as exc:
        logger.error("login unavailable: %s", exc)
        return error_page(request, 502, "Sign-in unavailable",
                          "The identity provider could not be reached. Try again shortly.")

    state = pysecrets.token_urlsafe(32)
    nonce = pysecrets.token_urlsafe(32)
    code_verifier = pysecrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b"=").decode()

    params = {
        "response_type": "code",
        "client_id": settings.OIDC_CLIENT_ID,
        "redirect_uri": settings.OIDC_REDIRECT_URI,
        # `email` is the only identity attribute the app uses. Not asking for
        # `profile` means never receiving a name or picture to look after.
        "scope": "openid email",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    endpoint = discovery["authorization_endpoint"]
    separator = "&" if "?" in endpoint else "?"
    # The trailing "#_" is deliberate. A browser following a redirect whose
    # Location has no fragment carries the *current* URL's fragment over to
    # the new one (RFC 9110, section 10.2.2) — and in this app a fragment is a
    # decryption key. The secret page's script strips the key before anyone
    # can get here, so this should never matter; if that ever failed, this
    # explicit fragment replaces the inherited one and the provider's page
    # sees "#_" instead of a key.
    auth_url = f"{endpoint}{separator}{urlencode(params)}#_"

    response = RedirectResponse(auth_url, status_code=302)
    _set_login_cookie(response, STATE_COOKIE, state)
    _set_login_cookie(response, NONCE_COOKIE, nonce)
    _set_login_cookie(response, VERIFIER_COOKIE, code_verifier)
    _set_login_cookie(response, NEXT_COOKIE, safe_next(next))
    return response


def _exchange_code(discovery: dict, code: str, code_verifier: str) -> str:
    """Trade the one-time authorization code for tokens. Server-to-server:
    the client secret never touches the browser. Returns the raw ID token."""
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.OIDC_REDIRECT_URI,
        "code_verifier": code_verifier,
    }
    auth = None
    # Providers differ on how the client authenticates to the token endpoint.
    # Use the form-body method where the provider lists it, otherwise the
    # HTTP Basic method, which is what the OIDC spec says to assume.
    methods = discovery.get("token_endpoint_auth_methods_supported", ["client_secret_basic"])
    if "client_secret_post" in methods:
        data["client_id"] = settings.OIDC_CLIENT_ID
        data["client_secret"] = settings.OIDC_CLIENT_SECRET
    else:
        auth = (settings.OIDC_CLIENT_ID, settings.OIDC_CLIENT_SECRET)

    try:
        with _http() as client:
            response = client.post(discovery["token_endpoint"], data=data, auth=auth)
    except httpx.HTTPError as exc:
        raise AuthError(f"token endpoint unreachable: {exc}") from exc
    if response.status_code != 200:
        raise AuthError(f"token endpoint returned {response.status_code}")
    try:
        id_token = response.json().get("id_token")
    except ValueError as exc:
        raise AuthError("token endpoint did not return JSON") from exc
    if not isinstance(id_token, str):
        raise AuthError("token response has no id_token")
    return id_token


def verify_id_token(id_token: str, expected_nonce: str) -> dict:
    """Return the claims of a valid ID token, or raise AuthError.

    "Valid" means all of:
      - signed by a key the provider currently publishes (JWKS), using one of
        ALLOWED_ALGORITHMS
      - iss  is the provider we are configured for
      - aud  includes our client ID (the token was issued to this app)
      - azp  if present, or if there are several audiences, is our client ID
      - exp  is in the future; exp, iat and sub are all present
      - nonce is the one this browser's login attempt started with
    """
    try:
        signing_key = get_jwk_client().get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=ALLOWED_ALGORITHMS,
            audience=settings.OIDC_CLIENT_ID,
            # Checked against our configuration, not against whatever the
            # discovery document says.
            issuer=settings.OIDC_ISSUER,
            leeway=CLOCK_SKEW_SECONDS,
            # PyJWT only validates a claim if it is present. Without this, a
            # token with no `exp` at all would be accepted and never expire.
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise AuthError(f"ID token rejected: {exc}") from exc

    # OIDC Core 3.1.3.7: with more than one audience, `azp` (authorized party)
    # says which client the token was actually issued to, and it must be us.
    audiences = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
    authorized_party = claims.get("azp")
    if len(audiences) > 1 and authorized_party is None:
        raise AuthError("ID token has several audiences and no azp")
    if authorized_party is not None and authorized_party != settings.OIDC_CLIENT_ID:
        raise AuthError("ID token azp is a different client")

    token_nonce = claims.get("nonce")
    if not isinstance(token_nonce, str) or not hmac.compare_digest(token_nonce, expected_nonce):
        raise AuthError("ID token nonce does not match this login attempt")
    return claims


@router.get("/callback", name="callback")
def callback(request: Request, code: str | None = None, state: str | None = None,
             error: str | None = None, db: DBSession = Depends(get_db)):
    try:
        if error:
            # e.g. the user pressed Cancel on the provider's page. The value
            # is attacker-controllable, so it is logged and never echoed.
            raise AuthError(f"provider returned error {error!r}")

        cookie_state = request.cookies.get(STATE_COOKIE)
        expected_nonce = request.cookies.get(NONCE_COOKIE)
        code_verifier = request.cookies.get(VERIFIER_COOKIE)
        if not (code and state and cookie_state and expected_nonce and code_verifier):
            raise AuthError("callback is missing parameters or login cookies")
        # compare_digest: the comparison takes the same time wherever the
        # first difference is, so response timing reveals nothing about it.
        if not hmac.compare_digest(state, cookie_state):
            raise AuthError("state does not match")

        discovery = get_discovery()
        id_token = _exchange_code(discovery, code, code_verifier)
        claims = verify_id_token(id_token, expected_nonce)
    except AuthError as exc:
        logger.warning("login refused: %s", exc)
        return _login_failed(request)

    # The allowlist compares against this value, so it must be an address the
    # provider has actually verified. Many providers let someone sign up as
    # any address and log in before confirming it; such a token carries
    # `email_verified: false`, and we then record no email at all. Strictly
    # the boolean `true` — a missing claim or the string "true" does not count.
    email = claims.get("email") if claims.get("email_verified") is True else None
    if not isinstance(email, str):
        email = None

    # Create OUR session. The cookie holds a random token; the database holds
    # only its hash (see models.py). The provider's tokens are discarded here.
    session_token = pysecrets.token_urlsafe(32)
    db.add(UserSession(
        token_hash=sha256_hex(session_token),
        sub=claims["sub"],
        email=email,
        expires_at=_utcnow() + timedelta(minutes=settings.SESSION_TTL_MINUTES),
    ))
    db.commit()

    # A relative path: the browser resolves it against the URL it is already
    # on, so the scheme and host cannot be influenced by request headers.
    response = RedirectResponse(safe_next(request.cookies.get(NEXT_COOKIE)), status_code=303)
    _clear_login_cookies(response)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_token,
        max_age=settings.SESSION_TTL_MINUTES * 60,
        httponly=True,                      # page script can't read it
        secure=settings.COOKIE_SECURE,      # HTTPS only, outside development
        samesite="lax",                     # withheld from cross-site POSTs
        path="/",
    )
    return response


@router.post("/logout", name="logout", dependencies=[Depends(require_same_origin_json)])
def logout(request: Request, db: DBSession = Depends(get_db)):
    """Revoke the session: delete the row, so the cookie stops working
    immediately wherever a copy of it exists. This is the property an opaque
    server-side session has and a signed-claims (JWT) cookie does not.

    Returns where the browser should go next. If the provider advertises an
    end-session endpoint (OIDC RP-Initiated Logout), that is the provider's
    logout page, so the provider's own session ends too — otherwise the next
    "Sign in" would silently log the same person straight back in."""
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if session_token:
        db.execute(delete(UserSession).where(
            UserSession.token_hash == sha256_hex(session_token)))
        db.commit()

    redirect_to = "/"
    try:
        end_session = get_discovery().get("end_session_endpoint")
    except AuthError:
        end_session = None
    if isinstance(end_session, str):
        separator = "&" if "?" in end_session else "?"
        redirect_to = end_session + separator + urlencode({
            "client_id": settings.OIDC_CLIENT_ID,
            "post_logout_redirect_uri": settings.APP_ORIGIN + "/",
        })

    response = JSONResponse({"redirect": redirect_to})
    response.delete_cookie(SESSION_COOKIE_NAME, path="/", secure=settings.COOKIE_SECURE,
                           httponly=True, samesite="lax")
    return response


def get_current_session(request: Request, db: DBSession) -> UserSession | None:
    """Resolve the cookie to a live session row, or None if missing/expired."""
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_token:
        return None
    session_row = db.get(UserSession, sha256_hex(session_token))
    if not session_row or session_row.is_expired():
        return None
    return session_row
