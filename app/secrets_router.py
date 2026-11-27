"""
The actual product logic: store an encrypted secret, hand it over exactly
once to whoever holds the full link (and, if the sender listed emails,
has signed in as one of them), and delete it in the same step.

The server's role is deliberately that of a locked-box courier. The browser
encrypts before sending and decrypts after receiving (app/static/crypto.js);
this module only ever handles ciphertext it has no key for. What it does own
is everything the server CAN enforce: who may collect the box (session +
allowlist), proof that they hold the whole link (claim token), that it is
collected at most once, and that it is destroyed afterwards.
"""
import base64
import binascii
import hmac
import re
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as DBSession

from app.auth import get_current_session
from app.config import get_settings
from app.database import get_db
from app.models import Secret, _utcnow, sha256_hex
from app.security import RateLimiter, client_ip, require_same_origin_json
from app.web import gone_page, humanize_minutes, templates

router = APIRouter(tags=["secrets"])
settings = get_settings()

# A paste-a-secret box, not a file upload — 100 KB comfortably covers any
# real credential/config/API-key blob. Counted in BYTES of UTF-8, which is
# what actually lands on disk (a character can be up to four bytes).
MAX_PLAINTEXT_BYTES = 100_000
GCM_TAG_BYTES = 16      # AES-GCM appends a 128-bit authentication tag
GCM_IV_BYTES = 12       # 96-bit nonce, the size GCM is designed around
KEY_BYTES = 32          # link secret and claim token are both 256 bits
MAX_CIPHERTEXT_BYTES = MAX_PLAINTEXT_BYTES + GCM_TAG_BYTES
MAX_ALLOWED_EMAILS_LENGTH = 2000

# Deliberately loose (no full RFC 5322 grammar) — this only needs to catch
# typos/garbage in the allowlist, not validate deliverability.
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+(?:\.[^@\s.]+)+$")
_BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]+")
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

create_limiter = RateLimiter(capacity=settings.CREATE_RATE_LIMIT_PER_MINUTE, per_seconds=60)

# One response for every reason a claim can fail: never existed, expired,
# already claimed, wrong claim token, caller not on the allowlist. Telling these apart would tell a prober which IDs are
# live, and tell a stranger that a secret exists but is meant for someone else.
def _gone() -> HTTPException:
    return HTTPException(404, "This secret is not available.")


class _ValidationError(Exception):
    """A user-fixable problem with a create request."""


def _b64url_decode(value: str) -> bytes:
    """Strict base64url without padding. Python's decoder is lenient by
    default (it skips characters outside the alphabet), so the alphabet is
    checked first: what we store is exactly what was sent, nothing else."""
    if not _BASE64URL_RE.fullmatch(value):
        raise ValueError("not base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except binascii.Error as exc:
        raise ValueError("not base64url") from exc


def _parse_allowed_emails(raw: str) -> str | None:
    """Validate + normalize the allowlist. Entries are separated by commas or
    any whitespace, so a list pasted one-per-line from a spreadsheet works; an
    unquoted email address cannot contain whitespace, so splitting on it never
    cuts a valid address in two. Returns None for
    "unrestricted" (blank input), otherwise a lowercased, deduped, comma-joined
    string. Rejects malformed entries outright rather than silently storing
    them — a typo'd email here would otherwise create a secret nobody can
    ever pass is_allowed() for, and the sender wouldn't find out until the
    recipient reports the link as broken."""
    raw = raw.strip()
    if not raw:
        return None

    emails = [e.lower() for e in re.split(r"[,\s]+", raw) if e]
    invalid = [e for e in emails if not EMAIL_RE.match(e)]
    if invalid:
        raise _ValidationError(f"Not a valid email address: {invalid[0]}")

    return ",".join(dict.fromkeys(emails)) or None  # dedupe, preserve order


class CreateSecretRequest(BaseModel):
    # Lengths here are coarse upper bounds on the encoded strings; the exact
    # decoded sizes are checked in the route.
    ciphertext: str = Field(max_length=MAX_CIPHERTEXT_BYTES * 4 // 3 + 4)
    iv: str = Field(max_length=32)
    claim_token: str = Field(max_length=64)
    allowed_emails: str = Field("", max_length=MAX_ALLOWED_EMAILS_LENGTH)


class ClaimSecretRequest(BaseModel):
    claim_token: str = Field(max_length=64)


# HEAD too: uptime monitors and link checkers probe the home page with it, and
# a 405 reads as "site down". Same handler; the server (uvicorn) sends no body.
@router.api_route("/", methods=["GET", "HEAD"], name="create_form")
def create_form(request: Request):
    # The lifetime is a fixed setting, so the page states it up front and on
    # the result view without a round trip.
    return templates.TemplateResponse(request, "create.html", {
        "max_plaintext_bytes": MAX_PLAINTEXT_BYTES,
        "secret_lifetime": humanize_minutes(get_settings().SECRET_TTL_MINUTES),
    })


@router.post("/api/secrets", status_code=201, dependencies=[Depends(require_same_origin_json)])
def create_secret(body: CreateSecretRequest, request: Request, db: DBSession = Depends(get_db)):
    # Creating is anonymous, so this endpoint is the one a stranger can use to
    # fill the disk. Two limits: a per-address rate, and a ceiling on how many
    # secrets may exist at once regardless of who made them.
    if not create_limiter.allow(client_ip(request)):
        raise HTTPException(429, "Too many secrets created from this address. Wait a minute.",
                            headers={"Retry-After": "60"})

    try:
        try:
            ciphertext = _b64url_decode(body.ciphertext)
            iv = _b64url_decode(body.iv)
            claim_token = _b64url_decode(body.claim_token)
        except ValueError:
            raise _ValidationError("Malformed request.") from None
        # The server cannot check that this really is ciphertext — it has no
        # key — but it can insist on the exact shape AES-256-GCM output has.
        if len(iv) != GCM_IV_BYTES or len(claim_token) != KEY_BYTES:
            raise _ValidationError("Malformed request.")
        if len(ciphertext) <= GCM_TAG_BYTES:
            raise _ValidationError("Secret cannot be empty.")
        if len(ciphertext) > MAX_CIPHERTEXT_BYTES:
            raise _ValidationError(f"Secret is too large (limit {MAX_PLAINTEXT_BYTES:,} bytes).")
        allowed_emails = _parse_allowed_emails(body.allowed_emails)
    except _ValidationError as exc:
        raise HTTPException(400, str(exc)) from None

    live = db.scalar(select(func.count()).select_from(Secret).where(Secret.expires_at > _utcnow()))
    if live >= settings.MAX_LIVE_SECRETS:
        raise HTTPException(503, "The service is at capacity. Try again later.")

    secret = Secret(
        ciphertext=body.ciphertext,
        iv=body.iv,
        claim_token_hash=sha256_hex(claim_token),
        allowed_emails=allowed_emails,
        expires_at=_utcnow() + timedelta(minutes=settings.SECRET_TTL_MINUTES),
    )
    db.add(secret)
    db.commit()

    # Only the ID goes back. The share link is assembled in the browser,
    # because its second half (the key) is something this server never sees.
    return {"id": secret.id, "expires_in_minutes": settings.SECRET_TTL_MINUTES}


@router.get("/secret/{secret_id}", name="view_secret")
def view_secret(request: Request, secret_id: str, db: DBSession = Depends(get_db)):
    """Serves the page that holds the Reveal button. Two things this route
    deliberately does NOT do:

    - It never redirects to login. A browser carries a URL's #fragment across
      redirects, and here the fragment is the decryption key: a redirect chain
      to the identity provider would deliver the key to the provider's page.
      Returning a normal page lets our script take the key out of the URL
      first; only then does the user click through to sign in.
    - It never looks the secret up. The response is the same whether the ID
      is live, used, expired or invented, so loading this page (which needs
      no login) reveals nothing about which IDs exist. Loading it also changes
      nothing, so link scanners and prefetchers cannot burn a secret."""
    if not _UUID_RE.fullmatch(secret_id):
        return gone_page(request)

    session_row = get_current_session(request, db)
    return templates.TemplateResponse(request, "secret.html", {
        "secret_id": secret_id,
        "authenticated": session_row is not None,
        "viewer_email": session_row.email if session_row else None,
        # secret_id matched the UUID pattern above, so it is safe to place in a URL.
        "login_url": f"/auth/login?next=/secret/{secret_id}",
    })


@router.post("/api/secrets/{secret_id}/claim", dependencies=[Depends(require_same_origin_json)])
def claim_secret(secret_id: str, body: ClaimSecretRequest, request: Request,
                 db: DBSession = Depends(get_db)):
    # Order matters here. Proof that the caller holds the FULL link comes
    # first, before identity: everything that fails it gets the same 404,
    # signed in or not, so a prober holding only an ID (or nothing) learns
    # nothing, including whether that ID is restricted. The token is derived
    # from the link's key in the browser; we only ever stored its hash.
    secret = db.get(Secret, secret_id) if _UUID_RE.fullmatch(secret_id) else None
    try:
        presented_hash = sha256_hex(_b64url_decode(body.claim_token))
    except ValueError:
        presented_hash = None
    if (not secret or presented_hash is None
            or not hmac.compare_digest(presented_hash, secret.claim_token_hash)):
        # Nothing is consumed: a damaged or guessed link cannot burn a secret.
        raise _gone()
    if secret.is_expired():
        raise _gone()

    # Sign-in is asked for only when the sender restricted the secret to
    # specific addresses, because only then does identity decide anything.
    # Without an allowlist the link alone is the credential (any account
    # would pass), so requiring a login would add friction and no protection.
    # The 401 is only ever seen by someone who already holds the whole link,
    # so "this one is restricted" leaks nothing a link-holder could not see.
    if secret.allowed_emails:
        session_row = get_current_session(request, db)
        if not session_row:
            raise HTTPException(401, "Sign in to reveal this secret.")
        if not secret.is_allowed(session_row.email):
            raise _gone()

    # Copy out what we will return before deleting the row it lives in.
    payload = {"ciphertext": secret.ciphertext, "iv": secret.iv}

    # Atomically claim-and-destroy: a single conditional DELETE, judged by how
    # many rows it removed. Two requests can both pass every check above
    # before either commits — but the database runs the two DELETEs one after
    # the other, and only the first finds a row. That row count, not the
    # checks above, is what makes "exactly once" true. Expiry is repeated in
    # the WHERE clause so a secret that expires mid-request is not released.
    result = db.execute(
        delete(Secret).where(Secret.id == secret_id, Secret.expires_at > _utcnow())
    )
    db.commit()
    if result.rowcount != 1:
        raise _gone()

    # Delivery is at-most-once by design: the row is already gone when this
    # response is sent. If the connection drops now, the secret is lost — the
    # alternative (delete after the browser confirms) would allow two reads.
    return payload
