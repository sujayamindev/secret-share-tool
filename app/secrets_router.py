"""
The actual product logic: create a secret, view it once (gated by Asgardeo auth),
then delete it. This is intentionally the smallest possible router — one feature,
done well, per the project scope decision.
"""
import re
from datetime import timedelta

from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import update
from sqlalchemy.orm import Session as DBSession

from app.config import get_settings
from app.database import get_db
from app.models import Secret, _utcnow
from app.crypto import encrypt, decrypt
from app.auth import get_current_session

router = APIRouter(tags=["secrets"])
templates = Jinja2Templates(directory="app/templates")
settings = get_settings()

# A paste-a-secret box, not a file upload — 100 KB comfortably covers any
# real credential/config/API-key blob without leaving the payload size
# (and therefore the encrypt/store cost per request) unbounded.
MAX_PAYLOAD_LENGTH = 100_000
MAX_ALLOWED_EMAILS_LENGTH = 2000
# Deliberately loose (no full RFC 5322 grammar) — this only needs to catch
# typos/garbage in the allowlist, not validate deliverability.
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class _ValidationError(Exception):
    """Raised for user-fixable input problems on /create. Caught in the route
    itself so the person gets the form back with their input intact and an
    inline message, rather than a bare JSON error from an uncaught HTTPException."""


def _parse_allowed_emails(raw: str) -> str | None:
    """Validate + normalize the comma-separated allowlist. Returns None for
    "unrestricted" (blank input), otherwise a lowercased, deduped, comma-joined
    string. Rejects malformed entries outright rather than silently storing
    them — a typo'd email here would otherwise create a secret nobody can
    ever pass is_allowed() for, and the sender wouldn't find out until the
    recipient reports the link as broken."""
    raw = raw.strip()
    if not raw:
        return None

    emails = [e.strip().lower() for e in raw.split(",") if e.strip()]
    invalid = [e for e in emails if not EMAIL_RE.match(e)]
    if invalid:
        raise _ValidationError(f"Not a valid email address: {invalid[0]}")

    return ",".join(dict.fromkeys(emails)) or None  # dedupe, preserve order


@router.get("/")
async def create_form(request: Request):
    return templates.TemplateResponse("create.html", {"request": request})


@router.post("/create")
async def create_secret(
    request: Request,
    payload: str = Form(..., max_length=MAX_PAYLOAD_LENGTH),
    allowed_emails: str = Form("", max_length=MAX_ALLOWED_EMAILS_LENGTH),
    db: DBSession = Depends(get_db),
):
    try:
        if not payload.strip():
            raise _ValidationError("Secret cannot be empty")
        parsed_allowed_emails = _parse_allowed_emails(allowed_emails)
    except _ValidationError as exc:
        # Re-render the form with what they typed still in place, rather than
        # a bare JSON 400 — this is the only path a malformed submission takes,
        # since the client-side pattern/maxlength checks are advisory only.
        return templates.TemplateResponse(
            "create.html",
            {
                "request": request,
                "error": str(exc),
                "payload": payload,
                "allowed_emails": allowed_emails,
            },
            status_code=400,
        )

    secret = Secret(
        encrypted_payload=encrypt(payload),
        expires_at=_utcnow() + timedelta(minutes=settings.SECRET_TTL_MINUTES),
        allowed_emails=parsed_allowed_emails,
    )
    db.add(secret)
    db.commit()

    # Redirect (Post/Redirect/Get) rather than rendering created.html directly:
    # refreshing this confirmation screen must not resubmit the form and mint
    # a second secret for the same paste.
    return RedirectResponse(
        request.url_for("created", secret_id=secret.id), status_code=303
    )


@router.get("/created/{secret_id}", name="created")
async def created(request: Request, secret_id: str, db: DBSession = Depends(get_db)):
    secret = db.get(Secret, secret_id)
    if not secret:
        return RedirectResponse(request.url_for("create_form"))

    share_url = request.url_for("view_secret", secret_id=secret_id)
    return templates.TemplateResponse(
        "created.html", {"request": request, "share_url": share_url}
    )


@router.get("/secret/{secret_id}", name="view_secret")
async def view_secret(request: Request, secret_id: str, db: DBSession = Depends(get_db)):
    # Auth is checked before existence, not after: an unauthenticated request
    # must get the *same* "go log in" redirect whether secret_id is real,
    # already-viewed, or made up. Checking existence first would let anyone
    # probe IDs for "gone (404)" vs "still live (redirect to login)" without
    # spending a single Asgardeo login — free existence-oracle for a UUID
    # that's otherwise unguessable. Authenticating first closes that off.
    session_row = get_current_session(request, db)
    if not session_row:
        login_url = request.url_for("login").include_query_params(next=request.url.path)
        return RedirectResponse(login_url)

    secret = db.get(Secret, secret_id)
    if not secret or not secret.is_available():
        # Same response whether it never existed, was already viewed, or expired —
        # deliberately not leaking *which* of those happened, that distinction
        # isn't useful to an attacker probing for valid-but-viewed IDs.
        return templates.TemplateResponse("gone.html", {"request": request}, status_code=404)

    # Authenticated. Check allowlist before revealing.
    if not secret.is_allowed(session_row.email):
        return templates.TemplateResponse("gone.html", {"request": request}, status_code=403)

    # Atomically claim the secret: an UPDATE ... WHERE viewed = 0, not a
    # read-then-write. Two concurrent requests for the same link can both
    # pass the is_available() check above before either commits — only one
    # of them may win this UPDATE, so only one can ever reach decrypt().
    # This is what actually makes "view exactly once" true, rather than
    # true-by-accident-of-current-deployment-config.
    result = db.execute(
        update(Secret)
        .where(Secret.id == secret.id, Secret.viewed == False)  # noqa: E712
        .values(viewed=True, viewed_by_sub=session_row.sub, viewed_at=_utcnow())
    )
    db.commit()
    if result.rowcount != 1:
        # Someone else won the race (or viewed it a moment ago) — same
        # indistinguishable "gone" response as any other unavailable secret.
        return templates.TemplateResponse("gone.html", {"request": request}, status_code=404)

    # Reveal once, then destroy — this is the core security property.
    plaintext = decrypt(secret.encrypted_payload)

    return templates.TemplateResponse(
        "view.html",
        {"request": request, "secret": plaintext, "viewer_email": session_row.email},
    )
