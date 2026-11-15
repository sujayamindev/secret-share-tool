"""
Cross-cutting protections that are not specific to one route:

- security response headers (CSP, framing, caching, HSTS)
- a cap on request body size, enforced before anything parses the body
- a same-origin check for the state-changing JSON endpoints (CSRF)
- a small in-memory rate limiter

Why these matter more in this app than in most: the decryption key lives in
the recipient's browser, on this origin. Anything that gets script to run on
this origin can read it. The Content-Security-Policy below is therefore the
main line of defence for the encryption, not an optional extra.
"""
import threading
import time

from fastapi import HTTPException, Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import get_settings

settings = get_settings()

# Everything is denied by default, then only this origin is allowed, per type.
# - script-src 'self'   : no inline script, no eval, no third-party script.
#                         That is why every script lives in app/static/.
# - style-src/font-src  : fonts are self-hosted so no other origin supplies
#                         anything to the page that shows the secret.
# - connect-src 'self'  : fetch() can only talk to this server.
# - frame-ancestors     : nobody can put the Reveal button in an iframe.
# - base-uri 'none'     : a stray <base> tag cannot re-point relative URLs.
CONTENT_SECURITY_POLICY = "; ".join([
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self'",
    "font-src 'self'",
    "connect-src 'self'",
    "form-action 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
])

# A JSON create request is at most ~133 KB of base64 plus a few fields.
MAX_BODY_BYTES = 256 * 1024


class SecurityHeadersMiddleware:
    """Adds the headers to every response, including error responses.

    Written as plain ASGI rather than with Starlette's BaseHTTPMiddleware:
    it only needs to add headers as the response starts, and plain ASGI does
    that without wrapping the request in an extra task."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        is_static = scope["path"].startswith("/static/")

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                extra = {
                    b"content-security-policy": CONTENT_SECURITY_POLICY.encode(),
                    # Never send this site's URLs (which contain secret IDs)
                    # to anywhere the user navigates next — including the
                    # identity provider.
                    b"referrer-policy": b"no-referrer",
                    b"x-content-type-options": b"nosniff",
                    # Same job as frame-ancestors, for older browsers.
                    b"x-frame-options": b"DENY",
                }
                if not is_static:
                    # Pages and API responses must not be written to the
                    # browser's disk cache or restored by the Back button.
                    extra[b"cache-control"] = b"no-store"
                if settings.COOKIE_SECURE:
                    # This host only: no includeSubDomains, since the parent
                    # domain hosts unrelated projects.
                    extra[b"strict-transport-security"] = b"max-age=31536000"
                present = {name.lower() for name, _ in headers}
                headers.extend((k, v) for k, v in extra.items() if k not in present)
            await send(message)

        await self.app(scope, receive, send_with_headers)


class BodySizeLimitMiddleware:
    """Rejects oversized request bodies before any parser buffers them.

    Field-level limits (max_length on a model) only apply after the whole
    body has been read into memory, so on their own they do nothing against
    a multi-gigabyte upload. This counts bytes as they arrive."""

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_BODY_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Fast path: an honest client declares the size up front.
        for name, value in scope["headers"]:
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = self.max_bytes + 1
                if declared > self.max_bytes:
                    await self._reject(send)
                    return

        # Slow path: the declared length can be missing (chunked upload) or a
        # lie, so count what actually arrives.
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise HTTPException(413, "Request body too large")
            return message

        await self.app(scope, limited_receive, send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = b'{"detail":"Request body too large"}'
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body})


def require_same_origin_json(request: Request) -> None:
    """FastAPI dependency for every state-changing endpoint. CSRF defence.

    The session cookie is SameSite=Lax, so browsers already withhold it from
    cross-site POSTs. These two checks are independent of that:

    1. Content-Type must be application/json. An HTML form cannot send that,
       and a cross-origin fetch() that tries must first pass a CORS preflight,
       which this app never answers.
    2. The Origin header must be this app's own origin. Browsers set Origin on
       every POST and page script cannot forge it.

    There is no CSRF token because there are no server-rendered forms to put
    one in: every write is a fetch() from our own script."""
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/json":
        raise HTTPException(415, "Content-Type must be application/json")
    if request.headers.get("origin") != settings.APP_ORIGIN:
        raise HTTPException(403, "Cross-origin request refused")


def client_ip(request: Request) -> str:
    """The address to rate-limit on.

    Behind a reverse proxy the socket's peer is the proxy, and the real client
    is in X-Forwarded-For. That header is a comma-separated list which each
    proxy appends to — so the client can pre-fill the left-hand side with
    anything it likes, and only the entries our own proxies appended (the
    right-hand side) can be believed. With one proxy that is the last entry."""
    hops = settings.TRUSTED_PROXY_HOPS
    if hops > 0:
        forwarded = [
            part.strip()
            for part in request.headers.get("x-forwarded-for", "").split(",")
            if part.strip()
        ]
        if len(forwarded) >= hops:
            return forwarded[-hops]
    return request.client.host if request.client else "unknown"


class RateLimiter:
    """Token bucket, one bucket per key, held in memory.

    Each key starts with `capacity` tokens and regains them at a steady rate.
    A request spends one token; no token, no request. Compared with "N per
    calendar minute" this has no boundary where a client can send 2N requests
    in two seconds by straddling the minute.

    In memory is correct for this deployment (one process). With several
    workers each would keep its own buckets and the effective limit would
    multiply; that would need a shared store such as Redis."""

    # Upper bound on tracked keys, so a flood of distinct addresses cannot
    # grow this dictionary without limit.
    MAX_KEYS = 10_000

    def __init__(self, capacity: int, per_seconds: float, clock=time.monotonic):
        self.capacity = capacity
        self.refill_per_second = capacity / per_seconds
        self._clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_seen)
        # Routes are plain `def`, so FastAPI runs them on a thread pool and
        # two requests can be in here at once.
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            tokens, last_seen = self._buckets.get(key, (float(self.capacity), now))
            tokens = min(self.capacity, tokens + (now - last_seen) * self.refill_per_second)
            if tokens < 1:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1, now)
            if len(self._buckets) > self.MAX_KEYS:
                self._prune(now)
            return True

    def _prune(self, now: float) -> None:
        # A bucket idle long enough to have refilled completely carries no
        # information: dropping it is the same as keeping it.
        full_after = self.capacity / self.refill_per_second
        self._buckets = {
            key: (tokens, last_seen)
            for key, (tokens, last_seen) in self._buckets.items()
            if now - last_seen < full_after
        }

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
