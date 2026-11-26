"""
App assembly: middleware, routers, error pages and the periodic cleanup task.
"""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import auth, secrets_router
from app.database import Base, engine, purge_expired, verify_schema
from app.security import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from app.web import error_page, gone_page

logger = logging.getLogger("secretshare")

CLEANUP_INTERVAL_SECONDS = 600

# Fail fast on a database file from an older version, then create tables if
# they don't exist. Fine for a single-VM SQLite deployment — no migration
# framework needed at this scale.
verify_schema()
Base.metadata.create_all(bind=engine)


async def _cleanup_loop() -> None:
    """Delete expired secrets and sessions at startup and every ten minutes.
    Runs inside the app process: one worker, one small table, so a separate
    scheduler or cron job would be more moving parts for no gain."""
    while True:
        try:
            secrets_removed, sessions_removed = await run_in_threadpool(purge_expired)
            if secrets_removed or sessions_removed:
                logger.info("purged %d expired secrets, %d expired sessions",
                            secrets_removed, sessions_removed)
        except Exception:  # a failed sweep must not end the loop
            logger.exception("cleanup sweep failed")
        await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    task = asyncio.create_task(_cleanup_loop())
    yield
    task.cancel()


# The interactive API docs are switched off. They are public by default, and
# Swagger UI loads its script from a CDN — third-party code running on the
# same origin that holds decryption keys in the browser.
app = FastAPI(
    title="Rahasya",
    docs_url=None, redoc_url=None, openapi_url=None,
    lifespan=lifespan,
)

# The middleware added last is the outermost. Headers go on the outside so
# that the body-size rejection gets them too.
app.add_middleware(BodySizeLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
app.include_router(auth.router)
app.include_router(secrets_router.router)


def _wants_json(request: Request) -> bool:
    return request.url.path.startswith("/api/") or request.method != "GET"


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    """Script callers get JSON; people get a page. Never a bare JSON blob in
    a browser tab, and never the exception text."""
    if _wants_json(request):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code,
                            headers=getattr(exc, "headers", None))
    if exc.status_code == 404:
        return gone_page(request)
    return error_page(request, exc.status_code, "Something went wrong",
                      "That request couldn't be completed.")


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, _exc: RequestValidationError):
    # FastAPI's default echoes the offending input back in the response. For
    # this app that input can be a ciphertext or a claim token.
    if _wants_json(request):
        return JSONResponse({"detail": "Malformed request."}, status_code=400)
    return error_page(request, 400, "Bad request", "That request couldn't be completed.")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
