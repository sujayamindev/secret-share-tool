from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.database import Base, engine
from app import auth, secrets_router

# Create tables on startup if they don't exist. Fine for a single-VM SQLite
# deployment — no migration framework needed at this scale.
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Secret Share — Asgardeo-gated one-time secrets")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(auth.router)
app.include_router(secrets_router.router)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
