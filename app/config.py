"""
Central place for all configuration. Everything sensitive comes from
environment variables (.env locally, real env vars in Docker) — nothing
sensitive is ever hardcoded or committed.
"""
import os
from functools import lru_cache
from dotenv import load_dotenv

# In Docker, env vars come from docker-compose's `env_file:` directive — already
# present in os.environ by the time this module loads, so this is a harmless no-op.
# Locally (plain `uvicorn app.main:app`), nothing else reads .env into the process,
# so this is what actually makes ASGARDEO_BASE_URL etc. available below.
load_dotenv()


class Settings:
    # --- Asgardeo OIDC ---
    ASGARDEO_BASE_URL: str = os.environ["ASGARDEO_BASE_URL"]  # e.g. https://api.asgardeo.io/t/<org-name>
    ASGARDEO_CLIENT_ID: str = os.environ["ASGARDEO_CLIENT_ID"]
    ASGARDEO_CLIENT_SECRET: str = os.environ["ASGARDEO_CLIENT_SECRET"]
    ASGARDEO_REDIRECT_URI: str = os.environ["ASGARDEO_REDIRECT_URI"]  # e.g. https://secrets.sujaya.dev/auth/callback

    # Discovery doc — we don't hardcode individual endpoints, we fetch them once at startup
    @property
    def OIDC_DISCOVERY_URL(self) -> str:
        return f"{self.ASGARDEO_BASE_URL}/oauth2/token/.well-known/openid-configuration"

    # --- App secrets ---
    # Used by `cryptography.Fernet` to encrypt secret payloads at rest in SQLite
    FERNET_KEY: str = os.environ["FERNET_KEY"]

    # --- App behavior ---
    SESSION_TTL_MINUTES: int = int(os.environ.get("SESSION_TTL_MINUTES", "30"))
    SECRET_TTL_MINUTES: int = int(os.environ.get("SECRET_TTL_MINUTES", "1440"))  # 24h default
    DATABASE_URL: str = os.environ.get("DATABASE_URL", "sqlite:///./data/app.db")
    ENVIRONMENT: str = os.environ.get("ENVIRONMENT", "development")  # development | production

    @property
    def COOKIE_SECURE(self) -> bool:
        # Only send the session cookie over HTTPS in production.
        # In local dev (http://localhost) Secure=True would silently break cookies.
        return self.ENVIRONMENT == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
