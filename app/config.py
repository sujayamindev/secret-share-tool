"""
Central place for all configuration. Everything sensitive comes from
environment variables (.env locally, real env vars in Docker) — nothing
sensitive is ever hardcoded or committed.

The identity provider settings are deliberately provider-neutral (OIDC_*):
the app speaks standard OpenID Connect and learns every endpoint from the
provider's discovery document, so switching providers is a change to .env,
not to code.

Note what is NOT here: there is no encryption key. Secrets are encrypted in
the sender's browser with a key the server never receives (see
docs/DESIGN-v2.md), so the server has nothing that could decrypt them.
"""
import os
from collections.abc import Mapping
from functools import lru_cache
from urllib.parse import urlsplit

from dotenv import load_dotenv

# In Docker, env vars come from docker-compose's `env_file:` directive — already
# present in os.environ by the time this module loads, so this is a harmless no-op.
# Locally (plain `uvicorn app.main:app`), nothing else reads .env into the process,
# so this is what actually makes OIDC_ISSUER etc. available below.
load_dotenv()


class ConfigError(RuntimeError):
    """Raised at startup for configuration that would be unsafe to run with."""


class Settings:
    def __init__(self, env: Mapping[str, str] | None = None):
        env = os.environ if env is None else env

        # --- App behaviour ---
        # "production" unless explicitly told otherwise. The insecure setting
        # has to be asked for, so a missing variable can never switch off
        # Secure cookies or HSTS by accident.
        self.ENVIRONMENT: str = env.get("ENVIRONMENT", "production")
        self.SESSION_TTL_MINUTES: int = int(env.get("SESSION_TTL_MINUTES", "30"))
        self.SECRET_TTL_MINUTES: int = int(env.get("SECRET_TTL_MINUTES", "1440"))  # 24h
        self.DATABASE_URL: str = env.get("DATABASE_URL", "sqlite:///./data/app.db")

        # --- OIDC provider ---
        # The issuer identifier exactly as it appears in the `iss` claim of the
        # provider's tokens, character for character (trailing slash included
        # if the provider uses one — copy it from the discovery document).
        self.OIDC_ISSUER: str = env["OIDC_ISSUER"]
        self.OIDC_CLIENT_ID: str = env["OIDC_CLIENT_ID"]
        self.OIDC_CLIENT_SECRET: str = env["OIDC_CLIENT_SECRET"]
        self.OIDC_REDIRECT_URI: str = env["OIDC_REDIRECT_URI"]
        # OIDC Discovery 1.0 defines the path below, and most providers use it.
        # Some publish the document elsewhere (Asgardeo:
        # <base>/oauth2/token/.well-known/openid-configuration), hence the override.
        self.OIDC_DISCOVERY_URL: str = env.get("OIDC_DISCOVERY_URL") or (
            self.OIDC_ISSUER.rstrip("/") + "/.well-known/openid-configuration"
        )

        # --- Abuse limits ---
        self.CREATE_RATE_LIMIT_PER_MINUTE: int = int(env.get("CREATE_RATE_LIMIT_PER_MINUTE", "10"))
        # Hard ceiling on stored secrets, so the worst case on disk is a known
        # number (about 135 MB at the default) rather than "until the disk fills".
        self.MAX_LIVE_SECRETS: int = int(env.get("MAX_LIVE_SECRETS", "1000"))
        # How many reverse proxies sit in front of the app. 0 = none, use the
        # socket's peer address. 1 = one proxy (nginx): use the last entry of
        # X-Forwarded-For, which is the one that proxy wrote. Entries further
        # left were supplied by the client and are never trusted.
        self.TRUSTED_PROXY_HOPS: int = int(env.get("TRUSTED_PROXY_HOPS", "0"))

        self._validate()

    @property
    def IS_DEVELOPMENT(self) -> bool:
        return self.ENVIRONMENT == "development"

    @property
    def COOKIE_SECURE(self) -> bool:
        # Secure cookies are only sent over HTTPS. On http://localhost that
        # would silently drop every cookie, so development turns it off.
        return not self.IS_DEVELOPMENT

    @property
    def COOKIE_PREFIX(self) -> str:
        # A cookie named `__Host-...` is only accepted by browsers if it is
        # Secure, has Path=/ and has no Domain attribute. That stops another
        # site on a sibling subdomain from overwriting it. The prefix requires
        # Secure, so it cannot be used over plain HTTP in development.
        return "__Host-" if self.COOKIE_SECURE else ""

    @property
    def APP_ORIGIN(self) -> str:
        """The app's own public origin (scheme://host[:port]), taken from the
        registered redirect URI. This is the single source of truth for "who
        are we" — used for the same-origin check and the logout return URL —
        rather than the request's Host header, which the client controls."""
        parts = urlsplit(self.OIDC_REDIRECT_URI)
        return f"{parts.scheme}://{parts.netloc}"

    def _validate(self) -> None:
        redirect = urlsplit(self.OIDC_REDIRECT_URI)
        if redirect.scheme not in ("http", "https") or not redirect.netloc:
            raise ConfigError("OIDC_REDIRECT_URI must be an absolute http(s) URL")
        if self.IS_DEVELOPMENT:
            return
        # Outside development, plain HTTP anywhere in the login flow would put
        # authorization codes and session cookies on the wire in clear text.
        for name in ("OIDC_ISSUER", "OIDC_REDIRECT_URI", "OIDC_DISCOVERY_URL"):
            if urlsplit(getattr(self, name)).scheme != "https":
                raise ConfigError(
                    f"{name} must use https unless ENVIRONMENT=development is set"
                )


@lru_cache
def get_settings() -> Settings:
    return Settings()
