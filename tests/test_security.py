"""
Cross-cutting protections: response headers, the body-size cap, the rate
limiter, client-address handling behind a proxy, and configuration that
fails closed.
"""
import pathlib
import re

import pytest

from app import security
from app.config import ConfigError, Settings
from app.security import RateLimiter
from tests.conftest import APP_ORIGIN

TEMPLATES = sorted(pathlib.Path("app/templates").glob("*.html"))
STATIC = pathlib.Path("app/static")


# --- headers ----------------------------------------------------------------

@pytest.mark.parametrize("path, status", [
    ("/", 200),
    ("/secret/11111111-2222-4333-8444-555555555555", 200),
    ("/secret/nope", 404),
    ("/no-such-page", 404),
    ("/auth/callback", 400),
    ("/healthz", 200),
])
def test_every_dynamic_response_has_the_security_headers(path, status, client):
    response = client.get(path, follow_redirects=False)

    assert response.status_code == status
    csp = response.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("path", ["/", "/healthz"])
def test_head_is_answered_like_get_without_a_body(path, client):
    response = client.head(path)

    assert response.status_code == 200
    assert response.content == b""
    assert "default-src 'none'" in response.headers["content-security-policy"]


def test_head_does_not_open_the_state_changing_routes(client):
    # /auth/login creates a login attempt; it stays GET-only.
    assert client.head("/auth/login").status_code == 405


def test_api_responses_are_not_cacheable(client):
    response = client.post("/api/secrets", json={})
    assert response.headers["cache-control"] == "no-store"
    assert "content-security-policy" in response.headers


def test_static_files_get_the_policy_but_may_be_cached(client):
    response = client.get("/static/crypto.js")
    assert response.status_code == 200
    assert "content-security-policy" in response.headers
    assert response.headers.get("cache-control") != "no-store"


def test_hsts_is_sent_only_when_cookies_are_secure(client, monkeypatch):
    assert "strict-transport-security" not in client.get("/").headers   # development

    monkeypatch.setattr(security.settings, "ENVIRONMENT", "production")
    hsts = client.get("/").headers["strict-transport-security"]
    assert hsts == "max-age=31536000"
    assert "includeSubDomains" not in hsts      # the parent domain hosts other projects


def test_interactive_api_docs_are_disabled(client):
    """Swagger UI would run CDN-hosted script on the origin that holds keys."""
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


# --- the pages themselves obey the policy ----------------------------------

@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: p.name)
def test_templates_have_no_inline_script_and_load_nothing_from_other_origins(template):
    html = template.read_text(encoding="utf-8")

    # Every <script> must have a src: inline script is what the CSP forbids.
    for tag in re.findall(r"<script\b[^>]*>", html):
        assert 'src="/static/' in tag, tag
    # No inline event handlers (onclick=...), no inline styles.
    assert not re.search(r"\son[a-z]+\s*=", html)
    assert not re.search(r"\sstyle\s*=", html) and "<style" not in html
    # Anything the page loads (script, stylesheet, image, font) is same-origin.
    for url in re.findall(r'<(?:script|link|img)\b[^>]*?(?:src|href)="([^"]+)"', html):
        assert url.startswith("/static/"), url


def test_stylesheet_loads_nothing_from_other_origins():
    css = (STATIC / "style.css").read_text(encoding="utf-8")
    assert "@import" not in css
    for url in re.findall(r"url\(([^)]+)\)", css):
        assert url.strip("'\"").startswith("/static/"), url


def test_secret_is_never_written_into_the_page_as_html():
    """The decrypted text is attacker-influenced (whoever wrote the secret).
    It must be inserted as text, so markup in it is displayed, not executed."""
    script = (STATIC / "secret.js").read_text(encoding="utf-8")
    assert ".textContent = plaintext" in script
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        for name in ("secret.js", "create.js", "crypto.js", "theme.js", "theme-init.js"):
            assert forbidden not in (STATIC / name).read_text(encoding="utf-8").replace(
                "never innerHTML", ""), f"{forbidden} in {name}"


def test_create_form_fields_cannot_be_submitted_as_plain_text():
    """With no `name`, a browser never includes a field in a form submission,
    so a failed script load cannot leak the plaintext to the server."""
    html = pathlib.Path("app/templates/create.html").read_text(encoding="utf-8")
    assert re.findall(r"<textarea\b[^>]*\sname=", html) == []


# --- body size --------------------------------------------------------------

def test_oversized_body_is_rejected_from_its_declared_length(client):
    response = client.post("/api/secrets", content=b"x" * (security.MAX_BODY_BYTES + 1),
                           headers={"content-type": "application/json"})
    assert response.status_code == 413
    assert "content-security-policy" in response.headers


def test_oversized_body_is_rejected_even_without_a_declared_length(client):
    """A chunked upload has no Content-Length, so the bytes are counted as
    they arrive."""
    def chunks():
        for _ in range(40):
            yield b"x" * 10_000

    response = client.post("/api/secrets", content=chunks(),
                           headers={"content-type": "application/json"})
    assert response.status_code == 413


def test_body_at_the_limit_is_not_rejected_for_size(client):
    response = client.post("/api/secrets", content=b"x" * security.MAX_BODY_BYTES,
                           headers={"content-type": "application/json"})
    assert response.status_code == 400      # not JSON, but it got past the size check


# --- rate limiter -----------------------------------------------------------

class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_rate_limiter_allows_a_burst_then_blocks():
    limiter = RateLimiter(capacity=3, per_seconds=60, clock=FakeClock())
    assert [limiter.allow("a") for _ in range(4)] == [True, True, True, False]


def test_rate_limiter_refills_steadily_over_time():
    clock = FakeClock()
    limiter = RateLimiter(capacity=3, per_seconds=60, clock=clock)
    for _ in range(3):
        limiter.allow("a")
    assert not limiter.allow("a")

    clock.now += 19         # one token takes 20 seconds
    assert not limiter.allow("a")
    clock.now += 1
    assert limiter.allow("a")
    assert not limiter.allow("a")


def test_rate_limiter_never_holds_more_than_its_capacity():
    clock = FakeClock()
    limiter = RateLimiter(capacity=3, per_seconds=60, clock=clock)
    clock.now += 100_000
    assert [limiter.allow("a") for _ in range(4)] == [True, True, True, False]


def test_rate_limiter_keys_are_independent():
    limiter = RateLimiter(capacity=1, per_seconds=60, clock=FakeClock())
    assert limiter.allow("a") and not limiter.allow("a")
    assert limiter.allow("b")


def test_rate_limiter_memory_is_bounded():
    clock = FakeClock()
    limiter = RateLimiter(capacity=2, per_seconds=60, clock=clock)
    limiter.MAX_KEYS = 100
    for i in range(100):
        limiter.allow(f"old-{i}")
    clock.now += 3600                   # those buckets have long since refilled
    limiter.allow("new")
    assert len(limiter._buckets) == 1


# --- client address ---------------------------------------------------------

class FakeRequest:
    def __init__(self, forwarded=None, peer="172.18.0.1"):
        self.headers = {"x-forwarded-for": forwarded} if forwarded else {}
        self.client = type("Client", (), {"host": peer})()


def test_forwarded_header_is_ignored_when_no_proxy_is_configured(monkeypatch):
    monkeypatch.setattr(security.settings, "TRUSTED_PROXY_HOPS", 0)
    assert security.client_ip(FakeRequest("9.9.9.9")) == "172.18.0.1"


def test_one_proxy_means_the_last_forwarded_entry(monkeypatch):
    monkeypatch.setattr(security.settings, "TRUSTED_PROXY_HOPS", 1)
    assert security.client_ip(FakeRequest("203.0.113.7")) == "203.0.113.7"


def test_client_cannot_dodge_the_rate_limit_by_forging_the_header(monkeypatch):
    """nginx appends the real address to whatever the client sent. Only that
    last entry is believed; a different forged prefix on every request still
    maps to the same key."""
    monkeypatch.setattr(security.settings, "TRUSTED_PROXY_HOPS", 1)
    first = security.client_ip(FakeRequest("1.1.1.1, 203.0.113.7"))
    second = security.client_ip(FakeRequest("2.2.2.2, 8.8.8.8, 203.0.113.7"))
    assert first == second == "203.0.113.7"


def test_missing_forwarded_header_falls_back_to_the_peer(monkeypatch):
    monkeypatch.setattr(security.settings, "TRUSTED_PROXY_HOPS", 1)
    assert security.client_ip(FakeRequest()) == "172.18.0.1"


# --- configuration ----------------------------------------------------------

PRODUCTION_ENV = {
    "OIDC_ISSUER": "https://tenant.example.auth0.com/",
    "OIDC_CLIENT_ID": "id",
    "OIDC_CLIENT_SECRET": "secret",
    "OIDC_REDIRECT_URI": "https://secrets.example.com/auth/callback",
}


def test_environment_defaults_to_production_so_cookies_fail_closed():
    settings = Settings(PRODUCTION_ENV)
    assert settings.ENVIRONMENT == "production"
    assert settings.COOKIE_SECURE is True
    assert settings.COOKIE_PREFIX == "__Host-"


def test_development_must_be_asked_for_and_drops_the_secure_only_prefix():
    settings = Settings({**PRODUCTION_ENV, "ENVIRONMENT": "development"})
    assert settings.COOKIE_SECURE is False
    assert settings.COOKIE_PREFIX == ""


@pytest.mark.parametrize("name, value", [
    ("OIDC_REDIRECT_URI", "http://secrets.example.com/auth/callback"),
    ("OIDC_ISSUER", "http://tenant.example.auth0.com/"),
    ("OIDC_DISCOVERY_URL", "http://tenant.example.auth0.com/.well-known/openid-configuration"),
])
def test_production_refuses_plain_http(name, value):
    with pytest.raises(ConfigError, match=name):
        Settings({**PRODUCTION_ENV, name: value})


def test_app_origin_comes_from_the_redirect_uri():
    assert Settings(PRODUCTION_ENV).APP_ORIGIN == "https://secrets.example.com"
    assert security.settings.APP_ORIGIN == APP_ORIGIN


def test_discovery_url_defaults_to_the_standard_path():
    assert Settings(PRODUCTION_ENV).OIDC_DISCOVERY_URL == (
        "https://tenant.example.auth0.com/.well-known/openid-configuration")


def test_discovery_url_can_be_overridden_for_providers_with_a_different_path():
    url = "https://api.asgardeo.io/t/org/oauth2/token/.well-known/openid-configuration"
    settings = Settings({**PRODUCTION_ENV, "OIDC_ISSUER": "https://api.asgardeo.io/t/org/oauth2/token",
                         "OIDC_DISCOVERY_URL": url})
    assert settings.OIDC_DISCOVERY_URL == url


def test_no_encryption_key_is_configured_on_the_server():
    """Zero-knowledge, stated as a test: the settings object has nothing that
    could decrypt a secret."""
    names = [name for name in vars(Settings(PRODUCTION_ENV)) if "KEY" in name or "FERNET" in name]
    assert names == []
