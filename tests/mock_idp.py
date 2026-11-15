"""
A throwaway OpenID Connect provider for trying the whole app in a real
browser without an Auth0 account. NEVER deploy this: it "authenticates"
whoever clicks a name.

    python -m tests.mock_idp

starts two servers in one process:

    http://localhost:8000   the app, in development mode, on a temporary database
    http://localhost:9000   this fake provider

It is a real (if tiny) OIDC provider as far as the app can tell: discovery
document, RS256-signed ID tokens, a JWKS endpoint, and it enforces PKCE. So
this exercises the same code paths a real provider does, including the one
thing unit tests cannot: a browser carrying the key across the sign-in round
trip. The sign-in page prints the URL fragment the provider's own script can
see, which should always be "#_" and never a key.
"""
import base64
import hashlib
import html
import os
import secrets
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlencode

ISSUER = "http://localhost:9000"
CLIENT_ID = "dev-client"
CLIENT_SECRET = "dev-secret"

USERS = {
    "alice": {"sub": "mock|alice", "email": "alice@example.com", "email_verified": True},
    "bob": {"sub": "mock|bob", "email": "bob@example.com", "email_verified": True},
    # Claims to be alice but never verified the address: must NOT get
    # through an allowlist that names alice@example.com.
    "mallory": {"sub": "mock|mallory", "email": "alice@example.com", "email_verified": False},
}


def build_provider():
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

    provider = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = "mock-key-1"
    codes: dict[str, dict] = {}     # authorization code -> what it was issued for
    seen_urls: list[str] = []       # every URL this provider was asked for

    @provider.middleware("http")
    async def record(request: Request, call_next):
        seen_urls.append(str(request.url))
        return await call_next(request)

    @provider.get("/.well-known/openid-configuration")
    def discovery():
        return {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/jwks",
            "end_session_endpoint": f"{ISSUER}/logout",
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
        }

    @provider.get("/jwks")
    def jwks():
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
        jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    @provider.get("/authorize", response_class=HTMLResponse)
    def authorize(request: Request):
        query = dict(request.query_params)
        links = "".join(
            f'<li><a id="as-{name}" href="/approve?{html.escape(urlencode({**query, "user": name}))}">'
            f"{name}</a> &mdash; {html.escape(user['email'])}, "
            f"email_verified={user['email_verified']}</li>"
            for name, user in USERS.items()
        )
        return f"""<!DOCTYPE html><html><head><title>Mock sign-in</title></head><body>
<h1>Mock identity provider</h1>
<p>Not a real login. Pick who to sign in as:</p><ul>{links}</ul>
<p>URL fragment visible to this page's script: <code id="fragment"></code></p>
<script>document.getElementById('fragment').textContent = location.hash || '(none)';</script>
</body></html>"""

    @provider.get("/approve")
    def approve(request: Request):
        query = request.query_params
        code = secrets.token_urlsafe(16)
        codes[code] = {
            "user": USERS[query["user"]],
            "nonce": query.get("nonce"),
            "code_challenge": query.get("code_challenge"),
            "redirect_uri": query["redirect_uri"],
        }
        target = query["redirect_uri"] + "?" + urlencode({"code": code, "state": query["state"]})
        return RedirectResponse(target, status_code=302)

    @provider.post("/token")
    async def token(request: Request):
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        grant = codes.pop(form.get("code", ""), None)   # codes are single-use
        if grant is None or form.get("client_id") != CLIENT_ID \
                or form.get("client_secret") != CLIENT_SECRET \
                or form.get("redirect_uri") != grant["redirect_uri"]:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        # PKCE: the verifier sent now must hash to the challenge sent earlier.
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(form.get("code_verifier", "").encode()).digest()
        ).rstrip(b"=").decode()
        if challenge != grant["code_challenge"]:
            return JSONResponse({"error": "invalid_grant", "error_description": "PKCE"},
                                status_code=400)
        now = int(time.time())
        id_token = jwt.encode(
            {"iss": ISSUER, "aud": CLIENT_ID, "iat": now, "exp": now + 300,
             "nonce": grant["nonce"], **grant["user"]},
            key, algorithm="RS256", headers={"kid": kid},
        )
        return {"access_token": "unused", "token_type": "Bearer", "id_token": id_token}

    @provider.get("/logout")
    def logout(post_logout_redirect_uri: str = "http://localhost:8000/"):
        return RedirectResponse(post_logout_redirect_uri, status_code=302)

    @provider.get("/debug/seen-urls")
    def debug_seen_urls():
        """Every URL the provider has been asked for. A decryption key must
        never appear in this list."""
        return seen_urls

    return provider


def main():
    os.environ.update({
        "OIDC_ISSUER": ISSUER,
        "OIDC_CLIENT_ID": CLIENT_ID,
        "OIDC_CLIENT_SECRET": CLIENT_SECRET,
        "OIDC_REDIRECT_URI": "http://localhost:8000/auth/callback",
        "ENVIRONMENT": "development",
        "DATABASE_URL": "sqlite:///" + os.path.join(
            tempfile.mkdtemp(prefix="secret-share-dev-"), "dev.db").replace("\\", "/"),
        "TRUSTED_PROXY_HOPS": "0",
    })
    os.environ.pop("OIDC_DISCOVERY_URL", None)

    import uvicorn

    provider_server = uvicorn.Server(
        uvicorn.Config(build_provider(), host="127.0.0.1", port=9000, log_level="warning"))
    threading.Thread(target=provider_server.run, daemon=True).start()

    print("app:      http://localhost:8000")
    print("provider: http://localhost:9000  (mock: alice, bob, mallory)")
    print("database:", os.environ["DATABASE_URL"])
    # Imported only now, after the environment above is in place.
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    main()
