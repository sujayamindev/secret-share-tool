# Secret Share

[![CI](https://github.com/sujayamindev/secret-share-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/sujayamindev/secret-share-tool/actions/workflows/ci.yml)

A one-time secret-sharing tool, like [onetimesecret.com](https://onetimesecret.com) — but the
recipient has to authenticate via **Asgardeo (OIDC)** before the secret unlocks. Once it's
viewed, it's permanently deleted.

**Live demo:** https://secrets.sujaya.dev

This README goes into more depth on the Asgardeo integration than a typical project README
would, since demonstrating a real, correctly-implemented OIDC integration is the point of
the project.

## How it works

1. **Create** — paste a secret (and optionally an allowlist of email addresses), get back a
   one-time share link.
2. **Auth-gate** — the recipient opens the link and is redirected to Asgardeo to sign in.
3. **View once** — after authenticating (and passing the allowlist check, if one was set),
   the secret is decrypted and shown exactly once.
4. **Delete** — the moment it's viewed, it's gone. A second visit to the same link — by
   anyone, including the original viewer — gets a generic "this secret is no longer
   available" page.

That's the entire feature set, deliberately. No accounts beyond the Asgardeo session, no
secret history, no editing or expiry-extension UI.

## Why it exists

This project was built as a way to demonstrate real, working use of a WSO2 product — Asgardeo
— rather than a toy integration bolted onto an unrelated app. The interesting engineering
problem isn't "add a login button," it's: *how do you correctly verify that a real person
authenticated, using only what the identity provider gives you back?*

## The Asgardeo integration

### OIDC Authorization Code flow

Standard Authorization Code flow against Asgardeo:

1. `GET /auth/login?next=<secret_id>` — the app generates a random `state` and `nonce`,
   stashes them in short-lived `HttpOnly` cookies, and redirects to Asgardeo's authorize
   endpoint (discovered once via the OIDC discovery document, not hardcoded).
2. The user authenticates on Asgardeo's hosted login page. This app never sees a password.
3. Asgardeo redirects back to `GET /auth/callback?code=...&state=...`.
4. The app checks `state` against the cookie (CSRF protection on the redirect itself), then
   exchanges `code` for tokens server-to-server, using the client secret.
5. The returned ID token is **cryptographically verified**, not trusted at face value —
   see below.
6. The app creates its own server-side session and sets a session cookie, then redirects the
   user back to the secret they were trying to view.

### ID token + JWKS verification, not `/userinfo`

The ID token's signature is verified against Asgardeo's published JWKS (`PyJWKClient`
fetches and caches the signing keys), and `aud` / `exp` / `issuer` / `nonce` are all checked
before any claim is trusted. `sub` and `email` are then read directly off the verified token
— no further network call to Asgardeo is needed.

This is deliberately chosen over calling Asgardeo's `/userinfo` endpoint with the access
token. `/userinfo` works, but it means trusting "whoever answered this HTTPS call with this
access token," which rests on transport trust rather than a cryptographic signature, and has
no replay protection. Verifying the ID token directly gives an offline-verifiable,
tamper-evident, replay-resistant proof of authentication — closer to how OIDC is meant to be
used.

The `nonce` is what specifically defeats replay: it's generated at `/auth/login`, stored in
a cookie, sent in the authorize request, embedded by Asgardeo inside the signed ID token, and
checked against the cookie value at `/auth/callback`. A previously-issued, still otherwise
valid ID token can't be replayed into a new login attempt, because it will carry the wrong
nonce.

### Opaque server-side sessions, not JWT cookies

After login, the app doesn't hand the browser a signed-claims cookie. It creates a row in a
`sessions` table and sets a cookie containing only a random session ID pointing at that row.

This buys two things a JWT-in-a-cookie doesn't: a session can be **revoked** by deleting the
row (a JWT cookie stays valid until it expires, no matter what the server does), and no
claims are ever exposed to the client for inspection or tampering.

Cookie flags, and why each one:

| Flag | Purpose |
|---|---|
| `HttpOnly` | JavaScript can't read it — blocks XSS-based token theft |
| `Secure` | HTTPS-only in production (`ENVIRONMENT=production` in config) |
| `SameSite=Lax` | CSRF mitigation on state-changing requests |

### Per-secret access control

A secret can optionally be restricted to a comma-separated allowlist of email addresses.
`allowed_emails = NULL` means any authenticated user may view it; otherwise the viewer's
Asgardeo-verified email claim must appear in the list. This is checked *after* authentication
and *before* decryption — Asgardeo isn't just gating "logged in or not," it's gating "logged
in as someone specific."

## Other design decisions worth knowing about

**Auth is checked before the secret's existence, in `view_secret`.** If existence were
checked first, an unauthenticated request could tell "404, never existed / already viewed"
apart from "still live, here's a login redirect" — for any guessed ID — without spending a
single Asgardeo login. That's a free existence-oracle. Checking auth first means every
unauthenticated visitor gets the same login redirect regardless of whether the ID is real.
Not exploitable in practice either way (secret IDs are UUIDv4, ~122 bits of entropy), but the
fix was free, so the order matters.

**Every "can't show you this" case renders the same page.** Missing, already-viewed, expired,
or not-on-the-allowlist all produce an identical response, so a probing visitor can't learn
*why* a given link doesn't work.

**The one-time view is enforced by an atomic `UPDATE ... WHERE viewed = 0`,** not a
read-then-write. Two concurrent requests for the same link can both pass an initial
"is this available" check before either commits — only one of them can win the conditional
update, so only one can ever reach the decrypt step. This is what actually makes "viewed
exactly once" true under concurrency, rather than true by accident of there being one
deployment worker.

**Secret payloads are encrypted at rest with [Fernet](https://cryptography.io/en/latest/fernet/)**
(from the `cryptography` library) — AES-128-CBC + HMAC authentication + correct IV handling,
bundled together specifically so this project doesn't hand-roll AES and get something subtly
wrong. Even though this is a demo app, the payload is never stored in plaintext.

**Creating a secret uses Post/Redirect/Get.** `POST /create` redirects (`303`) to
`GET /created/{secret_id}` instead of rendering the confirmation page directly in the POST
response — otherwise refreshing the confirmation screen would resubmit the form and silently
mint a second secret from the same paste.

**SQLite, not Postgres.** Single VM, low write volume — this is the right-sized choice for
what this app actually needs, not a placeholder for "real" infrastructure. There's no
migration framework; schema changes just drop and recreate the dev DB (see below). At this
scale, adding Alembic would be over-engineering, not correctness.

## Architecture

```
app/
├── main.py              # FastAPI app instance, router mounting, table creation
├── config.py             # env-driven Settings, load_dotenv() for local dev
├── database.py            # SQLite engine, session factory, get_db() dependency
├── models.py               # Secret, UserSession SQLAlchemy models
├── crypto.py                # Fernet encrypt/decrypt helpers
├── auth.py                   # OIDC login/callback, JWKS verification, session cookie mgmt
├── secrets_router.py          # create/created/view secret routes, input validation
├── templates/                  # Jinja2: create.html, created.html, view.html, gone.html
└── static/                      # style.css, theme.js, favicon.svg
```

Two tables: `secrets` (encrypted payload, expiry, viewed flag/by/at, allowlist) and
`sessions` (session ID, `sub`, email, expiry).

Frontend is plain Jinja2 + vanilla CSS/JS — no React, no build step. Each template is a
fully self-contained HTML document; there's no shared base template, so the dark/light theme
toggle and page chrome are duplicated (deliberately — the fastest way to keep four small,
independent pages simple).

## Tech stack

- **Backend:** FastAPI + SQLAlchemy
- **Auth:** Asgardeo (WSO2), OIDC Authorization Code flow, `PyJWT` + `PyJWKClient` for
  signature verification
- **Storage:** SQLite
- **Encryption:** `cryptography`'s Fernet recipe
- **Frontend:** Jinja2 templates, vanilla CSS/JS
- **Deployment:** Docker Compose behind nginx + Let's Encrypt, on an OCI ARM VM

## Running locally

Requires an [Asgardeo](https://asgardeo.io) account with a Traditional Web App registered
(free tier is sufficient).

```bash
git clone <this-repo>
cd secret-share-tool
pip install -r requirements.txt
cp .env.example .env
```

Fill in `.env`:

- `ASGARDEO_BASE_URL`, `ASGARDEO_CLIENT_ID`, `ASGARDEO_CLIENT_SECRET` — from your Asgardeo
  app's **Protocol** tab
- `ASGARDEO_REDIRECT_URI` — `http://localhost:8000/auth/callback` for local dev; this must
  also be registered in Asgardeo's console under the app's Protocol tab
- `FERNET_KEY` — generate one:
  ```bash
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
  ```

Two Asgardeo console settings that are easy to miss:

- **User Attributes** tab — `email` must be mapped as an ID-token claim (separately from
  requesting the `email` scope), or `claims.get("email")` comes back `None`.
- **Login Flow → Flow Completion Properties** — **Auto Login** must be enabled, or new
  registrations land on the Asgardeo dashboard instead of completing the OAuth callback.

Then:

```bash
uvicorn app.main:app --reload
```

Visit `http://localhost:8000`.

### Resetting the dev DB

No migration framework — after a schema change, just delete and let it recreate:

```bash
rm data/app.db        # Linux/Mac
del data\app.db        # Windows
```

## Deployment

Runs via Docker Compose on an existing OCI ARM VM, behind nginx with a Let's Encrypt cert,
proxying `secrets.sujaya.dev` to the container.

```bash
docker compose up --build -d
docker compose logs -f
```

The container binds to `127.0.0.1:8001` on the host (not 8000 or the container's internal
8000) — the standard host port was already taken by another project on the same VM. nginx
is what's actually reachable from the internet; the app itself is never exposed directly.

SQLite's data file is bind-mounted (`./data:/app/data`) so it survives container rebuilds.

### CI/CD

GitHub Actions (`.github/workflows/ci.yml`) runs on every push and pull request:

- **lint** — `ruff check .`
- **docker-build** — verifies the image builds

On a push to `main`, once both of those pass, a **deploy** job SSHes into the OCI VM,
`git pull`s the latest `main`, and runs `docker compose up --build -d`. Deploy credentials
(`VM_HOST`, `VM_USER`, `VM_SSH_KEY`) are stored as secrets on a `production` GitHub
Environment rather than as repo-level secrets, so they're only ever injected into the deploy
job — not into the lint/build jobs that also run on PRs from forks.

## What's deliberately out of scope

- No secret history, editing, or expiry-extension UI
- No user accounts beyond the Asgardeo session
- No rate limiting on `/create` yet — a reasonable next step for a production version of
  this, not something the current deployment relies on
- No automatic dependency updates — dependency versions are pinned (`==`, not ranges) so the
  repo stays reproducible as submission evidence; a Dependabot config would be the intended
  follow-up, not unpinned ranges
