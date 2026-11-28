# Rahasya

[![CI](https://github.com/sujayamindev/secret-share-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/sujayamindev/secret-share-tool/actions/workflows/ci.yml)

Zero-knowledge, one-time secret sharing, optionally gated by identity.

Rahasya (රහස්‍ය) is Sinhala for "secret".

- **Zero-knowledge:** the secret is encrypted in the sender's browser. The server stores
  ciphertext and never receives the key or the plaintext.
- **Optionally identity-gated:** the sender can restrict a secret to specific verified email
  addresses. The recipient then signs in through an OpenID Connect provider before the
  ciphertext is released. With no restriction, the link alone opens it.
- **One-time:** the first successful reveal deletes the secret from the server.

It works with any standards-compliant OIDC provider and is tested with Auth0.

**Live demo:** https://secrets.sujaya.dev (restricted secrets ask the recipient to sign in with Google, through Auth0)

"Zero-knowledge" here means *the service cannot read what it stores*. It is not a
zero-knowledge proof, and it has a hard limit that the [threat model](#threat-model) states
plainly.

## How it works

1. **Create.** You paste a secret. Your browser generates a random key, encrypts the secret
   with it, and sends only the ciphertext. The page then builds the share link itself:
   `https://host/secret/<id>#<key>`.
2. **Send.** You send that link to the recipient however you like.
3. **Open.** The recipient opens the link. The part after `#` (the key) is never sent to the
   server; the page moves it out of the address bar.
4. **Reveal.** The recipient presses **Reveal**. If the sender listed emails, the server
   answers "sign in first" and the recipient signs in, then presses Reveal again. The server
   checks the link (and, if restricted, who they are), deletes its copy, and returns the
   ciphertext. The browser decrypts it.

A second attempt, by anyone, gets "this secret isn't available".

That is the whole feature set, deliberately. No accounts beyond the sign-in session, no
secret history, no editing.

## The encryption

All of it is in [`app/static/crypto.js`](app/static/crypto.js), about 150 lines using the
browser's built-in WebCrypto API. No crypto library is shipped.

| Choice | Value | Why |
|---|---|---|
| Cipher | AES-256-GCM | Authenticated encryption: a ciphertext that was altered fails to decrypt instead of producing wrong output. |
| Link secret | 32 random bytes (`crypto.getRandomValues`) | The only secret. It lives in the link's fragment. |
| Key derivation | HKDF-SHA-256 | Turns the one link secret into two independent values (below). |
| IV | 12 random bytes per secret | The size GCM is designed around. Stored next to the ciphertext; not secret. |
| Auth tag | 128 bits | WebCrypto's default, appended to the ciphertext. |

### One link secret, two derived values

```
link secret (in the URL fragment)
   ├── HKDF, info = "secret-share/v1/enc"   ──► AES-256-GCM key   (never leaves the browser)
   └── HKDF, info = "secret-share/v1/claim" ──► claim token       (sent to the server)
```

The server stores `SHA-256(claim token)` and only releases the ciphertext to a request that
presents the matching token. That buys three things:

- Knowing a secret's ID is not enough to fetch it or to burn it. IDs appear in server logs
  and browser history; the key does not.
- A link that was cut off in transit cannot destroy the secret. The derived token will not
  match, the server refuses, and the intact link still works.
- The server learns nothing about the encryption key. HKDF is one-way and its outputs for
  different `info` labels are independent.

HKDF rather than something like `SHA-256(key + "claim")` because deriving several keys from
one secret is exactly what HKDF is standardised for, and WebCrypto provides it.

### Why a random IV is safe here

GCM fails badly if one key is ever used with the same IV twice. Here each key encrypts
exactly one message, ever, so a repeat cannot happen. The IV is random anyway because that
is the conventional form.

### Where the key is at each step

| Step | The key is | The server has |
|---|---|---|
| Sender clicks Create | 32 random bytes in page memory | nothing |
| Browser POSTs | still only in the browser | ciphertext, IV, hash of the claim token, allowlist |
| Link is shown | in the page text and the clipboard. The page URL stays `/` | unchanged |
| Link is sent | in whatever channel the sender chose | unchanged |
| Recipient opens it | in the address bar as the fragment, which is not part of the request | a `GET /secret/<id>` |
| Page script runs | moved to `sessionStorage`, removed from the address bar | unchanged |
| Recipient signs in (restricted secrets only) | in `sessionStorage` for this site and this tab | a session |
| Recipient clicks Reveal | used to derive the claim token, then to decrypt | deletes the row, returns ciphertext |
| Afterwards | removed from `sessionStorage` | nothing |

### No server-side encryption layer

v1 encrypted payloads at rest with Fernet, using a key in the server's environment. v2
removes it. The payload now arrives already encrypted under a key the server never has, so
a second layer would only matter if AES-GCM failed *and* the attacker had the database but
not the environment file sitting next to it. Removing it means the server holds no
decryption key of any kind, which is a simpler and stronger statement than "it holds one,
but it only decrypts to more ciphertext".

## Getting the key past the sign-in redirect

This is the subtle part of the design.

A browser that follows a redirect carries the original URL's `#fragment` over to the new
URL when the redirect does not specify one ([RFC 9110 §10.2.2][rfc9110]). So the obvious
flow, "not signed in? redirect to login", would produce this:

```
/secret/<id>#KEY  ──302──►  /auth/login  ──302──►  https://provider/authorize?...#KEY
```

The key would not go over the network, but it would be in the provider's address bar and
readable by any script on the provider's page. So:

1. `GET /secret/<id>` **always returns a page and never redirects**, signed in or not.
2. The page's script runs first: it copies the key to `sessionStorage` and removes it from
   the address bar with `history.replaceState`.
3. Only then can the recipient leave for sign-in: the **Sign in** link appears when a Reveal
   attempt gets a 401 (the secret is restricted). The URL has no fragment left to inherit.
4. As a second guard, the redirect to the provider ends in an explicit `#_`. A redirect that
   has its own fragment replaces any inherited one, so even a leftover key would arrive at
   the provider as `#_`.
5. After sign-in the browser returns to `/secret/<id>`, the script finds the key in
   `sessionStorage`, and the **Reveal** button appears again.

`sessionStorage` is the holding place because it is never sent in a request, is private to
this site, and is private to the tab. The alternatives all leak somewhere: the OAuth `state`
parameter goes to the provider, a cookie goes to the server, `localStorage` outlives the
tab, and `window.name` is readable by the next site.

If sign-in finishes in a different tab, that tab has no key. The page says the link is
incomplete and offers no Reveal button, so nothing is consumed and reopening the original
link works.

[rfc9110]: https://www.rfc-editor.org/rfc/rfc9110.html#name-location

## Identity: the OIDC integration

### Provider-agnostic by construction

The app is configured with four values and learns everything else from the provider's
discovery document:

| Setting | Meaning |
|---|---|
| `OIDC_ISSUER` | The provider's issuer identifier, exactly as it appears in its tokens |
| `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | This app's registration with the provider |
| `OIDC_REDIRECT_URI` | `https://<host>/auth/callback` |
| `OIDC_DISCOVERY_URL` | Optional. Defaults to `<issuer>/.well-known/openid-configuration`; some providers publish it elsewhere |

Nothing in the code names a provider.

### Authorization Code flow, with three per-attempt values

1. `GET /auth/login?next=/secret/<id>` generates `state`, `nonce` and a PKCE
   `code_verifier`, stores them in short-lived `HttpOnly` cookies, and redirects to the
   provider.
2. The user authenticates on the provider's page. This app never sees a password.
3. The provider redirects to `GET /auth/callback?code=...&state=...`.
4. The app checks `state`, then exchanges the code for tokens server-to-server.
5. The ID token is verified (next section).
6. The app creates its own session and sends the browser back to the secret.

| Value | Stops |
|---|---|
| `state` | An attacker completing, in the victim's browser, a login the attacker started (login CSRF) |
| `nonce` | A previously issued, still-valid ID token being replayed into a new login |
| PKCE `code_verifier` | A stolen authorization code being redeemed by someone who did not start the attempt |

### ID token verification, not `/userinfo`

The ID token's signature is verified against the provider's published keys (JWKS, via
`PyJWKClient`) before any claim is trusted. This gives an offline-verifiable, tamper-evident
proof of authentication. Calling `/userinfo` instead would rest on "whoever answered this
HTTPS request", with no signature and no replay protection.

What is checked, in [`verify_id_token`](app/auth.py):

- **Signature**, with an algorithm from a fixed list (`RS256`, `PS256`, `ES256`). The list is
  in the code; a token does not get to choose how it is checked. No `HS*` (anyone holding the
  public key could forge tokens) and no `none`.
- **`iss`** equals the configured `OIDC_ISSUER`. Not the value in the discovery document.
- **`aud`** contains this app's client ID. With several audiences, **`azp`** must be this app.
- **`exp`, `iat`, `sub`** are present. PyJWT only validates a claim that exists, so without
  this a token with no `exp` would be accepted and never expire.
- **`nonce`** matches the one this browser's attempt started with.

Separately, if the provider's redirect carries an `iss` parameter (RFC 9207; Auth0 sends
one), it must equal `OIDC_ISSUER` or the callback is refused before any token exchange.

The discovery document's own `issuer` must also equal `OIDC_ISSUER` exactly, or sign-in is
disabled. Everything else (endpoints, key location) comes from that document, so a wrong
discovery URL would otherwise silently change whose tokens are accepted.

### `email_verified` is required

Many providers let someone sign up with any address and log in before confirming it. Such a
token says `email_verified: false`. The app then records **no email at all** on the session,
so that session can never match an allowlist. Only the JSON boolean `true` counts.

### Opaque server-side sessions, not JWT cookies

After login the browser gets a cookie holding a random token. The `sessions` table stores
the SHA-256 of that token, with the user's `sub`, verified email and expiry.

- **Revocable.** `POST /auth/logout` deletes the row, and every copy of the cookie stops
  working immediately. A signed-claims cookie stays valid until it expires.
- **No claims on the client.** There is nothing to inspect or tamper with.
- **A database leak is not a session leak.** The table holds hashes, not tokens.

| Cookie attribute | Purpose |
|---|---|
| `HttpOnly` | Page script cannot read it |
| `Secure` | HTTPS only. On unless `ENVIRONMENT=development` is set explicitly |
| `SameSite=Lax` | Withheld from cross-site POSTs |
| `__Host-` name prefix | Other sites on sibling subdomains cannot overwrite it |

### Per-secret access control

A secret can be restricted to an allowlist of email addresses (separated by commas or new lines). The viewer's
verified email must be on it, so the recipient signs in first. With no allowlist there is
no sign-in: the full link is the only credential. Requiring a login there would add friction
and no access control, because any account at the provider would pass. The create form says
so.

## Other design decisions

**Reveal is a button, not a page load.** In v1, `GET /secret/<id>` consumed the secret, so
a link prefetcher or a cross-site navigation could burn it; `SameSite=Lax` does not help,
because Lax cookies are sent on top-level GETs. Now a GET changes nothing, and the claim is
a POST guarded three independent ways: the Lax cookie, a required
`Content-Type: application/json` (an HTML form cannot send it), and an `Origin` header that
must equal the app's own origin. There is no CSRF token because there are no server-rendered
forms to put one in.

**Proof of the link before anything, and one answer for every refusal.** The claim endpoint
checks the claim token first. "Never existed", "wrong claim token", "expired", "already
opened" and "not on the allowlist" all return the same 404, signed in or not. Only a caller
whose token matches a live, restricted secret and who has no session gets a 401, and nothing
is consumed. So the 401 tells "this one needs a sign-in" only to someone who already holds
the whole link. The secret page itself never queries the secrets table, so loading it reveals
nothing about whether an ID is real.

**The one-time guarantee is a conditional `DELETE` judged by row count.** Two concurrent
requests can both pass every check before either commits. The database runs the two
`DELETE`s one after the other and only the first removes a row; the request whose `DELETE`
reports zero rows gets the 404. A test fires two real threads at it.

**Deleted means deleted.** v1 marked a secret as viewed and kept the row. v2 deletes it in
the claim, purges expired secrets and sessions at startup and every ten minutes, and sets
SQLite's `secure_delete` so freed pages are overwritten rather than left in the file.

**Delivery is at-most-once.** The row is gone before the response is sent. If the
connection drops at that instant, the secret is lost. Deleting only after the browser
confirms would allow a second read, which is the worse failure for this tool.

**Strict Content-Security-Policy.** `default-src 'none'`, then `'self'` per type. No inline
script, no third-party script, fonts self-hosted. Because the key lives in the browser on
this origin, anything that gets script to run here could read it; the CSP is part of the
encryption design, not decoration. The interactive API docs are disabled for the same
reason: Swagger UI loads its script from a CDN.

**Abuse limits.** Creating is anonymous, so it is the endpoint a stranger could use to fill
the disk.

| Limit | Default |
|---|---|
| Request body | 256 KB, counted as bytes arrive |
| Secret size | 100,000 bytes |
| Creates per address | 10 per minute (token bucket, in memory) |
| Secrets stored at once | 1,000 |

The limiter is in memory, which is correct for one process. Several workers would each keep
their own counts and would need a shared store.

**Post-login redirects are an allow-list.** `next` must be exactly `/secret/<uuid>`;
anything else becomes `/`.

**SQLite, not Postgres.** One VM, low write volume. No migration framework: on a schema
change the database is deleted, and the app refuses to start against a file from an older
version instead of failing on the first query.

**Pinned dependencies.** Exact versions, for reproducibility. `pip-audit -r requirements.txt`
is clean as of the last dependency bump; pins do not update themselves.

## Threat model

### What it protects against

| Attacker | What they get |
|---|---|
| Someone who steals the database, a backup, or the server's whole directory | Ciphertext of secrets that are neither opened nor expired. There is no key on the server. |
| A curious operator reading the database or logs | Ciphertext, sizes, timestamps, allowlist addresses. No plaintext, no keys. |
| Someone who intercepts the link, when an allowlist is set | The key, but no way to fetch the ciphertext without signing in as a listed, verified address. |
| A compromised or malicious identity provider | It can sign in as anyone and fetch ciphertext, but has no key unless it also has the link. |
| Someone who knows only a secret's ID | Nothing. They cannot fetch or burn it without the claim token. |
| A link scanner, a prefetcher, a cross-site request | Nothing, unless it clicks Reveal (see below). Loading the page changes nothing; the claim is a same-origin POST. |
| A page trying to frame the app or inject script | Blocked by the CSP and `frame-ancestors`. |
| Someone who signs up at the provider with a victim's address and never verifies it | A session with no email, which matches no allowlist. |

### What it does not protect against

| Limit | Why |
|---|---|
| **A compromised server sending malicious JavaScript** | The browser runs whatever script the server serves. An attacker in control of the server can serve script that uploads the key. This is the basic limit of encryption delivered by a web page. The protection is against passive and after-the-fact compromise (stolen database, backups, logs), not an attacker actively controlling the server. |
| A compromised sender or recipient device | Malware, browser extensions and clipboard managers see the plaintext. |
| The channel that carries the link, when no allowlist is set | The link alone opens the secret. Anyone who sees it (a forwarded email, chat history, a screenshot) can read it first. |
| A scanner that runs the page and clicks Reveal, when no allowlist is set | Some email and chat security tools open links in a headless browser. One that clicks the button reads and burns an unrestricted secret. The recipient then sees "not available", so the loss is visible and the secret can be rotated. An allowlist stops this, because the scanner cannot sign in. |
| The key lingering in the recipient's browser history | The script removes it from the address bar at once, but whether the original URL was already recorded depends on the browser. Once the secret is revealed the ciphertext is gone, so an old key opens nothing. |
| Metadata | The server sees size (ciphertext length is plaintext length plus 16 bytes), timing, IP addresses, the allowlist and who claimed. |
| Denial of service | Anyone with the full link (and an allowed identity, if restricted) can burn the secret. The operator can delete rows. |
| Sender authenticity | The recipient cannot tell who created a secret. |
| A weak identity provider | The allowlist is only as strong as the provider's email verification and account security. |

### Reporting a vulnerability

Please report it privately, not in a public issue. [`SECURITY.md`](SECURITY.md) explains
how, and what counts: a way around one of the protections above is in scope, while the
limits listed above are known.

## Architecture

```
app/
├── main.py             # app assembly, error pages, periodic cleanup task
├── config.py           # env-driven settings (OIDC_*, limits), fail-closed validation
├── database.py         # SQLite engine, secure_delete, schema check, purge of expired rows
├── models.py           # Secret (ciphertext only) and UserSession (token hash only)
├── security.py         # security headers, body-size cap, origin check, rate limiter
├── auth.py             # OIDC login/callback/logout, ID token verification, sessions
├── secrets_router.py   # create, secret page, claim
├── web.py              # the shared Jinja2 environment and the error/gone pages
├── templates/          # create.html, secret.html, gone.html, error.html
└── static/
    ├── crypto.js       # all cryptography: HKDF, AES-GCM, base64url
    ├── create.js       # encrypt, POST, build the link
    ├── secret.js       # take the key out of the URL, sign-in/reveal views, decrypt
    ├── theme-init.js, theme.js, style.css
    └── fonts/          # self-hosted Space Grotesk, JetBrains Mono, and a Maname subset
                        # for the logo's six Sinhala characters (all OFL 1.1)

tests/
├── conftest.py              # isolated DB, a fake provider that signs real RS256 tokens
├── test_auth.py             # the OIDC flow and every way a token or callback can be forged
├── test_secrets.py          # create, the secret page, claim rules, the concurrent-claim race
├── test_security.py         # headers, CSP compliance of templates, limits, proxy handling, config
├── test_allowlist.py        # allowlist parsing and matching
├── test_crypto_vectors.py   # Python reproduces the known-answer vectors
├── js/crypto.test.js        # crypto.js under Node's test runner, same vectors
├── vectors/crypto_v1.json   # the known answers
└── mock_idp.py              # a local fake provider for trying the app in a browser
```

Two tables: `secrets` (ciphertext, IV, claim-token hash, allowlist, expiry) and `sessions`
(token hash, `sub`, verified email, expiry).

The frontend is Jinja2 templates and plain JavaScript files. No framework and no build
step. Each template is a self-contained HTML document; the small amount of shared page
chrome is duplicated across them on purpose.

## Tech stack

- **Backend:** FastAPI, SQLAlchemy, SQLite
- **Auth:** OpenID Connect Authorization Code flow with PKCE; `PyJWT` for ID token verification
- **Encryption:** WebCrypto in the browser (HKDF-SHA-256, AES-256-GCM)
- **Frontend:** Jinja2, vanilla JS and CSS
- **Tests:** pytest, and Node's built-in test runner for the browser crypto
- **Deployment:** Docker Compose behind nginx with Let's Encrypt

## Running locally

```bash
git clone https://github.com/sujayamindev/secret-share-tool.git
cd secret-share-tool
python -m venv .venv
.venv/Scripts/activate        # Windows. Linux/macOS: source .venv/bin/activate
pip install -r requirements-dev.txt
```

### Without an identity provider account

```bash
python -m tests.mock_idp
```

This starts the app on `http://localhost:8000` and a throwaway OIDC provider on
`http://localhost:9000`, with a temporary database. The provider's sign-in page lets you
pick a test user: `alice` and `bob` have verified emails, and `mallory` claims alice's
address without having verified it. It is a real provider as far as the app can tell
(discovery, signed tokens, PKCE enforcement), and it is for local use only.

### With Auth0

1. In the Auth0 dashboard, create an application of type **Regular Web App**.
2. In its **Settings**, under **Application URIs**:
   - **Allowed Callback URLs:** `http://localhost:8000/auth/callback`
   - **Allowed Logout URLs:** `http://localhost:8000/`
3. Open `https://<your-auth0-domain>/.well-known/openid-configuration` and copy the
   `issuer` value exactly, including the trailing slash if it has one.
4. `cp .env.example .env` and set:

   | Variable | Value |
   |---|---|
   | `OIDC_ISSUER` | the `issuer` value from step 3 |
   | `OIDC_CLIENT_ID` | the application's **Client ID** |
   | `OIDC_CLIENT_SECRET` | the application's **Client Secret** |
   | `OIDC_REDIRECT_URI` | `http://localhost:8000/auth/callback` |
   | `ENVIRONMENT` | `development` (local only) |

5. `uvicorn app.main:app --reload`, then open `http://localhost:8000`.

Things to know about Auth0:

- The ID token must be signed with an asymmetric algorithm. Check the application's
  **Advanced Settings → OAuth → JSON Web Token Signature Algorithm** is `RS256`.
- Sign-out sends the browser to Auth0's logout endpoint when the discovery document lists
  `end_session_endpoint`. Tenants created before 14 November 2023 need **Settings → Advanced
  → RP-Initiated Logout End Session Endpoint Discovery** switched on. Without it, sign-out
  still ends this app's session but not Auth0's.
- The app does not keep the ID token, so it cannot send `id_token_hint` on logout. Auth0
  therefore shows a short "are you sure?" page before returning to the app. This app's own
  session is already revoked by then.

For another provider, set `OIDC_ISSUER` to its issuer and, if it does not use the standard
discovery path, set `OIDC_DISCOVERY_URL`.

### Tests

```bash
pytest tests/
node --test tests/js/crypto.test.js
ruff check .
```

The pytest suite runs against an isolated temporary database and a fake provider that holds
a real RSA key, so forged, expired, unsigned and mis-addressed ID tokens are checked against
the app's real verification code. `tests/js/` runs the exact `crypto.js` the browser loads;
its known-answer vectors are also reproduced by Python's `cryptography` library, which shows
the JavaScript is doing standard HKDF and AES-GCM rather than something that only agrees
with itself.

Not covered by automated tests: the browser behaviour itself (the fragment surviving the
sign-in round trip). That was checked by hand, with the mock provider and against a real
Auth0 tenant (login with PKCE, reveal, and sign-out).

### Resetting the database

There are no migrations. After a schema change, stop the app and delete the file:

```bash
rm data/app.db        # Linux/macOS
del data\app.db       # Windows
```

## Deployment

Docker Compose, with nginx in front terminating TLS.

```bash
mkdir -p data && sudo chown 10001:10001 data
docker compose up --build -d
```

- The container runs as an unprivileged user (UID 10001), with all capabilities dropped.
  The bind-mounted `data/` directory must be owned by that UID.
- The volume is mounted with `:Z`. On an SELinux host (Oracle Linux, RHEL, Fedora) a
  container can only write to files labelled for containers, and `:Z` has Docker apply that
  label. Without it the app fails at startup with `unable to open database file` even though
  the Unix permissions are correct. Hosts without SELinux ignore the flag.
- The container port is published on `127.0.0.1:8001` only. nginx is what the internet
  reaches.
- `docker-compose.yml` sets `TRUSTED_PROXY_HOPS=1`, so the per-address rate limit uses the
  last `X-Forwarded-For` entry, which is the one nginx wrote. Entries to its left are
  supplied by the client and ignored. nginx must set that header
  (`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`).
- `.env` on the server needs the `OIDC_*` values with `https` URLs. `ENVIRONMENT` defaults
  to `production`; the app refuses to start with plain-HTTP provider URLs in that mode.

The in-app rate limit is a backstop. For a public deployment, also rate-limit at nginx
(`limit_req`); this repository does not configure nginx.

### CI/CD

`.github/workflows/ci.yml` runs on every push and pull request:

- **lint:** `ruff check .`, with ruff pinned and configured in `pyproject.toml`
- **test:** `pytest` and the Node crypto tests
- **docker-build:** the image builds

On a push to `main`, after all three pass, **deploy** connects to the VM over SSH,
fast-forwards the checkout to the exact commit that was tested, and runs
`docker compose up --build -d`.

- Actions are pinned to full commit SHAs rather than tags, since a tag can be moved.
- The workflow token is read-only.
- Deploy credentials are **Environment** secrets on a `production` environment, so only the
  deploy job receives them and jobs triggered by pull requests from forks do not.
- The deploy SSH key belongs to a dedicated VM user and is locked with `restrict` and a
  forced command that accepts only `deploy <full commit SHA>`, and only for a commit already
  on `origin/main`. A leaked key cannot open a shell, forward ports or deploy other code.

## Out of scope, and known limits

- No secret history, editing, or expiry extension
- No accounts beyond the sign-in session
- Ciphertext length reveals plaintext length; there is no padding
- The rate limiter is per process and in memory
- No protection against the server operator actively serving malicious script
  (see the threat model)
- Dependency versions are pinned. Dependabot opens a pull request when one has a security
  advisory; nothing is merged automatically

The audit that led to this version, and the reasoning behind each decision, is in
[`docs/DESIGN-v2.md`](docs/DESIGN-v2.md).
