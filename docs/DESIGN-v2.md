# Design v2: zero-knowledge, provider-agnostic OIDC

Status: **approved 2026-11-15**, with the recommended answer to every decision in section 11.
Branch: `feat/zero-knowledge-auth0`. Audit date: 2026-11-15, against commit `1de9a12`.
Sections 1 and 2 describe the code as it was at that commit, before any of the fixes.

Contents

1. Audit findings, ranked
2. Comparison with the known-issues appendix
3. Encryption design
4. How the key survives the login round trip
5. Threat model
6. Server-side Fernet: keep or remove
7. Identity provider design
8. Other fixes
9. Change checklist
10. Deployment cutover (manual steps, not done by this branch)
11. Decisions I need from you
12. What changed during the build
13. Sources and things I could not confirm

---

## 1. Audit findings, ranked

How to read this: "Measured" means I reproduced it against the current code with the test
client or a tool. "Read" means it follows from reading the code and I did not run it.

### High

**F1. Viewed secrets are never deleted.** *Measured.*
`view_secret` sets `viewed=True` and leaves the row. After a successful reveal the row still
exists and `decrypt(row.encrypted_payload)` still returns the plaintext. The Fernet key sits
in `.env` in the same directory as `data/app.db`.
- Scenario: anyone who obtains the VM directory (a backup, a stolen disk snapshot, a
  compromised sibling container with the mount) reads every secret ever shared, including
  ones the UI told the recipient were "permanently deleted".
- The README says "permanently deleted" and `view.html` repeats it. Both are false today.
- Fix: delete the row in the same atomic step that claims it. Turn on SQLite
  `secure_delete` so freed pages are overwritten.

**F2. The allowlist trusts an unverified email claim.** *Read.*
`callback` stores `claims.get("email")` without looking at `email_verified`.
- Scenario: a secret is restricted to `cfo@company.com`. The attacker signs up at the
  identity provider with that address and never clicks the verification mail. If the
  provider lets unverified users log in, the ID token carries `email: cfo@company.com`,
  `email_verified: false`, and the allowlist passes.
- This is the whole identity gate, so it is High. It matters more after the move to Auth0,
  where open sign-up with a database connection is the default setup.
- Fix: the session only records an email when `email_verified is True`. Otherwise the
  session has no email and every allowlisted secret rejects it.

**F3. The server reads every secret.** *By design in v1.*
The plaintext arrives in a form POST, and the server holds the only key. A curious operator,
a logging mistake or a memory dump exposes secrets. This is the reason for v2, not a bug,
but it belongs at the top of the list because it bounds what every other control can do.

### Medium

**F4. A GET request consumes the secret, and `SameSite=Lax` does not cover it.** *Read.*
The one state-changing authenticated action is `GET /secret/{id}`. Lax cookies are sent on
top-level cross-site GET navigations, which is exactly this request.
- Scenario: a recipient who is signed in hovers a link in a client that prefetches, or any
  page navigates them to the link. The secret is burned without the recipient choosing to
  open it.
- CLAUDE.md lists `SameSite=Lax` as "CSRF mitigation for state-changing requests". For this
  route it mitigates nothing.
- Fix: reveal becomes an explicit button that sends a POST. The POST is protected three
  ways (section 8).

**F5. The reveal page is cacheable.** *Measured: response has no `Cache-Control`.*
- Scenario: after the secret is "deleted", the browser's Back button or disk cache shows the
  plaintext again on a shared machine.
- Fix: `Cache-Control: no-store` on every non-static response.

**F6. No security headers, inline scripts, and third-party CSS on the secret page.** *Measured.*
The only response headers are `content-type` and `content-length`. Every template has an
inline `<script>`, two have inline `onclick` handlers, and all four load a stylesheet from
`fonts.googleapis.com`.
- Scenario A (clickjacking): the page can be framed by any site.
- Scenario B (third party): a stylesheet from another origin is applied to the page that
  shows the plaintext. CSS cannot run script, but it can leak which characters appear on a
  page through `@font-face` `unicode-range` requests. For a tool whose promise is "nobody
  else sees this", no other origin should supply anything to that page.
- Fix: strict CSP (`default-src 'none'`, everything `'self'`), `frame-ancestors 'none'`,
  `nosniff`, `Referrer-Policy: no-referrer`, HSTS in production, all scripts moved to
  `app/static/`, fonts no longer loaded from Google (decision D2).

**F7. Pinned dependencies have known advisories.** *Measured with `pip-audit` today.*
| Package | Pinned | Relevant advisories (pip-audit IDs) | Fixed in |
|---|---|---|---|
| starlette (via fastapi 0.115.0) | 0.38.6 | PYSEC-2026-1943: multipart text fields buffered with no size limit, reachable through `POST /create`. PYSEC-2026-249: form limits ignored for urlencoded bodies. PYSEC-2026-161 and -248: `request.url` rebuilt from an unvalidated Host header and path | 1.3.1 |
| pyjwt | 2.13.0 | PYSEC-2026-4144: `PyJWKClient` follows redirects when fetching JWKS. -4140, -4141, -4152: JWKS client denial of service and parsing issues. Several algorithm-confusion advisories that need an HMAC algorithm in the allow-list, which this app does not have | 2.15.0 |
| cryptography | 48.0.1 | X.509 and PKCS#7 issues. Not reachable from this app | 50.0.0 |
- Fix: bump and re-pin, then re-run `pip-audit` until clean. Dropping form parsing removes
  `python-multipart` entirely.

**F8. `POST /create` has no rate limit, no storage quota and no body cap.** *Measured.*
`max_length=100_000` counts characters, not bytes. 100,000 two-byte characters produced a
266,764-byte row. Nothing is ever purged (F1, F9).
- Scenario: a loop of POSTs fills the VM's disk, which also takes down the other projects on
  that VM. A single multi-gigabyte body is read into memory before validation (F7).
- Fix: body-size cap at the ASGI layer, per-IP token bucket on create, and a hard cap on the
  number of live secrets so the worst case on disk is a known number.

**F9. Expired secrets and sessions are never purged.** *Read.*
- Fix: a background task deletes expired rows at startup and every 10 minutes.

**F10. The authentication code has no tests.** *Measured: no test imports `app.auth`.*
State, nonce, signature, `aud`, `iss` and `exp` handling are the most security-critical lines
in the repo and nothing checks them. `_safe_next` is also untested.
- Fix: a fake identity provider inside the test suite that signs real RS256 tokens, plus one
  test per attack case (section 9).

**F11. CI and deploy pipeline.** *Measured where stated.*
- `pip install ruff` is unpinned. With today's ruff (0.17.5, `--isolated`) the repo has 24
  lint errors, so the lint job fails on the next push and blocks the deploy. *Measured.*
- `appleboy/ssh-action@v1.2.0` is a mutable tag, in the one job that holds the VM's SSH key.
  If the tag is moved, the key is exposed. Fix: pin the commit
  (`7eaf76671a0d7eec5d98ee897acda4f968735a17`, from `git ls-remote` today).
- The deploy runs `git pull origin main`, which deploys whatever is on `main` at that
  moment, not the commit that passed the tests.
- No `permissions:` block, no concurrency guard on deploy.

**F12. The live demo does not resolve.** *Measured.*
`secrets.sujaya.dev` returns NXDOMAIN from both 1.1.1.1 and 8.8.8.8. `sujaya.dev` itself
resolves (GitHub Pages). README and CLAUDE.md both present the demo as live. I have not
touched DNS; this needs you (decision D5).

### Low

**F13. `_safe_next` is a deny-list and lets `/\evil.com` through.** *Measured.*
The validator returns `/\evil.com` and `/<TAB>/evil.com` unchanged. See section 2 for why
this is not exploitable today. It also accepts `next=/auth/login`, which loops.
- Fix: an allow-list. `next` must match `/secret/<uuid>` exactly, otherwise `/`.

**F14. Not-on-the-allowlist returns 403, everything else returns 404.** *Measured.*
The README says these are identical. A signed-in stranger can tell "live and restricted to
someone else" from "gone".
- Fix: one status, one body.

**F15. `/created/{id}` is an unauthenticated existence oracle.** *Measured.*
It returns 200 for a real ID and a redirect for a made-up one, with no login, forever (rows
are never deleted). This undoes the "auth before existence" decision in CLAUDE.md. The page
also re-displays the link on refresh although it says it will not, and the link ends up in
the sender's browser history.
- Fix: the route goes away. In v2 the link is built in the browser and never has a URL of
  its own.

**F16. ID token validation gaps.** *Measured for the first two.*
- A token with no `exp` claim is accepted. PyJWT only checks `exp` if it is present.
- A token with several audiences and no `azp` is accepted (OIDC Core 3.1.3.7 says check it).
- The expected issuer is read from the discovery document rather than from configuration.
- Zero clock-skew leeway, so a slightly slow VM clock rejects valid logins.
- `get_signing_key_from_jwt` is outside the `try`, so a malformed token returns a 500.
- `state` is compared with `!=` rather than a constant-time compare (informational).

**F17. Sessions are "revocable" but nothing revokes them.** *Read.*
There is no logout route, so the property the README sells is never exercised. Session IDs
are stored in clear, so a database leak is also a leak of live sessions.
- Fix: `POST /auth/logout` deletes the row. The table stores a SHA-256 of the session token.

**F18. Cookie hardening.** *Read.*
`COOKIE_SECURE` is false unless `ENVIRONMENT=production` is set, so a missing variable fails
open. Cookies have no `__Host-` prefix, so another project on a sibling `*.sujaya.dev`
subdomain could overwrite them.

**F19. Redirects and the share link are absolute URLs built from the request.** *Measured in the test client.*
An unauthenticated request with `Host: secrets.sujaya.dev` gets
`Location: http://secrets.sujaya.dev/auth/login?...`. Uvicorn only trusts
`X-Forwarded-Proto` from 127.0.0.1, and behind Docker's bridge nginx is not 127.0.0.1. I
could not check production because of F12.
- Fix: relative redirects only, and the share link is built in the browser from
  `location.origin`.

**F20. `/docs` and `/openapi.json` are public.** *Measured.*
Swagger UI loads script from a CDN and runs it on this app's origin.
- Fix: disable both.

**F21. Error handling.** *Measured.*
Auth failures return bare JSON. The `error` query parameter is reflected into it, and
exception text is included. An over-length payload returns a JSON 422, although CLAUDE.md
says every malformed submission gets the form back.

**F22. Container and build.** *Read.*
The container runs as root. There is no `.dockerignore`, so `.env` and `data/` are sent to
the build context (they are not copied into the image). The base image tag floats.

**F23. Small race and failure windows.** *Read.*
Expiry is checked before the atomic `UPDATE` but is not part of it. A decrypt failure after
the claim burns the secret. Both are negligible and both disappear in v2.

**F24. `async def` routes call blocking code.** *Read.*
SQLAlchemy and the JWKS fetch are synchronous, so each request blocks the event loop. This
is why the race the atomic update guards against cannot occur in the current single-worker
deployment. Correctness is fine; the idiom is wrong.
- Fix: routes that touch the database become plain `def`, which FastAPI runs in a thread
  pool. That makes requests really concurrent, so the atomic claim starts to matter.

**F25. Repository hygiene.** *Measured.*
- `my-codeql-db/` and `codeql-custom-queries-python/` are not in `.gitignore`. Neither is
  tracked and neither has ever been committed (`git ls-files` and `git log --all` are both
  empty for them). Both currently contain zero files, which is why git does not show them.
- `.gitignore` ignores `CLAUDE.md` and `docs/`. So CLAUDE.md is not in the repository, and
  this document will not be committed unless that changes (decision D3).
- `.env` has never been committed.

**F26. README statements that do not match the code.**
"Permanently deleted" (F1), identical responses (F14), revocable sessions (F17),
"Asgardeo-verified email" (F2), "no automatic dependency updates" (the Actions history shows
Dependabot runs), and `next=<secret_id>` (it is a path).

**F27. No PKCE.** *Read.*
Not required for a confidential client, recommended for all clients by current OAuth
guidance. It stops an attacker injecting a stolen authorization code.

### What is sound and stays

- `state` and `nonce` are generated per login and bound to the browser with cookies.
- The algorithm allow-list is fixed in code and never read from the token.
- The one-time claim is a single conditional statement checked by row count.
- Jinja autoescaping is on, so there is no HTML injection through the secret or error text.
- Secrets are not baked into the image, and the SSH key is scoped to a GitHub Environment.

---

## 2. Comparison with the known-issues appendix

A caveat first. The appendix was part of the same message as the instructions, so I had
seen it before I started. I cannot prove I would have found each item unprompted. What I can
say is which items are plain from the code and which I checked.

| # | Your issue | Verdict |
|---|---|---|
| 1 | Secrets never deleted; nothing cleaned up | Found and reproduced (F1, F9). Agree. I would add `secure_delete`, since a plain `DELETE` leaves the bytes in the file. |
| 2 | Open redirect through `/\evil.com` | **Partly disagree.** The validator is wrong, but the exploit does not reach the browser (below). |
| 3 | `email_verified` not checked | Found (F2). Agree, and I rate it High. |
| 4 | No rate limit on create | Found (F8). Agree. The limit is also 100,000 characters, not bytes, and there is no body cap. |
| 5 | CodeQL folders not ignored | Checked (F25). Not tracked, never in history, both empty. Will add to `.gitignore`. |

**Why I partly disagree with #2.** `_safe_next("/\\evil.com")` does return `/\evil.com`. But
Starlette's `RedirectResponse` percent-encodes the header, so what the browser receives is
`Location: /%5Cevil.com`. A percent-encoded backslash is a path character, not a separator,
so this is a same-origin 404. I measured the same for the tab variant (`/%09/evil.com`).
So: a real bug in the validator, saved by a side effect of the framework. I will still fix
it, with an allow-list rather than a better deny-list, because protection that depends on an
accident of the framework is not protection you can explain.

**Missed:** none of the five. **Beyond the appendix:** F4 to F7, F10 to F12, F14 to F24, F26,
F27.

Your design suggestions: I agree with all five. Section 3 and 4 add four things to them
(claim token, fragment override on the provider redirect, a sign-in button instead of an
automatic redirect, and hard deletion).

---

## 3. Encryption design

### The idea

The server stores a locked box and never holds the key. The key is created in the sender's
browser, travels to the recipient inside the link, and is used in the recipient's browser.
The part of a URL after `#` is called the fragment. Browsers never include it in an HTTP
request, so a key placed there is not sent to the server by either browser.

### Algorithms

| Choice | Value | Why |
|---|---|---|
| Cipher | AES-256-GCM, WebCrypto `SubtleCrypto` | Built into every browser, so no library to ship. GCM is authenticated: a modified ciphertext fails to decrypt instead of producing garbage. |
| Link secret | 32 random bytes from `crypto.getRandomValues` | 256 bits. 43 characters in base64url. |
| Key derivation | HKDF-SHA-256, built into WebCrypto | One secret in the link, two independent values out (below). |
| IV | 12 random bytes per secret | The size GCM is designed around (MDN, AesGcmParams). |
| Auth tag | 128 bits | WebCrypto default, appended to the ciphertext. |
| Encoding | UTF-8 in, base64url on the wire | |

### Two values from one link secret (my addition, decision D1)

From the link secret the browser derives:

- `enc_key = HKDF(link_secret, info="secret-share/v1/enc")`: the AES-256-GCM key.
- `claim_token = HKDF(link_secret, info="secret-share/v1/claim")`: 32 bytes sent to the
  server when the secret is created and again when it is claimed.

The server stores only `SHA-256(claim_token)` and releases the ciphertext only to a request
that presents a matching token.

Why bother:

1. Knowing the secret's ID is no longer enough to fetch or burn it. The ID appears in server
   logs and in browser history after the fragment is stripped. The key does not.
2. A damaged link cannot burn the secret. If the fragment is truncated in transit, the
   derived token does not match, the server refuses, and the original link still works.
3. The server never sees the link secret. HKDF outputs are independent, so the claim token
   reveals nothing about the encryption key.

Why HKDF and not `SHA-256(key + "claim")`: HKDF is the standard tool for "derive several
independent keys from one secret", and WebCrypto ships it. A hand-made hash construction is
the first thing an interviewer would poke at.

Cost: one concept, one column, about 15 lines of JS and 5 of Python. If you would rather
keep the design to exactly what you proposed, the fallback is: the fragment is the AES key
itself and there is no claim token. Everything else in this document is unchanged.

### IV handling

GCM breaks badly if the same key and IV are ever used for two messages: an attacker can
recover the XOR of the plaintexts and forge messages. Here each key encrypts exactly one
message, so a repeat is impossible by construction. The IV is still random and stored next
to the ciphertext, because that is the conventional form and it costs nothing. The IV is not
secret.

### Where the key is at every step

| Step | Link secret / key | Server has |
|---|---|---|
| 1. Sender types the secret | Not created yet | Nothing |
| 2. Sender clicks Create | 32 random bytes in JS memory. Imported as non-extractable WebCrypto keys | Nothing |
| 3. Browser sends the POST | Stays in the browser | Ciphertext, IV, `SHA-256(claim_token)`, allowlist |
| 4. Link shown to the sender | In the page text and, on Copy, the clipboard. The page URL stays `/`, so it is not in the sender's history | Unchanged |
| 5. Sender sends the link | In whatever channel they choose. That channel sees the key but has no ciphertext | Unchanged |
| 6. Recipient opens the link | In the address bar as the fragment. Not in the request | Sees `GET /secret/<id>` only |
| 7. Page script runs | Copied to `sessionStorage`, then removed from the address bar with `history.replaceState` | Unchanged |
| 8. Recipient signs in | In `sessionStorage` for this origin and this tab. Not in any URL, cookie or request | A session for the recipient |
| 9. Recipient clicks Reveal | Read from `sessionStorage`. `claim_token` is derived and sent | Verifies token and allowlist, deletes the row, returns the ciphertext |
| 10. Decrypt | Used once in the browser, then removed from `sessionStorage` | Nothing. The row is gone |

### Why the server can never see the key

- It is generated in the browser and placed only in the fragment, which is not part of an
  HTTP request (RFC 9110).
- The only derived value the server receives is `claim_token`, which is one-way.
- The server does not hold a decryption key of its own (section 6), so there is nothing on
  the VM that turns a database row back into plaintext.

The honest limit: the server delivers the JavaScript that does all of this. See section 5.

### Limits I am choosing not to fix

- **Length is visible.** Ciphertext length is plaintext length plus 16 bytes. Padding to
  fixed sizes would hide it. Not planned; it is listed in the threat model.
- **At-most-once delivery.** The row is deleted before the response is sent. If the
  connection drops at that moment, the secret is lost. The alternative, delete after the
  browser confirms, would allow a second read, which is worse for this tool.

---

## 4. How the key survives the login round trip

### The problem

RFC 9110 section 10.2.2: if a redirect's `Location` has no fragment, the browser must carry
the original fragment over to the new URL. So this chain would hand the key to the identity
provider's page:

```
/secret/<id>#KEY  -> 302 /auth/login  -> 302 https://tenant.auth0.com/authorize?...#KEY
```

It would not be sent over the network, but it would be in the provider's address bar and
readable by any script on the provider's login page through `location.hash`.

### The steps

1. `GET /secret/<id>` always returns a 200 page. It never redirects, signed in or not.
2. The page's script runs first: validate the fragment (must decode to 32 bytes), save it to
   `sessionStorage` under the secret's ID, and remove it from the address bar with
   `history.replaceState`.
3. If the visitor is not signed in, the page shows a **Sign in to reveal** button. It links
   to `/auth/login?next=/secret/<id>`. By now the URL has no fragment to inherit.
4. `/auth/login` redirects to the provider with an explicit throwaway fragment (`#_`) on the
   `Location`. A `Location` that has its own fragment replaces any inherited one, so even if
   some future code path reached this redirect with the key still in the URL, the provider
   would receive `#_`. This is the same trick behind the `#_=_` Facebook appends to OAuth
   redirects.
5. After login, the callback redirects to `/secret/<id>`. The page finds the key in
   `sessionStorage` and shows the **Reveal** button.
6. Reveal sends the claim, decrypts, shows the text with `textContent` (never `innerHTML`)
   and deletes the key from `sessionStorage`.

A button rather than an automatic redirect in step 3: it gives the page a moment to say
what is about to happen, and a link scanner that loads the page never bounces off the
provider.

### Why `sessionStorage`

| Option | Verdict |
|---|---|
| `sessionStorage` | Chosen. Scoped to this origin and this tab, never sent in a request, cleared when the tab closes. |
| OAuth `state` parameter | No. It goes to the provider. |
| Cookie | No. It goes to the server. |
| `localStorage` | No. Shared across tabs and kept after the tab closes. |
| `window.name` | No. Readable by the next origin the tab visits. |
| Popup login, key stays in memory | Works, but popup blockers and a lot more code. |

Risk in this choice: anything that runs script on this origin can read `sessionStorage`.
That is why the CSP allows scripts from `'self'` only and why `/docs` is removed (F20).

Failure case: if the login finishes in a different tab (some providers open the
email-verification link in a new one), that tab has no key. The page says so and Reveal is
disabled. Nothing has been claimed, so reopening the original link works.

One thing I will test in a real browser before relying on it: that `sessionStorage` survives
the same tab going to another origin and back. I am confident it does (it is how this
pattern is normally built) but the documentation I fetched does not state it in so many
words. See section 12.

---

## 5. Threat model

"Zero-knowledge" here means the server never receives the key or the plaintext. It does not
mean a zero-knowledge proof, and the README will say so.

### Protects against

| Attacker | What they get |
|---|---|
| Someone who steals the database, a backup, or the whole VM directory | Ciphertext of secrets not yet viewed or expired. No keys exist on the server. |
| A curious operator reading the database or logs | Ciphertext, sizes, timestamps, allowlist emails. No plaintext. |
| Someone who intercepts the link, when an allowlist is set | The key, but no way to fetch the ciphertext without signing in as a listed, verified address. |
| A compromised or malicious identity provider | Can sign in as anyone and fetch ciphertext, but has no key unless it also has the link. |
| Someone who learns only the secret's ID | Cannot fetch or burn it without the claim token (D1). |
| A second viewer, a prefetcher, a cross-site request | Nothing. One claim, by POST, same-origin only. |
| Another site framing the page or injecting script | Blocked by CSP and `frame-ancestors`. |

### Does not protect against

| Limit | Why |
|---|---|
| **A compromised server serving malicious JavaScript** | The browser runs whatever script the server sends. A server under an attacker's control can send script that uploads the key. This is the basic limit of browser-delivered encryption. CSP, no third-party script and a small readable codebase reduce the ways in, but they do not defend against the server itself. The protection is against passive and after-the-fact compromise, not an active one. |
| A compromised sender or recipient device | Malware, extensions and clipboard managers see the plaintext. |
| The channel carrying the link, when no allowlist is set | Link plus any account at the provider opens the secret. Without an allowlist, sign-in is an audit step, not access control. |
| The link staying in the recipient's history | The script strips the fragment at once, but whether the original URL is already recorded is browser-dependent. What holds regardless: once revealed, the ciphertext is gone, so the old key opens nothing. |
| Metadata | The server sees size, time, IP addresses, the allowlist and who claimed. |
| Denial of service | Anyone holding the full link and an allowed identity can burn the secret. The operator can delete rows. |
| Sender authenticity | The recipient cannot tell who created a secret. |
| A weak identity provider | The allowlist is as strong as the provider's email verification and account security. |

---

## 6. Server-side Fernet: keep or remove

**Recommendation: remove it.**

| | Remove Fernet | Keep Fernet as a second layer |
|---|---|---|
| What protects the payload | AES-256-GCM under a key the server never has | The same, plus AES-128-CBC under a key in `.env` |
| When the second layer helps | n/a | Only if the attacker has the database but not `.env`, and AES-GCM has also failed. Both files live in the same directory. |
| Keys on the server | None | One, to generate, store, rotate and leak |
| The claim you can make | "A full server compromise yields nothing readable" | "...except there is a decryption key on the server, which decrypts to more ciphertext" |
| Code | `crypto.py` deleted, `FERNET_KEY` gone | Kept |

The argument an interviewer will raise is defence in depth. The answer: a second lock only
adds depth if its key is kept somewhere the first failure does not reach. This key sits
beside the data it protects, and the data is already encrypted under a key that is nowhere
on the machine. That is ceremony, and it makes the security claim harder to state.

What Fernet did protect, and what replaces it: it kept the database from holding plaintext.
In v2 the database cannot hold plaintext because the server never receives any.

Note: the `cryptography` package stays installed. PyJWT needs it to verify RS256 signatures.

---

## 7. Identity provider design

### Settings

| Variable | Required | Meaning |
|---|---|---|
| `OIDC_ISSUER` | yes | The provider's issuer identifier, exactly as it appears in tokens |
| `OIDC_CLIENT_ID` | yes | |
| `OIDC_CLIENT_SECRET` | yes | |
| `OIDC_REDIRECT_URI` | yes | `https://<host>/auth/callback`. The app's own public origin is taken from this value |
| `OIDC_DISCOVERY_URL` | no | Defaults to `<issuer>/.well-known/openid-configuration`. Asgardeo, for one, uses a different path |

### Rules

- The discovery document's `issuer` must equal `OIDC_ISSUER` exactly, or startup of the
  login flow fails with a message that says so. This matters once the discovery URL can be
  overridden: without it, a wrong URL silently changes who you trust.
- The token's `iss` is checked against `OIDC_ISSUER`, not against the discovery document.
- Kept: `state`, `nonce`, JWKS signature verification, `aud`, `exp`, opaque sessions.
- Added: `exp`, `iat`, `sub` required to be present; `azp` checked when there are several
  audiences; 60 seconds of clock leeway; PKCE with S256; `email_verified` (F2).
- Algorithms: a fixed list of asymmetric algorithms (`RS256`, `PS256`, `ES256`). Never read
  from the token, never `HS*`, never `none`.
- Scope: `openid email`. `profile` is dropped; nothing uses it.
- Logout: `POST /auth/logout` deletes the session row and the cookie. If the discovery
  document advertises `end_session_endpoint`, the browser is then sent there so the provider
  session ends too.

### Auth0 specifics (full setup steps come at the end of Phase 2)

- Application type: Regular Web App. Fields: Allowed Callback URLs, Allowed Logout URLs.
- Discovery: `https://<tenant-domain>/.well-known/openid-configuration` (the default path,
  so no override needed).
- Issuer: copy the `issuer` value from that document into `OIDC_ISSUER` character for
  character. Auth0's own documentation shows it both with and without a trailing slash, so
  do not type it from memory.
- Not confirmed from the documentation, to be tested against your tenant: PKCE for a Regular
  Web App, whether an unverified database user can log in, and logout without
  `id_token_hint` (Auth0 may show a confirmation prompt).

---

## 8. Other fixes

### Reveal by POST, with three independent CSRF defences

1. `SameSite=Lax`: the browser does not send the cookie on a cross-site POST.
2. The endpoint only accepts `Content-Type: application/json`. An HTML form cannot send
   that, and cross-origin script must first pass a CORS preflight the app never approves.
3. The `Origin` header must equal the app's own origin (taken from `OIDC_REDIRECT_URI`).

No CSRF token: there are no server-rendered forms left to put one in.

### One response for every failure

The claim endpoint checks in this order: signed in (401 if not, before any lookup), then
exists, not expired, allowlist, claim token. Every failure after sign-in returns the same
404 body. The secret page itself never queries the secrets table, so loading it reveals
nothing about whether an ID is real.

### Deletion

Claim = read the row, check it, then `DELETE ... WHERE id = ? AND expires_at > now`. Only the
request whose `DELETE` reports one row returns the ciphertext. Same row-count pattern as
today, so the existing race test carries over. `PRAGMA secure_delete = ON` overwrites freed
pages.

There is no "viewed" tombstone. The `viewed_by_sub` audit trail goes away. Nothing reads it
today, and keeping rows is what caused F1.

### Abuse limits

| Limit | Default | Where |
|---|---|---|
| Request body | 256 KB | ASGI middleware, before parsing |
| Plaintext | 100,000 bytes | Browser, and the server checks ciphertext length |
| Creates per IP | 10 per minute | In-memory token bucket |
| Live secrets | 1,000 | Checked on create. Worst case on disk is about 135 MB |

The limiter is in memory and hand-written (about 30 lines, tested) rather than a new
dependency. That is correct for one worker; several workers would need a shared store. The
per-IP limit depends on nginx passing the client address (section 10). The production-grade
layer is nginx `limit_req`; the README will give the snippet but this branch does not touch
nginx.

### Headers, on every response

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';
    img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self';
    base-uri 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Cache-Control: no-store                      (everything except /static)
Strict-Transport-Security: max-age=31536000  (production only, this host only)
```

Considered and left out: `Cross-Origin-Opener-Policy`. It changes how the tab is handled
across the provider round trip, and I do not want to risk the `sessionStorage` hand-off for
a header that protects nothing this app uses.

### Sessions and cookies

- Cookie value: `secrets.token_urlsafe(32)`. The table stores its SHA-256.
- Names: `__Host-session` (and `__Host-` on the short-lived login cookies) when secure.
- Secure is on unless `ENVIRONMENT=development` is set explicitly, so it fails closed.

---

## 9. Change checklist

### Backend
- [ ] `config.py`: `OIDC_*` settings, discovery default and override, app origin, limits; remove `ASGARDEO_*` and `FERNET_KEY`
- [ ] `crypto.py`: delete
- [ ] `models.py`: `Secret` = id, ciphertext, iv, claim_token_hash, allowed_emails, created_at, expires_at. `UserSession` keyed by token hash
- [ ] `database.py`: `secure_delete`, startup schema check that fails with a clear message instead of 500s later
- [ ] `secrets_router.py`: `GET /`, `POST /api/secrets`, `GET /secret/{id}`, `POST /api/secrets/{id}/claim`; remove `/created/{id}`; routes become `def`
- [ ] `auth.py`: provider-neutral, issuer pinning, required claims, `azp`, leeway, PKCE, `email_verified`, strict `next`, `#_` on the provider redirect, logout, error page instead of JSON
- [ ] `security.py` (new): headers middleware, body cap, origin check, rate limiter
- [ ] `main.py`: disable `/docs`, cleanup task, 404 handler
- [ ] Bump and re-pin fastapi/starlette, pyjwt, cryptography; drop python-multipart; `pip-audit` clean

### Frontend (plain JS in `app/static/`, no build step)
- [ ] `crypto.js`: HKDF, encrypt, decrypt, base64url. Pure functions, loadable in Node for tests
- [ ] `create.js`, `secret.js`, `theme-init.js`; no inline script or handlers anywhere
- [ ] Templates: `create.html`, `secret.html` (replaces `view.html`), `gone.html`, `error.html`; `created.html` removed. Still four self-contained documents plus the error page, per the no-shared-layout rule
- [ ] Fonts per decision D2
- [ ] `<noscript>` message: the app cannot work without JavaScript, by design

### Tests
- [ ] Fake provider fixture: RSA key, discovery, JWKS, token endpoint
- [ ] Token attacks: bad signature, wrong `aud`, wrong `iss`, expired, missing `exp`, `alg: none`, HS256 signed with the public key, wrong nonce, multi-audience without `azp`, unknown `kid`
- [ ] Flow attacks: missing or wrong `state`, discovery issuer mismatch, PKCE verifier sent, unverified email gets no session email
- [ ] `next`: `/\evil.com`, `//evil.com`, absolute URL, `/auth/login`, tab variant
- [ ] Claim: unauthenticated 401 for real and fake IDs alike; identical 404 for missing, expired, not allowed, wrong token; wrong token does not burn; row gone after claim; race with two threads; cross-origin and non-JSON rejected
- [ ] Create: size limits, malformed base64, wrong IV length, bad emails, rate limit, live-secret cap, oversized body
- [ ] Sessions: hash stored not token, logout deletes row, expired rejected, cleanup purges
- [ ] Headers present on HTML, API and error responses; `/docs` is 404
- [ ] JS (`node --test`): round trip, wrong key fails, tampered ciphertext fails, fresh IV each time, known-answer vectors that the Python `cryptography` library reproduces
- [ ] Dev-only mock provider so the whole flow can be driven in a real browser without Auth0

### Repo, CI, container
- [ ] `.gitignore`: CodeQL folders, `.venv` already covered; D3
- [ ] `pyproject.toml` ruff config, ruff pinned in `requirements-dev.txt`
- [ ] `ci.yml`: `permissions: contents: read`, ssh-action pinned to a commit, deploy the tested SHA, concurrency guard, Node test step
- [ ] `Dockerfile`: non-root user (D4), `--proxy-headers`; `.dockerignore`
- [ ] `.env.example`

### Docs
- [ ] README rewrite: new pitch, no WSO2 framing, design decisions at current depth, threat model, honest limits
- [ ] CLAUDE.md: scope list, new decisions and reasons, WSO2 context removed

---

## 10. Deployment cutover (manual, not done by this branch)

Update after approval (read-only check of the VM, 2026-11-15): v1 is no longer deployed.
`/mnt/data/secret-share-tool` does not exist and no container is running. Only the nginx
vhost is left, and it already passes `X-Forwarded-For` and `X-Forwarded-Proto`. So this is a
fresh deployment, not a migration, and there is no v1 database on the VM to destroy.

Merging to `main` triggers the deploy job, which will fail until the directory exists. In
order:

1. Restore the DNS record for `secrets.sujaya.dev` (F12) and check the certificate is still
   valid (`certbot certificates`).
2. Create the Auth0 application and add the production callback and logout URLs.
3. Clone the repository to `/mnt/data/secret-share-tool` and write a `.env` with the
   `OIDC_*` values and `ENVIRONMENT=production`.
4. Create `data/` and `chown` it to the container's user ID (10001), since the container no
   longer runs as root.
5. Any v1 `data/app.db` kept elsewhere (the dev machine has one) still holds every v1
   secret in decryptable form (F1). Delete it.

---

## 11. Decisions I need from you

| # | Question | My recommendation |
|---|---|---|
| D1 | Include the HKDF claim token (section 3)? | Yes. |
| D2 | Fonts: self-host the two font families in `app/static/fonts/` (I would download the open-licensed files, about 150 KB), or switch to system fonts (no files, slightly different look)? | Self-host. |
| D3 | Commit `docs/DESIGN-v2.md` to the public repo? `docs/` and `CLAUDE.md` are gitignored today. | Commit this one file; leave CLAUDE.md local as it is now. |
| D4 | Run the container as a non-root user? Needs one `chown` on the VM at cutover. | Yes. |
| D5 | The demo domain does not resolve. Keep the "Live demo" link in the README? | Keep it only if you plan to restore DNS. |

---

## 12. What changed during the build

- **Found by the browser test, not by the audit:** opening the full link while already on
  the secret page only changes the URL fragment. Browsers do not reload for that, so the
  script that strips the key did not run and the key stayed in the address bar. `secret.js`
  now also handles `hashchange`.
- **Client address:** the design said to pass `--proxy-headers` to uvicorn. Uvicorn's
  trust-everything mode takes the *first* `X-Forwarded-For` entry, which the client
  controls. The app instead reads the *last* entry itself when `TRUSTED_PROXY_HOPS=1`.
- **Token endpoint authentication:** the client secret goes in the form body when the
  provider lists `client_secret_post`, otherwise HTTP Basic, which is what the OIDC spec
  says to assume.
- **Not built:** nothing in the section 9 checklist was dropped. The Docker image has not
  been built, because Docker is not installed on the development machine; CI's
  `docker-build` job is the first check of the Dockerfile.

## 13. Sources and things I could not confirm

| Claim | Source | Status |
|---|---|---|
| Findings marked "Measured" | Test client script and `pip-audit` run on 2026-11-15 against `1de9a12` | Confirmed |
| A redirect without a fragment inherits the original one | RFC 9110 section 10.2.2 | Confirmed, quoted in section 4 |
| AES-GCM: 96-bit IV recommended, 128-bit default tag; WebCrypto needs a secure context; `http://localhost` counts as one | MDN: AesGcmParams, SubtleCrypto.encrypt, Secure Contexts | Confirmed |
| `sessionStorage` is per tab and per origin | MDN: Window.sessionStorage | Confirmed |
| `sessionStorage` survives a same-tab visit to another origin and back | Tested 2026-11-15 in a Chromium-based browser with `tests/mock_idp.py` (app on :8000, provider on :9000) | Confirmed in that browser. Not tested in Firefox or Safari |
| Auth0 discovery URL, Regular Web App, Allowed Callback/Logout URLs, `/oidc/logout` parameters | auth0.com/docs (discovery, auth code flow, logout pages) | Confirmed |
| Auth0 issuer has a trailing slash | Auth0 docs show both forms | **Not confirmed. Design does not depend on it** |
| Auth0 lets an unverified database user log in with `email_verified: false` | Pages read do not cover it | **Not confirmed. The fix is correct either way** |
| Auth0 accepts PKCE from a Regular Web App | Auth0's PKCE page only discusses public clients | **Not confirmed against Auth0.** PKCE is implemented and verified against the mock provider, which enforces it |
| Auth0 signs ID tokens with RS256 by default | Docs show RS256 as a setting, not as the default | **Not confirmed. Check the application's Advanced Settings** |
| Production sends `http://` redirects (F19) | Reproduced in the test client only | **Not confirmed in production: the domain does not resolve** |
| nginx forwards client IP and scheme | Read the vhost over SSH on 2026-11-15, after the owner gave access | Confirmed: both headers are set |
| ssh-action v1.2.0 commit | `git ls-remote` on 2026-11-15 | Confirmed |
