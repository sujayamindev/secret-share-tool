"""
The OIDC login flow, tested against a fake provider that signs real tokens
(see conftest.FakeProvider). Each "attack" test hands the app a token or a
callback that a correct client must refuse, and checks three things: the
response is the generic failure page, no session row was created, and no
session cookie was set.
"""
import base64
import hashlib
import time
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app import auth
from app.models import UserSession, sha256_hex
from tests.conftest import (
    APP_ORIGIN,
    CLIENT_ID,
    finish_login,
    login,
    new_client,
    sign_in,
    start_login,
)

SECRET_PATH = "/secret/11111111-2222-4333-8444-555555555555"


def session_count(db) -> int:
    db.expire_all()
    return db.query(UserSession).count()


def assert_refused(response, client, db, sessions_before):
    assert response.status_code == 400
    assert "Sign-in failed" in response.text
    assert auth.SESSION_COOKIE_NAME not in client.cookies
    assert session_count(db) == sessions_before


# --- the redirect to the provider ------------------------------------------

def test_login_redirect_carries_state_nonce_pkce_and_minimal_scope(client, idp):
    params = start_login(client, SECRET_PATH)

    assert params["_location"].startswith("https://idp.test/authorize?")
    assert params["response_type"] == "code"
    assert params["client_id"] == CLIENT_ID
    assert params["redirect_uri"] == "http://localhost:8000/auth/callback"
    assert params["scope"] == "openid email"
    assert len(params["state"]) >= 32 and len(params["nonce"]) >= 32
    assert params["code_challenge_method"] == "S256"
    assert params["state"] != params["nonce"]


def test_login_redirect_ends_with_a_fragment_so_none_can_be_inherited(client, idp):
    """A browser copies the current URL's #fragment onto a redirect target that
    has none. Here a fragment is a decryption key, so the redirect to the
    provider always carries its own throwaway one."""
    assert start_login(client)["_location"].endswith("#_")


def test_login_values_are_fresh_for_every_attempt(client, idp):
    first, second = start_login(client), start_login(client)
    assert first["state"] != second["state"]
    assert first["nonce"] != second["nonce"]
    assert first["code_challenge"] != second["code_challenge"]


def test_login_cookies_are_httponly_and_lax(client, idp):
    cookies = start_login(client)["_response"].headers.get_list("set-cookie")
    assert len(cookies) == 4
    for cookie in cookies:
        assert "HttpOnly" in cookie
        assert "SameSite=lax" in cookie
        assert "Path=/" in cookie


# --- the happy path ---------------------------------------------------------

def test_successful_login_creates_session_and_returns_to_the_secret(client, idp, db):
    before = session_count(db)

    response = login(client, idp, SECRET_PATH)

    assert response.status_code == 303
    # A relative path: no scheme or host for a proxy header to get wrong.
    assert response.headers["location"] == SECRET_PATH
    assert session_count(db) == before + 1

    set_cookies = response.headers.get_list("set-cookie")
    session_cookie = next(c for c in set_cookies if c.startswith(auth.SESSION_COOKIE_NAME + "="))
    assert "HttpOnly" in session_cookie and "SameSite=lax" in session_cookie
    # The four login-attempt cookies are cleared once used.
    assert sum("Max-Age=0" in c for c in set_cookies) == 4


def test_database_stores_a_hash_of_the_session_token_not_the_token(client, idp, db):
    login(client, idp)
    token = client.cookies[auth.SESSION_COOKIE_NAME]

    assert db.get(UserSession, token) is None
    row = db.get(UserSession, sha256_hex(token))
    assert row is not None and row.sub == "user-1"


def test_pkce_verifier_sent_to_token_endpoint_matches_the_challenge(client, idp):
    params = start_login(client)
    idp.id_token = idp.mint(nonce=params["nonce"])
    finish_login(client, params["state"])

    form = parse_qs(idp.token_requests[-1].content.decode())
    verifier = form["code_verifier"][0]
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    assert expected.rstrip(b"=").decode() == params["code_challenge"]
    assert form["grant_type"] == ["authorization_code"]
    assert form["code"] == ["good-code"]


def test_client_secret_goes_in_the_form_body_when_the_provider_lists_that_method(client, idp):
    login(client, idp)
    request = idp.token_requests[-1]
    assert parse_qs(request.content.decode())["client_secret"] == ["test-client-secret"]
    assert "authorization" not in request.headers


def test_client_secret_uses_http_basic_when_post_is_not_offered(client, idp):
    idp.discovery["token_endpoint_auth_methods_supported"] = ["client_secret_basic"]
    response = login(client, idp)

    assert response.status_code == 303
    request = idp.token_requests[-1]
    assert request.headers["authorization"].startswith("Basic ")
    assert "client_secret" not in parse_qs(request.content.decode())


def test_discovery_document_is_fetched_once_and_cached(idp):
    login(new_client(), idp)
    login(new_client(), idp)
    assert idp.discovery_requests == 1


# --- forged or invalid ID tokens -------------------------------------------

_ATTACKER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _other_key():
    """A valid RSA key that the provider does not publish."""
    return _ATTACKER_KEY


TOKEN_ATTACKS = {
    "signed by a different key": lambda idp, nonce: idp.mint(nonce=nonce, key=_other_key()),
    "unknown key id": lambda idp, nonce: idp.mint(nonce=nonce, kid="not-a-published-key"),
    "alg none (unsigned)": lambda idp, nonce: idp.mint_unsigned(nonce=nonce),
    "HS256 signed with the public key": lambda idp, nonce: idp.mint_hs256_with_public_key(
        nonce=nonce),
    "issued for a different client": lambda idp, nonce: idp.mint(nonce=nonce, aud="other-app"),
    "issued by a different issuer": lambda idp, nonce: idp.mint(
        nonce=nonce, iss="https://evil.test/"),
    "issuer differs only by trailing slash": lambda idp, nonce: idp.mint(
        nonce=nonce, iss="https://idp.test"),
    "expired": lambda idp, nonce: idp.mint(nonce=nonce, exp=int(time.time()) - 3600),
    "no exp claim at all": lambda idp, nonce: idp.mint(nonce=nonce, exp=None),
    "no iat claim": lambda idp, nonce: idp.mint(nonce=nonce, iat=None),
    "no sub claim": lambda idp, nonce: idp.mint(nonce=nonce, sub=None),
    "issued in the future": lambda idp, nonce: idp.mint(nonce=nonce, iat=int(time.time()) + 3600),
    "nonce from another login": lambda idp, nonce: idp.mint(nonce="replayed-from-elsewhere"),
    "no nonce": lambda idp, nonce: idp.mint(),
    "several audiences and no azp": lambda idp, nonce: idp.mint(
        nonce=nonce, aud=[CLIENT_ID, "other-app"]),
    "azp names a different client": lambda idp, nonce: idp.mint(
        nonce=nonce, aud=[CLIENT_ID, "other-app"], azp="other-app"),
    "not a JWT": lambda idp, nonce: "this.is.garbage",
    "tampered payload": lambda idp, nonce: _swap_payload(idp, nonce),
}


def _swap_payload(idp, nonce):
    """Take a validly signed token and replace its claims with a different
    (also validly signed) token's claims — the signature no longer matches."""
    header, _payload, signature = idp.mint(nonce=nonce).split(".")
    _header, admin_payload, _sig = idp.mint(nonce=nonce, email="admin@example.com").split(".")
    return f"{header}.{admin_payload}.{signature}"


@pytest.mark.parametrize("attack", TOKEN_ATTACKS)
def test_invalid_id_token_is_refused(attack, client, idp, db):
    before = session_count(db)
    params = start_login(client, SECRET_PATH)
    idp.id_token = TOKEN_ATTACKS[attack](idp, params["nonce"])

    response = finish_login(client, params["state"])

    assert_refused(response, client, db, before)


def test_expiry_allows_a_little_clock_skew(client, idp):
    """Our clock and the provider's can disagree by a few seconds."""
    params = start_login(client)
    idp.id_token = idp.mint(nonce=params["nonce"], exp=int(time.time()) - 10)
    assert finish_login(client, params["state"]).status_code == 303


def test_several_audiences_are_accepted_when_azp_is_this_client(client, idp):
    params = start_login(client)
    idp.id_token = idp.mint(nonce=params["nonce"], aud=[CLIENT_ID, "other-app"], azp=CLIENT_ID)
    assert finish_login(client, params["state"]).status_code == 303


# --- attacks on the callback itself ----------------------------------------

def test_callback_with_wrong_state_is_refused_before_contacting_the_provider(client, idp, db):
    before = session_count(db)
    params = start_login(client)
    idp.id_token = idp.mint(nonce=params["nonce"])

    response = finish_login(client, "attacker-chosen-state")

    assert_refused(response, client, db, before)
    assert idp.token_requests == []


def test_callback_without_login_cookies_is_refused(idp, db):
    """Login CSRF: an attacker sends the victim's browser straight to the
    callback with a code from the attacker's own login. The victim's browser
    has no matching state cookie, so it goes nowhere."""
    before = session_count(db)
    attacker = new_client()
    params = start_login(attacker)
    idp.id_token = idp.mint(nonce=params["nonce"], sub="attacker")

    victim = new_client()
    response = finish_login(victim, params["state"])

    assert_refused(response, victim, db, before)
    assert idp.token_requests == []


@pytest.mark.parametrize("query", [{}, {"state": "x"}, {"code": "x"}])
def test_callback_missing_parameters_is_refused(query, client, idp, db):
    before = session_count(db)
    start_login(client)
    response = client.get("/auth/callback", params=query, follow_redirects=False)
    assert_refused(response, client, db, before)


def test_callback_naming_a_different_issuer_is_refused(client, idp, db):
    """RFC 9207: a provider may say in the redirect who issued the response.
    If it names someone else, the response is not for this login."""
    before = session_count(db)
    params = start_login(client)
    idp.id_token = idp.mint(nonce=params["nonce"])

    response = client.get(
        "/auth/callback",
        params={"code": "good-code", "state": params["state"], "iss": "https://evil.test/"},
        follow_redirects=False,
    )

    assert_refused(response, client, db, before)
    assert idp.token_requests == []


def test_callback_naming_the_configured_issuer_is_accepted(client, idp):
    params = start_login(client)
    idp.id_token = idp.mint(nonce=params["nonce"])
    response = client.get(
        "/auth/callback",
        params={"code": "good-code", "state": params["state"], "iss": "https://idp.test/"},
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_provider_error_is_not_echoed_into_the_page(client, idp, db):
    before = session_count(db)
    start_login(client)
    response = client.get("/auth/callback",
                          params={"error": "<script>alert(1)</script>", "state": "x"})
    assert_refused(response, client, db, before)
    assert "alert(1)" not in response.text
    assert response.headers["content-type"].startswith("text/html")


def test_token_endpoint_failure_is_refused(client, idp, db):
    before = session_count(db)
    params = start_login(client)
    idp.token_status = 400
    assert_refused(finish_login(client, params["state"]), client, db, before)


def test_failed_login_clears_the_login_cookies(client, idp):
    params = start_login(client)
    response = finish_login(client, "wrong-state")
    cleared = [c for c in response.headers.get_list("set-cookie") if "Max-Age=0" in c]
    assert len(cleared) == 4
    assert params["state"] not in response.text


# --- discovery --------------------------------------------------------------

def test_discovery_issuer_mismatch_disables_login(client, idp, db):
    """If the discovery document says it belongs to a different issuer than
    the one configured, nothing in it can be trusted — including the URL the
    signing keys would be fetched from."""
    idp.discovery["issuer"] = "https://evil.test/"
    response = client.get("/auth/login", follow_redirects=False)

    assert response.status_code == 502
    assert "location" not in response.headers
    assert "evil.test" not in response.text


def test_discovery_issuer_trailing_slash_must_match_exactly(client, idp):
    idp.discovery["issuer"] = "https://idp.test"     # configured: https://idp.test/
    assert client.get("/auth/login", follow_redirects=False).status_code == 502


def test_discovery_missing_endpoint_disables_login(client, idp):
    del idp.discovery["jwks_uri"]
    assert client.get("/auth/login", follow_redirects=False).status_code == 502


# --- email_verified ---------------------------------------------------------

@pytest.mark.parametrize("email_verified", [False, None, "true", 1])
def test_unverified_email_is_not_recorded_on_the_session(email_verified, client, idp, db):
    """The attack: sign up at the provider as someone else's address and log
    in without confirming it. The login itself is allowed (the person did
    authenticate), but the session carries no email, so no allowlist matches.
    Only the JSON boolean `true` counts — not a missing claim, not a string."""
    response = login(client, idp, email="victim@example.com", email_verified=email_verified)

    assert response.status_code == 303
    row = db.get(UserSession, sha256_hex(client.cookies[auth.SESSION_COOKIE_NAME]))
    assert row.email is None


def test_verified_email_is_recorded_on_the_session(client, idp, db):
    login(client, idp, email="viewer@example.com", email_verified=True)
    row = db.get(UserSession, sha256_hex(client.cookies[auth.SESSION_COOKIE_NAME]))
    assert row.email == "viewer@example.com"


# --- where login may send you afterwards -----------------------------------

@pytest.mark.parametrize("candidate", [
    "https://evil.example",
    "//evil.example",
    "/\\evil.example",              # browsers read "/\" as "//"
    "/\t/evil.example",             # browsers strip tabs from URLs
    "/%5Cevil.example",
    "/auth/login",                  # would loop
    "/",
    "/secret/not-a-uuid",
    "/secret/11111111-2222-4333-8444-555555555555/../../x",
    "/secret/11111111-2222-4333-8444-555555555555?x=//evil.example",
    "/secret/11111111-2222-4333-8444-555555555555\n",
    "",
    None,
])
def test_safe_next_rejects_everything_but_a_secret_path(candidate):
    assert auth.safe_next(candidate) == "/"


def test_safe_next_accepts_a_secret_path():
    assert auth.safe_next(SECRET_PATH) == SECRET_PATH


def test_open_redirect_attempt_lands_on_the_home_page(client, idp):
    response = login(client, idp, "/\\evil.example")
    assert response.headers["location"] == "/"


def test_tampered_next_cookie_cannot_redirect_off_site(client, idp):
    params = start_login(client, SECRET_PATH)
    client.cookies.set(auth.NEXT_COOKIE, "https://evil.example")
    idp.id_token = idp.mint(nonce=params["nonce"])
    assert finish_login(client, params["state"]).headers["location"] == "/"


# --- sessions and logout ----------------------------------------------------

def _is_signed_in(client) -> bool:
    page = client.get(SECRET_PATH)
    return 'data-authenticated="true"' in page.text


def test_session_cookie_signs_the_browser_in(client, db):
    assert not _is_signed_in(client)
    sign_in(client, db)
    assert _is_signed_in(client)


def test_expired_session_is_not_signed_in(client, db):
    sign_in(client, db, expires_in_minutes=-1)
    assert not _is_signed_in(client)


def test_made_up_session_cookie_is_not_signed_in(client):
    client.cookies.set(auth.SESSION_COOKIE_NAME, "guessed-value")
    assert not _is_signed_in(client)


def test_logout_revokes_the_session_server_side(client, db):
    """The point of an opaque server-side session: a copy of the cookie taken
    before logout stops working, because the row it pointed to is gone."""
    token = sign_in(client, db)
    stolen_copy = new_client()
    stolen_copy.cookies.set(auth.SESSION_COOKIE_NAME, token)
    assert _is_signed_in(stolen_copy)

    response = client.post("/auth/logout", json={})

    assert response.status_code == 200
    assert response.json() == {"redirect": "/"}
    assert "Max-Age=0" in response.headers["set-cookie"]
    db.expire_all()
    assert db.get(UserSession, sha256_hex(token)) is None
    assert not _is_signed_in(stolen_copy)


def test_logout_sends_the_browser_to_the_providers_end_session_endpoint(client, idp, db):
    idp.discovery["end_session_endpoint"] = "https://idp.test/oidc/logout"
    sign_in(client, db)

    target = urlsplit(client.post("/auth/logout", json={}).json()["redirect"])

    assert f"{target.scheme}://{target.netloc}{target.path}" == "https://idp.test/oidc/logout"
    query = parse_qs(target.query)
    assert query["client_id"] == [CLIENT_ID]
    assert query["post_logout_redirect_uri"] == [APP_ORIGIN + "/"]


def test_logout_refuses_cross_site_requests(client, db):
    token = sign_in(client, db)

    assert client.post("/auth/logout", json={},
                       headers={"origin": "https://evil.example"}).status_code == 403
    assert client.post("/auth/logout", data={"x": "y"}).status_code == 415

    db.expire_all()
    assert db.get(UserSession, sha256_hex(token)) is not None


def test_logout_without_a_session_is_harmless(client):
    assert client.post("/auth/logout", json={}).status_code == 200
