"""
The secret lifecycle at the HTTP layer: create (ciphertext in), the page that
holds the Reveal button, and the claim (ciphertext out, row destroyed).

The server never has a key, so nothing here encrypts or decrypts. The tests
treat the ciphertext as the opaque bytes it is to the server, and check what
the server is responsible for: who may collect it, that they prove they hold
the link, that it is handed over once, and that it is then gone.
"""
import re
import threading

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from app import database, secrets_router
from app.main import app
from app.models import Secret, UserSession, sha256_hex
from app.web import humanize_minutes
from tests.conftest import (
    CIPHERTEXT,
    CLAIM_TOKEN,
    IV,
    OTHER_CLAIM_TOKEN,
    b64url,
    claim,
    login,
    make_secret,
    new_client,
    sign_in,
)

UNKNOWN_ID = "99999999-9999-4999-8999-999999999999"


def create(client, **overrides):
    body = {"ciphertext": CIPHERTEXT, "iv": IV, "claim_token": CLAIM_TOKEN, "allowed_emails": ""}
    body.update(overrides)
    return client.post("/api/secrets", json=body)


def exists(db, secret_id) -> bool:
    db.expire_all()
    return db.get(Secret, secret_id) is not None


# --- create -----------------------------------------------------------------

def test_create_stores_exactly_what_the_browser_sent(client, db):
    response = create(client, allowed_emails=" Jane@Example.com , sam@example.com")

    assert response.status_code == 201
    assert set(response.json()) == {"id", "expires_in_minutes"}
    row = db.get(Secret, response.json()["id"])
    assert row.ciphertext == CIPHERTEXT
    assert row.iv == IV
    assert row.allowed_emails == "jane@example.com,sam@example.com"


def test_create_stores_a_hash_of_the_claim_token_not_the_token(client, db):
    row = db.get(Secret, create(client).json()["id"])
    assert CLAIM_TOKEN not in (row.claim_token_hash, row.ciphertext, row.iv)
    assert len(row.claim_token_hash) == 64


@pytest.mark.parametrize("overrides, message", [
    ({"ciphertext": "not base64!!"}, "Malformed request."),
    ({"ciphertext": "abc="}, "Malformed request."),                 # padding is not accepted
    ({"iv": b64url(b"\x02" * 11)}, "Malformed request."),          # IV must be 12 bytes
    ({"iv": b64url(b"\x02" * 16)}, "Malformed request."),
    ({"claim_token": b64url(b"\x00" * 31)}, "Malformed request."),  # token must be 32 bytes
    ({"ciphertext": b64url(b"\x01" * 16)}, "Secret cannot be empty."),  # a tag and nothing else
    ({"ciphertext": b64url(b"\x01" * 100_017)}, "Secret is too large"),
    ({"allowed_emails": "good@example.com, not-an-email"}, "Not a valid email address"),
])
def test_create_rejects_malformed_input(overrides, message, client, db):
    before = db.query(Secret).count()
    response = create(client, **overrides)

    assert response.status_code == 400
    assert message in response.json()["detail"]
    assert db.query(Secret).count() == before


def test_create_accepts_the_largest_allowed_secret(client):
    assert create(client, ciphertext=b64url(b"\x01" * 100_016)).status_code == 201


def test_validation_errors_do_not_echo_the_request_back(client):
    """FastAPI's default 422 body repeats the offending input. Here that
    input could be a ciphertext or a claim token."""
    response = client.post("/api/secrets", json={"ciphertext": 12345, "claim_token": "SENTINEL"})
    assert response.status_code == 400
    assert response.json() == {"detail": "Malformed request."}


VALID_BODY = {"ciphertext": CIPHERTEXT, "iv": IV, "claim_token": CLAIM_TOKEN}


@pytest.mark.parametrize("origin", ["https://evil.example", "null", "http://localhost:8001"])
def test_create_refuses_other_origins(origin, client):
    response = client.post("/api/secrets", json=VALID_BODY, headers={"origin": origin})
    assert response.status_code == 403


def test_create_refuses_a_request_with_no_origin_header():
    bare = TestClient(app)      # no default Origin header, unlike the `client` fixture
    assert bare.post("/api/secrets", json=VALID_BODY).status_code == 403


def test_create_refuses_form_posts(client):
    """A cross-site HTML form can only send form encodings, never JSON."""
    response = client.post("/api/secrets", data={"ciphertext": CIPHERTEXT})
    assert response.status_code == 415


def test_create_is_rate_limited_per_address(client):
    limit = secrets_router.settings.CREATE_RATE_LIMIT_PER_MINUTE
    for _ in range(limit):
        assert create(client).status_code == 201

    blocked = create(client)

    assert blocked.status_code == 429
    assert blocked.headers["retry-after"] == "60"
    assert "detail" in blocked.json()


def test_create_refuses_when_the_store_is_full(client, db, monkeypatch):
    live = db.query(Secret).count()
    monkeypatch.setattr(secrets_router.settings, "MAX_LIVE_SECRETS", live + 1)

    assert create(client).status_code == 201
    assert create(client).status_code == 503


def test_expired_secrets_do_not_count_towards_the_cap(client, db, monkeypatch):
    database.purge_expired()
    live = db.query(Secret).count()
    make_secret(db, expires_in_minutes=-5)
    monkeypatch.setattr(secrets_router.settings, "MAX_LIVE_SECRETS", live + 1)
    assert create(client).status_code == 201


# --- the secret page --------------------------------------------------------

def test_secret_page_never_redirects_an_anonymous_visitor(client, db):
    """A redirect here would carry the URL's #fragment — the key — along to
    the sign-in provider. The page must load so its script can remove the
    fragment first."""
    secret = make_secret(db)
    response = client.get(f"/secret/{secret.id}", follow_redirects=False)

    assert response.status_code == 200
    assert "location" not in response.headers
    assert f'href="/auth/login?next=/secret/{secret.id}"' in response.text


def test_secret_page_is_identical_for_real_and_invented_ids(client, db):
    """No existence oracle: without logging in, nobody can tell a live ID
    from one that was never issued."""
    secret = make_secret(db)

    real = client.get(f"/secret/{secret.id}")
    fake = client.get(f"/secret/{UNKNOWN_ID}")

    assert real.status_code == fake.status_code == 200
    assert real.text.replace(secret.id, "ID") == fake.text.replace(UNKNOWN_ID, "ID")


def test_loading_the_secret_page_does_not_consume_the_secret(client, db):
    """Link scanners, prefetchers and a cross-site navigation all issue GETs.
    None of them may burn the secret."""
    secret = make_secret(db)
    sign_in(client, db)

    for _ in range(3):
        assert client.get(f"/secret/{secret.id}").status_code == 200

    assert exists(db, secret.id)


def test_secret_page_shows_who_is_signed_in(client, db):
    sign_in(client, db, email="viewer@example.com")
    page = client.get(f"/secret/{UNKNOWN_ID}").text
    assert "Signed in as viewer@example.com." in page


def test_secret_page_says_when_the_account_has_no_verified_email(client, db):
    sign_in(client, db, email=None)
    assert "no verified email address" in client.get(f"/secret/{UNKNOWN_ID}").text


@pytest.mark.parametrize("bad_id", ["x", "1234", "../etc/passwd", "<script>"])
def test_secret_page_with_a_malformed_id_is_a_plain_404(bad_id, client):
    response = client.get(f"/secret/{bad_id}")
    assert response.status_code == 404
    assert "<script>alert" not in response.text


def test_old_created_route_is_gone(client, db):
    """v1's /created/<id> answered 200 for real IDs and redirected for fake
    ones, with no login: an existence oracle."""
    secret = make_secret(db)
    assert client.get(f"/created/{secret.id}", follow_redirects=False).status_code == 404
    assert client.get(f"/created/{UNKNOWN_ID}", follow_redirects=False).status_code == 404


# --- claim ------------------------------------------------------------------

def test_claim_returns_the_ciphertext_and_deletes_the_row(client, db):
    secret = make_secret(db)
    sign_in(client, db)

    response = claim(client, secret.id)

    assert response.status_code == 200
    assert response.json() == {"ciphertext": CIPHERTEXT, "iv": IV}
    assert not exists(db, secret.id)


def test_second_claim_gets_nothing(client, db):
    secret = make_secret(db)
    sign_in(client, db)

    assert claim(client, secret.id).status_code == 200
    assert claim(client, secret.id).status_code == 404


def test_unrestricted_secret_opens_without_signing_in(client, db):
    """No allowlist: the full link is the credential, so no login is asked for."""
    secret = make_secret(db)

    response = claim(client, secret.id)

    assert response.status_code == 200
    assert response.json() == {"ciphertext": CIPHERTEXT, "iv": IV}
    assert not exists(db, secret.id)


def test_restricted_secret_asks_for_sign_in_without_consuming_it(client, db):
    secret = make_secret(db, allowed_emails="allowed@example.com")

    assert claim(client, secret.id).status_code == 401
    assert exists(db, secret.id)

    sign_in(client, db, email="allowed@example.com")
    assert claim(client, secret.id).status_code == 200


def test_anonymous_refusals_all_look_the_same(client, db):
    """Without the full link nothing is distinguishable, signed in or not:
    unknown ID, wrong token, a restricted secret with a wrong token, expired,
    used. In particular the 401 must not leak "this ID is restricted" to
    someone who has only the ID."""
    restricted = make_secret(db, allowed_emails="someone@example.com")
    plain = make_secret(db)
    expired = make_secret(db, expires_in_minutes=-5)
    used = make_secret(db)
    assert claim(client, used.id).status_code == 200

    responses = [
        claim(client, UNKNOWN_ID),
        claim(client, "not-a-uuid"),
        claim(client, plain.id, OTHER_CLAIM_TOKEN),
        claim(client, restricted.id, OTHER_CLAIM_TOKEN),
        claim(client, restricted.id, "not base64!!"),
        claim(client, expired.id),
        claim(client, used.id),
    ]

    assert {r.status_code for r in responses} == {404}
    assert len({r.text for r in responses}) == 1
    assert exists(db, plain.id) and exists(db, restricted.id)


def test_expired_restricted_secret_is_404_not_401(client, db):
    """An expired secret is gone; asking the holder to sign in would be a lie."""
    secret = make_secret(db, allowed_emails="someone@example.com", expires_in_minutes=-5)
    assert claim(client, secret.id).status_code == 404


def test_secret_page_hides_sign_out_from_anonymous_visitors(client, db):
    page = client.get(f"/secret/{UNKNOWN_ID}").text
    assert "sign-out" not in page


def test_every_refusal_looks_the_same_to_a_signed_in_caller(client, db):
    """Missing, expired, restricted to someone else, wrong claim token and
    already claimed must be indistinguishable — otherwise a stranger learns
    that a secret exists and who it is not for."""
    sign_in(client, db, email="stranger@example.com")
    expired = make_secret(db, expires_in_minutes=-5)
    restricted = make_secret(db, allowed_emails="someone-else@example.com")
    wrong_token = make_secret(db)
    used = make_secret(db)
    assert claim(client, used.id).status_code == 200

    responses = [
        claim(client, UNKNOWN_ID),
        claim(client, "not-a-uuid"),
        claim(client, expired.id),
        claim(client, restricted.id),
        claim(client, wrong_token.id, OTHER_CLAIM_TOKEN),
        claim(client, wrong_token.id, "not base64!!"),
        claim(client, used.id),
    ]

    assert {r.status_code for r in responses} == {404}
    assert len({r.text for r in responses}) == 1


def test_wrong_claim_token_does_not_burn_the_secret(client, db):
    """Knowing the ID is not enough, and a damaged link is not destructive."""
    secret = make_secret(db)
    sign_in(client, db)

    assert claim(client, secret.id, OTHER_CLAIM_TOKEN).status_code == 404
    assert exists(db, secret.id)
    assert claim(client, secret.id, CLAIM_TOKEN).status_code == 200


def test_expired_secret_cannot_be_claimed(client, db):
    secret = make_secret(db, expires_in_minutes=-5)
    sign_in(client, db)
    assert claim(client, secret.id).status_code == 404


def test_allowlisted_secret_refuses_an_unlisted_viewer_without_consuming_it(client, db):
    secret = make_secret(db, allowed_emails="allowed@example.com")
    sign_in(client, db, email="someone-else@example.com")

    assert claim(client, secret.id).status_code == 404
    assert exists(db, secret.id)


def test_allowlisted_secret_refuses_a_session_with_no_verified_email(client, db):
    secret = make_secret(db, allowed_emails="allowed@example.com")
    sign_in(client, db, email=None)

    assert claim(client, secret.id).status_code == 404
    assert exists(db, secret.id)


def test_allowlisted_secret_permits_a_listed_viewer_case_insensitively(client, db):
    secret = make_secret(db, allowed_emails="allowed@example.com")
    sign_in(client, db, email="Allowed@Example.com")
    assert claim(client, secret.id).status_code == 200


def test_unverified_email_from_a_real_login_cannot_open_an_allowlisted_secret(client, idp, db):
    """End to end: the unverified-email attack through the actual OIDC callback."""
    secret = make_secret(db, allowed_emails="victim@example.com")

    login(client, idp, email="victim@example.com", email_verified=False)

    assert claim(client, secret.id).status_code == 404
    assert exists(db, secret.id)


def test_claim_refuses_cross_site_requests(client, db):
    """CSRF: a page on another site cannot make a signed-in visitor's browser
    claim (and so destroy) a secret."""
    secret = make_secret(db)
    sign_in(client, db)

    assert claim(client, secret.id, headers={"origin": "https://evil.example"}).status_code == 403
    assert client.post(f"/api/secrets/{secret.id}/claim",
                       data={"claim_token": CLAIM_TOKEN}).status_code == 415
    assert exists(db, secret.id)


def test_claim_by_get_is_not_possible(client, db):
    secret = make_secret(db)
    sign_in(client, db)
    assert client.get(f"/api/secrets/{secret.id}/claim").status_code == 405
    assert exists(db, secret.id)


def test_two_concurrent_claims_only_one_gets_the_secret(db):
    """The race the conditional DELETE guards against: two requests for the
    same secret, released at the same instant from two real OS threads (see
    new_client's docstring for why separate clients matter here). Both pass
    every check; only one DELETE can remove the row."""
    clients = [new_client(), new_client()]
    for index, c in enumerate(clients):
        sign_in(c, db, sub=f"racer-{index}")
    # Read the ID on this thread. The two worker threads must not touch `db`
    # (a SQLAlchemy session is not thread-safe), and reading an attribute of
    # an ORM object can trigger a query on it.
    secret_id = make_secret(db).id

    results = [None, None]
    barrier = threading.Barrier(2)

    def fire(index):
        barrier.wait()
        results[index] = claim(clients[index], secret_id)

    threads = [threading.Thread(target=fire, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(r.status_code for r in results) == [200, 404]
    winner = next(r for r in results if r.status_code == 200)
    assert winner.json()["ciphertext"] == CIPHERTEXT
    assert not exists(db, secret_id)


# --- cleanup and schema -----------------------------------------------------

def test_purge_removes_expired_rows_and_keeps_live_ones(client, db):
    # IDs are read now: once a row is deleted, its ORM object can't be reloaded.
    live_id = make_secret(db).id
    dead_id = make_secret(db, expires_in_minutes=-5).id
    live_token = sign_in(new_client(), db)
    dead_token = sign_in(new_client(), db, expires_in_minutes=-5)

    secrets_removed, sessions_removed = database.purge_expired()

    assert secrets_removed >= 1 and sessions_removed >= 1
    assert exists(db, live_id) and not exists(db, dead_id)
    assert db.get(UserSession, sha256_hex(live_token)) is not None
    assert db.get(UserSession, sha256_hex(dead_token)) is None


def test_deleted_rows_are_overwritten_not_just_unlinked(db):
    assert db.execute(text("PRAGMA secure_delete")).scalar() == 1


def test_startup_refuses_a_database_from_an_older_version(tmp_path, monkeypatch):
    """v1's `secrets` table has different columns. Without this check the app
    would start and then fail on the first query."""
    old =create_engine(f"sqlite:///{(tmp_path / 'v1.db').as_posix()}")
    with old.begin() as conn:
        conn.execute(text(
            "CREATE TABLE secrets (id VARCHAR PRIMARY KEY, encrypted_payload VARCHAR, "
            "viewed BOOLEAN, expires_at DATETIME)"))
    monkeypatch.setattr(database, "engine", old)

    with pytest.raises(database.SchemaMismatchError, match="delete the database file"):
        database.verify_schema()
    old.dispose()


def test_startup_accepts_the_current_schema():
    database.verify_schema()


@pytest.mark.parametrize("minutes, words", [
    (1440, "24 hours"), (60, "1 hour"), (2880, "48 hours"),
    (4320, "3 days"), (10080, "7 days"), (90, "90 minutes"), (1, "1 minute"),
])
def test_humanize_minutes(minutes, words):
    assert humanize_minutes(minutes) == words


def test_create_page_states_the_lifetime(client):
    # The sender should know the link expires before they send it.
    # Compare text, not markup: the lifetime is wrapped in a span.
    page = re.sub(r"<[^>]+>", "", client.get("/").text)
    assert "expire after 24 hours" in page
    assert "expires in 24 hours" in page
