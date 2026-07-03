"""
Integration tests for GET /secret/{secret_id} (view_secret): the one-time-view
guarantee, expiry, and allowlist enforcement at the HTTP layer. Auth is faked
by inserting a UserSession row directly and sending its cookie — the real
Asgardeo OIDC exchange is out of scope here, this tests our own claim logic.
"""
import threading

from app.models import Secret
from tests.conftest import make_secret, make_authenticated_cookie


def test_unauthenticated_request_redirects_to_login(client, db):
    secret = make_secret(db)
    resp = client.get(f"/secret/{secret.id}", follow_redirects=False)
    assert resp.status_code in (302, 307)
    assert "/auth/login" in resp.headers["location"]


def test_first_view_reveals_plaintext_then_second_view_is_gone(client, db):
    secret = make_secret(db, payload="top-secret-value")
    cookie = make_authenticated_cookie(db)

    first = client.get(f"/secret/{secret.id}", cookies=cookie)
    assert first.status_code == 200
    assert "top-secret-value" in first.text

    second = client.get(f"/secret/{secret.id}", cookies=cookie)
    assert second.status_code == 404

    db.refresh(secret)
    assert secret.viewed is True


def test_expired_secret_is_gone_even_though_unviewed(client, db):
    secret = make_secret(db, expires_in_minutes=-5)
    cookie = make_authenticated_cookie(db)

    resp = client.get(f"/secret/{secret.id}", cookies=cookie)

    assert resp.status_code == 404
    db.refresh(secret)
    assert secret.viewed is False


def test_allowlisted_secret_rejects_unlisted_viewer(client, db):
    secret = make_secret(db, allowed_emails="allowed@example.com")
    cookie = make_authenticated_cookie(db, email="someone-else@example.com")

    resp = client.get(f"/secret/{secret.id}", cookies=cookie)

    assert resp.status_code == 403
    db.refresh(secret)
    assert secret.viewed is False  # rejected before the atomic claim, not consumed


def test_allowlisted_secret_permits_listed_viewer_case_insensitively(client, db):
    secret = make_secret(db, allowed_emails="allowed@example.com", payload="only-for-allowed")
    cookie = make_authenticated_cookie(db, email="Allowed@Example.com")

    resp = client.get(f"/secret/{secret.id}", cookies=cookie)

    assert resp.status_code == 200
    assert "only-for-allowed" in resp.text


def test_two_concurrent_views_only_one_reveals_the_secret(client, db):
    """The actual race the atomic `UPDATE ... WHERE viewed = 0` guards
    against: two requests for the same link, dispatched as close to
    simultaneously as possible from two real OS threads (see the `client`
    fixture docstring for why a fresh TestClient portal per call matters
    here), must not both be able to decrypt and return the secret."""
    secret = make_secret(db, payload="only-once")
    cookie = make_authenticated_cookie(db)

    results = [None, None]
    barrier = threading.Barrier(2)

    def fire(index):
        barrier.wait()
        results[index] = client.get(f"/secret/{secret.id}", cookies=cookie)

    threads = [threading.Thread(target=fire, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    statuses = sorted(r.status_code for r in results)
    assert statuses == [200, 404]

    winner = next(r for r in results if r.status_code == 200)
    assert "only-once" in winner.text

    db.expire_all()
    persisted = db.get(Secret, secret.id)
    assert persisted.viewed is True
    assert persisted.viewed_by_sub is not None
    assert persisted.viewed_at is not None
