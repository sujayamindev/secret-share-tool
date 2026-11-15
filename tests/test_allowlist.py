"""
Unit tests for the allowlist logic: parsing/validating the create-form input
(_parse_allowed_emails) and enforcing it against a viewer's verified email
(Secret.is_allowed). No DB or HTTP needed for either.
"""
import pytest

from app.models import Secret
from app.secrets_router import _parse_allowed_emails, _ValidationError


class TestParseAllowedEmails:
    def test_blank_string_means_unrestricted(self):
        assert _parse_allowed_emails("") is None

    def test_whitespace_only_string_means_unrestricted(self):
        assert _parse_allowed_emails("   \t  ") is None

    def test_single_valid_email_is_normalized(self):
        assert _parse_allowed_emails("Someone@Example.com") == "someone@example.com"

    def test_multiple_emails_mixed_case_and_whitespace(self):
        raw = "  Alice@Example.com ,  BOB@example.com  ,charlie@example.com"
        assert _parse_allowed_emails(raw) == "alice@example.com,bob@example.com,charlie@example.com"

    def test_duplicate_emails_are_deduped(self):
        raw = "a@b.com, A@B.com, a@b.com"
        assert _parse_allowed_emails(raw) == "a@b.com"

    def test_malformed_email_among_valid_ones_raises(self):
        raw = "good@example.com, not-an-email, other@example.com"
        with pytest.raises(_ValidationError) as exc_info:
            _parse_allowed_emails(raw)
        assert "not-an-email" in str(exc_info.value)

    def test_trailing_leading_and_empty_entries_are_dropped(self):
        raw = ",a@b.com,,c@d.com,"
        assert _parse_allowed_emails(raw) == "a@b.com,c@d.com"


class TestSecretIsAllowed:
    def _secret(self, allowed_emails=None):
        return Secret(ciphertext="irrelevant", iv="irrelevant", claim_token_hash="irrelevant",
                      expires_at=None, allowed_emails=allowed_emails)

    def test_no_allowlist_permits_any_email(self):
        secret = self._secret(allowed_emails=None)
        assert secret.is_allowed("anyone@example.com") is True

    def test_no_allowlist_permits_missing_email(self):
        secret = self._secret(allowed_emails=None)
        assert secret.is_allowed(None) is True

    def test_allowlist_set_rejects_missing_email(self):
        secret = self._secret(allowed_emails="a@b.com")
        assert secret.is_allowed(None) is False

    def test_allowlist_set_rejects_email_not_in_list(self):
        secret = self._secret(allowed_emails="a@b.com,c@d.com")
        assert secret.is_allowed("stranger@example.com") is False

    def test_allowlist_set_accepts_case_insensitive_match(self):
        secret = self._secret(allowed_emails="a@b.com")
        assert secret.is_allowed("A@B.COM") is True
