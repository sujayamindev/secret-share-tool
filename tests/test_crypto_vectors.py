"""
Known-answer tests for the browser crypto, computed independently in Python.

app/static/crypto.js is the only place a secret is encrypted, and the server
cannot check its work (it has no key). So the scheme is pinned down from two
sides against one file of fixed inputs and expected outputs,
tests/vectors/crypto_v1.json:

  - here, the `cryptography` library derives the keys and encrypts with
    standard HKDF-SHA-256 and AES-256-GCM, and must reproduce the file;
  - in tests/js/crypto.test.js, crypto.js must reproduce the same file.

If both agree with the file, the JavaScript is doing textbook HKDF + AES-GCM
and not something that merely round-trips with itself.

Regenerate the file (only if the scheme deliberately changes) with:
    python -m tests.test_crypto_vectors
"""
import base64
import json
import pathlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VECTORS_PATH = pathlib.Path(__file__).parent / "vectors" / "crypto_v1.json"

# Must match the constants at the top of app/static/crypto.js.
INFO_ENCRYPTION = b"secret-share/v1/enc"
INFO_CLAIM = b"secret-share/v1/claim"
HKDF_SALT = bytes(32)

INPUTS = [
    {"name": "ascii", "link_secret": bytes(range(32)), "iv": bytes(range(12)),
     "plaintext": "correct horse battery staple"},
    {"name": "unicode and newlines", "link_secret": bytes(range(100, 132)),
     "iv": bytes(range(50, 62)), "plaintext": "pässwörd ✓ 秘密\nline two\t<b>not html</b>"},
    {"name": "single byte", "link_secret": bytes([255] * 32), "iv": bytes([0] * 12),
     "plaintext": "x"},
]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def derive(link_secret: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=HKDF_SALT, info=info).derive(link_secret)


def compute(entry: dict) -> dict:
    encryption_key = derive(entry["link_secret"], INFO_ENCRYPTION)
    claim_token = derive(entry["link_secret"], INFO_CLAIM)
    # AESGCM.encrypt returns ciphertext || 16-byte tag, the same layout WebCrypto uses.
    ciphertext = AESGCM(encryption_key).encrypt(entry["iv"], entry["plaintext"].encode(), None)
    return {
        "name": entry["name"],
        "link_secret": b64url(entry["link_secret"]),
        "iv": b64url(entry["iv"]),
        "plaintext": entry["plaintext"],
        "ciphertext": b64url(ciphertext),
        "claim_token": b64url(claim_token),
    }


def test_python_reproduces_the_committed_vectors():
    committed = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    assert committed == [compute(entry) for entry in INPUTS]


def test_encryption_key_and_claim_token_are_different_values():
    """Key separation: what the server sees (the claim token) is not the key."""
    for entry in INPUTS:
        assert derive(entry["link_secret"], INFO_ENCRYPTION) != derive(
            entry["link_secret"], INFO_CLAIM)


def test_ciphertext_is_plaintext_length_plus_the_tag():
    """The size limit the server enforces relies on this."""
    for vector in json.loads(VECTORS_PATH.read_text(encoding="utf-8")):
        ciphertext = base64.urlsafe_b64decode(vector["ciphertext"] + "==")
        assert len(ciphertext) == len(vector["plaintext"].encode()) + 16


if __name__ == "__main__":
    VECTORS_PATH.parent.mkdir(exist_ok=True)
    VECTORS_PATH.write_text(
        json.dumps([compute(entry) for entry in INPUTS], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8", newline="\n",
    )
    print(f"wrote {VECTORS_PATH}")
