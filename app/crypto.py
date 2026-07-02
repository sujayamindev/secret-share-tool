"""
Symmetric encryption for the secret payload before it touches SQLite.

Why Fernet specifically: it's the `cryptography` library's recommended
high-level recipe — AES-128 in CBC mode + HMAC for authentication, bundled
with a timestamp and base64 encoding, all handled for you. For a project
this size, reaching for raw AES primitives yourself is the kind of thing
that's easy to get subtly wrong (IV reuse, missing authentication, etc.).
Fernet exists specifically so app developers don't roll their own crypto.
"""
from cryptography.fernet import Fernet
from app.config import get_settings

settings = get_settings()
_fernet = Fernet(settings.FERNET_KEY.encode())


def encrypt(plaintext: str) -> str:
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    return _fernet.decrypt(ciphertext.encode()).decode()
