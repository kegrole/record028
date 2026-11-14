"""Content-based nonce and hash comparison helpers."""

import base64
import hashlib


HASH_ALGORITHMS = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


def _as_bytes(value):
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8")


def content_digest(script_text, algorithm):
    """Return the unpadded standard Base64 digest of script content."""
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError("Unsupported hash algorithm: {}".format(algorithm))
    digest = HASH_ALGORITHMS[algorithm](_as_bytes(script_text)).digest()
    return base64.b64encode(digest).decode("ascii").rstrip("=")


def hash_matches(script_text, algorithm, expected_value):
    """Compare a script's digest with the declared CSP hash value."""
    if not expected_value:
        return False
    try:
        actual_value = content_digest(script_text, algorithm)
    except (TypeError, ValueError):
        return False
    return actual_value == expected_value


def nonce_matches(actual_nonce, declared_nonce):
    """Perform an exact byte comparison; prefixes are intentionally rejected."""
    if actual_nonce is None or not declared_nonce:
        return False
    return _as_bytes(actual_nonce) == _as_bytes(declared_nonce)
