"""Safe constant-time comparison examples for cryptographic values."""

import hmac
import secrets


def verify_signature(received: bytes, expected_signature: bytes) -> bool:
    # SAFE:: compare_digest performs a constant-time comparison.
    return hmac.compare_digest(received, expected_signature)


def reject_wrong_token(provided_token: str, stored_token: str) -> bool:
    # SAFE:: invert compare_digest instead of using != directly.
    return not hmac.compare_digest(provided_token, stored_token)


def verify_mac(mac: bytes, expected_mac: bytes) -> bool:
    # SAFE:: secrets.compare_digest is also constant-time.
    return secrets.compare_digest(mac, expected_mac)


def check_password_hash(password_hash: bytes, expected_hash: bytes) -> bool:
    # SAFE:: password hashes are compared through compare_digest.
    return hmac.compare_digest(password_hash, expected_hash)


def verify_digest(digest: bytes, expected_digest: bytes) -> bool:
    # SAFE:: digest comparison uses the constant-time stdlib helper.
    return secrets.compare_digest(digest, expected_digest)


def verify_hmac(hmac_value: bytes, expected_hmac: bytes) -> bool:
    # SAFE:: HMAC comparison uses the constant-time stdlib helper.
    return hmac.compare_digest(hmac_value, expected_hmac)


def is_success_status(status: str, expected_status: str) -> bool:
    # SAFE:: ordinary business-status comparison is not cryptographic.
    return status == expected_status


def is_retry_count(count: int, expected_count: int) -> bool:
    # SAFE:: ordinary numeric comparison is not cryptographic.
    return count != expected_count
