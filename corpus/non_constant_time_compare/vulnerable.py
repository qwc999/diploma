"""Examples of non-constant-time comparisons of cryptographic values."""

import hashlib
import hmac


def verify_signature(received: bytes, expected_signature: bytes) -> bool:
    # VULN:: signature comparison through == leaks timing information.
    return received == expected_signature


def reject_wrong_token(provided_token: str, stored_token: str) -> bool:
    # VULN:: token comparison through != leaks timing information.
    return provided_token != stored_token


def verify_mac(payload: bytes, mac: bytes, key: bytes) -> bool:
    expected_mac = hmac.new(key, payload, hashlib.sha256).digest()
    # VULN:: MAC comparison through == leaks timing information.
    return mac == expected_mac


def check_password_hash(password_hash: bytes, expected_hash: bytes) -> bool:
    # VULN:: password hash comparison through == leaks timing information.
    return password_hash == expected_hash


def verify_digest(digest: bytes, expected_digest: bytes) -> bool:
    # VULN:: digest comparison through == leaks timing information.
    return digest == expected_digest


def verify_hmac(hmac_value: bytes, expected_hmac: bytes) -> bool:
    # VULN:: HMAC comparison through == leaks timing information.
    return hmac_value == expected_hmac
