"""pbkdf2_low_iterations: PBKDF2 с числом итераций ниже OWASP-минимума (CWE-916).

OWASP Password Storage Cheat Sheet (2023):
- SHA-1   → не менее 1 300 000
- SHA-256 → не менее 600 000
- SHA-512 → не менее 210 000

Severity:
- high   — итераций меньше половины порога (грубое нарушение)
- medium — итераций больше половины, но меньше порога (близко, но не достаёт)

Покрываются обе формы вызова PBKDF2:
- cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC(..., iterations=N, ...)
- hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, ...)
"""
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from hashlib import pbkdf2_hmac


def derive_pbkdf2hmac_100(password, salt):
    # VULN: 100 итераций для SHA-256 — на 4 порядка ниже OWASP-минимума 600k
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100)
    return kdf.derive(password)


def derive_pbkdf2hmac_1000(password, salt):
    # VULN: 1000 — типичное значение из старых туториалов
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=1000)
    return kdf.derive(password)


def derive_pbkdf2hmac_10k(password, salt):
    # VULN: 10 000 — старая рекомендация, в 60 раз ниже OWASP-2023
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=10_000)
    return kdf.derive(password)


def derive_pbkdf2hmac_400k_sha256(password, salt):
    # VULN: 400 000 для SHA-256 — близко к порогу 600 000, но всё ещё ниже (medium)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=400_000)
    return kdf.derive(password)


def derive_pbkdf2hmac_sha512_50k(password, salt):
    # VULN: 50 000 для SHA-512 — порог 210 000, ниже половины 105k → high
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=salt, iterations=50_000)
    return kdf.derive(password)


def derive_hashlib_sha256_100(password, salt):
    # VULN: 100 итераций через hashlib.pbkdf2_hmac (4-й позиционный аргумент)
    return hashlib.pbkdf2_hmac("sha256", password, salt, 100, dklen=32)


def derive_hashlib_sha1_100k(password, salt):
    # VULN: 100 000 для SHA-1 — порог 1 300 000, ниже половины 650k → high
    return hashlib.pbkdf2_hmac("sha1", password, salt, 100_000)


def derive_hashlib_sha512_150k(password, salt):
    # VULN: 150 000 для SHA-512 — между половиной 105k и порогом 210k → medium
    return pbkdf2_hmac("sha512", password, salt, 150_000)
