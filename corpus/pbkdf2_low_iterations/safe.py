"""pbkdf2_low_iterations: безопасные значения iterations по OWASP-2023.

Соответствие vulnerable.py: восемь функций, каждая с iterations на пороге
OWASP-минимума или выше. Линтер на этом файле обязан молчать.
"""
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from hashlib import pbkdf2_hmac


def derive_pbkdf2hmac_owasp_min(password, salt):
    # SAFE: 600 000 — OWASP-минимум для SHA-256
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    return kdf.derive(password)


def derive_pbkdf2hmac_strong(password, salt):
    # SAFE: 1 000 000 — комфортный запас прочности
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=1_000_000)
    return kdf.derive(password)


def derive_pbkdf2hmac_million_two(password, salt):
    # SAFE: 1 200 000 — двукратный запас над OWASP-минимумом
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=1_200_000)
    return kdf.derive(password)


def derive_pbkdf2hmac_sha256_extra(password, salt):
    # SAFE: 800 000 для SHA-256 — выше OWASP-минимума 600k
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=800_000)
    return kdf.derive(password)


def derive_pbkdf2hmac_sha512_owasp(password, salt):
    # SAFE: 210 000 для SHA-512 — OWASP-минимум для этого алгоритма
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=salt, iterations=210_000)
    return kdf.derive(password)


def derive_hashlib_sha256_owasp(password, salt):
    # SAFE: 600 000 для SHA-256 через hashlib.pbkdf2_hmac
    return hashlib.pbkdf2_hmac("sha256", password, salt, 600_000, dklen=32)


def derive_hashlib_sha1_owasp(password, salt):
    # SAFE: 1 300 000 для SHA-1 — OWASP-минимум для устаревшего хэша
    return hashlib.pbkdf2_hmac("sha1", password, salt, 1_300_000)


def derive_hashlib_sha512_above(password, salt):
    # SAFE: 250 000 для SHA-512 — выше порога 210k
    return pbkdf2_hmac("sha512", password, salt, 250_000)
