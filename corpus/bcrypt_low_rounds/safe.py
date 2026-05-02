"""bcrypt_low_rounds: safe bcrypt password-hashing cost factors."""

import bcrypt
import bcrypt as bc
from bcrypt import gensalt
from bcrypt import gensalt as gs


def hash_password_with_rounds_12(password: bytes) -> bytes:
    # SAFE: rounds=12 is the minimum accepted cost factor for this rule.
    return bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))


def hash_password_with_alias_rounds_14(password: bytes) -> bytes:
    # SAFE: rounds=14 is above the minimum and suitable after latency testing.
    return bc.hashpw(password, bc.gensalt(rounds=14))


def hash_password_with_imported_gensalt_rounds_12(password: bytes) -> bytes:
    # SAFE: imported gensalt with rounds=12 is accepted.
    return bcrypt.hashpw(password, gensalt(rounds=12))


def hash_password_with_imported_alias_rounds_14(password: bytes) -> bytes:
    # SAFE: imported alias with rounds=14 is accepted.
    return bcrypt.hashpw(password, gs(rounds=14))


def hash_password_with_default_rounds(password: bytes) -> bytes:
    # SAFE: bcrypt.gensalt() without explicit rounds is not flagged in the MVP.
    return bcrypt.hashpw(password, bcrypt.gensalt())
