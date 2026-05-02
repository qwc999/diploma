"""bcrypt_low_rounds: bcrypt with a weak password-hashing cost factor."""

import bcrypt
import bcrypt as bc
from bcrypt import gensalt
from bcrypt import gensalt as gs


def hash_password_with_rounds_4(password: bytes) -> bytes:
    # VULN: rounds=4 is far below the accepted minimum for password hashing.
    return bcrypt.hashpw(password, bcrypt.gensalt(rounds=4))


def hash_password_with_alias_rounds_8(password: bytes) -> bytes:
    # VULN: rounds=8 is too cheap for bcrypt password hashing.
    return bc.hashpw(password, bc.gensalt(rounds=8))


def hash_password_with_imported_gensalt_rounds_10(password: bytes) -> bytes:
    # VULN: rounds=10 is below the project minimum of 12.
    return bcrypt.hashpw(password, gensalt(rounds=10))


def hash_password_with_imported_alias_rounds_11(password: bytes) -> bytes:
    # VULN: rounds=11 is still below the project minimum of 12.
    return bcrypt.hashpw(password, gs(rounds=11))
