"""Кейс random_lib_for_crypto: уязвимые примеры использования модуля random.

Все вызовы ниже подпадают под правило CRYPTO001. Безопасные аналоги —
в safe.py. Файл валидный Python, но запускать его не обязательно.
"""

import random
import random as rnd
from random import choice, getrandbits


ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def generate_session_token() -> str:
    # VULN: random.choice для токена аутентификации (контекст: token -> high)
    token = "".join(random.choice(ALPHABET) for _ in range(32))
    return token


def generate_reset_token() -> int:
    # VULN: random.randint для password-reset token (контекст: reset_token -> high)
    reset_token = random.randint(10**15, 10**16 - 1)
    return reset_token


def make_iv() -> bytes:
    # VULN: random.randbytes для IV блочного шифра (контекст: iv -> high)
    iv = random.randbytes(16)
    return iv


def make_password_salt() -> bytes:
    # VULN: from-import getrandbits + имя salt (контекст: salt -> high)
    salt = getrandbits(128).to_bytes(16, "big")
    return salt


def make_nonce_with_alias() -> bytes:
    # VULN: alias `import random as rnd` + имя nonce (контекст: nonce -> high)
    nonce = rnd.randbytes(12)
    return nonce


def pick_greeting() -> str:
    # VULN (medium): правило ловит `choice` из `random`, но крипто-контекста
    # нет (имя "greeting" не в словаре), поэтому severity=medium.
    greeting = choice(["hi", "hello", "hey"])
    return greeting
