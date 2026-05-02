"""Кейс random_lib_for_crypto: безопасные аналоги из vulnerable.py.

Каждая функция решает ту же задачу, что в vulnerable.py, но через
secrets / os.urandom / random.SystemRandom. Линтер не должен выдавать
ни одного срабатывания на этом файле.
"""

import os
import secrets
import random as _r


ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def generate_session_token() -> str:
    # SAFE: secrets.choice — криптостойкий выбор
    token = "".join(secrets.choice(ALPHABET) for _ in range(32))
    return token


def generate_reset_token() -> int:
    # SAFE: secrets.randbelow для диапазона [10**15, 10**16)
    reset_token = 10**15 + secrets.randbelow(10**16 - 10**15)
    return reset_token


def make_iv() -> bytes:
    # SAFE: secrets.token_bytes возвращает криптостойкие случайные байты
    iv = secrets.token_bytes(16)
    return iv


def make_password_salt() -> bytes:
    # SAFE: secrets.token_bytes — корректный способ сгенерировать соль
    salt = secrets.token_bytes(16)
    return salt


def make_nonce_with_alias() -> bytes:
    # SAFE: os.urandom напрямую
    nonce = os.urandom(12)
    return nonce


def pick_greeting() -> str:
    # SAFE: random.SystemRandom() — обёртка над os.urandom; даже для
    # некрипто-выбора её использование считается безопасным.
    rng = _r.SystemRandom()
    greeting = rng.choice(["hi", "hello", "hey"])
    return greeting
