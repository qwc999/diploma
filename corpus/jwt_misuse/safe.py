"""jwt_misuse: безопасные аналоги для vulnerable.py.

Каждая функция решает ту же задачу, что в vulnerable.py, но:

- алгоритм всегда явный и не равен 'none' (HS256/RS256/ES256);
- список ``algorithms`` для ``decode`` явный и не содержит 'none';
- ``options`` либо не передан (тогда все verify_* включены по умолчанию),
  либо все verify_* остаются True; вместо отключения проверки claim-а
  передаётся сам claim (``audience=...``, ``issuer=...``).

Линтер CRYPTO005 не должен выдавать ни одного срабатывания на этом файле.
"""
import jwt
from jwt import encode, decode
import jwt as j


PAYLOAD = {"sub": "user-1", "aud": "service-x"}
SECRET = b"x" * 32


def issue_hs256_kwarg(payload: dict, secret: bytes) -> str:
    # SAFE: HMAC-SHA256 с реальным секретом — корректный симметричный JWT
    return jwt.encode(payload, key=secret, algorithm="HS256")


def issue_rs256(payload: dict, private_pem: bytes) -> str:
    # SAFE: асимметричный RS256 через прямой импорт; явный не-'none' алгоритм
    return encode(payload, key=private_pem, algorithm="RS256")


def verify_explicit_hs256(token: str, secret: bytes) -> dict:
    # SAFE: явный список algorithms без 'none'
    return jwt.decode(token, key=secret, algorithms=["HS256"])


def verify_explicit_aliased(token: str, secret: bytes) -> dict:
    # SAFE: алиас импорта, явный список algorithms без 'none'
    return j.decode(token, key=secret, algorithms=["HS256"])


def verify_default_options(token: str, secret: bytes) -> dict:
    # SAFE: options не передан — все verify_* включены по умолчанию
    return jwt.decode(token, key=secret, algorithms=["HS256"])


def verify_with_audience(token: str, secret: bytes, audience: str) -> dict:
    # SAFE: audience передан явно вместо verify_aud=False
    return decode(token, key=secret, algorithms=["HS256"], audience=audience)


def verify_no_options(token: str, secret: bytes) -> dict:
    # SAFE: options не задан — verify_exp по умолчанию True
    return jwt.decode(token, key=secret, algorithms=["HS256"])


def verify_with_audience_and_issuer(
    token: str, secret: bytes, audience: str, issuer: str
) -> dict:
    # SAFE: явные audience и issuer — стандартные проверки выполняются
    return jwt.decode(
        token, key=secret, algorithms=["HS256"], audience=audience, issuer=issuer
    )
