"""jwt_misuse: опасные конфигурации при выпуске и проверке JWT (CWE-327, CWE-347).

Покрывает обе формы misuse'а одной семьи «токен принимается без валидной
подписи»:

- ``algorithm='none'`` / ``algorithms=['none']`` — выпуск или приём токена
  без подписи. Заголовок токена позволяет атакующему подделать любой payload,
  и при ``alg=none`` подпись не проверяется (CWE-327: использование сломанного
  алгоритма; CWE-347: отсутствие проверки подписи).
- ``options={'verify_*': False}`` — отключение проверки сигнатуры или
  стандартных claim-ов (audience, expiration, issued-at, not-before, issuer).
  Подпись или относящиеся к ней проверки игнорируются (CWE-347).

Сценарии распределены по трём формам импорта (``import jwt``,
``from jwt import encode/decode``, ``import jwt as j``), чтобы правило
тестировалось на alias-mapping. Восемь сценариев — четыре по ветви alg=none
и четыре по ветви verify_*=False.
"""
import jwt
from jwt import encode, decode
import jwt as j


PAYLOAD = {"sub": "user-1", "aud": "service-x"}
SECRET = b"x" * 32


def issue_alg_none_kwarg(payload: dict) -> str:
    # VULN: encode с algorithm='none' — токен выпускается без подписи (CWE-327, CWE-347)
    return jwt.encode(payload, key=None, algorithm="none")


def issue_alg_none_uppercase(payload: dict) -> str:
    # VULN: 'NONE' в любом регистре эквивалентен 'none' для PyJWT (нормализуется к нижнему)
    return encode(payload, key=None, algorithm="NONE")


def verify_accepts_none_in_list(token: str) -> dict:
    # VULN: 'none' в списке algorithms — атакующий подсунет токен без подписи (CWE-347)
    return jwt.decode(token, key="", algorithms=["HS256", "none"])


def verify_accepts_none_aliased(token: str) -> dict:
    # VULN: тот же сценарий через алиас импорта `import jwt as j`
    return j.decode(token, key="", algorithms=["none", "HS256"])


def verify_signature_off(token: str) -> dict:
    # VULN: verify_signature=False — подпись не проверяется вовсе (CWE-347)
    return jwt.decode(token, options={"verify_signature": False})


def verify_aud_off(token: str, secret: bytes) -> dict:
    # VULN: verify_aud=False — claim audience игнорируется (cross-tenant attack)
    return decode(
        token, key=secret, algorithms=["HS256"], options={"verify_aud": False}
    )


def verify_exp_off(token: str, secret: bytes) -> dict:
    # VULN: verify_exp=False — claim expiration игнорируется (replay-атаки)
    return jwt.decode(
        token, key=secret, algorithms=["HS256"], options={"verify_exp": False}
    )


def verify_signature_and_aud_off(token: str, secret: bytes) -> dict:
    # VULN: несколько verify_* ключей off в одном dict — одно срабатывание со списком ключей
    return jwt.decode(
        token,
        key=secret,
        algorithms=["HS256"],
        options={"verify_signature": False, "verify_aud": False},
    )
