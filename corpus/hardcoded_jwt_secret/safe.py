"""hardcoded_jwt_secret: safe JWT signing key sources.

The secret is supplied from runtime configuration, environment, a caller
parameter or a secret-management function. The encode calls mirror the
vulnerable import and argument forms without embedding the secret literal.
"""
import os
import jwt
from jwt import encode
from jwt import encode as e
import jwt as j


PAYLOAD = {"sub": "user-1", "role": "admin"}


class Settings:
    JWT_SECRET: str


settings = Settings()


def get_jwt_secret() -> str:
    return os.environ["JWT_SECRET"]


def get_secret_from_kms(name: str) -> bytes:
    raise NotImplementedError("secret manager client is outside the corpus")


def issue_with_env_secret(payload: dict) -> str:
    # SAFE: signing secret is read from the process environment
    secret = os.environ["JWT_SECRET"]
    return jwt.encode(payload, secret, algorithm="HS256")


def issue_with_param_secret(payload: dict, secret: str) -> str:
    # SAFE: signing secret is provided by the caller at runtime
    return jwt.encode(payload, secret, algorithm="HS256")


def issue_with_settings_secret(payload: dict) -> str:
    # SAFE: signing secret comes from application configuration
    return jwt.encode(payload, key=settings.JWT_SECRET, algorithm="HS256")


def issue_with_function_secret(payload: dict) -> str:
    # SAFE: signing secret is returned by a runtime provider function
    return j.encode(payload, key=get_jwt_secret(), algorithm="HS256")


def issue_with_from_import_secret(payload: dict, secret: str) -> str:
    # SAFE: direct function import uses a non-literal key argument
    return encode(payload, secret, algorithm="HS256")


def issue_with_kms_secret(payload: dict) -> str:
    # SAFE: bytes key comes from a secret manager instead of source code
    return e(payload, get_secret_from_kms("jwt-signing-key"), algorithm="HS256")
