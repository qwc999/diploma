"""hardcoded_jwt_secret: JWT is signed with a literal secret (CWE-798).

The scenarios cover PyJWT module imports, module aliases, direct function
imports and keyword/positional forms of the signing key.
"""
import jwt
from jwt import encode
from jwt import encode as e
import jwt as j


PAYLOAD = {"sub": "user-1", "role": "admin"}


def issue_with_short_literal(payload: dict) -> str:
    # VULN: literal JWT signing secret is stored directly in source code
    return jwt.encode(payload, "secret", algorithm="HS256")


def issue_with_default_literal(payload: dict) -> str:
    # VULN: default-looking hardcoded secret is still a real signing secret
    return jwt.encode(payload, "change_me", algorithm="HS256")


def issue_with_kwarg_literal(payload: dict) -> str:
    # VULN: keyword argument key= contains a hardcoded signing secret
    return jwt.encode(payload, key="my-app-secret", algorithm="HS256")


def issue_with_module_alias(payload: dict) -> str:
    # VULN: the same PyJWT encode call through import jwt as j
    return j.encode(payload, "this-is-a-very-secret-passphrase", algorithm="HS256")


def issue_with_from_import(payload: dict) -> str:
    # VULN: direct function import keeps the literal secret in the repository
    return encode(payload, "hardcoded-from-import", algorithm="HS256")


def issue_with_bytes_literal(payload: dict) -> str:
    # VULN: bytes literal is also a hardcoded JWT signing secret
    return e(payload, b"byte-secret", algorithm="HS256")
