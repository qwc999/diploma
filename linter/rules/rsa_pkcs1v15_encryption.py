"""CRYPTO009 - RSA encrypt/decrypt with PKCS#1 v1.5 padding.

Case: ``corpus/rsa_pkcs1v15_encryption/``. Case class: advanced.

PyCA ``cryptography`` exposes two padding families for RSA encryption:
``PKCS1v15()`` and ``OAEP(...)``. PKCS#1 v1.5 encryption padding is a legacy
construction associated with Bleichenbacher-style oracle attacks. For RSA
encryption and decryption, OAEP should be used instead. The same
``PKCS1v15()`` API is valid for RSA signatures, so this rule must distinguish
``encrypt``/``decrypt`` from ``sign``/``verify``.

What is considered vulnerable:

- ``public_key.encrypt(message, padding.PKCS1v15())``;
- ``private_key.decrypt(ciphertext, padding.PKCS1v15())``;
- the same forms through ``padding as <alias>``;
- direct imports ``from ...padding import PKCS1v15 [as <alias>]``.

What is intentionally not covered in the AST-only MVP:

- padding stored in a variable:
  ``pad = padding.PKCS1v15(); public_key.encrypt(message, pad)``;
- indirect wrapper functions around ``encrypt``/``decrypt``;
- non-PyCA RSA APIs.

Severity is always ``high``: PKCS#1 v1.5 encryption padding is a direct
cryptographic misuse in this context.
"""

from __future__ import annotations

import ast

from linter.core import BaseRule, Finding
from linter.rules import register

_ASYMMETRIC_MODULE = "cryptography.hazmat.primitives.asymmetric"
_ASYMMETRIC_PADDING_MODULE = "cryptography.hazmat.primitives.asymmetric.padding"

_PADDING_SUBMODULE = "padding"
_PKCS1V15_CLASS = "PKCS1v15"
_RSA_ENCRYPT_DECRYPT_METHODS = frozenset({"encrypt", "decrypt"})


@register
class RsaPkcs1v15EncryptionRule(BaseRule):
    """Rule CRYPTO009 - RSA encrypt/decrypt with PKCS#1 v1.5 padding."""

    rule_id = "CRYPTO009"
    severity = "high"
    message = "RSA encryption/decryption uses PKCS#1 v1.5 padding; use OAEP instead."

    @staticmethod
    def _collect_imports(tree: ast.AST) -> tuple[set[str], set[str]]:
        """Collect local names for module and direct PKCS1v15 imports.

        Returns ``(padding_aliases, pkcs1v15_aliases)``:

        - ``padding_aliases`` covers
          ``from cryptography.hazmat.primitives.asymmetric import padding``.
        - ``pkcs1v15_aliases`` covers
          ``from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15``.

        Function-local imports are included, matching the approximation used
        by CRYPTO003/CRYPTO005.
        """
        padding_aliases: set[str] = set()
        pkcs1v15_aliases: set[str] = set()

        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            if node.level != 0:
                continue

            if node.module == _ASYMMETRIC_MODULE:
                for alias in node.names:
                    if alias.name == _PADDING_SUBMODULE:
                        padding_aliases.add(alias.asname or alias.name)
            elif node.module == _ASYMMETRIC_PADDING_MODULE:
                for alias in node.names:
                    if alias.name == _PKCS1V15_CLASS:
                        pkcs1v15_aliases.add(alias.asname or alias.name)

        return padding_aliases, pkcs1v15_aliases

    @staticmethod
    def _is_encrypt_decrypt_call(call: ast.Call) -> bool:
        """True for method calls named ``encrypt`` or ``decrypt``."""
        return (
            isinstance(call.func, ast.Attribute)
            and call.func.attr in _RSA_ENCRYPT_DECRYPT_METHODS
        )

    @staticmethod
    def _is_pkcs1v15_call(
        node: ast.AST,
        padding_aliases: set[str],
        pkcs1v15_aliases: set[str],
    ) -> bool:
        """True if ``node`` is ``padding.PKCS1v15()`` or ``PKCS1v15()``."""
        if not isinstance(node, ast.Call):
            return False

        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == _PKCS1V15_CLASS
            and isinstance(func.value, ast.Name)
            and func.value.id in padding_aliases
        ):
            return True

        return isinstance(func, ast.Name) and func.id in pkcs1v15_aliases

    @staticmethod
    def _has_pkcs1v15_argument(
        call: ast.Call,
        padding_aliases: set[str],
        pkcs1v15_aliases: set[str],
    ) -> bool:
        """Check direct args and keyword values of an encrypt/decrypt call."""
        for arg in call.args:
            if RsaPkcs1v15EncryptionRule._is_pkcs1v15_call(
                arg,
                padding_aliases,
                pkcs1v15_aliases,
            ):
                return True

        for kw in call.keywords:
            if RsaPkcs1v15EncryptionRule._is_pkcs1v15_call(
                kw.value,
                padding_aliases,
                pkcs1v15_aliases,
            ):
                return True

        return False

    @staticmethod
    def _build_suggestion() -> str:
        return "Use RSA-OAEP with MGF1 and SHA-256 for encryption/decryption."

    def check(self, tree: ast.AST, source: str, filename: str) -> list[Finding]:
        padding_aliases, pkcs1v15_aliases = self._collect_imports(tree)
        if not (padding_aliases or pkcs1v15_aliases):
            return []

        findings: list[Finding] = []
        suggestion = self._build_suggestion()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not self._is_encrypt_decrypt_call(node):
                continue
            if not self._has_pkcs1v15_argument(
                node,
                padding_aliases,
                pkcs1v15_aliases,
            ):
                continue

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=self.message,
                    filename=filename,
                    line=node.lineno,
                    col=node.col_offset,
                    suggestion=suggestion,
                )
            )

        return findings
