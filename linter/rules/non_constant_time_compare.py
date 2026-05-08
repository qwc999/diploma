"""CRYPTO006 — обычное сравнение криптографических значений.

Кейс: ``corpus/non_constant_time_compare/``. Класс кейса — продвинутый:
Bandit 1.9.4 и Semgrep 1.161.0 с локальным open-source набором
``semgrep-rules/python`` пропускают все ожидаемые строки.

Что считается уязвимым:
1. Простое сравнение ``a == b``.
2. Простое сравнение ``a != b``.

Оба операнда должны быть статически видимыми именами: ``ast.Name`` или
``ast.Attribute``. Хотя бы одно имя должно содержать чувствительный
криптографический сегмент: ``token``, ``signature``, ``mac``, ``hmac``,
``digest``, ``hash``, ``password_hash`` и т.п. Сегментация повторяет подход
``linter.context.detect_crypto_name``: ``expected_signature`` матчится по
``signature``, ``password_hash`` — по полному имени или по сегментам.

Почему это опасно: обычное сравнение строк/байтов может завершаться быстрее
или медленнее в зависимости от позиции первого отличающегося байта. Для
MAC, HMAC, подписей, токенов и password hash это создаёт timing side-channel
(CWE-208). Безопасные альтернативы — ``hmac.compare_digest`` и
``secrets.compare_digest``.

Что НЕ ловится в MVP:
- цепочки сравнений вроде ``a == b == c``;
- сравнения результата вызова функции, например ``get_token() == expected``;
- dataflow: ``x = token; x == expected_token``;
- сложные выражения и subscripts, если имя значения не видно как
  ``Name``/``Attribute``;
- кастомные wrapper-функции поверх ``compare_digest``.

Severity всегда ``high``: если сравнение криптографического значения уже
видно по имени, обычный оператор сравнения является прямым нарушением.
"""

from __future__ import annotations

import ast
import re

from linter.context import CRYPTO_NAMES
from linter.core import BaseRule, Finding
from linter.rules import register

SENSITIVE_COMPARE_NAMES: frozenset[str] = CRYPTO_NAMES.union(
    {
        "signature",
        "sig",
        "mac",
        "hmac",
        "digest",
        "hash",
        "password_hash",
    }
)

_SENSITIVE_COMPARE_NAMES_GLUED: frozenset[str] = frozenset(
    name.replace("_", "") for name in SENSITIVE_COMPARE_NAMES if "_" in name
)

_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def _detect_sensitive_compare_name(name: str | None) -> str | None:
    """Вернуть чувствительный токен из имени или ``None``.

    Это локальный аналог ``detect_crypto_name`` с дополнительными словами,
    специфичными для сравнения MAC/подписей/хешей. Глобальный
    ``CRYPTO_NAMES`` не расширяется, чтобы не менять поведение CRYPTO001.
    """
    if not name:
        return None

    lower = name.lower()
    if lower in SENSITIVE_COMPARE_NAMES:
        return lower
    if lower in _SENSITIVE_COMPARE_NAMES_GLUED:
        for original in SENSITIVE_COMPARE_NAMES:
            if original.replace("_", "") == lower:
                return original

    parts = [p for p in _SPLIT_RE.split(lower) if p]
    for part in parts:
        if part in SENSITIVE_COMPARE_NAMES:
            return part
        if part in _SENSITIVE_COMPARE_NAMES_GLUED:
            for original in SENSITIVE_COMPARE_NAMES:
                if original.replace("_", "") == part:
                    return original
    return None


def _operand_name(node: ast.expr) -> str | None:
    """Извлечь простое имя сравниваемого значения."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _operator_symbol(op: ast.cmpop) -> str:
    if isinstance(op, ast.Eq):
        return "=="
    if isinstance(op, ast.NotEq):
        return "!="
    raise AssertionError(f"unsupported comparison operator: {type(op).__name__}")


@register
class NonConstantTimeCompareRule(BaseRule):
    """Правило CRYPTO006 — сравнение крипто-значений через == / !=."""

    rule_id = "CRYPTO006"
    severity = "high"
    message = "Cryptographic values must be compared in constant time"

    @staticmethod
    def _match_sensitive_compare(
        node: ast.Compare,
    ) -> tuple[str, str, str, str] | None:
        """Если ``node`` — опасное сравнение, вернуть детали для Finding."""
        if len(node.ops) != 1 or len(node.comparators) != 1:
            return None

        op = node.ops[0]
        if not isinstance(op, (ast.Eq, ast.NotEq)):
            return None

        left_name = _operand_name(node.left)
        right_name = _operand_name(node.comparators[0])
        if left_name is None or right_name is None:
            return None

        left_token = _detect_sensitive_compare_name(left_name)
        right_token = _detect_sensitive_compare_name(right_name)
        if left_token is None and right_token is None:
            return None

        context_name = left_name if left_token is not None else right_name
        matched_token = left_token or right_token
        return left_name, right_name, context_name, matched_token or ""

    @staticmethod
    def _build_message(
        left_name: str,
        right_name: str,
        context_name: str,
        op_symbol: str,
    ) -> str:
        return (
            f"Non-constant-time comparison of cryptographic value `{context_name}` "
            f"with `{op_symbol}` can leak timing information "
            f"({left_name} {op_symbol} {right_name})"
        )

    @staticmethod
    def _build_suggestion(op_symbol: str) -> str:
        if op_symbol == "!=":
            return (
                "use `not hmac.compare_digest(a, b)` or "
                "`not secrets.compare_digest(a, b)`"
            )
        return "use `hmac.compare_digest(a, b)` or `secrets.compare_digest(a, b)`"

    def check(self, tree: ast.AST, source: str, filename: str) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue

            match = self._match_sensitive_compare(node)
            if match is None:
                continue

            left_name, right_name, context_name, _matched_token = match
            op_symbol = _operator_symbol(node.ops[0])
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=self._build_message(
                        left_name, right_name, context_name, op_symbol
                    ),
                    filename=filename,
                    line=node.lineno,
                    col=node.col_offset,
                    suggestion=self._build_suggestion(op_symbol),
                )
            )

        return findings
