"""CRYPTO007 — hardcoded JWT signing secret in ``jwt.encode``.

Кейс: ``corpus/hardcoded_jwt_secret/``. Класс кейса — продвинутый.
Эмпирическое обоснование на финальном корпусе из 6 сценариев:

- Bandit 1.9.4 не имеет правила для PyJWT ``jwt.encode`` и полностью
  пропускает кейс: 0/6 TP, 6 FN, 0 FP.
- Semgrep 1.161.0 с локальным ``semgrep-rules`` @ ``fdc73542`` ловит
  позиционные литералы, включая alias/direct import формы, но пропускает
  kwarg ``key="..."``: 5/6 TP, 1 FN. Дополнительно смежное правило
  ``jwt-python-exposed-data`` шумит на любом ``jwt.encode``, включая
  безопасные вызовы в ``safe.py``.

Что считается уязвимым:

- ``jwt.encode(payload, "secret", algorithm="HS256")``;
- ``jwt.encode(payload, b"secret", algorithm="HS256")``;
- ``jwt.encode(payload, key="secret", algorithm="HS256")``;
- те же формы через ``import jwt as j``, ``from jwt import encode`` и
  ``from jwt import encode as e``.

Проблема не в длине секрета, а в месте хранения: строковый или bytes-литерал
попадает в исходный код, историю Git, форки, CI-логи и артефакты сборки.
Если атакующий получает такой секрет, он может выпускать валидные JWT от
имени любого пользователя (CWE-798).

Что НЕ ловится в MVP:

- секрет, записанный в переменную:
  ``secret = "hardcoded"; jwt.encode(payload, secret)``;
- f-string, конкатенация и другие выражения:
  ``jwt.encode(payload, f"{prefix}-secret")``,
  ``jwt.encode(payload, "abc" + "def")``;
- секрет в объекте конфигурации: ``settings.JWT_SECRET``;
- ``jwt.decode(...)`` — правило проверяет только выпуск токена через
  ``jwt.encode``;
- ``algorithm="none"`` — это зона CRYPTO005.

Все эти исключения требуют dataflow или отдельной семантики. MVP остаётся
AST-only и флагует только очевидный факт передачи литерала как signing key.
Severity всегда ``high``: хардкод JWT-секрета напрямую компрометирует
подпись токенов независимо от длины литерала.
"""

from __future__ import annotations

import ast

from linter.core import BaseRule, Finding
from linter.rules import register

_JWT_MODULE = "jwt"
_ENCODE_FUNC = "encode"


@register
class HardcodedJwtSecretRule(BaseRule):
    """Правило CRYPTO007 — hardcoded JWT signing secret."""

    rule_id = "CRYPTO007"
    severity = "high"
    message = "JWT signing secret is hardcoded"

    @staticmethod
    def _collect_imports(tree: ast.AST) -> tuple[set[str], set[str]]:
        """Собрать локальные имена PyJWT encode-вызовов.

        Возвращает ``(jwt_module_aliases, encode_aliases)``:

        - ``jwt_module_aliases`` — имена модуля после ``import jwt [as ...]``;
          через них ищется ``<alias>.encode(...)``.
        - ``encode_aliases`` — имена функции после
          ``from jwt import encode [as ...]``; через них ищется ``encode(...)``.

        Как и в CRYPTO005, импорты внутри функций учитываются через
        ``ast.walk``. Это приближённая модель областей видимости, достаточная
        для AST-only правила корпуса.
        """
        jwt_module_aliases: set[str] = set()
        encode_aliases: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == _JWT_MODULE:
                        jwt_module_aliases.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level != 0 or node.module != _JWT_MODULE:
                    continue
                for alias in node.names:
                    if alias.name == _ENCODE_FUNC:
                        encode_aliases.add(alias.asname or alias.name)

        return jwt_module_aliases, encode_aliases

    @staticmethod
    def _get_kwarg(call: ast.Call, name: str) -> ast.expr | None:
        """Вернуть AST-узел значения kwarg ``name`` или ``None``."""
        for kw in call.keywords:
            if kw.arg == name:
                return kw.value
        return None

    @staticmethod
    def _identify_encode_call(
        call: ast.Call,
        jwt_module_aliases: set[str],
        encode_aliases: set[str],
    ) -> bool:
        """Проверить, что ``call`` — PyJWT ``encode`` в поддержанной форме."""
        func = call.func

        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in jwt_module_aliases
            and func.attr == _ENCODE_FUNC
        ):
            return True

        return isinstance(func, ast.Name) and func.id in encode_aliases

    @staticmethod
    def _key_node(call: ast.Call) -> ast.expr | None:
        """Извлечь аргумент signing key из ``jwt.encode``.

        PyJWT принимает ключ как второй позиционный аргумент или как kwarg
        ``key=...``. Если обе формы указаны одновременно, отдаём приоритет
        kwarg — такой код всё равно невалиден для runtime, а правило должно
        не создавать два finding'а на один вызов.
        """
        key_kwarg = HardcodedJwtSecretRule._get_kwarg(call, "key")
        if key_kwarg is not None:
            return key_kwarg
        if len(call.args) >= 2:
            return call.args[1]
        return None

    @staticmethod
    def _literal_secret_kind(node: ast.expr | None) -> str | None:
        """Вернуть тип hardcoded-секрета: ``"string"`` / ``"bytes"``."""
        if not isinstance(node, ast.Constant):
            return None
        if isinstance(node.value, str):
            return "string"
        if isinstance(node.value, bytes):
            return "bytes"
        return None

    @staticmethod
    def _build_message(secret_kind: str) -> str:
        return (
            f"JWT is signed with a hardcoded {secret_kind} literal. "
            "The signing secret can leak through source control, CI logs or "
            "build artifacts (CWE-798)."
        )

    @staticmethod
    def _build_suggestion() -> str:
        return (
            "load the JWT signing secret from an environment variable, "
            "secret manager/KMS, or runtime configuration and pass that "
            "value to `jwt.encode` instead of a literal"
        )

    def check(self, tree: ast.AST, source: str, filename: str) -> list[Finding]:
        jwt_aliases, encode_aliases = self._collect_imports(tree)
        if not (jwt_aliases or encode_aliases):
            return []

        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not self._identify_encode_call(node, jwt_aliases, encode_aliases):
                continue

            secret_kind = self._literal_secret_kind(self._key_node(node))
            if secret_kind is None:
                continue

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=self._build_message(secret_kind),
                    filename=filename,
                    line=node.lineno,
                    col=node.col_offset,
                    suggestion=self._build_suggestion(),
                )
            )

        return findings
