"""CRYPTO008 — deprecated or insecure TLS/SSL protocol constants.

Кейс: ``corpus/tls_old_protocol_constant/``. Правило ищет создание
``ssl.SSLContext`` с устаревшими protocol-константами stdlib ``ssl``:
``PROTOCOL_TLSv1``, ``PROTOCOL_TLSv1_1``, ``PROTOCOL_SSLv23``,
``PROTOCOL_SSLv3`` и дополнительно ``PROTOCOL_SSLv2``.

Эти значения не должны использоваться в новом коде: TLS 1.0 и TLS 1.1
deprecated по RFC 8996, SSLv3 небезопасен после POODLE, а
``PROTOCOL_SSLv23`` является legacy-константой с устаревшим именем. Вместо
них следует создавать клиентский или серверный контекст через
``PROTOCOL_TLS_CLIENT`` / ``PROTOCOL_TLS_SERVER`` и явно задавать
``minimum_version``.

Поддержанные формы:

- ``import ssl`` и ``ssl.SSLContext(ssl.PROTOCOL_TLSv1)``;
- ``import ssl as s`` и ``s.SSLContext(s.PROTOCOL_TLSv1_1)``;
- ``from ssl import SSLContext, PROTOCOL_SSLv23`` и
  ``SSLContext(PROTOCOL_SSLv23)``;
- те же прямые импорты с алиасами.

Что НЕ ловится в MVP:

- protocol-константа, предварительно записанная в переменную;
- сборка аргументов через dataflow;
- вызовы wrapper-функций вокруг ``SSLContext``.

Без потокового анализа такие случаи нельзя отличить от безопасной
конфигурации без риска FP, поэтому правило намеренно остаётся узким.
"""

from __future__ import annotations

import ast

from linter.core import BaseRule, Finding
from linter.rules import register

_SSL_MODULE = "ssl"
_SSL_CONTEXT = "SSLContext"

DANGEROUS_PROTOCOLS: frozenset[str] = frozenset(
    {
        "PROTOCOL_TLSv1",
        "PROTOCOL_TLSv1_1",
        "PROTOCOL_SSLv23",
        "PROTOCOL_SSLv3",
        "PROTOCOL_SSLv2",
    }
)


@register
class TlsOldProtocolConstantRule(BaseRule):
    """Правило CRYPTO008 — legacy TLS/SSL protocol constants in SSLContext."""

    rule_id = "CRYPTO008"
    severity = "high"
    message = "Use of deprecated or insecure TLS/SSL protocol constant in SSLContext"

    @staticmethod
    def _collect_imports(tree: ast.AST) -> tuple[set[str], set[str], dict[str, str]]:
        """Собрать локальные имена stdlib ``ssl``.

        Возвращает ``(ssl_module_aliases, ssl_context_aliases, protocol_aliases)``:

        - ``ssl_module_aliases`` — имена после ``import ssl [as ...]``;
        - ``ssl_context_aliases`` — имена после
          ``from ssl import SSLContext [as ...]``;
        - ``protocol_aliases`` — локальное имя опасной protocol-константы
          после прямого импорта, отображённое в оригинальное имя константы.
        """
        ssl_module_aliases: set[str] = set()
        ssl_context_aliases: set[str] = set()
        protocol_aliases: dict[str, str] = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == _SSL_MODULE:
                        ssl_module_aliases.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level != 0 or node.module != _SSL_MODULE:
                    continue
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    if alias.name == _SSL_CONTEXT:
                        ssl_context_aliases.add(local_name)
                    elif alias.name in DANGEROUS_PROTOCOLS:
                        protocol_aliases[local_name] = alias.name

        return ssl_module_aliases, ssl_context_aliases, protocol_aliases

    @staticmethod
    def _is_ssl_context_call(
        call: ast.Call,
        ssl_module_aliases: set[str],
        ssl_context_aliases: set[str],
    ) -> bool:
        """True, если ``call`` создаёт stdlib ``ssl.SSLContext``."""
        func = call.func

        if (
            isinstance(func, ast.Attribute)
            and func.attr == _SSL_CONTEXT
            and isinstance(func.value, ast.Name)
            and func.value.id in ssl_module_aliases
        ):
            return True

        return isinstance(func, ast.Name) and func.id in ssl_context_aliases

    @staticmethod
    def _protocol_arg(call: ast.Call) -> ast.expr | None:
        """Извлечь protocol-аргумент из ``SSLContext``.

        Основная форма в корпусе — первый позиционный аргумент. Keyword
        ``protocol=...`` тоже поддержан, потому что это тот же параметр
        конструктора и не требует dataflow.
        """
        if call.args:
            return call.args[0]
        for kw in call.keywords:
            if kw.arg == "protocol":
                return kw.value
        return None

    @staticmethod
    def _dangerous_protocol_name(
        node: ast.expr | None,
        ssl_module_aliases: set[str],
        protocol_aliases: dict[str, str],
    ) -> str | None:
        """Вернуть имя опасной protocol-константы или ``None``."""
        if (
            isinstance(node, ast.Attribute)
            and node.attr in DANGEROUS_PROTOCOLS
            and isinstance(node.value, ast.Name)
            and node.value.id in ssl_module_aliases
        ):
            return node.attr

        if isinstance(node, ast.Name):
            return protocol_aliases.get(node.id)

        return None

    @staticmethod
    def _build_message(protocol: str) -> str:
        return (
            "Use of deprecated or insecure TLS/SSL protocol constant in "
            f"SSLContext: {protocol}."
        )

    @staticmethod
    def _build_suggestion() -> str:
        return (
            "use `ssl.PROTOCOL_TLS_CLIENT` or `ssl.PROTOCOL_TLS_SERVER` and "
            "set `context.minimum_version` to `ssl.TLSVersion.TLSv1_2` or "
            "`ssl.TLSVersion.TLSv1_3`"
        )

    def check(self, tree: ast.AST, source: str, filename: str) -> list[Finding]:
        ssl_aliases, context_aliases, protocol_aliases = self._collect_imports(tree)
        if not (ssl_aliases or context_aliases):
            return []

        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not self._is_ssl_context_call(node, ssl_aliases, context_aliases):
                continue

            protocol_node = self._protocol_arg(node)
            protocol = self._dangerous_protocol_name(
                protocol_node,
                ssl_aliases,
                protocol_aliases,
            )
            if protocol is None:
                continue

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=self._build_message(protocol),
                    filename=filename,
                    line=getattr(protocol_node, "lineno", node.lineno),
                    col=getattr(protocol_node, "col_offset", node.col_offset),
                    suggestion=self._build_suggestion(),
                )
            )

        return findings
