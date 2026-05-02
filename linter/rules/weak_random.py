"""CRYPTO001 — использование модуля ``random`` в криптографических целях.

Кейс: ``corpus/random_lib_for_crypto/``. Класс кейса — базовый
(аналог Bandit B311 покрывает все 6 строк vulnerable.py с FP=0).
Чем правило отличается от Bandit: контекстная severity (``high`` в
крипто-контексте, ``medium`` иначе), сообщение с упоминанием конкретного
крипто-имени, suggestion с готовой заменой по конкретной функции.

Что считается уязвимым:
1. ``random.<func>(...)``         — атрибутный доступ через имя модуля.
2. ``rnd.<func>(...)``            — то же через алиас (``import random as rnd``).
3. ``<func>(...)``                — после ``from random import <func>``.

Для каждого паттерна ``<func>`` проверяется по ``DANGEROUS_FUNCS``.

Что НЕ ловится (явно):
- ``random.SystemRandom()`` и любые методы экземпляра ``SystemRandom`` —
  это обёртка над ``os.urandom``, считается безопасной;
- ``secrets.*`` и ``os.urandom(...)`` — безопасные альтернативы;
- ``numpy.random.*``, ``random.Random(seed).<func>`` и прочие смежные сценарии —
  вне базового кейса, при необходимости заводится отдельный кейс.

Severity:
- ``high``   — результат вызова присваивается переменной с крипто-именем
              либо передаётся как аргумент функции с крипто-именем
              (см. ``linter.context.iter_crypto_name_candidates``);
- ``medium`` — иначе.
"""

from __future__ import annotations

import ast

from linter.context import (
    attach_parents,
    detect_crypto_name,
    iter_crypto_name_candidates,
)
from linter.core import BaseRule, Finding
from linter.rules import register

# Опасные функции модуля random. Источник списка — ВКР и
# ``project_linter_architecture.md``.
DANGEROUS_FUNCS: frozenset[str] = frozenset(
    {
        "random",
        "randint",
        "randrange",
        "randbytes",
        "getrandbits",
        "choice",
        "choices",
        "sample",
        "shuffle",
        "uniform",
    }
)

# Конкретные предложения замены по каждой функции. Если функции нет
# в этом словаре, выдаётся обобщённое предложение использовать ``secrets``.
SUGGESTIONS: dict[str, str] = {
    "random": "use `secrets.randbelow(N) / N` for a uniform float in [0, 1)",
    "randint": "use `a + secrets.randbelow(b - a + 1)`",
    "randrange": "use `secrets.randbelow(stop - start) + start`",
    "randbytes": "use `secrets.token_bytes(n)` or `os.urandom(n)`",
    "getrandbits": "use `secrets.randbits(k)`",
    "choice": "use `secrets.choice(seq)`",
    "choices": "use a loop over `secrets.choice(seq)` (no direct equivalent)",
    "sample": "use `secrets.SystemRandom().sample(seq, k)`",
    "shuffle": "use `secrets.SystemRandom().shuffle(seq)`",
    "uniform": "use `secrets.SystemRandom().uniform(a, b)`",
}


@register
class WeakRandomRule(BaseRule):
    """Правило CRYPTO001 — random для крипто-целей."""

    rule_id = "CRYPTO001"
    severity = "medium"
    message = "Standard `random` module is not suitable for cryptographic purposes"

    # ------------------------------------------------------------------
    # Сбор импортов
    # ------------------------------------------------------------------
    @staticmethod
    def _collect_imports(
        tree: ast.AST,
    ) -> tuple[set[str], dict[str, str]]:
        """Собрать имена, по которым в этом файле доступен модуль ``random``.

        Возвращает кортеж (module_aliases, from_imports), где:
        - ``module_aliases`` — имена, через которые виден сам модуль random,
          т.е. для ``import random`` это ``{"random"}``, для
          ``import random as rnd`` — ``{"rnd"}``;
        - ``from_imports``   — мапа ``local_name -> orig_name`` для
          ``from random import ...``: например, ``{"choice": "choice"}`` или
          ``{"c": "choice"}`` для алиаса.

        ``import`` внутри функций тоже учитывается — мы делаем ``ast.walk``
        по всему дереву. Это нестрого по областям видимости, но для линтера
        крипто-ошибок этого достаточно: альтернатива — полноценный анализ
        scope-ов, что выходит за рамки правила.
        """
        module_aliases: set[str] = set()
        from_imports: dict[str, str] = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "random":
                        module_aliases.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module == "random" and node.level == 0:
                    for alias in node.names:
                        local = alias.asname or alias.name
                        from_imports[local] = alias.name

        return module_aliases, from_imports

    # ------------------------------------------------------------------
    # Распознавание уязвимого вызова
    # ------------------------------------------------------------------
    @staticmethod
    def _match_dangerous_call(
        call: ast.Call,
        module_aliases: set[str],
        from_imports: dict[str, str],
    ) -> str | None:
        """Если вызов ``call`` — это опасная функция random, вернуть её имя.

        Иначе ``None``. Имя возвращается в каноничном виде
        (как в ``DANGEROUS_FUNCS``), без локальных алиасов — это нужно
        для подбора suggestion.
        """
        func = call.func

        # Паттерн 1/2: random.foo(...) или alias.foo(...)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.value.id in module_aliases and func.attr in DANGEROUS_FUNCS:
                return func.attr

        # Паттерн 3: foo(...) после `from random import foo` (с возможным as)
        if isinstance(func, ast.Name) and func.id in from_imports:
            orig = from_imports[func.id]
            if orig in DANGEROUS_FUNCS:
                return orig

        return None

    # ------------------------------------------------------------------
    # Контекстная severity
    # ------------------------------------------------------------------
    @staticmethod
    def _classify_context(call: ast.Call) -> tuple[str, str | None]:
        """Определить severity по окружению вызова.

        Возвращает (severity, matched_token):
        - severity == ``"high"``  — найдено крипто-имя, ``matched_token`` его содержит;
        - severity == ``"medium"`` — крипто-контекста нет, ``matched_token`` is None.
        """
        for candidate in iter_crypto_name_candidates(call):
            token = detect_crypto_name(candidate)
            if token is not None:
                return "high", candidate
        return "medium", None

    # ------------------------------------------------------------------
    # Сборка сообщения и suggestion
    # ------------------------------------------------------------------
    @staticmethod
    def _build_message(func_name: str, severity: str, context_name: str | None) -> str:
        if severity == "high" and context_name:
            return (
                f"Weak random for cryptographic purposes: value used as "
                f"`{context_name}` — `random.{func_name}` is not cryptographically secure"
            )
        return (
            f"Weak random: `random.{func_name}` is not cryptographically secure; "
            f"in a cryptographic context use `secrets` or `os.urandom` instead"
        )

    @staticmethod
    def _build_suggestion(func_name: str) -> str:
        return SUGGESTIONS.get(
            func_name,
            "use `secrets.SystemRandom()` or functions from the `secrets` module",
        )

    # ------------------------------------------------------------------
    # Главный метод
    # ------------------------------------------------------------------
    def check(self, tree: ast.AST, source: str, filename: str) -> list[Finding]:
        # Перед обходом навешиваем родителей — нужно для определения
        # крипто-контекста (см. linter/context.py).
        attach_parents(tree)

        module_aliases, from_imports = self._collect_imports(tree)
        # Если в файле нет ни одного импорта random — проверять нечего.
        if not module_aliases and not from_imports:
            return []

        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func_name = self._match_dangerous_call(
                node, module_aliases, from_imports
            )
            if func_name is None:
                continue

            severity, context_name = self._classify_context(node)
            message = self._build_message(func_name, severity, context_name)
            suggestion = self._build_suggestion(func_name)

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=severity,  # type: ignore[arg-type]
                    message=message,
                    filename=filename,
                    line=node.lineno,
                    col=node.col_offset,
                    suggestion=suggestion,
                )
            )

        return findings
