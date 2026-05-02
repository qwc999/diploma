"""CRYPTO002 — PBKDF2 с числом итераций ниже OWASP-минимума.

Кейс: ``corpus/pbkdf2_low_iterations/``. Класс кейса — продвинутый
(Bandit 1.9.4 и Semgrep 1.161.0 с локальным `semgrep-rules` @ fdc73542
оба пропускают все 8 сценариев — 0 TP, 8 FN). Чем правило отличается
от аналогов: численная проверка `iterations` против hash-зависимых
порогов OWASP-2023, поддержка двух форм PBKDF2 одним правилом,
двухуровневая severity по близости к порогу, конкретный suggestion
с целевым числом и упоминанием современных KDF.

Что считается уязвимым:

1. ``PBKDF2HMAC(..., algorithm=hashes.<HASH>(), ..., iterations=N, ...)``
   — форма из ``cryptography.hazmat.primitives.kdf.pbkdf2``;
   ``N`` сравнивается с порогом по фактическому ``<HASH>``.
2. ``hashlib.pbkdf2_hmac(<hash_name>, password, salt, N, ...)``
   — форма из stdlib; ``N`` берётся из 4-го позиционного аргумента
   или kwarg ``iterations``; ``<hash_name>`` — из 1-го позиционного
   аргумента-строки или kwarg ``hash_name``.

Имена импорта обрабатываются через таблицу алиасов: ``import hashlib as h``,
``from hashlib import pbkdf2_hmac as pb``, ``from cryptography.hazmat...
import PBKDF2HMAC as Kdf`` — все три случая распознаются как тот же вызов.

Пороги (OWASP Password Storage Cheat Sheet, 2023):

- SHA-1   → 1 300 000
- SHA-256 → 600 000
- SHA-512 → 210 000

Для родственных алгоритмов (SHA-224, SHA-384) используем порог родителя
по выходу: SHA-224 как SHA-256, SHA-384 как SHA-512. Если алгоритм не
распознан (вычисляется в runtime / задан переменной / пришёл с импортом
в обход словаря) — применяем самый строгий порог 1 300 000, чтобы
не пропустить нарушение.

Severity:

- ``high``   — ``iterations`` < половины порога (грубое нарушение,
              кратное отставание от стандарта).
- ``medium`` — половина порога ≤ ``iterations`` < порог (отставание
              есть, но в пределах одного порядка).

Что НЕ ловится (явно, по согласованному решению для MVP):

- ``iterations`` задан переменной, а не литералом (``Call.keywords``
  содержит ``ast.Name``/``ast.Attribute`` вместо ``ast.Constant``):
  без анализа потоков мы не отличим безопасный конфиг
  (``ITER = 600_000``) от опасного (``ITER = 100``). Срабатывание на
  «неизвестно» гарантированно даст FP в реальном коде, поэтому
  правило молчит. Расширение — отдельный кейс с потоковым анализом.
- Сторонние реализации PBKDF2 (например, ``Crypto.Protocol.KDF.PBKDF2``
  из pycryptodome) — отдельный кейс с другим набором импортов
  и сигнатурой; в текущее правило не входит.
"""

from __future__ import annotations

import ast

from linter.context import get_kwarg, literal_int
from linter.core import BaseRule, Finding
from linter.rules import register

# OWASP Password Storage Cheat Sheet (2023): минимальное число итераций
# PBKDF2 в зависимости от внутреннего hash-алгоритма. Ключи — имена,
# приведённые к нижнему регистру (как у класса PyCA `hashes.SHA256` →
# `"sha256"` и у первого аргумента `hashlib.pbkdf2_hmac("sha256", ...)`).
OWASP_MIN_ITERATIONS: dict[str, int] = {
    "sha1": 1_300_000,
    "sha224": 600_000,
    "sha256": 600_000,
    "sha384": 210_000,
    "sha512": 210_000,
}

# Самый строгий порог. Используется, когда hash-алгоритм не удалось
# распознать (нелитерал, не из словаря). Не пропускаем нарушение даже
# в неоднозначном случае — лучше ложное срабатывание high уровня
# на редкой форме, чем пропуск настоящей слабой настройки.
DEFAULT_THRESHOLD: int = max(OWASP_MIN_ITERATIONS.values())

# Полные пути модулей, по которым приходит API. Хранятся отдельно от
# имён функций/классов, чтобы при добавлении новых форм (например,
# ``Crypto.Protocol.KDF.PBKDF2``) можно было расширить таблицу,
# не трогая логику обхода.
_PYCA_MODULE = "cryptography.hazmat.primitives.kdf.pbkdf2"
_PYCA_CLASS = "PBKDF2HMAC"
_HASHLIB_MODULE = "hashlib"
_HASHLIB_FUNC = "pbkdf2_hmac"


@register
class PBKDF2IterationsRule(BaseRule):
    """Правило CRYPTO002 — слишком мало итераций PBKDF2."""

    rule_id = "CRYPTO002"
    severity = "high"
    message = "PBKDF2 with insufficient iterations"

    # ------------------------------------------------------------------
    # Сбор импортов
    # ------------------------------------------------------------------
    @staticmethod
    def _collect_imports(
        tree: ast.AST,
    ) -> tuple[set[str], set[str], set[str]]:
        """Собрать локальные имена для трёх форм импорта.

        Возвращает кортеж (pyca_aliases, hashlib_module_aliases,
        hashlib_func_aliases), где:

        - ``pyca_aliases``           — локальные имена класса
          ``PBKDF2HMAC`` после ``from cryptography.hazmat.primitives.kdf.pbkdf2
          import PBKDF2HMAC [as ...]``;
        - ``hashlib_module_aliases`` — локальные имена самого модуля
          ``hashlib`` после ``import hashlib [as ...]``;
        - ``hashlib_func_aliases``   — локальные имена функции
          ``pbkdf2_hmac`` после ``from hashlib import pbkdf2_hmac [as ...]``.

        Импорты внутри функций тоже учитываются (``ast.walk`` идёт по
        всему дереву). Это нестрого по областям видимости, но для
        линтера крипто-ошибок этого достаточно.
        """
        pyca_aliases: set[str] = set()
        hashlib_module_aliases: set[str] = set()
        hashlib_func_aliases: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == _HASHLIB_MODULE:
                        hashlib_module_aliases.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level != 0:
                    continue
                if node.module == _PYCA_MODULE:
                    for alias in node.names:
                        if alias.name == _PYCA_CLASS:
                            pyca_aliases.add(alias.asname or alias.name)
                elif node.module == _HASHLIB_MODULE:
                    for alias in node.names:
                        if alias.name == _HASHLIB_FUNC:
                            hashlib_func_aliases.add(alias.asname or alias.name)

        return pyca_aliases, hashlib_module_aliases, hashlib_func_aliases

    # ------------------------------------------------------------------
    # Извлечение значений из AST
    # ------------------------------------------------------------------
    # ``get_kwarg`` и ``literal_int`` живут в ``linter.context`` — общие
    # с CRYPTO004 (bcrypt_low_rounds). Локально остаётся только
    # ``_literal_str``: пока строковый литерал нужен только этому
    # правилу (для распознавания ``hash_name`` у hashlib.pbkdf2_hmac).

    @staticmethod
    def _literal_str(node: ast.expr | None) -> str | None:
        """Вернуть строковый литерал ``node`` или ``None``."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    # ------------------------------------------------------------------
    # Извлечение hash-алгоритма
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_pyca_hash(call: ast.Call) -> str | None:
        """Из вызова PBKDF2HMAC(...) вытащить нормализованное имя hash.

        Значение kwarg ``algorithm`` ожидается в форме
        ``hashes.SHA256()``  → ``Call(func=Attribute(attr='SHA256'))``,
        либо ``SHA256()`` после ``from cryptography.hazmat.primitives.hashes
        import SHA256`` → ``Call(func=Name(id='SHA256'))``.

        Возвращает имя класса в нижнем регистре (``"sha256"``) или
        ``None``, если ``algorithm`` задан переменной/выражением,
        результат которого статически не известен.
        """
        algo_node = get_kwarg(call, "algorithm")
        if not isinstance(algo_node, ast.Call):
            return None
        func = algo_node.func
        if isinstance(func, ast.Name):
            return func.id.lower()
        if isinstance(func, ast.Attribute):
            return func.attr.lower()
        return None

    @staticmethod
    def _extract_hashlib_hash(call: ast.Call) -> str | None:
        """Из вызова hashlib.pbkdf2_hmac(...) вытащить нормализованное имя hash.

        Сигнатура: ``pbkdf2_hmac(hash_name, password, salt, iterations,
        dklen=None)``. ``hash_name`` — строка, обычно передаётся
        позиционно. Поддерживается и kwarg-форма.
        """
        if call.args:
            value = PBKDF2IterationsRule._literal_str(call.args[0])
            if value is not None:
                return value.lower()
        kw_value = PBKDF2IterationsRule._literal_str(
            get_kwarg(call, "hash_name")
        )
        if kw_value is not None:
            return kw_value.lower()
        return None

    # ------------------------------------------------------------------
    # Извлечение значения iterations
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_pyca_iterations(call: ast.Call) -> ast.expr | None:
        """Узел значения ``iterations`` для PBKDF2HMAC. Только kwarg.

        В сигнатуре ``PBKDF2HMAC(algorithm, length, salt, iterations,
        backend=None)`` параметр позиционно стоит 4-м. На практике
        в реальном коде PBKDF2HMAC всегда зовут с keyword-аргументами
        (так показано во всех примерах PyCA), поэтому позиционную
        форму не поддерживаем — это упростило бы AST-логику ценой
        нулевой реальной выгоды.
        """
        return get_kwarg(call, "iterations")

    @staticmethod
    def _extract_hashlib_iterations(call: ast.Call) -> ast.expr | None:
        """Узел значения ``iterations`` для hashlib.pbkdf2_hmac.

        Поддерживаются обе формы: 4-й позиционный аргумент
        (как в документации stdlib) и kwarg ``iterations``.
        """
        if len(call.args) > 3:
            return call.args[3]
        return get_kwarg(call, "iterations")

    # ------------------------------------------------------------------
    # Распознавание формы вызова
    # ------------------------------------------------------------------
    @staticmethod
    def _match_form(
        call: ast.Call,
        pyca_aliases: set[str],
        hashlib_module_aliases: set[str],
        hashlib_func_aliases: set[str],
    ) -> tuple[ast.expr, str | None] | None:
        """Если вызов — PBKDF2 в одной из известных форм, вернуть
        (iterations_node, hash_name). Иначе ``None``.

        ``iterations_node`` — это AST-узел значения, ещё не литерал;
        приводится к int позже. ``hash_name`` — нормализованное имя
        алгоритма или ``None``, если статически не распознан.
        """
        func = call.func

        # Форма 1: PBKDF2HMAC(...) — после `from cryptography... import PBKDF2HMAC`.
        if isinstance(func, ast.Name) and func.id in pyca_aliases:
            iterations_node = PBKDF2IterationsRule._extract_pyca_iterations(call)
            if iterations_node is None:
                return None
            return iterations_node, PBKDF2IterationsRule._extract_pyca_hash(call)

        # Форма 2: hashlib.pbkdf2_hmac(...) — после `import hashlib [as h]`.
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in hashlib_module_aliases
            and func.attr == _HASHLIB_FUNC
        ):
            iterations_node = PBKDF2IterationsRule._extract_hashlib_iterations(call)
            if iterations_node is None:
                return None
            return iterations_node, PBKDF2IterationsRule._extract_hashlib_hash(call)

        # Форма 3: pbkdf2_hmac(...) — после `from hashlib import pbkdf2_hmac`.
        if isinstance(func, ast.Name) and func.id in hashlib_func_aliases:
            iterations_node = PBKDF2IterationsRule._extract_hashlib_iterations(call)
            if iterations_node is None:
                return None
            return iterations_node, PBKDF2IterationsRule._extract_hashlib_hash(call)

        return None

    # ------------------------------------------------------------------
    # Severity и сообщение
    # ------------------------------------------------------------------
    @staticmethod
    def _classify_severity(iterations: int, threshold: int) -> str:
        """``high``, если итераций меньше половины порога; иначе ``medium``.

        Деление целочисленное — для нечётных порогов «половина»
        округляется вниз. Это безопасно (итерации = ``threshold // 2``
        формально не «грубое нарушение», а пограничное; medium
        корректнее).
        """
        return "high" if iterations < threshold // 2 else "medium"

    @staticmethod
    def _hash_label(hash_name: str | None) -> str:
        """Человеко-читаемое имя hash: SHA-256 / SHA-512 / unknown."""
        if hash_name is None:
            return "unknown algorithm"
        # `sha256` -> `SHA-256`. Нормализуем к стилю стандарта.
        if hash_name.startswith("sha"):
            digits = hash_name[3:]
            return f"SHA-{digits}" if digits else hash_name.upper()
        return hash_name.upper()

    @staticmethod
    def _build_message(
        iterations: int, threshold: int, hash_name: str | None
    ) -> str:
        label = PBKDF2IterationsRule._hash_label(hash_name)
        if hash_name is None:
            return (
                f"PBKDF2 with insufficient iterations: {iterations} < "
                f"strictest OWASP-2023 minimum {threshold} "
                f"(hash algorithm not statically resolvable)"
            )
        return (
            f"PBKDF2 with insufficient iterations: {iterations} < "
            f"OWASP-2023 minimum {threshold} for {label}"
        )

    @staticmethod
    def _build_suggestion(threshold: int, hash_name: str | None) -> str:
        label = PBKDF2IterationsRule._hash_label(hash_name)
        prefix = f"increase iterations to at least {threshold}"
        if hash_name is not None:
            prefix += f" for {label}"
        return (
            f"{prefix} (OWASP-2023 Password Storage Cheat Sheet); "
            f"for new code prefer Argon2id (`argon2-cffi`) or scrypt "
            f"(`hashlib.scrypt`)"
        )

    # ------------------------------------------------------------------
    # Главный метод
    # ------------------------------------------------------------------
    def check(self, tree: ast.AST, source: str, filename: str) -> list[Finding]:
        pyca_aliases, hashlib_module_aliases, hashlib_func_aliases = (
            self._collect_imports(tree)
        )
        # Если в файле нет ни одного релевантного импорта — проверять нечего.
        if not (pyca_aliases or hashlib_module_aliases or hashlib_func_aliases):
            return []

        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            matched = self._match_form(
                node, pyca_aliases, hashlib_module_aliases, hashlib_func_aliases
            )
            if matched is None:
                continue
            iterations_node, hash_name = matched

            iterations = literal_int(iterations_node)
            if iterations is None:
                # Согласованное решение MVP: переменные пропускаем,
                # чтобы не плодить FP. См. модульный docstring.
                continue

            threshold = (
                OWASP_MIN_ITERATIONS.get(hash_name) if hash_name else None
            )
            if threshold is None:
                threshold = DEFAULT_THRESHOLD

            if iterations >= threshold:
                continue

            severity = self._classify_severity(iterations, threshold)
            message = self._build_message(iterations, threshold, hash_name)
            suggestion = self._build_suggestion(threshold, hash_name)

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
