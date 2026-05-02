"""CRYPTO003 — обнаружение AES в режиме ECB.

Кейс: ``corpus/aes_ecb_mode/``. Класс кейса — продвинутый. Эмпирическое
обоснование на расширенном корпусе (5 сценариев, две библиотеки):

- Bandit 1.9.4 ловит только PyCA Hazmat (B305) — 2 TP / 3 FN. Систематический
  пробел: B305 — это чёрный список вызовов
  ``cryptography.hazmat.primitives.ciphers.modes.ECB``, и формы pycryptodome
  (``AES.MODE_ECB`` — целочисленная константа атрибута класса) в чёрный список
  не попадают.
- Semgrep 1.161.0 с локальным `semgrep-rules` @ ``fdc73542`` не имеет правила
  про ECB ни для одной библиотеки — 0 TP / 5 FN. Полный пробел набора по
  данной теме.

Что считается уязвимым (две библиотеки, пять форм вызова):

1. PyCA Hazmat ``Cipher(algorithms.AES(key), modes.ECB(), backend=...)``
   — режим как ``<modes-alias>.ECB()`` после
   ``from cryptography.hazmat.primitives.ciphers import modes [as <alias>]``.
2. PyCA Hazmat ``Cipher(algorithms.AES(key), ECB(), backend=...)`` — режим как
   прямой вызов ``ECB()`` после
   ``from cryptography.hazmat.primitives.ciphers.modes import ECB [as <alias>]``.
3. pycryptodome ``AES.new(key, AES.MODE_ECB)`` — позиционный аргумент.
4. pycryptodome ``AES.new(key, mode=AES.MODE_ECB)`` — kwarg ``mode=``.
5. pycryptodome ``A.new(key, A.MODE_ECB)`` после
   ``from Crypto.Cipher import AES as A`` — учёт алиаса импорта.

Severity: всегда ``high``. Шкалы нет — режим ECB бинарный, промежуточного
«менее опасного» состояния не существует.

CWE-327 (Use of a Broken or Risky Cryptographic Algorithm).

Suggestion: переход на AES-GCM как AEAD-режим по умолчанию. У PyCA это
``cryptography.hazmat.primitives.ciphers.aead.AESGCM``; у pycryptodome —
``AES.new(key, AES.MODE_GCM, nonce=...)``.

Что НЕ ловится (явно, по согласованному решению для MVP):

- Режим, переданный через переменную (``m = AES.MODE_ECB; AES.new(key, m)``),
  не флагуется. Без потокового анализа отличить безопасный конфиг
  (``MODE = AES.MODE_GCM``) от опасного (``MODE = AES.MODE_ECB``) невозможно;
  срабатывание на «неизвестно» гарантированно даст FP в реальном коде.
- Импорт ``from cryptography.hazmat.primitives.ciphers.modes import ECB``
  с произвольным алиасом учитывается через alias mapping (фактическое
  имя берётся из ``ImportFrom.names[].asname``); без алиаса — имя ``ECB``.
- Сторонние реализации AES (например, чистый Python через ``pyaes``) —
  отдельный кейс с другим набором импортов; в текущее правило не входит.
"""

from __future__ import annotations

import ast

from linter.core import BaseRule, Finding
from linter.rules import register

# Полные пути модулей, по которым приходит API. Хранятся отдельно от имён
# классов/констант — при добавлении новых форм (например, AES-OFB того же
# pycryptodome) расширяется таблица, а не логика обхода.
_PYCA_CIPHERS_MODULE = "cryptography.hazmat.primitives.ciphers"
_PYCA_MODES_MODULE = "cryptography.hazmat.primitives.ciphers.modes"
_PYCRYPTODOME_CIPHER_MODULE = "Crypto.Cipher"

# Имена внутри этих модулей, которые нас интересуют.
_PYCA_MODES_SUBMODULE = "modes"  # доступ ``modes.ECB()``
_PYCA_ECB_CLASS = "ECB"          # прямой импорт ``from ...modes import ECB``
_PYCRYPTODOME_AES_CLASS = "AES"  # ``from Crypto.Cipher import AES``
_PYCRYPTODOME_NEW_METHOD = "new"  # ``AES.new(...)``
_PYCRYPTODOME_ECB_CONSTANT = "MODE_ECB"  # ``AES.MODE_ECB``


@register
class AesEcbModeRule(BaseRule):
    """Правило CRYPTO003 — AES в режиме ECB."""

    rule_id = "CRYPTO003"
    severity = "high"
    message = "AES is used in ECB mode (CWE-327)"

    # ------------------------------------------------------------------
    # Сбор импортов
    # ------------------------------------------------------------------
    @staticmethod
    def _collect_imports(
        tree: ast.AST,
    ) -> tuple[set[str], set[str], set[str]]:
        """Собрать локальные имена для трёх форм импорта.

        Возвращает кортеж (modes_aliases, ecb_direct_aliases, aes_aliases),
        где:

        - ``modes_aliases``     — локальные имена модуля ``modes`` после
          ``from cryptography.hazmat.primitives.ciphers import modes [as ...]``;
          под этим именем потом ищется атрибут ``ECB``.
        - ``ecb_direct_aliases`` — локальные имена класса ``ECB`` после
          ``from cryptography.hazmat.primitives.ciphers.modes import ECB [as ...]``;
          вызов как ``ECB()``.
        - ``aes_aliases``       — локальные имена класса ``AES`` после
          ``from Crypto.Cipher import AES [as ...]``; под этим именем ищутся
          и ``.new(...)``, и ``.MODE_ECB``.

        Импорты внутри функций тоже учитываются (``ast.walk`` идёт по всему
        дереву). Это нестрого по областям видимости, но для линтера крипто-
        ошибок этого достаточно — у CRYPTO002 та же модель.
        """
        modes_aliases: set[str] = set()
        ecb_direct_aliases: set[str] = set()
        aes_aliases: set[str] = set()

        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            if node.level != 0:
                continue

            module = node.module or ""

            if module == _PYCA_CIPHERS_MODULE:
                for alias in node.names:
                    if alias.name == _PYCA_MODES_SUBMODULE:
                        modes_aliases.add(alias.asname or alias.name)
            elif module == _PYCA_MODES_MODULE:
                for alias in node.names:
                    if alias.name == _PYCA_ECB_CLASS:
                        ecb_direct_aliases.add(alias.asname or alias.name)
            elif module == _PYCRYPTODOME_CIPHER_MODULE:
                for alias in node.names:
                    if alias.name == _PYCRYPTODOME_AES_CLASS:
                        aes_aliases.add(alias.asname or alias.name)

        return modes_aliases, ecb_direct_aliases, aes_aliases

    # ------------------------------------------------------------------
    # PyCA: распознавание вызова ECB()
    # ------------------------------------------------------------------
    @staticmethod
    def _is_pyca_ecb_call(
        node: ast.Call,
        modes_aliases: set[str],
        ecb_direct_aliases: set[str],
    ) -> bool:
        """True, если ``node`` — это PyCA-вызов вида ``modes.ECB()`` или ``ECB()``.

        Распознаются обе формы импорта одинаковой семантикой: создание
        экземпляра класса ``cryptography.hazmat.primitives.ciphers.modes.ECB``,
        который дальше обычно передаётся в ``Cipher(...)``. Сам факт создания
        этого объекта означает выбор ECB как режима шифрования AES; без
        дальнейшей передачи в ``Cipher`` он бессмыслен, а с передачей —
        опасен.
        """
        func = node.func

        # Форма 1: ``<modes-alias>.ECB()`` — Attribute(value=Name, attr='ECB').
        if (
            isinstance(func, ast.Attribute)
            and func.attr == _PYCA_ECB_CLASS
            and isinstance(func.value, ast.Name)
            and func.value.id in modes_aliases
        ):
            return True

        # Форма 2: ``ECB()`` после прямого импорта — Name(id=<ecb-alias>).
        if isinstance(func, ast.Name) and func.id in ecb_direct_aliases:
            return True

        return False

    # ------------------------------------------------------------------
    # pycryptodome: AES.new(...) с MODE_ECB среди аргументов
    # ------------------------------------------------------------------
    @staticmethod
    def _is_pycryptodome_aes_new(
        node: ast.Call,
        aes_aliases: set[str],
    ) -> bool:
        """True, если ``node`` — это вызов ``<aes-alias>.new(...)``."""
        func = node.func
        return (
            isinstance(func, ast.Attribute)
            and func.attr == _PYCRYPTODOME_NEW_METHOD
            and isinstance(func.value, ast.Name)
            and func.value.id in aes_aliases
        )

    @staticmethod
    def _is_aes_mode_ecb(node: ast.AST, aes_aliases: set[str]) -> bool:
        """True, если ``node`` — это атрибут ``<aes-alias>.MODE_ECB``."""
        return (
            isinstance(node, ast.Attribute)
            and node.attr == _PYCRYPTODOME_ECB_CONSTANT
            and isinstance(node.value, ast.Name)
            and node.value.id in aes_aliases
        )

    @staticmethod
    def _has_mode_ecb_argument(
        call: ast.Call,
        aes_aliases: set[str],
    ) -> bool:
        """True, если среди args или keywords[arg='mode'] есть ``<aes>.MODE_ECB``.

        Проверка узкая по умыслу: атрибут ``MODE_ECB`` сам по себе встречается
        в коде почти всегда как индикатор выбора режима шифрования; защитные
        конструкции вида ``if x == AES.MODE_ECB: raise`` редки и в такой
        форме у нас не флагуются (у них родительский узел — не ``Call``-аргумент
        и не ``keyword(arg='mode')``).

        Ограничиваемся ``call.args`` и kwarg ``mode=``: это покрывает обе
        формы из спецификации pycryptodome (``AES.new(key, mode, ...)``)
        и не рискует поймать сравнение/проверку.
        """
        for arg in call.args:
            if AesEcbModeRule._is_aes_mode_ecb(arg, aes_aliases):
                return True
        for kw in call.keywords:
            if (
                kw.arg == "mode"
                and AesEcbModeRule._is_aes_mode_ecb(kw.value, aes_aliases)
            ):
                return True
        return False

    # ------------------------------------------------------------------
    # Сообщение и suggestion
    # ------------------------------------------------------------------
    @staticmethod
    def _build_message(library: str) -> str:
        """Краткое сообщение для Finding.

        ``library`` — короткая метка библиотеки (``"PyCA Hazmat"`` или
        ``"pycryptodome"``), чтобы по выводу было понятно, какая форма
        поймана. Это удобно и для отладки правила, и для презентации
        результатов в главе диплома про сравнение с Bandit/Semgrep.
        """
        return (
            f"AES is used in ECB mode ({library}). ECB does not hide patterns "
            f"in plaintext (identical 16-byte blocks produce identical "
            f"ciphertext blocks) and provides no authentication. CWE-327."
        )

    @staticmethod
    def _build_suggestion() -> str:
        """Единое предложение замены — AES-GCM."""
        return (
            "use AES-GCM (AEAD provides authenticated encryption); "
            "for `cryptography` use "
            "`cryptography.hazmat.primitives.ciphers.aead.AESGCM`, "
            "for `pycryptodome` use `AES.new(key, AES.MODE_GCM, nonce=...)`"
        )

    # ------------------------------------------------------------------
    # Главный метод
    # ------------------------------------------------------------------
    def check(self, tree: ast.AST, source: str, filename: str) -> list[Finding]:
        modes_aliases, ecb_direct_aliases, aes_aliases = self._collect_imports(
            tree
        )
        # Если в файле нет ни одного релевантного импорта — проверять нечего.
        if not (modes_aliases or ecb_direct_aliases or aes_aliases):
            return []

        suggestion = self._build_suggestion()
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # PyCA Hazmat: ``modes.ECB()`` или ``ECB()``.
            if self._is_pyca_ecb_call(node, modes_aliases, ecb_direct_aliases):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=self._build_message("PyCA Hazmat"),
                        filename=filename,
                        line=node.lineno,
                        col=node.col_offset,
                        suggestion=suggestion,
                    )
                )
                continue

            # pycryptodome: ``<aes>.new(...)`` с ``<aes>.MODE_ECB`` в аргументах.
            if self._is_pycryptodome_aes_new(node, aes_aliases):
                if self._has_mode_ecb_argument(node, aes_aliases):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=self._build_message("pycryptodome"),
                            filename=filename,
                            line=node.lineno,
                            col=node.col_offset,
                            suggestion=suggestion,
                        )
                    )

        return findings
