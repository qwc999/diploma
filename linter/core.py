"""Базовый слой линтера: класс правила и структура finding.

Здесь живут только примитивы, общие для всех правил:
- ``Finding`` — одна найденная проблема в коде
- ``BaseRule`` — родительский класс для каждого правила в ``linter/rules/``
- ``Severity`` — псевдоним типа уровня важности

Сами правила и обход AST — в ``linter/rules/``. Контекстные утилиты
(словарь крипто-имён, подъём по родителям) — в ``linter/context.py``.

Контракт правила: метод ``check(tree, source, filename)`` возвращает список
``Finding`` и не мутирует входной AST. Без сетевых обращений и без чтения
сторонних файлов.
"""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from typing import ClassVar, Literal

Severity = Literal["high", "medium", "low"]


@dataclass(frozen=True)
class Finding:
    """Одна находка линтера.

    Поля:
        rule_id:    идентификатор правила, например ``"CRYPTO001"``.
        severity:   уровень важности — ``high`` / ``medium`` / ``low``.
        message:    человеко-читаемое сообщение для отчёта.
        filename:   путь к файлу, в котором найдена проблема.
        line:       номер строки (1-based, как в ``ast.AST.lineno``).
        col:        номер колонки (0-based, как в ``ast.AST.col_offset``).
        suggestion: опциональное предложение, чем заменить уязвимый вызов.
    """

    rule_id: str
    severity: Severity
    message: str
    filename: str
    line: int
    col: int = 0
    suggestion: str | None = None

    def to_dict(self) -> dict:
        """Сериализуется в простой dict для JSON-вывода и сравнения в тестах."""
        return asdict(self)


class BaseRule:
    """Родительский класс для всех правил линтера.

    Атрибуты ``rule_id`` / ``severity`` / ``message`` — это **метаданные
    класса**, а не instance state. Поэтому BaseRule НЕ ``@dataclass``: иначе
    сгенерированный ``__init__`` затёр бы переопределения наследников
    дефолтами из родителя (тонкая, но воспроизводимая ловушка
    dataclass-наследования).

    Наследник обязан переопределить:
        rule_id:  ``"CRYPTO###"`` (формат проверяется в реестре правил).
        severity: дефолтный уровень важности; в правиле может корректироваться
                  по контексту перед созданием конкретного ``Finding``.
        message:  короткое сообщение по умолчанию.

    И реализовать ``check()``. Реализация по умолчанию падает —
    это сигнал, что правило неполное.
    """

    # ``ClassVar`` явно говорит, что это атрибуты класса. Type checker не будет
    # требовать их как параметры конструктора и не примет за instance state.
    rule_id: ClassVar[str] = ""
    severity: ClassVar[Severity] = "medium"
    message: ClassVar[str] = ""

    def __init__(self, options: dict | None = None) -> None:
        # ``options`` — единственное instance-поле; зарезервировано под
        # конфигурацию правила (например, переключатели severity из CLI).
        self.options: dict = options or {}

    def check(self, tree: ast.AST, source: str, filename: str) -> list[Finding]:
        """Главный метод правила. Возвращает список ``Finding`` без мутаций AST."""
        raise NotImplementedError(
            f"Rule {type(self).__name__} ({self.rule_id}) must implement check()"
        )
