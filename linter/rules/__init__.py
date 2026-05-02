"""Реестр правил линтера.

Правило регистрируется при импорте соответствующего модуля через декоратор
``@register``. Одно правило — один ``rule_id`` вида ``CRYPTO###``. Повторная
регистрация под тем же ``rule_id`` — ошибка.

Пример:

    # linter/rules/weak_random.py
    from linter.rules import register

    @register
    class WeakRandomRule(BaseRule):
        rule_id = "CRYPTO001"
        severity = "high"
        message = "Weak random for cryptographic purposes"
        ...

Человеко-читаемая таблица правил лежит в ``docs/rules_registry.md`` и должна
обновляться одновременно с регистрацией правила в коде.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from linter.core import BaseRule


_RULE_ID_PATTERN = re.compile(r"^CRYPTO\d{3}$")

_REGISTRY: dict[str, "type[BaseRule]"] = {}


def register(rule_cls):
    """Зарегистрировать класс правила в глобальном реестре.

    Используется как декоратор над классом-наследником ``BaseRule``.
    Падает при дубликате ``rule_id`` или несоответствии формату.
    """
    rule_id = getattr(rule_cls, "rule_id", None)
    if not isinstance(rule_id, str) or not _RULE_ID_PATTERN.match(rule_id):
        raise ValueError(
            f"Rule class {rule_cls.__name__} must declare rule_id matching "
            f"CRYPTO### (three digits); got {rule_id!r}"
        )
    if rule_id in _REGISTRY:
        existing = _REGISTRY[rule_id].__name__
        raise ValueError(
            f"Duplicate rule_id {rule_id}: already registered as {existing}"
        )
    _REGISTRY[rule_id] = rule_cls
    return rule_cls


def all_rules() -> list["type[BaseRule]"]:
    """Все зарегистрированные классы правил в порядке регистрации."""
    return list(_REGISTRY.values())


def get_rule(rule_id: str) -> "type[BaseRule]":
    """Достать класс правила по rule_id. KeyError, если не найдено."""
    return _REGISTRY[rule_id]


def iter_rule_ids() -> Iterator[str]:
    return iter(_REGISTRY)


# ---------------------------------------------------------------------------
# Автоподключение правил
# ---------------------------------------------------------------------------
# Импорт каждого модуля правила запускает декоратор ``@register`` и наполняет
# реестр. Импорт делается в конце файла, после определения ``register``,
# чтобы избежать частично инициализированного состояния. При добавлении
# нового правила сюда добавляется одна строка ``from . import <slug>``.
from linter.rules import weak_random as _weak_random  # noqa: E402, F401
from linter.rules import pbkdf2_iterations as _pbkdf2_iterations  # noqa: E402, F401
from linter.rules import aes_ecb as _aes_ecb  # noqa: E402, F401
from linter.rules import bcrypt_low_rounds as _bcrypt_low_rounds  # noqa: E402, F401
from linter.rules import jwt_misuse as _jwt_misuse  # noqa: E402, F401
