"""Форматирование вывода линтера.

Поддерживает два формата:
- ``text`` — компактные строки ``filename:line:col: SEVERITY RULE сообщение``,
  совместимые с большинством редакторов и pre-commit-парсеров;
- ``json`` — массив объектов ``Finding``, удобен для машинной обработки и
  сравнения с ``expected.json`` в тестах корпуса.

Сами файлы не открываются: на вход даётся уже собранный список ``Finding``.
"""

from __future__ import annotations

import json
from typing import Iterable

from linter.core import Finding


def format_text(findings: Iterable[Finding]) -> str:
    """Текстовый вывод по одному finding на строку.

    Формат: ``<file>:<line>:<col>: <SEVERITY> <RULE_ID> <message>``.
    Если у finding есть ``suggestion``, он добавляется отдельной строкой
    с отступом — пользователь видит «что чинить» сразу под основной строкой.
    """
    lines: list[str] = []
    for f in findings:
        lines.append(
            f"{f.filename}:{f.line}:{f.col}: "
            f"{f.severity.upper()} {f.rule_id} {f.message}"
        )
        if f.suggestion:
            lines.append(f"    suggestion: {f.suggestion}")
    return "\n".join(lines)


def format_json(findings: Iterable[Finding]) -> str:
    """JSON-вывод: массив объектов с полями ``Finding``.

    Стабильный порядок ключей для воспроизводимости тестов.
    """
    payload = [f.to_dict() for f in findings]
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
