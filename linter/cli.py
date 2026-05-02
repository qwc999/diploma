"""Точка входа линтера: ``python -m linter <path>``.

CLI принимает один или несколько путей (файл или директория). Директории
рекурсивно обходятся по ``*.py``. Для каждого файла парсится AST, после чего
все зарегистрированные правила запускаются по очереди и собирают
``Finding``-и в общий список.

Код возврата:
- ``0`` — ни одного finding не найдено;
- ``1`` — есть хотя бы один finding (рекомендуется для использования в CI);
- ``2`` — ошибка обработки (несуществующий путь, невалидный синтаксис файла).

Импорт ``linter.rules`` обязателен: при импорте пакета регистрируются все
правила (см. ``linter/rules/__init__.py``).
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

from linter.core import Finding
from linter.report import format_json, format_text
from linter.rules import all_rules  # noqa: F401  (важен side-effect импорта)
import linter.rules  # noqa: F401  (триггерит регистрацию правил)


def _collect_files(paths: list[str]) -> tuple[list[Path], list[str]]:
    """Собрать список .py-файлов из списка путей.

    Возвращает (files, errors). Ошибки не прерывают сбор — они выводятся
    в stderr в конце, чтобы пользователь видел все проблемные пути сразу.
    """
    files: list[Path] = []
    errors: list[str] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            files.extend(sorted(p.rglob("*.py")))
        elif p.is_file():
            files.append(p)
        else:
            errors.append(f"path not found: {raw}")
    return files, errors


def _lint_file(path: Path) -> tuple[list[Finding], str | None]:
    """Запустить все правила на одном файле.

    Возвращает (findings, error). Если файл не парсится, findings пустой,
    а error содержит сообщение о синтаксической ошибке.
    """
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], f"cannot read {path}: {exc}"
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return [], f"cannot parse {path}: {exc}"

    findings: list[Finding] = []
    for rule_cls in all_rules():
        rule = rule_cls()
        findings.extend(rule.check(tree, source, str(path)))
    return findings, None


def _ensure_utf8_stdio() -> None:
    """Перевести stdout/stderr на UTF-8.

    На Windows консоль по умолчанию использует cp1251/cp866, в которых
    нет, например, длинного тире (``—``) и кириллицы — Unicode-символы
    выводятся как ``?`` или мусор. ``reconfigure`` доступен с Python 3.7
    и не влияет на платформы, где stdout уже utf-8 (Linux/macOS).
    """
    for stream in (sys.stdout, sys.stderr):
        encoding = getattr(stream, "encoding", "") or ""
        if encoding.lower() == "utf-8":
            continue
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            # Старая версия Python либо не-перенастраиваемый поток —
            # вывод останется в дефолтной кодировке, это не блокер.
            pass


def main(argv: list[str] | None = None) -> int:
    """Главная функция CLI. Возвращает код выхода."""
    _ensure_utf8_stdio()
    parser = argparse.ArgumentParser(
        prog="cryptolint",
        description="Линтер криптографических ошибок в Python-коде.",
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="Пути к файлам или директориям с Python-кодом.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Формат вывода findings (по умолчанию text).",
    )
    args = parser.parse_args(argv)

    files, path_errors = _collect_files(args.paths)
    for err in path_errors:
        print(f"error: {err}", file=sys.stderr)

    all_findings: list[Finding] = []
    parse_errors: list[str] = []
    for f in files:
        findings, err = _lint_file(f)
        if err is not None:
            parse_errors.append(err)
            continue
        all_findings.extend(findings)

    for err in parse_errors:
        print(f"error: {err}", file=sys.stderr)

    if all_findings:
        if args.format == "json":
            print(format_json(all_findings))
        else:
            print(format_text(all_findings))

    if path_errors or parse_errors:
        return 2
    return 1 if all_findings else 0


if __name__ == "__main__":
    sys.exit(main())
