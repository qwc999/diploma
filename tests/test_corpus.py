"""Тесты корпуса: для каждого кейса в ``corpus/`` сравниваем вывод линтера с ``expected.json``.

Тест параметризован по подкаталогам ``corpus/``, в которых лежит файл
``expected.json``. Запуск конкретного кейса:

    pytest tests/test_corpus.py -k random_lib_for_crypto

Контракт сравнения (см. ``docs/rule_authoring.md``):
- На ``vulnerable.py`` каждый ожидаемый finding из ``expected.json`` должен
  присутствовать в выводе линтера. Лишние findings допустимы (правило может
  быть строже expected).
- На ``safe.py`` (если ``must_be_empty_on_safe=True``) линтер обязан вернуть
  пустой список.
- Поля ``rule`` и ``line`` сравниваются всегда. ``severity`` — если задано
  в expected. ``col`` — если задано.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from linter.core import Finding
from linter.rules import all_rules
import linter.rules  # noqa: F401  (триггерит регистрацию правил)


CORPUS_DIR = Path(__file__).resolve().parents[1] / "corpus"


def _discover_cases() -> list[Path]:
    """Все подпапки corpus/, в которых лежит expected.json."""
    if not CORPUS_DIR.is_dir():
        return []
    return sorted(
        p for p in CORPUS_DIR.iterdir() if p.is_dir() and (p / "expected.json").is_file()
    )


def _run_linter(path: Path) -> list[Finding]:
    """Прогнать все зарегистрированные правила на одном файле."""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    findings: list[Finding] = []
    for rule_cls in all_rules():
        rule = rule_cls()
        findings.extend(rule.check(tree, source, str(path)))
    return findings


def _find_matching(
    findings: list[Finding], expected_line: int, expected_rule: str
) -> Finding | None:
    """Первый finding, совпадающий по (line, rule_id)."""
    for f in findings:
        if f.line == expected_line and f.rule_id == expected_rule:
            return f
    return None


@pytest.mark.parametrize(
    "case_dir", _discover_cases(), ids=lambda p: p.name
)
def test_corpus_case(case_dir: Path) -> None:
    expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))

    # --- vulnerable.py: все ожидаемые findings присутствуют ---------------
    vuln_path = case_dir / "vulnerable.py"
    assert vuln_path.is_file(), f"missing vulnerable.py in {case_dir}"
    actual = _run_linter(vuln_path)

    for ef in expected["findings"]:
        match = _find_matching(actual, ef["line"], ef["rule"])
        assert match is not None, (
            f"[{case_dir.name}] expected finding not produced: "
            f"line={ef['line']} rule={ef['rule']}; got: "
            f"{[(f.line, f.rule_id, f.severity) for f in actual]}"
        )
        if "severity" in ef:
            assert match.severity == ef["severity"], (
                f"[{case_dir.name}] severity mismatch on line {ef['line']}: "
                f"expected {ef['severity']}, got {match.severity}"
            )
        if "col" in ef:
            assert match.col == ef["col"], (
                f"[{case_dir.name}] col mismatch on line {ef['line']}: "
                f"expected {ef['col']}, got {match.col}"
            )

    # --- safe.py: ни одного finding ----------------------------------------
    if expected.get("must_be_empty_on_safe", False):
        safe_path = case_dir / "safe.py"
        assert safe_path.is_file(), f"missing safe.py in {case_dir}"
        safe_findings = _run_linter(safe_path)
        assert not safe_findings, (
            f"[{case_dir.name}] linter triggered on safe.py: "
            f"{[(f.line, f.rule_id, f.severity, f.message) for f in safe_findings]}"
        )
