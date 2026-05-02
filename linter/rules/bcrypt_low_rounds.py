"""CRYPTO004 - bcrypt.gensalt with an insufficient cost factor.

Case: ``corpus/bcrypt_low_rounds/``. The case is advanced: Bandit 1.9.4
and Semgrep 1.161.0 with local ``semgrep-rules`` @ ``fdc73542`` both miss
all 4 vulnerable scenarios (0 TP, 4 FN) and produce 0 FP on safe code.

What is considered vulnerable:

1. ``bcrypt.gensalt(rounds=N)`` after ``import bcrypt``.
2. ``bc.gensalt(rounds=N)`` after ``import bcrypt as bc``.
3. ``gensalt(rounds=N)`` after ``from bcrypt import gensalt``.
4. ``gs(rounds=N)`` after ``from bcrypt import gensalt as gs``.

Only integer literals are checked. ``bcrypt.gensalt()`` without explicit
``rounds`` is not flagged in the MVP: current bcrypt defaults are acceptable
for this rule, and unknown defaults should not create false positives.

Thresholds:

- ``rounds >= 12`` - accepted.
- ``rounds < 10`` - high severity (grossly weak cost factor).
- ``10 <= rounds < 12`` - medium severity (borderline legacy value).

Known MVP limits:

- ``rounds`` passed through a variable is skipped. Without dataflow analysis
  a linter cannot distinguish ``ROUNDS = 14`` from ``ROUNDS = 4`` reliably.
- Positional ``bcrypt.gensalt(8)`` is not included in this case. It can be
  added as a separate extension if needed.
"""

from __future__ import annotations

import ast

from linter.context import get_kwarg, literal_int
from linter.core import BaseRule, Finding
from linter.rules import register

_BCRYPT_MODULE = "bcrypt"
_GENSALT_FUNC = "gensalt"
_MIN_SAFE_ROUNDS = 12
_HIGH_SEVERITY_CUTOFF = 10


@register
class BcryptLowRoundsRule(BaseRule):
    """Rule CRYPTO004 - bcrypt cost factor below the accepted minimum."""

    rule_id = "CRYPTO004"
    severity = "medium"
    message = "bcrypt.gensalt with insufficient rounds"

    @staticmethod
    def _collect_imports(tree: ast.AST) -> tuple[set[str], set[str]]:
        """Collect local names for bcrypt module aliases and gensalt aliases."""
        module_aliases: set[str] = set()
        gensalt_aliases: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == _BCRYPT_MODULE:
                        module_aliases.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level != 0 or node.module != _BCRYPT_MODULE:
                    continue
                for alias in node.names:
                    if alias.name == _GENSALT_FUNC:
                        gensalt_aliases.add(alias.asname or alias.name)

        return module_aliases, gensalt_aliases

    @staticmethod
    def _is_gensalt_call(
        call: ast.Call,
        module_aliases: set[str],
        gensalt_aliases: set[str],
    ) -> bool:
        """Check whether ``call`` invokes bcrypt.gensalt in a supported form."""
        func = call.func

        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in module_aliases
            and func.attr == _GENSALT_FUNC
        ):
            return True

        if isinstance(func, ast.Name) and func.id in gensalt_aliases:
            return True

        return False

    @staticmethod
    def _classify_severity(rounds: int) -> str:
        return "high" if rounds < _HIGH_SEVERITY_CUTOFF else "medium"

    @staticmethod
    def _build_message(rounds: int) -> str:
        return (
            f"bcrypt.gensalt with weak cost factor: rounds={rounds} < "
            f"OWASP-2023 minimum {_MIN_SAFE_ROUNDS} (CWE-916)."
        )

    @staticmethod
    def _build_suggestion() -> str:
        return (
            f"increase bcrypt rounds to at least {_MIN_SAFE_ROUNDS} "
            "(OWASP-2023 Password Storage Cheat Sheet); for new code prefer "
            "Argon2id (`argon2-cffi`) as the OWASP-recommended modern KDF; "
            "on bcrypt — choose the highest cost factor that fits the "
            "latency budget"
        )

    def check(self, tree: ast.AST, source: str, filename: str) -> list[Finding]:
        module_aliases, gensalt_aliases = self._collect_imports(tree)
        if not (module_aliases or gensalt_aliases):
            return []

        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not self._is_gensalt_call(node, module_aliases, gensalt_aliases):
                continue

            rounds_node = get_kwarg(node, "rounds")
            rounds = literal_int(rounds_node)
            if rounds is None:
                continue
            if rounds >= _MIN_SAFE_ROUNDS:
                continue

            severity = self._classify_severity(rounds)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=severity,  # type: ignore[arg-type]
                    message=self._build_message(rounds),
                    filename=filename,
                    line=node.lineno,
                    col=node.col_offset,
                    suggestion=self._build_suggestion(),
                )
            )

        return findings
