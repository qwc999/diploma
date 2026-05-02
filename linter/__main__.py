"""Запуск линтера через ``python -m linter``.

Делегирует в ``linter.cli.main``. Сделано отдельным модулем,
чтобы ``cli.main`` оставалась удобной для импорта в тестах и обвязках.
"""

from __future__ import annotations

import sys

from linter.cli import main

if __name__ == "__main__":
    sys.exit(main())
