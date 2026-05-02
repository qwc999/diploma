"""Контекстные утилиты, общие для всех правил.

Здесь — только примитивы анализа окружения вокруг подозрительного узла AST.
Сами проверки — в правилах. Главный артефакт — словарь крипто-имён,
по которому правило поднимает severity до ``high``.

Словарь един для всех правил проекта (см. ``project_methodology.md``,
``docs/rules_registry.md``). Менять состав — через PR с обоснованием.
"""

from __future__ import annotations

import ast
import re
from typing import Iterable

# ---------------------------------------------------------------------------
# Словарь крипто-имён
# ---------------------------------------------------------------------------
# Единый набор «крипто-токенов», по которому правила определяют, что
# результат вызова используется в криптографическом контексте. Имена в нижнем
# регистре, без подчёркиваний — поиск идёт по сегментам имени.
CRYPTO_NAMES: frozenset[str] = frozenset(
    {
        "token",
        "key",
        "iv",
        "nonce",
        "secret",
        "password",
        "salt",
        "session_id",
        "api_key",
    }
)

# Дополнительный набор «склеенных» вариантов: API-имена часто пишут без
# подчёркивания (``apikey``, ``sessionid``). Хранится отдельно, чтобы не
# раздувать основной словарь и явно фиксировать, что это эвристика.
_CRYPTO_NAMES_GLUED: frozenset[str] = frozenset(
    name.replace("_", "") for name in CRYPTO_NAMES if "_" in name
)

# Любой не-словесный символ — разделитель сегмента имени.
_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def detect_crypto_name(name: str | None) -> str | None:
    """Если имя похоже на крипто-имя, вернуть совпавший токен; иначе ``None``.

    Логика:
    1. Имя приводится к нижнему регистру и режется по не-буквенно-цифровым
       символам (``reset_token`` → ``["reset", "token"]``).
    2. Совпадение засчитывается, если хотя бы один сегмент целиком равен
       одному из ``CRYPTO_NAMES``.
    3. Дополнительно проверяется «склеенная» форма для составных имён —
       ``apikey`` / ``sessionid``.

    Возврат именно совпавшего токена нужен для message правила: вместо
    обобщённого «weak random» отчёт упоминает конкретный контекст
    (например, ``token`` или ``salt``).

    Возвращает ``None`` для пустого имени, имени без крипто-сегментов,
    а также для имени, содержащего крипто-токен только как часть слова
    (``monkey`` не считается крипто-контекстом из-за подстроки ``key``).
    """
    if not name:
        return None
    lower = name.lower()
    parts = [p for p in _SPLIT_RE.split(lower) if p]
    for part in parts:
        if part in CRYPTO_NAMES:
            return part
        if part in _CRYPTO_NAMES_GLUED:
            # Восстановим оригинальную форму с подчёркиванием для message.
            for original in CRYPTO_NAMES:
                if original.replace("_", "") == part:
                    return original
    return None


# ---------------------------------------------------------------------------
# Подъём по AST
# ---------------------------------------------------------------------------
# Стандартный модуль ``ast`` не даёт ссылок на родителя. Чтобы определить,
# в какой ``Assign``/``Call``/``Return`` встроен подозрительный вызов,
# проходим один раз по дереву и навешиваем атрибут ``parent``. Это не мутация
# семантики (AST остаётся валидным), а локальная нотация для нашего обхода.

_PARENT_ATTR = "_cryptolint_parent"


def attach_parents(tree: ast.AST) -> None:
    """Навесить на каждый узел ссылку на родителя.

    Атрибут хранится под ``_cryptolint_parent``, чтобы случайно не пересечься
    с пользовательским кодом или другими инструментами. У корня parent == None.
    """
    setattr(tree, _PARENT_ATTR, None)
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            setattr(child, _PARENT_ATTR, node)


def get_parent(node: ast.AST) -> ast.AST | None:
    """Достать родителя, выставленного через ``attach_parents``."""
    return getattr(node, _PARENT_ATTR, None)


# Узлы, на которых подъём по родителям обрывается: дальше уже не «контекст
# выражения», а уровень statement-а или функции.
_STATEMENT_BOUNDARY: tuple[type, ...] = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.Module,
    ast.If,
    ast.For,
    ast.While,
    ast.With,
    ast.Try,
)


def find_assignment_target_name(node: ast.AST) -> str | None:
    """Имя переменной, которой присваивается результат выражения с ``node``.

    Поднимается по родителям от ``node``, пока не встретит ``Assign`` или
    ``AnnAssign`` с одним target — ``Name``. Если по пути встретился
    statement-узел из ``_STATEMENT_BOUNDARY``, подъём прекращается
    (мы вышли за границы одного выражения).

    Поведение:
    - ``token = random.choice(...)``    → ``"token"``
    - ``self.token = random.choice(...)`` → ``"token"`` (атрибут)
    - ``a, b = random.randint(...), 0`` → ``None`` (множественное присваивание
      не разбираем — это редкий паттерн в крипто-коде)
    - ``return random.randint(...)``    → ``None``
    """
    parent = get_parent(node)
    while parent is not None and not isinstance(parent, _STATEMENT_BOUNDARY):
        if isinstance(parent, ast.Assign):
            if len(parent.targets) == 1:
                target = parent.targets[0]
                if isinstance(target, ast.Name):
                    return target.id
                if isinstance(target, ast.Attribute):
                    return target.attr
            return None
        if isinstance(parent, ast.AnnAssign):
            target = parent.target
            if isinstance(target, ast.Name):
                return target.id
            if isinstance(target, ast.Attribute):
                return target.attr
            return None
        parent = get_parent(parent)
    return None


def find_enclosing_call_func_name(node: ast.AST) -> str | None:
    """Имя функции, в чьи аргументы передаётся выражение с ``node``.

    Поднимается по родителям, ищет ближайший ``Call``, у которого ``node``
    (или его предок до этого Call) — один из аргументов. Возвращает простое
    имя функции: для ``foo(...)`` — ``"foo"``, для ``mod.bar(...)`` — ``"bar"``.

    Паттерн нужен, чтобы повышать severity в случаях вроде
    ``make_token(random.randint(...))`` — даже если результат прямо никуда
    не присваивается, он используется как аргумент функции, чьё имя содержит
    крипто-токен.
    """
    current = node
    parent = get_parent(current)
    while parent is not None and not isinstance(parent, _STATEMENT_BOUNDARY):
        if isinstance(parent, ast.Call) and current in parent.args:
            func = parent.func
            if isinstance(func, ast.Name):
                return func.id
            if isinstance(func, ast.Attribute):
                return func.attr
            return None
        current = parent
        parent = get_parent(parent)
    return None


def iter_crypto_name_candidates(node: ast.AST) -> Iterable[str]:
    """Вернуть последовательность имён, в которых имеет смысл искать крипто-контекст.

    Сейчас это (a) имя цели присваивания, (b) имя ближайшей охватывающей функции.
    Порядок важен: цель присваивания имеет приоритет над аргументом функции.
    """
    target = find_assignment_target_name(node)
    if target is not None:
        yield target
    enclosing_call = find_enclosing_call_func_name(node)
    if enclosing_call is not None:
        yield enclosing_call


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------
# Низкоуровневые операции над узлами ``ast``, общие для нескольких правил.
# Они не «контекстные» в смысле крипто-контекста, но живут здесь, чтобы
# каждое правило не плодило собственный набор копипастных helper-ов.
# На момент выноса (CRYPTO004) общий код был у CRYPTO002 и CRYPTO004 —
# идентичные ``_get_kwarg`` и ``_literal_int``. Если паттерн расширится
# (``literal_str``, ``literal_bool``, ``literal_bytes``), кладём сюда же.


def get_kwarg(call: ast.Call, name: str) -> ast.expr | None:
    """Вернуть AST-узел значения keyword-аргумента ``name`` или ``None``.

    Если у ``call`` нет ключевого аргумента с таким именем — возвращается
    ``None``. Аргументы вида ``**kwargs`` (у них ``kw.arg is None``)
    игнорируются: статически их содержимое не разрешается, и сравнивать
    их имя со значением ``name`` бессмысленно.
    """
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def literal_int(node: ast.expr | None) -> int | None:
    """Вернуть целочисленный литерал ``node`` или ``None``.

    ``True`` / ``False`` отсекаются проверкой ``type(...) is int``: в Python
    ``bool`` — подкласс ``int``, и без явного отсечения вызов вроде
    ``gensalt(rounds=True)`` распознался бы как литерал ``1``. Это бессмысленно
    в коде, но именно поэтому правило обязано считать такое значение
    «не статически разрешимым» и пропустить, а не интерпретировать как
    ``rounds=1`` и поднять FP по бессмысленному коду.

    Отрицательные литералы (``rounds=-1``) тоже не распознаются: в AST они
    представлены как ``UnaryOp(USub, Constant(1))``, а не ``Constant(-1)``.
    Для типичных параметров KDF / cost factor отрицательные значения нелегальны
    на уровне самой библиотеки, поэтому отдельная обработка не нужна.
    """
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    return None
