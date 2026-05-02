"""CRYPTO005 — JWT misuses: алгоритм 'none' и отключение verify_*.

Кейс: ``corpus/jwt_misuse/``. Класс кейса — продвинутый. Эмпирическое
обоснование на расширенном корпусе (8 сценариев, две оси misuse, три
формы импорта):

- Bandit 1.9.4 не имеет ни одного правила для PyJWT — 0 TP / 8 FN.
  Полный систематический пробел набора по библиотеке.
- Semgrep 1.161.0 с локальным `semgrep-rules` @ ``fdc73542`` ловит
  5/8 TP с тремя FN: регистр ``'NONE'`` (правило ``jwt-python-none-alg``
  pattern-матчит литерал ``'none'``), а также ``verify_aud``/``verify_exp``
  (правило ``unverified-jwt-decode`` распознаёт только ``verify_signature``).
  При нескольких отключённых ключах в одном словаре отчёт неполный.

Что считается уязвимым (две ветви, восемь форм вызова):

1. Алгоритм 'none' при выпуске или приёме токена (CWE-327, CWE-347):
    - ``jwt.encode(..., algorithm='none')`` — kwarg, любая регистровая форма
      (``'none'``, ``'NONE'``, ``'None'``); PyJWT нормализует к нижнему регистру.
    - ``jwt.decode(..., algorithms=['HS256', 'none'])`` — литерал ``'none'``
      в любой позиции списка ``algorithms``, регистронезависимо.
2. Отключение проверок при `decode` (CWE-347):
    - ``jwt.decode(..., options={'verify_signature': False, ...})`` —
      любой ключ из ``DANGEROUS_VERIFY_KEYS`` со значением ``False``.
      Поддерживается dict с несколькими отключёнными ключами одновременно
      (одно срабатывание на вызов с перечислением всех ключей в message).

Имена импорта обрабатываются через таблицу алиасов: ``import jwt``,
``import jwt as j``, ``from jwt import encode``, ``from jwt import decode``,
``from jwt import encode as e`` — все формы распознаются как тот же вызов.
Архитектура повторяет ``_collect_imports`` из CRYPTO002/CRYPTO003.

Severity: всегда ``high``. Шкалы нет — обе формы означают «токен принимается
без валидной подписи»; промежуточного «менее опасного» состояния не
существует (как и у CRYPTO003 / ECB).

Что НЕ ловится (явно, по согласованному решению для MVP):

- ``algorithm`` или ``options`` заданы переменной, а не литералом
  (``a = 'none'; jwt.encode(..., algorithm=a)``;
  ``opts = {'verify_signature': False}; jwt.decode(..., options=opts)``):
  без анализа потоков мы не отличим безопасный конфиг (``OPTS = {...: True}``)
  от опасного (``OPTS = {...: False}``). Срабатывание на «неизвестно»
  гарантированно даст FP в реальном коде, поэтому правило молчит.
  Архитектурно такое же ограничение принято в CRYPTO002 (переменная
  вместо литерала ``iterations``) и CRYPTO003 (переменная вместо
  литерала ``MODE_ECB``).
- Позиционная передача алгоритма (``jwt.encode(payload, key, 'none')``)
  не покрывается. На практике PyJWT не используется так — в документации
  только kwarg-форма. Расширение тривиально, но в MVP не делалось.
- Сборка словаря ``options`` по частям
  (``opts = {}; opts['verify_signature'] = False``) — не покрывается
  по той же причине, что и переменная-dict.
"""

from __future__ import annotations

import ast

from linter.core import BaseRule, Finding
from linter.rules import register

# Имя модуля и интересующие нас функции PyJWT. Имена констант не зашиваются
# в логику обхода — при появлении новых форм (например, ``jwt.api_jwt.encode``)
# таблица расширяется без правок основного check().
_JWT_MODULE = "jwt"
_ENCODE_FUNC = "encode"
_DECODE_FUNC = "decode"

# Полный набор «опасных при False» ключей словаря ``options`` PyJWT.
# Источник — документация PyJWT (`pyjwt.readthedocs.io/en/stable/usage.html`,
# раздел про ``options``). Все эти ключи по умолчанию True; перевод в False
# отключает соответствующую проверку — подписи (verify_signature) или
# стандартного claim-а (audience/expiration/issued-at/not-before/issuer).
DANGEROUS_VERIFY_KEYS: frozenset[str] = frozenset(
    {
        "verify_signature",
        "verify_aud",
        "verify_exp",
        "verify_iat",
        "verify_nbf",
        "verify_iss",
    }
)


@register
class JwtMisuseRule(BaseRule):
    """Правило CRYPTO005 — JWT misuses (алгоритм 'none' и verify_*=False)."""

    rule_id = "CRYPTO005"
    severity = "high"
    message = "JWT misuse: signature verification bypassed"

    # ------------------------------------------------------------------
    # Сбор импортов
    # ------------------------------------------------------------------
    @staticmethod
    def _collect_imports(
        tree: ast.AST,
    ) -> tuple[set[str], set[str], set[str]]:
        """Собрать локальные имена для трёх форм импорта.

        Возвращает кортеж (jwt_module_aliases, encode_aliases, decode_aliases),
        где:

        - ``jwt_module_aliases`` — локальные имена самого модуля ``jwt``
          после ``import jwt [as ...]``; под этим именем потом ищутся
          атрибуты ``.encode``/``.decode``.
        - ``encode_aliases``    — локальные имена функции ``encode`` после
          ``from jwt import encode [as ...]``; вызов как ``encode(...)``.
        - ``decode_aliases``    — локальные имена функции ``decode`` после
          ``from jwt import decode [as ...]``; вызов как ``decode(...)``.

        Импорты внутри функций тоже учитываются (``ast.walk`` идёт по
        всему дереву). Это нестрого по областям видимости, но для линтера
        крипто-ошибок этого достаточно — у CRYPTO002 и CRYPTO003 та же модель.
        """
        jwt_module_aliases: set[str] = set()
        encode_aliases: set[str] = set()
        decode_aliases: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == _JWT_MODULE:
                        jwt_module_aliases.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level != 0:
                    continue
                if node.module == _JWT_MODULE:
                    for alias in node.names:
                        if alias.name == _ENCODE_FUNC:
                            encode_aliases.add(alias.asname or alias.name)
                        elif alias.name == _DECODE_FUNC:
                            decode_aliases.add(alias.asname or alias.name)

        return jwt_module_aliases, encode_aliases, decode_aliases

    # ------------------------------------------------------------------
    # Извлечение значений из AST
    # ------------------------------------------------------------------
    @staticmethod
    def _get_kwarg(call: ast.Call, name: str) -> ast.expr | None:
        """Вернуть AST-узел значения kwarg ``name`` или ``None``."""
        for kw in call.keywords:
            if kw.arg == name:
                return kw.value
        return None

    @staticmethod
    def _literal_str(node: ast.expr | None) -> str | None:
        """Вернуть строковый литерал ``node`` или ``None``."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    # ------------------------------------------------------------------
    # Распознавание формы вызова
    # ------------------------------------------------------------------
    @staticmethod
    def _identify_call(
        call: ast.Call,
        jwt_module_aliases: set[str],
        encode_aliases: set[str],
        decode_aliases: set[str],
    ) -> str | None:
        """Распознать форму вызова PyJWT.

        Возвращает один из ``"encode"`` / ``"decode"`` / ``None``.
        ``None`` означает, что это не PyJWT-вызов и его не надо проверять.
        """
        func = call.func

        # Форма 1: ``<jwt-alias>.encode(...)`` или ``<jwt-alias>.decode(...)``
        # после ``import jwt [as ...]``.
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in jwt_module_aliases
        ):
            if func.attr == _ENCODE_FUNC:
                return "encode"
            if func.attr == _DECODE_FUNC:
                return "decode"
            return None

        # Форма 2: ``encode(...)`` / ``decode(...)`` после
        # ``from jwt import encode/decode [as ...]``.
        if isinstance(func, ast.Name):
            if func.id in encode_aliases:
                return "encode"
            if func.id in decode_aliases:
                return "decode"

        return None

    # ------------------------------------------------------------------
    # Проверки конкретных нарушений
    # ------------------------------------------------------------------
    @staticmethod
    def _algorithm_value_if_none(call: ast.Call) -> str | None:
        """Если kwarg ``algorithm`` — литерал, эквивалентный ``'none'``,
        вернуть оригинальное написание (с сохранением регистра).

        Регистр сохраняется, чтобы message правила сообщил то же значение,
        которое стоит в коде (``'NONE'`` / ``'None'`` / ``'none'`` —
        наглядность для пользователя).
        """
        node = JwtMisuseRule._get_kwarg(call, "algorithm")
        value = JwtMisuseRule._literal_str(node)
        if value is None:
            return None
        if value.lower() == "none":
            return value
        return None

    @staticmethod
    def _none_in_algorithms_list(call: ast.Call) -> str | None:
        """Если kwarg ``algorithms`` — список с литералом ``'none'`` (cs-i),
        вернуть оригинальное написание первого совпавшего элемента.

        Положение элемента в списке не важно — наличие ``'none'`` в любой
        позиции означает, что декодер согласится принять токен без подписи.
        """
        node = JwtMisuseRule._get_kwarg(call, "algorithms")
        if not isinstance(node, ast.List):
            return None
        for elt in node.elts:
            value = JwtMisuseRule._literal_str(elt)
            if value is not None and value.lower() == "none":
                return value
        return None

    @staticmethod
    def _disabled_verify_keys(call: ast.Call) -> list[str]:
        """Все ключи из ``DANGEROUS_VERIFY_KEYS`` со значением ``False``
        в kwarg ``options``. Порядок сохраняется, как в исходном словаре,
        чтобы message читался естественно («verify_signature, verify_aud»).

        Используется ``is False`` (не ``== False``), чтобы случайно
        не засчитать ``0`` как False. PyJWT во внутреннем сравнении
        полагается на ``not value``, но у литералов AST ``Constant(False)``
        и ``Constant(0)`` различимы статически — мы фиксируем именно
        семантически явное «отключить проверку».
        """
        node = JwtMisuseRule._get_kwarg(call, "options")
        if not isinstance(node, ast.Dict):
            return []

        bad: list[str] = []
        for key_node, value_node in zip(node.keys, node.values):
            # ast.Dict.keys содержит ``None`` для записи ``**unpacking``
            # (``{**other_dict}``); такие ключи пропускаем — потоковый
            # анализ не делаем.
            key = JwtMisuseRule._literal_str(key_node)
            if key is None or key not in DANGEROUS_VERIFY_KEYS:
                continue
            if (
                isinstance(value_node, ast.Constant)
                and value_node.value is False
            ):
                bad.append(key)
        return bad

    # ------------------------------------------------------------------
    # Сообщения и suggestion'ы
    # ------------------------------------------------------------------
    @staticmethod
    def _build_alg_none_encode_message(algo: str) -> str:
        return (
            f"JWT issued with algorithm='{algo}' — token is unsigned and "
            f"can be forged by anyone (CWE-327, CWE-347)."
        )

    @staticmethod
    def _build_alg_none_decode_message(algo: str) -> str:
        return (
            f"JWT decode accepts '{algo}' in `algorithms=[...]` — attacker "
            f"can submit an unsigned token and bypass signature check "
            f"(CWE-347)."
        )

    @staticmethod
    def _build_alg_none_suggestion() -> str:
        return (
            "use a real algorithm (HS256/RS256/ES256) when issuing; "
            "pass an explicit `algorithms=[...]` list without 'none' to "
            "`jwt.decode`"
        )

    @staticmethod
    def _build_verify_off_message(keys: list[str]) -> str:
        # Порядок ключей сохраняется как в исходном словаре — это удобнее
        # пользователю при поиске нарушения в большом dict.
        keys_str = ", ".join(f"{k}=False" for k in keys)
        return (
            f"JWT decode with verification disabled: {keys_str}. "
            f"Signature or claim validation is bypassed (CWE-347)."
        )

    @staticmethod
    def _build_verify_off_suggestion() -> str:
        return (
            "do not disable JWT verification; remove "
            "`options={'verify_*': False}`. If you need claim-specific "
            "behavior, pass `audience=`/`issuer=` to `jwt.decode` "
            "explicitly instead of disabling `verify_aud` / `verify_iss`"
        )

    # ------------------------------------------------------------------
    # Главный метод
    # ------------------------------------------------------------------
    def check(self, tree: ast.AST, source: str, filename: str) -> list[Finding]:
        jwt_aliases, encode_aliases, decode_aliases = self._collect_imports(tree)
        # Если в файле нет ни одного релевантного импорта — проверять нечего.
        if not (jwt_aliases or encode_aliases or decode_aliases):
            return []

        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            kind = self._identify_call(
                node, jwt_aliases, encode_aliases, decode_aliases
            )
            if kind is None:
                continue

            if kind == "encode":
                # Ветвь 1: algorithm='none' при выпуске токена.
                bad_algo = self._algorithm_value_if_none(node)
                if bad_algo is not None:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=self._build_alg_none_encode_message(bad_algo),
                            filename=filename,
                            line=node.lineno,
                            col=node.col_offset,
                            suggestion=self._build_alg_none_suggestion(),
                        )
                    )
                # Других проверок для encode нет — у jwt.encode нет options/
                # algorithms аргументов, влияющих на верификацию.
                continue

            # kind == "decode" — две независимые проверки. Один Call может
            # дать оба finding'а: и про 'none' в algorithms, и про
            # verify_*=False в options. Это намеренно: семантически это
            # разные нарушения одного и того же decode-вызова.
            bad_alg = self._none_in_algorithms_list(node)
            if bad_alg is not None:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=self._build_alg_none_decode_message(bad_alg),
                        filename=filename,
                        line=node.lineno,
                        col=node.col_offset,
                        suggestion=self._build_alg_none_suggestion(),
                    )
                )

            bad_keys = self._disabled_verify_keys(node)
            if bad_keys:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=self._build_verify_off_message(bad_keys),
                        filename=filename,
                        line=node.lineno,
                        col=node.col_offset,
                        suggestion=self._build_verify_off_suggestion(),
                    )
                )

        return findings
