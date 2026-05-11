# Прогон аналогов на кейсе hardcoded_jwt_secret

## Команды запуска

Bandit (из корня репозитория, bandit установлен в `.venv`):

```powershell
.\.venv\Scripts\bandit.exe -f json -o corpus\hardcoded_jwt_secret\_bandit_vuln.json corpus\hardcoded_jwt_secret\vulnerable.py
.\.venv\Scripts\bandit.exe -f json -o corpus\hardcoded_jwt_secret\_bandit_safe.json corpus\hardcoded_jwt_secret\safe.py
```

Semgrep (через WSL, локальный open-source набор правил):

```powershell
wsl -e env PATH=/home/alex/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off semgrep --metrics=off --config=/mnt/c/repos/semgrep-rules/python --json --output /mnt/c/repos/diploma/corpus/hardcoded_jwt_secret/_semgrep_vuln.json /mnt/c/repos/diploma/corpus/hardcoded_jwt_secret/vulnerable.py

wsl -e env PATH=/home/alex/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off semgrep --metrics=off --config=/mnt/c/repos/semgrep-rules/python --json --output /mnt/c/repos/diploma/corpus/hardcoded_jwt_secret/_semgrep_safe.json /mnt/c/repos/diploma/corpus/hardcoded_jwt_secret/safe.py
```

Semgrep запускался оффлайн с локального клона `semgrep/semgrep-rules` @ `fdc73542dfd6ff4efd8a6710310a4ee5326db6d7`, директория `python/`. Реестровый `p/python` через `semgrep.dev` не использовался: в предыдущих сессиях он был нестабилен, поэтому для сопоставимости применён локальный open-source набор, как в CRYPTO001–CRYPTO006.

CodeQL: не запускался. Для этого AST-only кейса уже есть измеримый пробел двух основных аналогов: полный пропуск Bandit и частичный семантический пропуск Semgrep на `key=`.

## Bandit

Версия: 1.9.4. Дата прогона: 2026-05-31.

### vulnerable.py

Bandit не сработал ни на одной ожидаемой строке. Все 6 ожидаемых срабатываний — FN.

| line | ожидалось (наше) | Bandit нашёл | вердикт |
|------|-------------------|--------------|---------|
| 17 | high, позиционный строковый секрет `"secret"` | — | FN |
| 22 | high, позиционный строковый секрет `"change_me"` | — | FN |
| 27 | high, kwarg `key="my-app-secret"` | — | FN |
| 32 | high, `import jwt as j`, позиционный строковый секрет | — | FN |
| 37 | high, `from jwt import encode`, позиционный строковый секрет | — | FN |
| 42 | high, `from jwt import encode as e`, bytes-литерал | — | FN |

Лишних срабатываний: 0.

### safe.py

Bandit: 0 срабатываний. FP = 0.

### Причина пробела

Bandit 1.9.4 не содержит правила для PyJWT `jwt.encode` и не проверяет источник signing key. Это тот же систематический пробел по библиотеке PyJWT, который уже зафиксирован в CRYPTO005, но здесь он проявляется на управлении секретом, а не на отключении проверки подписи.

## Semgrep

Версия: 1.161.0. Дата прогона: 2026-05-31. Источник правил: локальный open-source `semgrep-rules/python` @ `fdc73542dfd6ff4efd8a6710310a4ee5326db6d7`.

### vulnerable.py

По теме hardcoded JWT secret Semgrep сработал на 5 строках из 6. Пропущена kwarg-форма `key="..."` на L27.

| line | ожидалось (наше) | Semgrep по теме | вердикт |
|------|-------------------|-----------------|---------|
| 17 | high, позиционный строковый секрет `"secret"` | `jwt-python-hardcoded-secret` ERROR | TP |
| 22 | high, позиционный строковый секрет `"change_me"` | `jwt-python-hardcoded-secret` ERROR | TP |
| 27 | high, kwarg `key="my-app-secret"` | — | FN |
| 32 | high, `import jwt as j`, позиционный строковый секрет | `jwt-python-hardcoded-secret` ERROR | TP |
| 37 | high, `from jwt import encode`, позиционный строковый секрет | `jwt-python-hardcoded-secret` ERROR | TP |
| 42 | high, `from jwt import encode as e`, bytes-литерал | `jwt-python-hardcoded-secret` ERROR | TP |

Дополнительно по другой теме Semgrep выдал `jwt-python-exposed-data` WARNING на всех строках с `jwt.encode`: 17, 22, 27, 32, 37, 42. Это общее предупреждение про данные в payload и не является TP по теме hardcoded secret.

### safe.py

По теме hardcoded JWT secret: 0 срабатываний. FP по теме = 0.

Шум по другой теме: `jwt-python-exposed-data` WARNING на строках 35, 40, 45, 50, 55, 60. Это срабатывания на безопасных вызовах `jwt.encode`, где секрет приходит из окружения, параметра, конфигурации или KMS-функции. CRYPTO007 такого шума не порождает, потому что проверяет только literal signing key.

### Причина пробела

Правило Semgrep `jwt-python-hardcoded-secret` распознаёт позиционную форму второго аргумента `jwt.encode(payload, "...")`, включая alias/import варианты, но не покрывает keyword-форму `key="..."`. Для PyJWT эти формы эквивалентны: `key` — документированный параметр signing key. Поэтому L27 — семантический FN.

## CodeQL

Не запускался. Обоснование: кейс уже классифицируется по Bandit и Semgrep; CodeQL полезнее подключать к будущим dataflow-кейсам, где источник секрета передаётся через переменную или конфигурацию.

## Итог

Класс кейса: **продвинутый**.

Обоснование:

- **Ось 1 (полное отсутствие у Bandit)**: Bandit 1.9.4 не имеет правила для PyJWT signing key — 0/6 TP.
- **Ось 3 (семантический пропуск у Semgrep)**: Semgrep покрывает позиционный литерал, но пропускает эквивалентную kwarg-форму `key="..."`; дополнительно шумит `jwt-python-exposed-data` на безопасных `jwt.encode`.

Что закрывает CRYPTO007 сверх аналогов:

1. Поддержка обеих форм signing key: второй позиционный аргумент и `key=`.
2. Поддержка alias-mapping для PyJWT: `import jwt`, `import jwt as j`, `from jwt import encode`, `from jwt import encode as e`.
3. Строковые и bytes-литералы считаются одинаково опасными.
4. Один уровень severity — `high`, потому что проблема в хранении секрета в исходниках, а не в длине литерала.
5. Rule-specific сообщение и suggestion без шума на безопасном `jwt.encode`.

Известные ограничения MVP:

- переменная с литералом (`secret = "hardcoded"; jwt.encode(payload, secret)`) не ловится;
- f-string (`f"{prefix}-secret"`) и конкатенация строк (`"abc" + "def"`) не ловятся;
- `settings.JWT_SECRET` и другие config object формы считаются безопасными или неизвестными;
- `jwt.decode(...)` не проверяется;
- `algorithm="none"` остаётся зоной CRYPTO005.
