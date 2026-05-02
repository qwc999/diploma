Прогон аналогов на кейсе pbkdf2_low_iterations

# Команды запуска

Bandit (из корня репозитория, bandit установлен в .venv):

```
.venv/Scripts/bandit.exe -f json -o corpus/pbkdf2_low_iterations/_bandit_vuln.json corpus/pbkdf2_low_iterations/vulnerable.py
.venv/Scripts/bandit.exe -f json -o corpus/pbkdf2_low_iterations/_bandit_safe.json corpus/pbkdf2_low_iterations/safe.py
```

Semgrep (из WSL, semgrep установлен в `~/.local/bin`):

```
export PATH="$HOME/.local/bin:$PATH"
semgrep --metrics=off --config=/mnt/c/repos/semgrep-rules/python --json \
  --output /mnt/c/repos/diploma/corpus/pbkdf2_low_iterations/_semgrep_vuln.json \
  /mnt/c/repos/diploma/corpus/pbkdf2_low_iterations/vulnerable.py
semgrep --metrics=off --config=/mnt/c/repos/semgrep-rules/python --json \
  --output /mnt/c/repos/diploma/corpus/pbkdf2_low_iterations/_semgrep_safe.json \
  /mnt/c/repos/diploma/corpus/pbkdf2_low_iterations/safe.py
```

Конфигурация запускалась оффлайн с локального клона `semgrep/semgrep-rules` @ `fdc73542dfd6ff4efd8a6710310a4ee5326db6d7` (директория `C:/repos/semgrep-rules`, ветка default, depth=1). Реестр `p/python` через `semgrep.dev` не прогонялся — 2026-04-25 при разведке был ReadTimeoutError.

CodeQL: не запускался. Кейс не базовый, но Bandit и Semgrep оба пропускают его по понятной систематической причине (никакой из них не проверяет числовое значение `iterations`); запуск CodeQL добавит статистики, но не закроет дополнительный пробел в постановке кейса.

Контекст: прогон проводился на расширенном vulnerable.py (8 сценариев) — это надстройка над минимальным разведочным набором из 3 сценариев, который лежит в `C:/repos/diploma_scouting/candidate_pbkdf2_low_iterations/`. Расширения: hashlib.pbkdf2_hmac (3 сценария — позиционный 4-й аргумент, SHA-1 и SHA-512), один medium-сценарий ниже порога SHA-256, один medium-сценарий ниже порога SHA-512.

# Bandit

Версия: 1.9.4. Дата прогона: 2026-04-28.

## vulnerable.py

Сработал на: 0 строк из 8 ожидаемых. Все 8 ожидаемых срабатываний — FN.

| line | ожидалось (наше)                                  | Bandit нашёл | вердикт |
|------|---------------------------------------------------|--------------|---------|
| 25   | high (PBKDF2HMAC SHA-256 100)                     | —            | FN      |
| 31   | high (PBKDF2HMAC SHA-256 1000)                    | —            | FN      |
| 37   | high (PBKDF2HMAC SHA-256 10_000)                  | —            | FN      |
| 43   | medium (PBKDF2HMAC SHA-256 400_000)               | —            | FN      |
| 49   | high (PBKDF2HMAC SHA-512 50_000)                  | —            | FN      |
| 55   | high (hashlib.pbkdf2_hmac sha256 100)             | —            | FN      |
| 60   | high (hashlib.pbkdf2_hmac sha1 100_000)           | —            | FN      |
| 65   | medium (pbkdf2_hmac sha512 150_000)               | —            | FN      |

Лишние срабатывания (FP): 0.

## safe.py

Сработал на: 0 строк. FP: 0.

## Причина

В Bandit нет правила, проверяющего значение `iterations` у `PBKDF2HMAC` или `hashlib.pbkdf2_hmac`. Проверка ограничивается фактом использования слабых криптопримитивов (B311, B324, B505 и др.) — числовые пороги OWASP не закодированы.

# Semgrep

Версия: 1.161.0. Дата прогона: 2026-04-28. Источник правил: локальный клон `semgrep/semgrep-rules` @ `fdc73542dfd6ff4efd8a6710310a4ee5326db6d7`, директория `python/` (371 правило, языки python + multilang). Реестр `p/python` через `semgrep.dev` остаётся не прогнан.

## vulnerable.py

Сработал на: 0 строк из 8 ожидаемых. Все 8 ожидаемых срабатываний — FN.

| line | ожидалось (наше)                                  | Semgrep нашёл | вердикт |
|------|---------------------------------------------------|---------------|---------|
| 25   | high (PBKDF2HMAC SHA-256 100)                     | —             | FN      |
| 31   | high (PBKDF2HMAC SHA-256 1000)                    | —             | FN      |
| 37   | high (PBKDF2HMAC SHA-256 10_000)                  | —             | FN      |
| 43   | medium (PBKDF2HMAC SHA-256 400_000)               | —             | FN      |
| 49   | high (PBKDF2HMAC SHA-512 50_000)                  | —             | FN      |
| 55   | high (hashlib.pbkdf2_hmac sha256 100)             | —             | FN      |
| 60   | high (hashlib.pbkdf2_hmac sha1 100_000)           | —             | FN      |
| 65   | medium (pbkdf2_hmac sha512 150_000)               | —             | FN      |

Лишние срабатывания (FP): 0.

## safe.py

Сработал на: 0 строк. FP: 0.

## Причина

В open-source наборе `semgrep/semgrep-rules` под `python/` (на коммите `fdc73542`) нет правила, проверяющего значение параметра `iterations` у PBKDF2. Поиск по тексту правил подтверждает: вхождения `pbkdf2` встречаются только в `cryptography/audit/` (упоминание PBKDF2 как факт KDF), числовых порогов нет.

## Допущение

Реестровый пакет `p/python` от Semgrep, недоступный в этом прогоне, может включать дополнительные правила сверх open-source `semgrep-rules`. До прогона `--config=p/python` вывод по Semgrep считаем предварительным.

# CodeQL

Не запускался. Обоснование выше.

# Итог

Класс кейса: **продвинутый**. Обоснование: Bandit и Semgrep оба пропустили все 8 ожидаемых срабатываний (0 TP, 8 FN). Причина систематическая, а не точечная: ни один из них не реализует семантику «числовое сравнение значения kwarg/позиционного аргумента с числовым порогом из стандарта». Полный двойной пробел.

Что закрывает наше правило CRYPTO002 сверх аналогов:

1. Численная проверка `iterations` против OWASP-2023 порогов: SHA-1 → 1 300 000, SHA-256 → 600 000, SHA-512 → 210 000.
2. Hash-зависимый порог: правило извлекает фактический hash-алгоритм из вызова (для PBKDF2HMAC — из kwarg `algorithm=hashes.<HASH>()`, для hashlib.pbkdf2_hmac — из первого позиционного аргумента-строки) и применяет порог именно этого алгоритма. При нераспознанном алгоритме применяется самый строгий порог 1 300 000.
3. Двухуровневая severity: `high`, если итераций меньше половины порога (грубое нарушение); `medium`, если выше половины, но ниже порога (отставание есть, но не катастрофическое).
4. Покрытие двух форм одним правилом: и `cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC` (с алиасами через `from … import … as`), и `hashlib.pbkdf2_hmac` (через `import hashlib` + атрибут, и через `from hashlib import pbkdf2_hmac`).
5. Suggestion с конкретным целевым числом и алгоритмом, плюс упоминание Argon2 / scrypt как современных альтернатив.

Известное ограничение MVP: если `iterations` задан переменной (а не литералом), правило молчит. Это согласованный компромисс — без потокового анализа отличить безопасный конфиг (`ITER = 600_000`) от опасного (`ITER = 100`) невозможно, и срабатывание на «неизвестно» гарантированно даст FP в реальном коде. Вынесенный отдельно сценарий с переменной может быть оформлен как новый кейс с расширенным правилом.
