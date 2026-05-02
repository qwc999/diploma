Прогон аналогов на кейсе random_lib_for_crypto

# Команды запуска

Bandit (из корня репозитория, bandit установлен в .venv):

```
.venv/Scripts/bandit.exe -f json -o corpus/random_lib_for_crypto/_bandit_vuln.json corpus/random_lib_for_crypto/vulnerable.py
.venv/Scripts/bandit.exe -f json -o corpus/random_lib_for_crypto/_bandit_safe.json corpus/random_lib_for_crypto/safe.py
```

Semgrep (из WSL, semgrep установлен в `~/.local/bin`):

```
export PATH="$HOME/.local/bin:$PATH"
semgrep --metrics=off --config=/mnt/c/repos/semgrep-rules/python --json \
  --output /mnt/c/repos/diploma/corpus/random_lib_for_crypto/_semgrep_vuln.json \
  /mnt/c/repos/diploma/corpus/random_lib_for_crypto/vulnerable.py
semgrep --metrics=off --config=/mnt/c/repos/semgrep-rules/python --json \
  --output /mnt/c/repos/diploma/corpus/random_lib_for_crypto/_semgrep_safe.json \
  /mnt/c/repos/diploma/corpus/random_lib_for_crypto/safe.py
```

Конфигурация запускалась оффлайн с локального клона `semgrep/semgrep-rules` @ `fdc73542dfd6ff4efd8a6710310a4ee5326db6d7` (директория `C:/repos/semgrep-rules`, ветка default, depth=1). Реестр `p/python` через `semgrep.dev` недоступен: ReadTimeoutError при загрузке правил.

CodeQL: не запускается на базовых кейсах. Подключим на первом продвинутом.

# Bandit

Версия: 1.9.4. Дата прогона: 2026-04-24; повторно воспроизведён 2026-04-27 (числа идентичны, см. `_bandit_vuln.json` / `_bandit_safe.json`).

## vulnerable.py

Сработал на 6 строках из 6 ожидаемых.

| line | test_id | severity | confidence | issue_text                                                                       |
|------|---------|----------|------------|----------------------------------------------------------------------------------|
| 17   | B311    | LOW      | HIGH       | Standard pseudo-random generators are not suitable for security/cryptographic... |
| 23   | B311    | LOW      | HIGH       | Standard pseudo-random generators are not suitable for security/cryptographic... |
| 29   | B311    | LOW      | HIGH       | Standard pseudo-random generators are not suitable for security/cryptographic... |
| 35   | B311    | LOW      | HIGH       | Standard pseudo-random generators are not suitable for security/cryptographic... |
| 41   | B311    | LOW      | HIGH       | Standard pseudo-random generators are not suitable for security/cryptographic... |
| 48   | B311    | LOW      | HIGH       | Standard pseudo-random generators are not suitable for security/cryptographic... |

Вердикт по каждой ожидаемой строке expected.json:

| line | ожидалось (наше) | Bandit нашёл | вердикт TP/FN | расхождение с нашим правилом                |
|------|------------------|--------------|---------------|-------------------------------------------|
| 17   | high (token)     | B311 LOW     | TP            | Bandit не различает крипто-контекст        |
| 23   | high (reset_token) | B311 LOW   | TP            | то же                                      |
| 29   | high (iv)        | B311 LOW     | TP            | то же                                      |
| 35   | high (salt)      | B311 LOW     | TP            | то же                                      |
| 41   | high (nonce)     | B311 LOW     | TP            | то же                                      |
| 48   | medium (no-crypto) | B311 LOW   | TP            | случайно совпадает по уровню (но по другой причине — Bandit всегда LOW) |

Лишние срабатывания (FP): 0.

## safe.py

Сработал на: 0 строк. FP: 0.

Проверено явно: `secrets.choice`, `secrets.randbelow`, `secrets.token_bytes`, `os.urandom`, `random.SystemRandom().choice(...)` не триггерят B311.

# Semgrep

Версия: 1.161.0. Дата прогона: 2026-04-25; повторно воспроизведён 2026-04-27 на `vulnerable.py` (числа идентичны, см. `_semgrep_vuln.json`; `safe.py` в повторе не прогонялся, актуальный результат по нему — от 2026-04-25). Источник правил: локальный клон `semgrep/semgrep-rules` @ `fdc73542dfd6ff4efd8a6710310a4ee5326db6d7`, директория `python/` (371 правило, языки python + multilang). Реестр `p/python` через `semgrep.dev` остаётся не прогнан: 2026-04-25 — `ReadTimeoutError`, 2026-04-27 — повторная попытка не делалась.

## vulnerable.py

Сработал на: 0 строк из 6 ожидаемых. Все 6 ожидаемых срабатываний — FN.

| line | ожидалось (наше)   | Semgrep нашёл | вердикт |
|------|--------------------|---------------|---------|
| 17   | high (token)       | —             | FN      |
| 23   | high (reset_token) | —             | FN      |
| 29   | high (iv)          | —             | FN      |
| 35   | high (salt)        | —             | FN      |
| 41   | high (nonce)       | —             | FN      |
| 48   | medium (no-crypto) | —             | FN      |

Лишние срабатывания (FP): 0.

## safe.py

Сработал на: 0 строк. FP: 0.

## Причина

В open-source наборе `semgrep/semgrep-rules` под `python/` (на коммите `fdc73542`) нет ни одного правила, проверяющего использование функций модуля `random` в крипто-контексте. По grep-проверке слово `random` встречается только в `insecure-uuid-version.yaml` (про `uuid1` vs `uuid4`) и в JWT/boto-правилах (где речь не о `random`-модуле). Аналог Bandit B311 в open-source реестре отсутствует.

## Допущение

Реестровый пакет `p/python` от Semgrep, недоступный в этом прогоне, может включать дополнительные правила сверх open-source `semgrep-rules`. Подтвердить или опровергнуть удастся только после прогона с `--config=p/python`. До тех пор вывод считаем предварительным.

# CodeQL

Не запускался на этом кейсе. Обоснование: кейс базовый, Bandit уже показал TP по всем строкам.

# Итог

Класс кейса: базовый. Обоснование: Bandit (B311) нашёл все 6 ожидаемых срабатываний с confidence HIGH, FP на safe.py отсутствуют.

Чем наше правило CRYPTO001 превосходит Bandit B311 на этом же кейсе:

1. Контекстная severity. Bandit выставляет LOW всем срабатываниям одинаково. Наше правило ставит `high`, если имя цели (переменная, аргумент, имя функции) совпадает со словарём крипто-терминов (`token`, `key`, `iv`, `nonce`, `secret`, `password`, `salt`, `session_id`, `api_key`), и `medium` иначе. В пользовательском интерфейсе линтера это даёт приоритезацию: «сначала чини high».
2. Явное сообщение с привязкой к контексту. Вместо обобщённого "Standard pseudo-random generators are not suitable..." — сообщение вида "Weak random for cryptographic purposes: value is assigned to `token` — use `secrets.choice(...)` instead of `random.choice(...)`".
3. Предложение замены (suggestion) на уровне конкретного вызова: `random.choice` → `secrets.choice`, `random.randbytes(n)` → `secrets.token_bytes(n)`, `random.randint(a, b)` → `a + secrets.randbelow(b - a + 1)`, `random.getrandbits(k)` → `secrets.randbits(k)`. У Bandit предложений нет.

Bandit-паритет: наше правило обязано поймать те же 6 строк и не сработать на safe.py. Это пункт приёмки в `expected.json`.

Пробел Semgrep на этом же кейсе: open-source набор правил `semgrep/semgrep-rules` для Python не содержит правила про `random`-модуль (0/6 TP, 6 FN на vulnerable.py). Наше правило CRYPTO001 закрывает этот пробел напрямую. Финальная классификация Semgrep'а зависит от прогона `--config=p/python` через Registry — отложено до восстановления доступа к `semgrep.dev`.
