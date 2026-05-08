# Прогон аналогов на кейсе non_constant_time_compare

## Команды запуска

Bandit (из корня репозитория, bandit установлен в `.venv`):

```
.\.venv\Scripts\bandit.exe -f json -o corpus\non_constant_time_compare\_bandit_vuln.json corpus\non_constant_time_compare\vulnerable.py
.\.venv\Scripts\bandit.exe -f json -o corpus\non_constant_time_compare\_bandit_safe.json corpus\non_constant_time_compare\safe.py
```

Semgrep (из WSL, локальный open-source набор `semgrep-rules/python`):

```
wsl -e env PATH=/home/alex/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off semgrep --metrics=off --config=/mnt/c/repos/semgrep-rules/python --json --output /mnt/c/repos/diploma/corpus/non_constant_time_compare/_semgrep_vuln.json /mnt/c/repos/diploma/corpus/non_constant_time_compare/vulnerable.py

wsl -e env PATH=/home/alex/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off semgrep --metrics=off --config=/mnt/c/repos/semgrep-rules/python --json --output /mnt/c/repos/diploma/corpus/non_constant_time_compare/_semgrep_safe.json /mnt/c/repos/diploma/corpus/non_constant_time_compare/safe.py
```

Конфигурация Semgrep запускалась оффлайн с локального клона `semgrep/semgrep-rules` (директория `C:/repos/semgrep-rules`, набор `python/`, 371 правило в отчёте). Реестровый `p/python` не использовался в качестве блокирующего источника из-за ранее зафиксированной нестабильности `semgrep.dev`; для CRYPTO006, как и для предыдущих правил, фиксируется результат локального open-source набора.

CodeQL: не запускался. Для этого кейса полный двойной пробел Bandit/Semgrep уже подтверждён, а само правило не требует межпроцедурного анализа.

Дата прогона: 2026-05-31.

## Bandit

Версия: 1.9.4.

### vulnerable.py

Bandit не сработал ни на одной строке. Все 6 ожидаемых срабатываний — FN.

| line | ожидалось (наше) | Bandit нашёл | вердикт |
|------|------------------|--------------|---------|
| 9    | high (`received == expected_signature`) | — | FN |
| 14   | high (`provided_token != stored_token`) | — | FN |
| 20   | high (`mac == expected_mac`) | — | FN |
| 25   | high (`password_hash == expected_hash`) | — | FN |
| 30   | high (`digest == expected_digest`) | — | FN |
| 35   | high (`hmac_value == expected_hmac`) | — | FN |

Лишние срабатывания: 0.

### safe.py

Bandit: 0 срабатываний. FP = 0.

### Причина пробела

Bandit 1.9.4 не содержит правила, которое связывает операторы сравнения `==` / `!=` с криптографически чувствительными именами переменных. Это не blacklist-вызов конкретного API, а контекстная проверка обычного AST-узла `Compare`, поэтому стандартные правила Bandit на этом корпусе не реагируют.

## Semgrep

Версия: 1.161.0. Источник правил: локальный open-source набор `semgrep-rules/python`.

### vulnerable.py

Semgrep не сработал ни на одной строке. Все 6 ожидаемых срабатываний — FN.

| line | ожидалось (наше) | Semgrep нашёл | вердикт |
|------|------------------|---------------|---------|
| 9    | high (`received == expected_signature`) | — | FN |
| 14   | high (`provided_token != stored_token`) | — | FN |
| 20   | high (`mac == expected_mac`) | — | FN |
| 25   | high (`password_hash == expected_hash`) | — | FN |
| 30   | high (`digest == expected_digest`) | — | FN |
| 35   | high (`hmac_value == expected_hmac`) | — | FN |

Лишние срабатывания: 0.

### safe.py

Semgrep: 0 срабатываний. FP = 0.

### Причина пробела

В локальном open-source наборе `semgrep-rules/python` нет правила для non-constant-time comparison в Python. Набор не сопоставляет обычные операторы `==` / `!=` с именами вроде `expected_signature`, `provided_token`, `expected_mac`, `password_hash`, `digest` и `hmac_value`, поэтому все сценарии проходят без находок.

## Граница кейса

CRYPTO006 — эвристика по именам, как CRYPTO001, но для сравнений. Правило считает сегмент `mac` криптографическим Message Authentication Code. Спорные бизнес-имена вроде `mac_address` в корпус намеренно не включены: без типовой информации AST-only правило не отличает сетевой MAC-адрес от MAC-аутентификатора. Эта граница зафиксирована как ограничение MVP, а не как false positive в текущем корпусе.

Правило также намеренно не проверяет:

- цепочки сравнений `a == b == c`;
- сравнения результата вызова функции, например `get_token() == expected`;
- dataflow вида `x = token; x == expected_token`;
- сложные выражения и индексацию, если имя значения не видно как `Name` или `Attribute`;
- кастомные wrapper-функции вокруг `hmac.compare_digest` / `secrets.compare_digest`.

## Итог

Класс кейса: **продвинутый**.

Обоснование: Bandit 1.9.4 и Semgrep 1.161.0 на финальном корпусе из 6 сценариев дали 0/6 TP, 6 FN и 0 FP на safe-файле. Это полный двойной пробел по оси 1, а правило закрывает его через ось 4: контекст по именам переменных, уже принятый в CRYPTO001, но применённый к сравнениям криптографических значений.

Что закрывает наш линтер сверх аналогов:

1. AST-проверку `Compare` для операторов `==` и `!=`.
2. Локальный словарь чувствительных имён для сравнений: `signature`, `sig`, `mac`, `hmac`, `digest`, `hash`, `password_hash` плюс базовые crypto-имена `token`, `key`, `secret`, `password`, `session_id`, `api_key` и т.п.
3. Поддержку `ast.Name` и `ast.Attribute`, например `token == expected_token` и `self.signature == expected_signature`.
4. Единый `high` severity и suggestion на `hmac.compare_digest` / `secrets.compare_digest`, для `!=` — на `not compare_digest(...)`.
