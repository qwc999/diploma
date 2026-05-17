# Прогон аналогов на кейсе tls_old_protocol_constant

## Команды запуска

Bandit (из корня репозитория, bandit установлен в `.venv`):

```powershell
poetry run bandit -f json -o corpus/tls_old_protocol_constant/_bandit_vuln.json corpus/tls_old_protocol_constant/vulnerable.py
poetry run bandit -f json -o corpus/tls_old_protocol_constant/_bandit_safe.json corpus/tls_old_protocol_constant/safe.py
```

Semgrep (через WSL, локальный open-source набор правил):

```powershell
wsl -e env PATH=/home/alex/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off semgrep --metrics=off --config=/mnt/c/repos/semgrep-rules/python --json --output /mnt/c/repos/diploma/corpus/tls_old_protocol_constant/_semgrep_vuln.json /mnt/c/repos/diploma/corpus/tls_old_protocol_constant/vulnerable.py

wsl -e env PATH=/home/alex/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off semgrep --metrics=off --config=/mnt/c/repos/semgrep-rules/python --json --output /mnt/c/repos/diploma/corpus/tls_old_protocol_constant/_semgrep_safe.json /mnt/c/repos/diploma/corpus/tls_old_protocol_constant/safe.py
```

Semgrep запускался оффлайн с локального клона `semgrep/semgrep-rules` @ `fdc73542dfd6ff4efd8a6710310a4ee5326db6d7`, директория `python/`. Реестровый `p/python` через `semgrep.dev` не использовался: для сопоставимости применён тот же локальный open-source набор, что и в предыдущих кейсах.

CodeQL: не запускался. Для этого AST-only кейса достаточно сравнения с Bandit и Semgrep; CodeQL оставлен для будущих dataflow-кейсов.

## Bandit

Версия: 1.9.4. Дата прогона: 2026-05-31.

### vulnerable.py

Bandit не сработал ни на одной ожидаемой строке. Все 4 ожидаемых срабатывания — FN.

| line | ожидалось (наше) | Bandit нашёл | вердикт |
|------|-------------------|--------------|---------|
| 11 | high, `ssl.SSLContext(ssl.PROTOCOL_TLSv1)` | — | FN |
| 16 | high, `s.SSLContext(s.PROTOCOL_TLSv1_1)` | — | FN |
| 21 | high, `SSLContext(PROTOCOL_SSLv23)` | — | FN |
| 26 | high, `TLSContext(SSL_V3)` | — | FN |

Лишних срабатываний: 0.

### safe.py

Bandit: 0 срабатываний. FP = 0.

### Причина пробела

Bandit 1.9.4 не срабатывает на stdlib-форму `ssl.SSLContext(ssl.PROTOCOL_*)`. Его SSL/TLS проверки ориентированы на другие API и настройки, поэтому прямой выбор устаревшей protocol-константы в конструкторе `SSLContext` остаётся незамеченным.

## Semgrep

Версия: 1.161.0. Дата прогона: 2026-05-31. Источник правил: локальный open-source `semgrep-rules/python` @ `fdc73542dfd6ff4efd8a6710310a4ee5326db6d7`.

### vulnerable.py

По теме устаревших TLS/SSL protocol-констант Semgrep сработал на 3 строках из 4. Пропущена legacy-константа `PROTOCOL_SSLv23` на L21.

| line | ожидалось (наше) | Semgrep по теме | вердикт |
|------|-------------------|-----------------|---------|
| 11 | high, `ssl.PROTOCOL_TLSv1` | `weak-ssl-version` WARNING | TP |
| 16 | high, `s.PROTOCOL_TLSv1_1` | `weak-ssl-version` WARNING | TP |
| 21 | high, `PROTOCOL_SSLv23` | — | FN |
| 26 | high, `SSL_V3` alias for `PROTOCOL_SSLv3` | `weak-ssl-version` WARNING | TP |

Лишних срабатываний: 0.

Сообщение Semgrep: `An insecure SSL version was detected. TLS versions 1.0, 1.1, and all SSL versions are considered weak encryption and are deprecated. Use 'ssl.PROTOCOL_TLSv1_2' or higher.`

### safe.py

Semgrep: 0 срабатываний. FP = 0.

### Причина пробела

Правило Semgrep `weak-ssl-version` знает про TLSv1, TLSv1_1 и SSLv3, включая alias-импорт SSLv3, но не покрывает `PROTOCOL_SSLv23`. Для современного кода эта константа всё равно является legacy-вариантом: имя унаследовано от SSLv2/SSLv3 era и заменяется более явными `PROTOCOL_TLS_CLIENT` / `PROTOCOL_TLS_SERVER` с `minimum_version`.

## CodeQL

Не запускался. Обоснование: кейс уже даёт измеримый результат по двум основным аналогам — полный пробел Bandit и частичный семантический пробел Semgrep.

## Итог

Класс кейса: **базовый**.

Обоснование: Semgrep покрывает 3 из 4 уязвимых сценариев, поэтому кейс не является полным двойным пробелом. При этом остаются два измеримых преимущества CRYPTO008:

1. Bandit 1.9.4 полностью пропускает stdlib `ssl.SSLContext(ssl.PROTOCOL_*)`: 0/4 TP.
2. Semgrep 1.161.0 пропускает `PROTOCOL_SSLv23`: 3/4 TP, 1 FN.

Что закрывает CRYPTO008 сверх аналогов:

1. Единая проверка всех legacy protocol-констант для `ssl.SSLContext`: `PROTOCOL_TLSv1`, `PROTOCOL_TLSv1_1`, `PROTOCOL_SSLv23`, `PROTOCOL_SSLv3`; в коде правила также заложен `PROTOCOL_SSLv2`.
2. Поддержка alias-mapping: `import ssl`, `import ssl as s`, `from ssl import SSLContext, PROTOCOL_SSLv23`, прямые alias-импорты.
3. Один уровень severity — `high`, потому что выбор устаревшего TLS/SSL протокола напрямую снижает безопасность канала.
4. Suggestion направляет к `PROTOCOL_TLS_CLIENT` / `PROTOCOL_TLS_SERVER` и явному `minimum_version`.

Известные ограничения MVP:

- переменная с protocol-константой (`proto = ssl.PROTOCOL_TLSv1; ssl.SSLContext(proto)`) не ловится;
- wrapper-функции вокруг `SSLContext` не анализируются;
- динамические выражения и dataflow не покрываются.
