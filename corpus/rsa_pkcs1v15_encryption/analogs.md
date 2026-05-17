# Прогон аналогов на кейсе rsa_pkcs1v15_encryption

## Команды запуска

Bandit (из корня репозитория, через Poetry):

```
poetry run bandit -f json -o corpus/rsa_pkcs1v15_encryption/_bandit_vuln.json corpus/rsa_pkcs1v15_encryption/vulnerable.py
poetry run bandit -f json -o corpus/rsa_pkcs1v15_encryption/_bandit_safe.json corpus/rsa_pkcs1v15_encryption/safe.py
```

Semgrep (из WSL, локальный клон `semgrep-rules`):

```
wsl -e env PATH=/home/alex/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off semgrep --metrics=off --config=/mnt/c/repos/semgrep-rules/python --json --output /mnt/c/repos/diploma/corpus/rsa_pkcs1v15_encryption/_semgrep_vuln.json /mnt/c/repos/diploma/corpus/rsa_pkcs1v15_encryption/vulnerable.py
wsl -e env PATH=/home/alex/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off semgrep --metrics=off --config=/mnt/c/repos/semgrep-rules/python --json --output /mnt/c/repos/diploma/corpus/rsa_pkcs1v15_encryption/_semgrep_safe.json /mnt/c/repos/diploma/corpus/rsa_pkcs1v15_encryption/safe.py
```

CodeQL: не запускался. Кейс уже подтверждает полный двойной пробел Bandit и Semgrep для AST-only проверки без потокового анализа.

Контекст: прогон проводился на расширенном корпусе из 4 уязвимых сценариев. Это расширение разведочного набора из `C:/repos/diploma_scouting/candidate_rsa_pkcs1v15_encryption/`, где было 2 сценария (`encrypt` и `decrypt` через `padding.PKCS1v15()`).

## Bandit

Версия: 1.9.4. Дата прогона: 2026-05-31.

### vulnerable.py

По теме RSA PKCS#1 v1.5 encryption padding Bandit не нашёл ни одного из 4 ожидаемых срабатываний.

| line | ожидалось (наше)                                      | Bandit нашёл | вердикт |
|------|-------------------------------------------------------|---------------|---------|
| 15   | high (`public_key.encrypt(..., padding.PKCS1v15())`)  | —             | FN      |
| 20   | high (`private_key.decrypt(..., padding.PKCS1v15())`) | —             | FN      |
| 25   | high (`public_key.encrypt(..., asym_padding.PKCS1v15())`) | —         | FN      |
| 30   | high (`private_key.decrypt(..., PKCS1v15())`)         | —             | FN      |

Лишних срабатываний: 0.

Итог по vulnerable.py: TP=0, FN=4, FP=0.

### safe.py

Bandit не выдал срабатываний. FP=0, включая безопасные сценарии RSA-OAEP и сценарии `sign`/`verify` с `padding.PKCS1v15()`.

## Semgrep

Версия: 1.161.0. Дата прогона: 2026-05-31. Источник правил: локальный клон `semgrep/semgrep-rules` @ `fdc73542dfd6ff4efd8a6710310a4ee5326db6d7`, директория `python/`.

### vulnerable.py

По теме RSA PKCS#1 v1.5 encryption padding Semgrep не нашёл ни одного из 4 ожидаемых срабатываний.

| line | ожидалось (наше)                                      | Semgrep нашёл | вердикт |
|------|-------------------------------------------------------|----------------|---------|
| 15   | high (`public_key.encrypt(..., padding.PKCS1v15())`)  | —              | FN      |
| 20   | high (`private_key.decrypt(..., padding.PKCS1v15())`) | —              | FN      |
| 25   | high (`public_key.encrypt(..., asym_padding.PKCS1v15())`) | —          | FN      |
| 30   | high (`private_key.decrypt(..., PKCS1v15())`)         | —              | FN      |

Лишних срабатываний: 0.

Итог по vulnerable.py: TP=0, FN=4, FP=0.

### safe.py

Semgrep не выдал срабатываний. FP=0, включая безопасные сценарии RSA-OAEP и сценарии `sign`/`verify` с `padding.PKCS1v15()`.

## Причина пробела

Bandit 1.9.4 не имеет правила, различающего RSA encryption/decryption padding `PKCS1v15()` и безопасную альтернативу OAEP в PyCA `cryptography`. Semgrep open-source ruleset также не содержит проверки на `cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15()` в контексте `.encrypt(...)` / `.decrypt(...)`.

Простая проверка самого факта вызова `PKCS1v15()` была бы некорректной: тот же padding допустим для RSA signatures (`sign`/`verify`). Поэтому правило должно учитывать контекст метода и флаговать только RSA encryption/decryption.

## Итог

Класс кейса: **продвинутый**. Обоснование: полный двойной пробел Bandit и Semgrep на расширенном корпусе из 4 сценариев: оба аналога дают 0/4 TP, 4 FN, 0 FP.

Что закрывает наше правило CRYPTO009 сверх аналогов:

1. Распознаёт `padding.PKCS1v15()` внутри RSA `.encrypt(...)` и `.decrypt(...)`.
2. Поддерживает alias-import `padding as asym_padding`.
3. Поддерживает direct import `from ...padding import PKCS1v15`.
4. Не даёт FP на `private_key.sign(..., padding.PKCS1v15(), ...)` и `public_key.verify(..., padding.PKCS1v15(), ...)`.

Известное ограничение MVP: padding, сохранённый в переменную (`pad = padding.PKCS1v15(); public_key.encrypt(message, pad)`), не флагуется. Это сознательное ограничение AST-only правила без dataflow.
