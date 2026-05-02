Прогон аналогов на кейсе bcrypt_low_rounds

# Команды запуска

Bandit (из корня репозитория, bandit установлен в .venv):

```
.venv/Scripts/bandit.exe -f json -o corpus/bcrypt_low_rounds/_bandit_vuln.json corpus/bcrypt_low_rounds/vulnerable.py
.venv/Scripts/bandit.exe -f json -o corpus/bcrypt_low_rounds/_bandit_safe.json corpus/bcrypt_low_rounds/safe.py
```

Semgrep (из WSL, semgrep установлен в `~/.local/bin`):

```
wsl -e env PATH=/home/alex/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off semgrep --metrics=off --config=/mnt/c/repos/semgrep-rules/python --json --output /mnt/c/repos/diploma/corpus/bcrypt_low_rounds/_semgrep_vuln.json /mnt/c/repos/diploma/corpus/bcrypt_low_rounds/vulnerable.py
wsl -e env PATH=/home/alex/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off semgrep --metrics=off --config=/mnt/c/repos/semgrep-rules/python --json --output /mnt/c/repos/diploma/corpus/bcrypt_low_rounds/_semgrep_safe.json /mnt/c/repos/diploma/corpus/bcrypt_low_rounds/safe.py
```

Конфигурация Semgrep запускалась оффлайн с локального клона `semgrep/semgrep-rules` @ `fdc73542dfd6ff4efd8a6710310a4ee5326db6d7` (директория `C:/repos/semgrep-rules`, поддиректория `python/`). Реестр `p/python` через `semgrep.dev` не использовался в этом прогоне: для предыдущих правил он уже был нестабилен, поэтому для DoD применён локальный open-source набор правил.

CodeQL: не запускался. Кейс уже показывает полный двойной пробел Bandit и Semgrep на числовом параметре bcrypt; CodeQL отложен до кейсов, где нужен потоковый анализ.

Контекст: прогон проводился на полном корпусе из 4 уязвимых и 5 безопасных сценариев. Каждый уязвимый сценарий вынесен в отдельную функцию с префиксом `# VULN:`, каждый безопасный — с `# SAFE:`. Формы импорта: `import bcrypt`, `import bcrypt as bc`, `from bcrypt import gensalt`, `from bcrypt import gensalt as gs`.

# Bandit

Версия: 1.9.4. Дата прогона: 2026-04-29.

## vulnerable.py

Bandit не сработал ни на одной строке. Все 4 ожидаемых срабатывания — FN.

| line | ожидалось (наше)                                      | Bandit нашёл | вердикт |
|------|-------------------------------------------------------|--------------|---------|
| 11   | high (`bcrypt.gensalt(rounds=4)`)                     | —            | FN      |
| 16   | high (`bc.gensalt(rounds=8)`)                         | —            | FN      |
| 21   | medium (`gensalt(rounds=10)`)                         | —            | FN      |
| 26   | medium (`gs(rounds=11)`)                              | —            | FN      |

Лишних срабатываний: 0.

## safe.py

Bandit: 0 срабатываний. FP = 0.

## Причина пробела

В Bandit 1.9.4 нет правила, проверяющего числовое значение `rounds` у `bcrypt.gensalt`. Набор правил покрывает часть небезопасных криптопримитивов и режимов, но не сравнивает cost factor password hashing API с минимальным порогом.

# Semgrep

Версия: 1.161.0. Дата прогона: 2026-04-29. Источник правил: локальный клон `semgrep/semgrep-rules` @ `fdc73542dfd6ff4efd8a6710310a4ee5326db6d7`, директория `python/` (371 правил выполнено на файле).

## vulnerable.py

Semgrep не сработал ни на одной строке. Все 4 ожидаемых срабатывания — FN.

| line | ожидалось (наше)                                      | Semgrep нашёл | вердикт |
|------|-------------------------------------------------------|---------------|---------|
| 11   | high (`bcrypt.gensalt(rounds=4)`)                     | —             | FN      |
| 16   | high (`bc.gensalt(rounds=8)`)                         | —             | FN      |
| 21   | medium (`gensalt(rounds=10)`)                         | —             | FN      |
| 26   | medium (`gs(rounds=11)`)                              | —             | FN      |

Лишних срабатываний: 0.

## safe.py

Semgrep: 0 срабатываний. FP = 0.

## Причина пробела

В open-source наборе `semgrep/semgrep-rules` под `python/` нет правила, проверяющего значение параметра `rounds` у `bcrypt.gensalt`. Это тот же класс пробела, что и у CRYPTO002: конкурент может иметь правила про отдельные криптографические API, но не кодирует численные требования к параметрам password hashing.

# CodeQL

Не запускался. Обоснование выше.

# Итог

Класс кейса: **продвинутый**. Обоснование: Bandit и Semgrep оба пропустили все 4 ожидаемых срабатывания (0 TP, 4 FN) и не дали ложных срабатываний на `safe.py` (0 FP). Причина систематическая: ни один из двух инструментов не реализует семантику «bcrypt cost factor меньше порога».

Что закрывает наше правило CRYPTO004 сверх аналогов:

1. Численная проверка `rounds` у `bcrypt.gensalt` против порога проекта: безопасно `rounds >= 12`, уязвимо `rounds < 12`.
2. Двухуровневая severity: `high`, если `rounds < 10`; `medium`, если `10 <= rounds < 12`.
3. Поддержка четырёх форм импорта: `import bcrypt`, `import bcrypt as bc`, `from bcrypt import gensalt`, `from bcrypt import gensalt as gs`.
4. Преднамеренно тихое поведение на `bcrypt.gensalt()` без явного `rounds` и на нелитералах: это снижает FP в MVP.

Известные ограничения MVP:

- Если `rounds` задан переменной, правило молчит. Без потокового анализа невозможно отличить безопасный конфиг (`ROUNDS = 12`) от опасного (`ROUNDS = 4`), не создавая FP.
- Позиционная форма `bcrypt.gensalt(8)` в этот корпус и правило не включена. Она допустима API, но не нужна для закрытия текущего DoD; её можно оформить отдельным расширением, если понадобится.
