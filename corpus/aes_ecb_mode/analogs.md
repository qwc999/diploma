Прогон аналогов на кейсе aes_ecb_mode

# Команды запуска

Bandit (из корня репозитория, bandit установлен в .venv):

```
.venv/Scripts/bandit.exe -f json -o corpus/aes_ecb_mode/_bandit_vuln.json corpus/aes_ecb_mode/vulnerable.py
.venv/Scripts/bandit.exe -f json -o corpus/aes_ecb_mode/_bandit_safe.json corpus/aes_ecb_mode/safe.py
```

Semgrep (из WSL, semgrep установлен в `~/.local/bin`):

```
wsl -e bash -lc 'export SEMGREP_ENABLE_VERSION_CHECK=0; export SEMGREP_SEND_METRICS=off; \
  semgrep --metrics=off --config=/mnt/c/repos/semgrep-rules/python --json \
    --output /mnt/c/repos/diploma/corpus/aes_ecb_mode/_semgrep_vuln.json \
    /mnt/c/repos/diploma/corpus/aes_ecb_mode/vulnerable.py'
wsl -e bash -lc 'export SEMGREP_ENABLE_VERSION_CHECK=0; export SEMGREP_SEND_METRICS=off; \
  semgrep --metrics=off --config=/mnt/c/repos/semgrep-rules/python --json \
    --output /mnt/c/repos/diploma/corpus/aes_ecb_mode/_semgrep_safe.json \
    /mnt/c/repos/diploma/corpus/aes_ecb_mode/safe.py'
```

Конфигурация запускалась оффлайн с локального клона `semgrep/semgrep-rules` @ `fdc73542dfd6ff4efd8a6710310a4ee5326db6d7` (директория `C:/repos/semgrep-rules`, ветка default, depth=1). Реестр `p/python` через `semgrep.dev` не прогонялся — на разведке (2026-04-25) и на CRYPTO002 (2026-04-28) сохранялся ReadTimeoutError.

CodeQL: не запускался. Пробел эмпирически подтверждён по двум аналогам (Semgrep — полный, Bandit — частичный, систематический по pycryptodome). CodeQL отложен до CRYPTO006 (`static_iv_aes_cbc` / `hardcoded_aes_key`), где полезен потоковый анализ.

Контекст: прогон проводился на расширенном vulnerable.py (5 сценариев, каждый в отдельной функции с префиксом `# VULN:` по шаблону `docs/rule_authoring.md`) — это надстройка над минимальным разведочным набором из 2 сценариев в `C:/repos/diploma_scouting/candidate_aes_ecb_mode/`. Расширения: PyCA через прямой импорт `ECB()`, pycryptodome через kwarg `mode=AES.MODE_ECB`, pycryptodome через алиас импорта `from Crypto.Cipher import AES as A`.

# Bandit

Версия: 1.9.4. Дата прогона: 2026-04-29.

## vulnerable.py

По теме ECB сработал на 2 строки из 5 ожидаемых. 3 ожидаемых срабатывания — FN.

| line | ожидалось (наше)                                  | Bandit нашёл           | вердикт |
|------|---------------------------------------------------|------------------------|---------|
| 34   | high (PyCA `Cipher(... modes.ECB() ...)`)         | B305 MEDIUM/HIGH conf  | TP      |
| 41   | high (PyCA `Cipher(... ECB() ...)` прямой импорт) | B305 MEDIUM/HIGH conf  | TP      |
| 48   | high (pycryptodome `AES.new(key, AES.MODE_ECB)`)  | —                      | FN      |
| 54   | high (pycryptodome `AES.new(key, mode=AES.MODE_ECB)`) | —                  | FN      |
| 60   | high (pycryptodome `A.new(key, A.MODE_ECB)` алиас)| —                      | FN      |

Лишних срабатываний по теме ECB: 0.

Дополнительно Bandit нашёл по другой теме (не относится к ECB):

| line | правило | severity | заметка |
|------|---------|----------|---------|
| 24   | B413    | HIGH     | импорт `from Crypto.Cipher import AES` помечен как deprecated pycryptodome |
| 25   | B413    | HIGH     | импорт `from Crypto.Cipher import AES as A` — то же самое |

B413 — отдельная тема (deprecated библиотека), не TP и не FP по теме ECB. Аналог тому, как в CRYPTO001 у Semgrep попадались `use-timeout` и `raise-for-status`.

## safe.py

По теме ECB: 0 срабатываний. FP = 0.

Дополнительно по другой теме: B413 на строках 19 и 20 (импорты pycryptodome). Это шум от смежного правила, не относящийся к проверяемому свойству.

## Причина пробела

Bandit B305 (`b304-b305-ciphers-and-modes`) реализован как чёрный список вызовов `cryptography.hazmat.primitives.ciphers.modes.ECB`. Он совпадает с PyCA Hazmat и пропускает pycryptodome (`Crypto.Cipher.AES` + аргумент `MODE_ECB`), потому что в pycryptodome режим — это не самостоятельный класс-вызов, а целочисленная константа атрибута, и в чёрный список она не входит. Семантика «AES в режиме ECB» одинакова у обеих библиотек, но Bandit покрывает только одну из них.

# Semgrep

Версия: 1.161.0. Дата прогона: 2026-04-29. Источник правил: локальный клон `semgrep/semgrep-rules` @ `fdc73542dfd6ff4efd8a6710310a4ee5326db6d7`, директория `python/` (371 правило, языки python + multilang). Реестр `p/python` через `semgrep.dev` остаётся не прогнан.

## vulnerable.py

Сработал на 0 строк из 5 ожидаемых. Все 5 ожидаемых срабатываний — FN.

| line | ожидалось (наше)                                  | Semgrep нашёл | вердикт |
|------|---------------------------------------------------|---------------|---------|
| 34   | high (PyCA `Cipher(... modes.ECB() ...)`)         | —             | FN      |
| 41   | high (PyCA `Cipher(... ECB() ...)` прямой импорт) | —             | FN      |
| 48   | high (pycryptodome `AES.new(key, AES.MODE_ECB)`)  | —             | FN      |
| 54   | high (pycryptodome `AES.new(key, mode=AES.MODE_ECB)`) | —         | FN      |
| 60   | high (pycryptodome `A.new(key, A.MODE_ECB)` алиас)| —             | FN      |

Лишние срабатывания (FP): 0.

## safe.py

Сработал на 0 строк. FP: 0.

## Причина пробела

В open-source наборе `semgrep/semgrep-rules` под `python/` (на коммите `fdc73542`) нет правила, проверяющего использование AES в режиме ECB ни для PyCA, ни для pycryptodome. Поиск по тексту правил подтверждает: совпадения по `ECB` и `MODE_ECB` отсутствуют в директории `python/`. Это полный пробел набора по данной теме.

## Допущение

Реестровый пакет `p/python` от Semgrep, недоступный в этом прогоне, может включать дополнительные правила сверх open-source `semgrep-rules`. До прогона `--config=p/python` вывод по Semgrep считаем предварительным.

# CodeQL

Не запускался. Обоснование выше.

# Итог

Класс кейса: **продвинутый**. Обоснование двойное:

- **Ось 1 (полное отсутствие у Semgrep)**: open-source `semgrep-rules` @ `fdc73542` не имеет правила про AES-ECB ни в одной форме — 0 TP / 5 FN. Полный систематический пробел.
- **Ось 3 (асимметрия у Bandit)**: B305 ловит PyCA Hazmat (2/2 формы), но не ловит pycryptodome (0/3 формы). 2 TP / 3 FN. Систематический пробел по второй библиотеке: один и тот же режим ECB одновременно опасен и одинаково семантичен в обеих библиотеках, но детектируется только в одной.

Что закрывает наше правило CRYPTO003 сверх аналогов:

1. Покрытие двух библиотек одним правилом: `cryptography.hazmat.primitives.ciphers.modes.ECB` (PyCA, обе формы импорта — `modes.ECB()` и прямой `ECB()`) и `Crypto.Cipher.AES.MODE_ECB` (pycryptodome).
2. Покрытие трёх форм вызова pycryptodome: позиционный аргумент, kwarg `mode=`, импорт с алиасом (`from Crypto.Cipher import AES as A`).
3. Информативное сообщение с CWE-327 и единым предложением замены — AES-GCM (AEAD по умолчанию).
4. Один уровень severity — `high`. Шкалы нет: ECB — бинарное состояние, промежуточного «менее опасного» ECB не существует.

Известные ограничения MVP:

- Если режим передан через переменную (`m = AES.MODE_ECB; AES.new(key, m)`), правило молчит — без потокового анализа отличить безопасный конфиг (`MODE = AES.MODE_GCM`) от опасного (`MODE = AES.MODE_ECB`) невозможно, и срабатывание на «неизвестно» гарантированно даст FP.
- Если режим выбран динамически (`AES.new(key, AES.MODE_ECB if cond else AES.MODE_GCM)`), правило сработает на узел `AES.MODE_ECB` и зафиксирует, что один из путей опасен; это допустимое поведение, а не ограничение.
- Импорт PyCA через `from cryptography.hazmat.primitives.ciphers.modes import ECB as <alias>` с произвольным алиасом не покрывается явно (известно только имя `ECB`); расширение тривиально, но в MVP не делалось ради простоты.
