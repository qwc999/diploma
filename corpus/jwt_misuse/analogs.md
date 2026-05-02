Прогон аналогов на кейсе jwt_misuse

# Команды запуска

Bandit (из корня репозитория, bandit установлен в .venv):

```
.venv/Scripts/bandit.exe -f json -o corpus/jwt_misuse/_bandit_vuln.json corpus/jwt_misuse/vulnerable.py
.venv/Scripts/bandit.exe -f json -o corpus/jwt_misuse/_bandit_safe.json corpus/jwt_misuse/safe.py
```

Semgrep (из WSL, semgrep установлен в `~/.local/bin`):

```
wsl -e bash -lc 'export SEMGREP_ENABLE_VERSION_CHECK=0; export SEMGREP_SEND_METRICS=off; \
  semgrep --metrics=off --config=/mnt/c/repos/semgrep-rules/python --json \
    --output /mnt/c/repos/diploma/corpus/jwt_misuse/_semgrep_vuln.json \
    /mnt/c/repos/diploma/corpus/jwt_misuse/vulnerable.py'
wsl -e bash -lc 'export SEMGREP_ENABLE_VERSION_CHECK=0; export SEMGREP_SEND_METRICS=off; \
  semgrep --metrics=off --config=/mnt/c/repos/semgrep-rules/python --json \
    --output /mnt/c/repos/diploma/corpus/jwt_misuse/_semgrep_safe.json \
    /mnt/c/repos/diploma/corpus/jwt_misuse/safe.py'
```

Конфигурация запускалась оффлайн с локального клона `semgrep/semgrep-rules` @ `fdc73542dfd6ff4efd8a6710310a4ee5326db6d7` (директория `C:/repos/semgrep-rules`, ветка default, depth=1). Реестр `p/python` через `semgrep.dev` не прогонялся — на разведке (2026-04-25), на CRYPTO002 (2026-04-28) и на CRYPTO003 (2026-04-29) сохранялся ReadTimeoutError.

CodeQL: не запускался. Двойной пробел двух основных конкурентов уже эмпирически доказан на этом кейсе (Bandit — полный, Semgrep — частичный, систематический по семантике dict-options и регистру алгоритма). CodeQL отложен до CRYPTO006 (`static_iv_aes_cbc` / `hardcoded_aes_key`), где полезен потоковый анализ.

Контекст: прогон проводился на полном корпусе из 8 сценариев в `vulnerable.py`. Каждый сценарий вынесен в отдельную функцию с префиксом `# VULN:` по шаблону `docs/rule_authoring.md`. Сценарии распределены по двум осям misuse (alg=none и verify_*=False) и трём формам импорта (`import jwt`, `from jwt import encode/decode`, `import jwt as j`).

# Bandit

Версия: 1.9.4. Дата прогона: 2026-04-29.

## vulnerable.py

Bandit не сработал ни на одной строке. Все 8 ожидаемых срабатываний — FN.

| line | ожидалось (наше)                                          | Bandit нашёл | вердикт |
|------|-----------------------------------------------------------|--------------|---------|
| 30   | high (encode `algorithm='none'`)                          | —            | FN      |
| 35   | high (encode `algorithm='NONE'` — регистр)                | —            | FN      |
| 40   | high (decode `'none'` в `algorithms=[...]`)               | —            | FN      |
| 45   | high (decode `'none'` через алиас `import jwt as j`)      | —            | FN      |
| 50   | high (decode `options={'verify_signature': False}`)       | —            | FN      |
| 55   | high (decode `options={'verify_aud': False}`)             | —            | FN      |
| 62   | high (decode `options={'verify_exp': False}`)             | —            | FN      |
| 69   | high (decode `options={'verify_signature': False, 'verify_aud': False}`) | —            | FN      |

Лишних срабатываний: 0.

## safe.py

Bandit: 0 срабатываний. FP = 0.

## Причина пробела

В Bandit 1.9.4 (как и в `bandit/core/extension_loader.py` под `python` plugin set) **отсутствует** правило для PyJWT. В чёрном списке вызовов `bandit.plugins.general_bad_file_permissions`/`bandit.plugins.general_hardcoded_password_string`/etc нет проверок `jwt.encode`, `jwt.decode`, значений `algorithm` или содержимого `options`. Это полное систематическое отсутствие покрытия PyJWT — 0/8 TP по обоим паттернам misuse.

# Semgrep

Версия: 1.161.0. Дата прогона: 2026-04-29. Источник правил: локальный клон `semgrep/semgrep-rules` @ `fdc73542dfd6ff4efd8a6710310a4ee5326db6d7`, директория `python/` (371 правило, языки python + multilang, всего 378 правил с multilang). Реестр `p/python` через `semgrep.dev` остаётся не прогнан.

## vulnerable.py

Сработал на 5 строк из 8 ожидаемых (по теме alg=none и verify=False). 3 ожидаемых срабатывания — FN. Лишних шумовых срабатываний по посторонней теме `jwt-python-exposed-data` — 2 (на L30 и L35), они общие для любого `jwt.encode` и не относятся к проверяемому свойству.

| line | ожидалось (наше)                                              | Semgrep по теме                                  | вердикт |
|------|---------------------------------------------------------------|--------------------------------------------------|---------|
| 30   | high (encode `algorithm='none'`)                              | `jwt-python-none-alg` ERROR                      | TP      |
| 35   | high (encode `algorithm='NONE'` — регистр)                    | —                                                | FN      |
| 40   | high (decode `'none'` в `algorithms=[...]`)                   | `jwt-python-none-alg` ERROR                      | TP      |
| 45   | high (decode `'none'` через алиас `import jwt as j`)          | `jwt-python-none-alg` ERROR                      | TP      |
| 50   | high (decode `options={'verify_signature': False}`)           | `unverified-jwt-decode` ERROR                    | TP      |
| 55   | high (decode `options={'verify_aud': False}`)                 | —                                                | FN      |
| 62   | high (decode `options={'verify_exp': False}`)                 | —                                                | FN      |
| 69   | high (decode `options={'verify_signature': False, 'verify_aud': False}`) | `unverified-jwt-decode` ERROR на L73 (по `verify_signature`) | TP*     |

\*L69 засчитан как TP (нарушение по этой функции зафиксировано), но Semgrep сообщил о нём на L73 (точка ключа `verify_signature`) и не упомянул второй опасный ключ `verify_aud` в том же словаре. Семантика «несколько отключённых проверок в одном dict» им не передаётся.

Дополнительно по другой теме (`jwt-python-exposed-data`):

| line | правило                       | severity | заметка |
|------|-------------------------------|----------|---------|
| 30   | `jwt-python-exposed-data`     | WARNING  | общее предупреждение про любой `jwt.encode` (срабатывает и на safe.py) |
| 35   | `jwt-python-exposed-data`     | WARNING  | то же |

`jwt-python-exposed-data` — отдельная тема (sensitive data в payload), не TP и не FP по теме alg=none / verify=False. Аналог тому, как у Bandit B413 (deprecated pycryptodome) попадался в CRYPTO003.

## safe.py

По теме alg=none / verify=False: 0 срабатываний. FP по теме = 0.

Дополнительно по другой теме: `jwt-python-exposed-data` WARNING на L24 и L29 (любой `jwt.encode` / `encode`). Это шум от смежного правила, не относящийся к проверяемому свойству, но при формальной классификации «срабатывание на безопасном коде» — это два FP по теме «JWT misuse» в широком смысле. Наше правило этого шума не воспроизводит.

## Причины пробелов

Три FN у Semgrep — три систематические дыры разной природы.

1. **L35 — регистр `'NONE'`**. Правило `jwt-python-none-alg` сравнивает значение kwarg `algorithm` с буквальной строкой `'none'`. PyJWT нормализует значение к нижнему регистру, поэтому `'NONE'` и `'none'` для рантайма эквивалентны. Semgrep этого не учитывает — pattern-match по литералу.
2. **L55 / L62 — `verify_aud` / `verify_exp`**. Правило `unverified-jwt-decode` распознаёт только ключ `verify_signature` (а также legacy-синтаксис `verify=False` без options). Для остальных ключей словаря `options` (`verify_aud`, `verify_exp`, `verify_iat`, `verify_nbf`, `verify_iss`) отдельных правил нет. Семантически все они означают одно и то же — «отключить проверку», просто разных аспектов; правило не обобщено по префиксу `verify_`.
3. **L69 — частичный отчёт по нескольким ключам**. Когда в одном `options` отключены и `verify_signature`, и `verify_aud`, Semgrep упоминает только первый. Пользователь не видит, что второй ключ тоже выключен.

Дополнительно: на любой `jwt.encode` (в том числе на безопасный `algorithm='HS256'` в `safe.py`) срабатывает `jwt-python-exposed-data` WARNING. Это не FP по теме alg=none, но при оценке кейса в широком смысле «JWT misuse» — это лишний шум, который наше правило не порождает.

## Допущение

Реестровый пакет `p/python` от Semgrep, недоступный в этом прогоне, может включать дополнительные правила сверх open-source `semgrep-rules`. До прогона `--config=p/python` вывод по Semgrep считаем предварительным.

# CodeQL

Не запускался. Обоснование выше.

# Итог

Класс кейса: **продвинутый**. Обоснование двойное:

- **Ось 1 (полное отсутствие у Bandit)**: Bandit 1.9.4 не имеет правила для PyJWT — 0/8 TP по обоим паттернам (alg=none и verify_*=False). Полный систематический пробел набора по библиотеке PyJWT.
- **Ось 3 (семантический пропуск у Semgrep)**: open-source `semgrep-rules` @ `fdc73542` ловит 5/8 TP с тремя систематическими FN: регистр `'NONE'` (L35), частичные `verify_aud` / `verify_exp` (L55, L62), и неполный отчёт при нескольких отключённых ключах в одном словаре (L69 — упомянут только первый ключ).

Что закрывает наше правило CRYPTO005 сверх аналогов:

1. **Покрытие двух семантически связанных, но синтаксически разных паттернов одним правилом**: алгоритм `'none'` (CWE-327, CWE-347) при выпуске токена и любая разновидность `verify_*=False` в `options` при проверке (CWE-347). Обе формы — «токен принимается без валидной подписи».
2. **Регистронезависимость алгоритма**: PyJWT нормализует значение `algorithm` к нижнему регистру; правило сравнивает `value.lower() == 'none'`, что закрывает FN Semgrep на L35.
3. **Полная семантика опций verify**: правило проходит словарь `options` и проверяет любой ключ из набора `verify_signature`, `verify_aud`, `verify_exp`, `verify_iat`, `verify_nbf`, `verify_iss`. Один dict с несколькими отключёнными ключами даёт одно срабатывание со списком всех нарушенных ключей в message — что закрывает FN Semgrep на L55, L62 и неполный отчёт на L69.
4. **Поддержка трёх форм импорта** через alias-mapping: `import jwt`, `from jwt import encode/decode`, `import jwt as j`. Архитектурно повторяет подход CRYPTO002/CRYPTO003 (`_collect_imports`).
5. **Информативное сообщение** с конкретным указанием проблемы (`algorithm='NONE'`, `verify_aud`+`verify_exp`) и suggestion'ом замены: для alg=none — реальный алгоритм (HS256/RS256/ES256) и явный список `algorithms=` без `'none'`; для verify=False — не отключать проверки и передавать `audience=`/`issuer=` как явные claim-аргументы.
6. **Один уровень severity — `high`**. Шкалы нет: обе формы — критическое нарушение проверки подписи; промежуточного «менее опасного» состояния не существует (как и у CRYPTO003 / ECB).

Известные ограничения MVP:

- Если значение `algorithm` или dict `options` передано через переменную (`a = 'none'; jwt.encode(..., algorithm=a)`; `opts = {'verify_signature': False}; jwt.decode(..., options=opts)`), правило молчит — без потокового анализа отличить безопасный конфиг от опасного статически невозможно. Архитектурно такое же ограничение принято в CRYPTO002 (переменная вместо литерала `iterations`) и CRYPTO003 (переменная вместо литерала `MODE_ECB`).
- Позиционная передача алгоритма (`jwt.encode(payload, key, 'none')`) — не покрывается. На практике PyJWT не используется так в реальном коде; в документации только kwarg-форма. Расширение тривиально, но в MVP не делалось ради простоты.
- Сборка словаря `options` по частям (`opts = {}; opts['verify_signature'] = False; jwt.decode(..., options=opts)`) — не покрывается по той же причине, что и переменная-dict. Без потокового анализа правило молчит.
- Дополнительные verify-ключи PyJWT за пределами стандартных шести (`verify_jti` встречается в некоторых клиентских библиотеках, но не в стандартной документации PyJWT) — не покрываются. Расширение списка `DANGEROUS_VERIFY_KEYS` тривиально, если потребуется.
