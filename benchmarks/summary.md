# Сводная таблица результатов на корпусе

Сравнение результатов нашего линтера и аналогов на каждом кейсе из `corpus/`.
Обновляется одновременно с переходом правила в статус «реализован» в
`docs/rules_registry.md`.

## Условные обозначения

- **TP** — true positive: аналог нашёл реальную уязвимость.
- **FN** — false negative: аналог пропустил уязвимость.
- **FP** — false positive: аналог сработал на безопасном коде (`safe.py`).
- **n/m** — найдено `n` срабатываний из `m` ожидаемых на `vulnerable.py`.

Для собственного линтера severity указана отдельно по строкам, потому что
у нас severity контекстная (см. `docs/rules_registry.md`).

## Результаты

| rule_id   | case_id                | наш линтер (TP/FN на vuln, FP на safe) | Bandit          | Semgrep (open-source `python/`) | CodeQL          |
|-----------|------------------------|----------------------------------------|------------------|-----------------------------------|------------------|
| CRYPTO001 | random_lib_for_crypto  | 6/6 TP, 0 FP; severity 5×high + 1×medium | B311: 6/6 TP, severity LOW для всех, 0 FP | 0/6 TP, 6 FN, 0 FP (правила `random` нет в наборе) | не запускался (базовый кейс) |
| CRYPTO002 | pbkdf2_low_iterations  | 8/8 TP, 0 FP; severity 6×high + 2×medium | 0/8 TP, 8 FN, 0 FP (числовых порогов на iterations нет) | 0/8 TP, 8 FN, 0 FP (правила про iterations нет в наборе) | не запускался (см. ниже) |
| CRYPTO003 | aes_ecb_mode           | 5/5 TP, 0 FP; severity 5×high | B305: 2/5 TP, 3 FN, 0 FP (ловит только PyCA, пропускает pycryptodome `MODE_ECB`) | 0/5 TP, 5 FN, 0 FP (правила про ECB в наборе нет) | не запускался (см. ниже) |
| CRYPTO004 | bcrypt_low_rounds      | 4/4 TP, 0 FP; severity 2×high + 2×medium | 0/4 TP, 4 FN, 0 FP (числовых порогов на `rounds` нет) | 0/4 TP, 4 FN, 0 FP (правила про bcrypt `rounds` нет в наборе) | не запускался (см. ниже) |
| CRYPTO005 | jwt_misuse             | 8/8 TP, 0 FP; severity 8×high | 0/8 TP, 8 FN, 0 FP (PyJWT не покрыт ни одним правилом Bandit) | 5/8 TP, 3 FN (`'NONE'` uppercase, `verify_aud`, `verify_exp`); 0 FP по теме, +2 шумовых `jwt-python-exposed-data` на любом `jwt.encode` (в т.ч. на safe.py) | не запускался (см. ниже) |
| CRYPTO006 | non_constant_time_compare | 6/6 TP, 0 FP; severity 6×high | 0/6 TP, 6 FN, 0 FP (нет правила для timing-safe compare по именам) | 0/6 TP, 6 FN, 0 FP (нет правила для `==` / `!=` по crypto-именам) | не запускался (см. ниже) |
| CRYPTO007 | hardcoded_jwt_secret   | 6/6 TP, 0 FP; severity 6×high | 0/6 TP, 6 FN, 0 FP (PyJWT signing key не покрыт) | 5/6 TP, 1 FN (`key="..."` kwarg); 0 FP по теме, +6 шумовых `jwt-python-exposed-data` на safe.py | не запускался (см. ниже) |
| CRYPTO008 | tls_old_protocol_constant | 4/4 TP, 0 FP; severity 4×high | 0/4 TP, 4 FN, 0 FP (stdlib `ssl.SSLContext(ssl.PROTOCOL_*)` не покрыт) | 3/4 TP, 1 FN (`PROTOCOL_SSLv23`); 0 FP | не запускался (базовый кейс) |
| CRYPTO009 | rsa_pkcs1v15_encryption | 4/4 TP, 0 FP; severity 4×high | 0/4 TP, 4 FN, 0 FP (нет правила для RSA PKCS#1 v1.5 encryption padding в PyCA) | 0/4 TP, 4 FN, 0 FP (нет правила для `PKCS1v15()` в контексте `encrypt`/`decrypt`) | не запускался (см. ниже) |

## Заметки по кейсам

### CRYPTO001 / random_lib_for_crypto

Класс кейса: **базовый** (Bandit покрывает 6/6).

Вклад нашего правила сверх Bandit на этом же кейсе:

1. Контекстная severity: `high` для строк 17/23/29/35/41 (имена `token`,
   `reset_token`, `iv`, `salt`, `nonce`), `medium` для строки 48 (имя
   `greeting` не в словаре крипто-имён). У Bandit во всех 6 строках
   одинаково LOW.
2. Сообщение упоминает конкретное крипто-имя из контекста: «value used as
   `iv` — `random.randbytes` is not cryptographically secure».
3. Suggestion на конкретную замену под каждую функцию:
   `random.choice` → `secrets.choice(seq)`,
   `random.randbytes(n)` → `secrets.token_bytes(n)`,
   `random.randint(a, b)` → `a + secrets.randbelow(b - a + 1)`,
   `random.getrandbits(k)` → `secrets.randbits(k)`.

Пробел Semgrep: open-source набор `semgrep/semgrep-rules` (директория
`python/`, 371 правило, коммит `fdc73542`) не содержит правила для модуля
`random` — 0/6 TP. Реестровый `p/python` через `semgrep.dev` в момент
прогона аналогов был недоступен (ReadTimeoutError); финальный вывод по
Semgrep считается предварительным до повторного прогона. Сырые JSON и
подробности — в `corpus/random_lib_for_crypto/analogs.md`.

### CRYPTO002 / pbkdf2_low_iterations

Класс кейса: **продвинутый** (Bandit и Semgrep оба пропускают все 8
сценариев — 0/8 TP). Причина систематическая: ни в Bandit 1.9.4, ни
в open-source `semgrep/semgrep-rules` (коммит `fdc73542`, 371 правило)
нет правила, сравнивающего числовое значение `iterations` PBKDF2
с OWASP-порогами.

Вклад нашего правила сверх аналогов на этом кейсе:

1. Численная проверка против hash-зависимых порогов OWASP-2023: SHA-1
   → 1 300 000, SHA-256 → 600 000, SHA-512 → 210 000. Алгоритм
   извлекается из самого вызова: для PBKDF2HMAC — из kwarg
   `algorithm=hashes.<HASH>()`, для `hashlib.pbkdf2_hmac` — из 1-го
   позиционного аргумента-строки. Если алгоритм статически не
   распознан, применяется самый строгий порог 1 300 000.
2. Двухуровневая severity: `high` для строк 25/31/37/49/55/60
   (итераций меньше половины порога — кратное отставание),
   `medium` для строк 43/65 (между половиной и порогом — отставание
   есть, но в одном порядке). Конкуренты не различают эти уровни,
   поскольку вообще не реагируют.
3. Покрытие двух форм одним правилом: `cryptography` PBKDF2HMAC
   и stdlib `hashlib.pbkdf2_hmac`, оба в нескольких вариантах
   импорта (`import`, `import as`, `from ... import`,
   `from ... import as`).
4. Конкретный suggestion с целевым числом и алгоритмом, а также
   упоминание Argon2id / scrypt как современных альтернатив.

Известное ограничение MVP: переменные в `iterations` (нелитерал)
правило не флагует — без потокового анализа отличие безопасного
конфига от опасного статически невозможно. Зафиксировано
в `corpus/pbkdf2_low_iterations/analogs.md` и в docstring правила.

CodeQL: не запускался. Кейс уже доказывает преимущество над двумя
основными конкурентами без дополнительной статистики; CodeQL
подключим на отдельном будущем кейсе с потоковым анализом, например
`static_iv_aes_cbc` или `hardcoded_aes_key`.
Сырые JSON и подробности — в `corpus/pbkdf2_low_iterations/analogs.md`.

### CRYPTO003 / aes_ecb_mode

Класс кейса: **продвинутый**. Ось преимущества двойная:

- **Ось 1 (полное отсутствие у Semgrep)**: open-source `semgrep/semgrep-rules`
  под `python/` (коммит `fdc73542`, 371 правило) не имеет правила про AES-ECB
  ни для одной из двух библиотек — 0/5 TP.
- **Ось 3 (асимметрия у Bandit)**: B305 ловит PyCA Hazmat (2/2 формы) и
  пропускает pycryptodome (0/3 формы). 2/5 TP, 3 FN. Систематический пробел:
  B305 устроен как чёрный список вызовов
  `cryptography.hazmat.primitives.ciphers.modes.ECB`; в pycryptodome режим —
  целочисленная константа `AES.MODE_ECB`, в чёрный список не попадает.

Вклад нашего правила сверх аналогов на этом кейсе:

1. Покрытие двух библиотек одной семантикой («режим, переданный AES-шифру,
   — ECB»): `cryptography.hazmat.primitives.ciphers.modes.ECB` (PyCA, формы
   `modes.ECB()` и прямой `ECB()`) и `Crypto.Cipher.AES.MODE_ECB`
   (pycryptodome). Закрывает оба пробела одним правилом.
2. Покрытие трёх форм вызова pycryptodome: позиционный аргумент `MODE_ECB`,
   kwarg `mode=AES.MODE_ECB`, импорт с алиасом
   `from Crypto.Cipher import AES as <X>`.
3. Информативное сообщение с CWE-327 и единым предложением замены — AES-GCM
   как AEAD-режим по умолчанию, с конкретными API обеих библиотек.
4. Один уровень severity — `high`, всегда. Шкалы нет: ECB — бинарное состояние,
   промежуточного «менее опасного» ECB не существует.

Дополнительная находка Bandit B413 (`from Crypto.Cipher import AES`,
deprecated pycryptodome) — посторонняя по теме ECB; не TP и не FP по
проверяемому свойству. Зафиксирована в `analogs.md` отдельно для полноты.

Известные ограничения MVP: режим, переданный через переменную
(`m = AES.MODE_ECB; AES.new(key, m)`), не флагуется — без потокового анализа
отличие безопасного конфига от опасного статически невозможно. Зафиксировано
в `corpus/aes_ecb_mode/analogs.md` и в docstring правила.

CodeQL: не запускался. Двойной пробел двух основных конкурентов уже
эмпирически доказан на этом кейсе.
Сырые JSON и подробности — в `corpus/aes_ecb_mode/analogs.md`.

### CRYPTO004 / bcrypt_low_rounds

Класс кейса: **продвинутый**. Ось преимущества — **ось 2
(параметры KDF/password hashing)**, парный кейс к CRYPTO002
`pbkdf2_low_iterations`: оба правила проверяют числовую настройку
password hashing API, которую конкуренты не сравнивают с порогом.

Bandit 1.9.4 и Semgrep 1.161.0 с локальным open-source набором
`semgrep-rules` @ `fdc73542` пропустили все 4 сценария:
0/4 TP, 4 FN, 0 FP. Причина систематическая — ни один из двух
инструментов не проверяет значение `rounds` у `bcrypt.gensalt`.

Вклад нашего правила сверх аналогов на этом кейсе:

1. Численная проверка cost factor: `rounds >= 12` считается безопасным,
   `rounds < 12` — нарушением.
2. Двухуровневая severity: `high` для грубо слабых значений
   `rounds < 10`; `medium` для пограничных устаревших значений
   `10 <= rounds < 12`.
3. Поддержка четырёх форм импорта: `import bcrypt`, `import bcrypt as bc`,
   `from bcrypt import gensalt`, `from bcrypt import gensalt as gs`.
4. Информативный suggestion: поднять cost factor минимум до 12, а для
   новых production-систем выбирать значение по latency budget.

Известные ограничения MVP: переменные вместо числового литерала и
позиционная форма `bcrypt.gensalt(8)` не флагуются. Вызов
`bcrypt.gensalt()` без явного `rounds` тоже не флагуется, чтобы не
порождать FP на текущих безопасных дефолтах библиотеки.

CodeQL: не запускался. Полный двойной пробел Bandit/Semgrep уже
эмпирически доказан на этом параметрическом кейсе.
Сырые JSON и подробности — в `corpus/bcrypt_low_rounds/analogs.md`.

### CRYPTO005 / jwt_misuse

Класс кейса: **продвинутый**. Ось преимущества двойная:

- **Ось 1 (полное отсутствие у Bandit)**: Bandit 1.9.4 не имеет ни
  одного правила для PyJWT — 0/8 TP по обоим паттернам (alg=none и
  verify_*=False). Полный систематический пробел набора по библиотеке
  PyJWT, включая значения `algorithm` и содержимое словаря `options`.
- **Ось 3 (семантический пропуск у Semgrep)**: open-source
  `semgrep-rules` @ `fdc73542` ловит 5/8 TP с тремя FN разной природы:
    - регистр `'NONE'` — `jwt-python-none-alg` сравнивает с буквальной
      строкой `'none'`, тогда как PyJWT нормализует к нижнему регистру;
    - `verify_aud` / `verify_exp` — `unverified-jwt-decode` распознаёт
      только `verify_signature` и legacy-синтаксис `verify=False`;
      остальные ключи `options` им не покрыты;
    - при нескольких отключённых ключах в одном словаре отчёт неполный
      (упомянут только первый).
  Дополнительно правило `jwt-python-exposed-data` срабатывает на любой
  `jwt.encode` — в том числе на безопасный `algorithm='HS256'` в
  `safe.py`. Это шум, не FP по теме alg=none, но при широкой оценке
  «JWT misuse» — два срабатывания на безопасном коде, которых наше
  правило не порождает.

Вклад нашего правила сверх аналогов на этом кейсе:

1. **Покрытие двух семантически связанных, но синтаксически разных
   паттернов одним правилом** (CRYPTO005). Алгоритм `'none'`
   (CWE-327, CWE-347) при выпуске или приёме токена и любая
   разновидность `verify_*=False` в `options` при `jwt.decode`
   (CWE-347). Обе формы — «токен принимается без валидной подписи».
2. **Регистронезависимость алгоритма**: значение kwarg `algorithm`
   и любого элемента `algorithms=[...]` сравнивается через
   `value.lower() == 'none'`, что закрывает FN Semgrep на L35.
3. **Полная семантика опций verify**: правило проходит словарь
   `options` и проверяет любой ключ из набора `verify_signature`,
   `verify_aud`, `verify_exp`, `verify_iat`, `verify_nbf`, `verify_iss`.
   Один dict с несколькими отключёнными ключами даёт одно срабатывание
   со списком всех нарушенных ключей в message — закрывает FN Semgrep
   на L55, L62 и неполный отчёт на L69.
4. **Поддержка трёх форм импорта** через alias-mapping: `import jwt`,
   `from jwt import encode/decode`, `import jwt as j`. Архитектурно
   повторяет подход CRYPTO002/CRYPTO003 (`_collect_imports`).
5. **Информативное сообщение** с конкретным указанием проблемы
   (`algorithm='NONE'`, `verify_aud=False, verify_exp=False`) и
   suggestion'ом замены: для alg=none — реальный алгоритм
   (HS256/RS256/ES256) и явный `algorithms=[...]` без `'none'`;
   для verify=False — не отключать проверки и передавать
   `audience=`/`issuer=` явно вместо `verify_aud`/`verify_iss`.
6. **Один уровень severity — `high`**. Шкалы нет: обе формы —
   критическое нарушение проверки подписи; промежуточного «менее
   опасного» состояния не существует (как и у CRYPTO003 / ECB).

Известные ограничения MVP (зафиксированы в `analogs.md` и docstring
правила): `algorithm` или dict `options`, переданные через переменную;
позиционная передача алгоритма; сборка `options` по частям. Все три
требуют потокового анализа — без него правило молчит, чтобы не
плодить FP. Архитектурно те же ограничения уже приняты в CRYPTO002
(переменная вместо `iterations`) и CRYPTO003 (переменная вместо
`MODE_ECB`).

CodeQL: не запускался. Двойной пробел разной природы (Bandit —
полный, Semgrep — семантический по dict-options и регистру) уже
эмпирически доказан на двух основных конкурентах. CodeQL отложен до
отдельного будущего кейса, где полезен потоковый анализ
(`static_iv_aes_cbc` / `hardcoded_aes_key`).
Сырые JSON и подробности — в `corpus/jwt_misuse/analogs.md`.

### CRYPTO006 / non_constant_time_compare

Класс кейса: **продвинутый**. Ось преимущества — **ось 1 + ось 4**:
полный двойной пробел Bandit/Semgrep и контекст по именам переменных,
аналогичный CRYPTO001, но применённый к сравнениям криптографических
значений.

Bandit 1.9.4 и Semgrep 1.161.0 с локальным open-source набором
`semgrep-rules/python` пропустили все 6 сценариев: 0/6 TP, 6 FN,
0 FP. Причина систематическая: оба инструмента не связывают обычные
операторы `==` / `!=` с криптографическими именами вроде
`expected_signature`, `provided_token`, `expected_mac`,
`password_hash`, `digest`, `hmac_value`.

Вклад нашего правила сверх аналогов на этом кейсе:

1. AST-проверка простых `Compare`-узлов с одним оператором `==` или `!=`.
2. Локальный набор чувствительных имён для сравнений: базовые crypto-имена
   из `linter/context.py` плюс `signature`, `sig`, `mac`, `hmac`, `digest`,
   `hash`, `password_hash`.
3. Поддержка `ast.Name` и `ast.Attribute`, чтобы ловить как
   `token == expected_token`, так и `self.signature == expected_signature`.
4. Один уровень severity — `high`. Шкалы нет: обычное сравнение MAC,
   HMAC, подписи, токена или password hash является прямым timing
   side-channel риском (CWE-208).
5. Suggestion указывает безопасную замену:
   `hmac.compare_digest(a, b)` или `secrets.compare_digest(a, b)`,
   для `!=` — `not compare_digest(...)`.

Известные ограничения MVP: цепочки сравнений, результаты вызовов функций,
dataflow через промежуточные переменные, subscripts/сложные выражения и
кастомные wrappers поверх `compare_digest` не анализируются. Сегмент `mac`
считается криптографическим Message Authentication Code; неоднозначные имена
вроде `mac_address` вынесены за пределы текущего корпуса.

CodeQL: не запускался. Полный двойной пробел двух основных конкурентов уже
эмпирически доказан, а MVP-правило намеренно остаётся AST-only без dataflow.
Сырые JSON и подробности — в
`corpus/non_constant_time_compare/analogs.md`.

### CRYPTO007 / hardcoded_jwt_secret

Класс кейса: **продвинутый**. Ось преимущества — **ось 1 + ось 3**:
полный пробел Bandit на PyJWT signing key и семантический пропуск Semgrep
на kwarg-форме `key="..."`.

Bandit 1.9.4 пропустил все 6 сценариев: 0/6 TP, 6 FN, 0 FP. Semgrep
1.161.0 с локальным open-source набором `semgrep-rules/python` нашёл
5/6 сценариев правилом `jwt-python-hardcoded-secret`, но пропустил
`jwt.encode(payload, key="my-app-secret", algorithm="HS256")`. Дополнительно
смежное правило `jwt-python-exposed-data` сработало на всех безопасных
`jwt.encode` в `safe.py` — 6 шумовых предупреждений вне темы hardcoded secret.

Вклад нашего правила сверх аналогов на этом кейсе:

1. Поддержка обеих форм передачи signing key в PyJWT: второй позиционный
   аргумент и keyword-аргумент `key=`.
2. Alias-mapping как в CRYPTO005: `import jwt`, `import jwt as j`,
   `from jwt import encode`, `from jwt import encode as e`.
3. Строковые и bytes-литералы считаются уязвимыми независимо от длины:
   проблема в хранении секрета в исходниках, а не только в энтропии.
4. Один уровень severity — `high`. Если JWT-секрет попал в репозиторий,
   атакующий может выпускать валидные токены после утечки секрета (CWE-798).
5. Suggestion направляет к runtime-источникам секрета: environment,
   secret manager/KMS или защищённая конфигурация.

Известные ограничения MVP: переменная с литералом, f-string, конкатенация
строк и dataflow через конфигурацию не анализируются. `settings.JWT_SECRET`
считается безопасным или неизвестным. `jwt.decode(...)` и `algorithm="none"`
не входят в это правило; последнее покрывает CRYPTO005.

CodeQL: не запускался. Для текущего AST-only кейса достаточно подтверждённого
пробела Bandit/Semgrep; CodeQL оставлен для будущих dataflow-проверок
источника секрета.

### CRYPTO008 / tls_old_protocol_constant

Класс кейса: **базовый**. Semgrep 1.161.0 с локальным open-source набором
`semgrep-rules/python` ловит 3 из 4 сценариев правилом `weak-ssl-version`:
`PROTOCOL_TLSv1`, `PROTOCOL_TLSv1_1` и `PROTOCOL_SSLv3`. При этом он
пропускает `PROTOCOL_SSLv23`. Bandit 1.9.4 полностью пропускает stdlib-форму
`ssl.SSLContext(ssl.PROTOCOL_*)`: 0/4 TP.

Вклад нашего правила сверх аналогов на этом кейсе:

1. Покрытие legacy-констант TLS/SSL в одном AST-only правиле:
   `PROTOCOL_TLSv1`, `PROTOCOL_TLSv1_1`, `PROTOCOL_SSLv23`,
   `PROTOCOL_SSLv3`; в реализации также заложен `PROTOCOL_SSLv2`.
2. Поддержка alias-mapping: `import ssl`, `import ssl as s`,
   `from ssl import SSLContext, PROTOCOL_SSLv23`,
   `from ssl import SSLContext as TLSContext, PROTOCOL_SSLv3 as SSL_V3`.
3. Фокус на `SSLContext`: константа флагуется только как protocol-аргумент
   конструктора `SSLContext`, а не по факту любого упоминания имени в файле.
4. Один уровень severity — `high`, потому что выбор устаревшего протокола
   напрямую ослабляет TLS-канал.

Известные ограничения MVP: protocol-константа, переданная через переменную,
wrapper-функции вокруг `SSLContext` и динамическая сборка аргументов не
анализируются. Это намеренное ограничение AST-only правила без dataflow.

CodeQL: не запускался. Кейс уже классифицируется по Bandit и Semgrep; CodeQL
оставлен для будущих dataflow-проверок.
Сырые JSON и подробности — в
`corpus/tls_old_protocol_constant/analogs.md`.

### CRYPTO009 / rsa_pkcs1v15_encryption

Класс кейса: **продвинутый**. Ось преимущества — **ось 1**:
полный двойной пробел Bandit/Semgrep на PyCA `cryptography` RSA
encryption/decryption padding. Оба инструмента пропустили все 4 сценария:
`public_key.encrypt(..., padding.PKCS1v15())`,
`private_key.decrypt(..., padding.PKCS1v15())`, alias-import
`asym_padding.PKCS1v15()` и direct import `PKCS1v15()`.

Вклад нашего правила сверх аналогов на этом кейсе:

1. Проверяет не сам факт вызова `PKCS1v15()`, а контекст RSA
   `.encrypt(...)` / `.decrypt(...)`, поэтому не даёт FP на корректное
   использование PKCS#1 v1.5 padding в RSA signatures.
2. Поддерживает две формы импорта PyCA padding: модульный импорт
   `from cryptography.hazmat.primitives.asymmetric import padding [as ...]`
   и прямой импорт
   `from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15`.
3. Даёт один уровень severity — `high`: PKCS#1 v1.5 padding для RSA
   encryption/decryption является прямым криптографическим нарушением;
   безопасная альтернатива — RSA-OAEP с MGF1 и SHA-256.

Известное ограничение MVP: padding, сохранённый в переменную
(`pad = padding.PKCS1v15(); public_key.encrypt(message, pad)`), не
флагуется. Это сознательное ограничение AST-only правила без dataflow.

CodeQL: не запускался. Полный двойной пробел двух основных конкурентов
зафиксирован в `corpus/rsa_pkcs1v15_encryption/analogs.md`.
