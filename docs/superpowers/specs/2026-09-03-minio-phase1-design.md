# MinIO модуль — Фаза 1 (Фундамент)

Дата: 2026-09-03
Статус: дизайн, ожидает ревью

## Контекст и общий план

Задача — добавить полноценный top-level модуль `redposture minio` с цепочкой
`discovery → anonymous → auth → defcreds → admin capability → bounded
enumeration → secret discovery`. Полный объём (26 разделов ТЗ) декомпозирован
на фазы; **этот документ описывает только Фазу 1**. Каждая фаза самодостаточна
и тестируема; модуль безопасен (read-only) и полезен уже после Фазы 1.

Фазы (обзор, детали — в отдельных спеках):

1. **Фундамент** — CLI+регистрация, SigV4, S3/Admin-клиент, detection,
   anonymous, верификация explicit-креды, TXT/JSON/цвет, unit-тесты. ← этот док.
2. Креды вглубь — `--defcreds` каталог, credential files, session token в
   каталоге, stop-on-success, admin-capability детект, permission-классификация.
3. Энумерация + secret discovery (streaming/bounded, existing secret engine).
4. Labs (локально, gitignored) + integration-тесты + большой dataset.
5. Docs/help финализация + полный CI + self-review.

Решения, зафиксированные на brainstorming:

- **Доступ к S3/Admin API — свой SigV4 поверх `http_session`**, без MinIO/boto3
  SDK. Нужный объём API мал, а SDK не ложится на proxy/TLS/pooling-lifecycle и
  тянет тяжёлую зависимость (раздел 24 ТЗ).
- **Labs (`lab/`, `lab_tests/`) — gitignored**, синкаются вне репозитория.
  Docker-lab + fixtures + integration-тесты (Фаза 4) в коммит НЕ идут; в коммит
  Фазы 1 идут код модуля, SigV4/клиент, регистрация, unit/regression в `tests/`,
  README/help.

## Цель Фазы 1

`redposture minio <target>` без дополнительных флагов:
1. обнаруживает MinIO (multi-signal, отличает от произвольного S3);
2. выполняет минимальные безопасные anonymous checks;
3. определяет необходимость authentication;
4. при наличии explicit-креды проверяет их реальным подписанным вызовом;
5. печатает компактный TXT и структурный JSON, с цветом и `--no-color`.

Никаких модификаций, энумерации, скачивания, brute-force.

## Границы Фазы 1

**Вне scope (Фазы 2–4):** `--defcreds` каталог, admin-capability детект,
permission-классификация, `--show-*` энумерация, secret discovery, bounded
content-reading, checkpoint, Docker-labs, integration-тесты, `--probe-write`.

В Фазу 1 включена общая credential-инфраструктура, которая и так предоставляется
runtime: явные `-u/-p` (= access/secret key), credential files (через
`build_basic_audit_plan`), `--session-token`. Каталог defcreds — Фаза 2.

## Интеграция в существующую архитектуру

Модуль строится по паттерну `modules/grafana` и `modules/clickhouse` через
`ModuleAuditSpec` + `run_basic_host_audit` (никаких собственных target/output/
progress-циклов).

**Регистрация** (`redposture_core/module_registry.py`):
- `COMMAND_MINIO = "minio"`.
- `_STAGE_RUNNER_MODULES[COMMAND_MINIO] = "redposture_core.modules.minio.stage"`.
- `from .cli_modules.minio import configure_minio_parser`.
- В `COMMAND_SPECS` добавить `CommandSpec(name=COMMAND_MINIO, help=..., runner_attr="run_minio_stage", configure_parser=_make_configurator(configure_minio_parser, _HTTP_MODULE_HELPERS))`.
- MinIO попадёт в `AUDIT_MODULE_NAMES` автоматически (маппинг на
  `redposture_core.modules.*`).

**Lifecycle-хуки** (`ModuleAuditSpec`, заполняются в `modules/minio/stage.py`):
- `detect` → fingerprint MinIO (Фаза 1).
- `auth` → верификация одной credential-кандидатуры (Фаза 1).
- `capabilities` → admin-capability (Фаза 2, в Фазе 1 = None).
- `data` → энумерация/discovery (Фаза 3, в Фазе 1 = None).
- `render_module` → `modules/minio/render`, `colorize` → `_render_colored_minio_line`.
- `skip_credentials_without_verifier = True` (см. «403 ≠ invalid»).

## Файловая структура (в коммит)

| Файл | Ответственность |
|---|---|
| `redposture_core/cli_modules/minio.py` | `configure_minio_parser` — общие флаги через helpers, `--port`, auth-группа (`-u/-p`, `--session-token`), TLS/insecure/CA. `--defcreds` добавляется в Фазе 2 вместе с каталогом (не мёртвый флаг). |
| `redposture_core/clients/s3_sigv4.py` | Чистый AWS SigV4-signer: canonical request → заголовки `Authorization`, `x-amz-date`, `x-amz-content-sha256`, опц. `x-amz-security-token`. Без сети, без зависимостей. |
| `redposture_core/clients/minio_api.py` | Тонкий клиент поверх `HttpSessionPool`: подписанный/анонимный запрос, парсинг S3-error XML (Code/Message), health/admin-пробы. Переиспользует пул (один на target-lifecycle). |
| `redposture_core/modules/minio/__init__.py` | Пакет. |
| `redposture_core/modules/minio/types.py` | Dataclasses: `MinioDetection`, `AnonymousResult`, `CredentialResult`, evidence-модели. |
| `redposture_core/modules/minio/policy.py` | `validate_args` — валидация флагов (порт>0, взаимоисключения), как в других модулях. |
| `redposture_core/modules/minio/actions.py` | `detect_minio`, `verify_credential`, `_build_credential_candidates` (Фаза 1: только явные + session token), классификаторы anonymous/auth. |
| `redposture_core/modules/minio/render.py` | `_format_minio_record`/detail-функции (TXT/JSON) + `_render_colored_minio_line` (spans). |
| `redposture_core/modules/minio/stage.py` | `build_minio_plan(args)`, `MODULE_SPEC` (ModuleAuditSpec), `run_minio_stage(args, logger)` → `run_basic_host_audit`. |

## Компонент: SigV4 (`clients/s3_sigv4.py`)

Стандартный AWS Signature Version 4 (MinIO использует его как есть):
- Вход: метод, host, path, query, headers, payload-hash (или `UNSIGNED-PAYLOAD`),
  access_key, secret_key, region (`us-east-1` по умолчанию для MinIO), service
  (`s3` для S3 API, `s3` для Admin API MinIO), опц. session_token, timestamp.
- Шаги: canonical request → string-to-sign → signing key (HMAC-цепочка
  `AWS4<secret>`→date→region→service→`aws4_request`) → signature → заголовки.
- Выход: dict заголовков для добавления к запросу. При наличии session_token
  добавляется `x-amz-security-token` (входит в signed headers).
- Тестируется по опубликованным AWS SigV4 тест-векторам (детерминированно).

## Компонент: S3/Admin-клиент (`clients/minio_api.py`)

Обёртка над существующим `HttpSessionPool` (proxy/TLS/pooling/retry — как есть):
- `MinioClient(pool, base_url, *, access_key=None, secret_key=None, session_token=None)`.
- Методы Фазы 1: `get_service_root()` (GET `/`, анонимный или подписанный →
  ListBuckets), `head_bucket(bucket)`, `list_objects_v2(bucket, *, max_keys, prefix)`
  (Фаза 1 — только для anonymous read-probe, `max-keys=1`), `health(kind)` (GET
  `/minio/health/{live,ready,cluster}`), `admin_info()` (подписанный GET
  `/minio/admin/v3/info` — в Фазе 1 используется только для верификации
  креды/наличия admin-плоскости, разбор ответа — Фаза 2).
- Все ответы читаются с `response_size_cap` (bounded). S3-ошибки парсятся в
  `(http_status, s3_code, s3_message)`; `s3_code` — ключ классификации.
- Никаких write/delete/PutObject.

## Компонент: Detection (`actions.detect_minio`)

**Порты:** bare host без явного порта → пробуем
`9000, 9001, 80, 443, 10080, 10443, 19000, 19001, 20080, 20443, 29000, 29001`
через `build_basic_audit_plan(default_port=9000, default_ports=(9000, 9001, 80,
443, 10080, 10443, 19000, 19001, 20080, 20443, 29000, 29001))` (тот же механизм
`_DEFAULT_PORTS`, что у grafana `(3000, 13000, 23000)`). Явный порт → текущий
контракт targeting без добавления.

**Сигналы** (ни один не является единственным доказательством):
- S3-форма: GET `/` → XML `ListAllMyBucketsResult` (анон-list) ИЛИ S3-error XML
  с `<Code>` (AccessDenied/InvalidAccessKeyId и т.п.).
- Заголовок `Server: MinIO` (если не срезан reverse-proxy) — усиливающий, не
  обязательный.
- Health: GET `/minio/health/live` (204/200), `/minio/health/cluster` —
  MinIO-специфичны.
- Admin-плоскость: подписанный/анонимный GET `/minio/admin/v3/info` → 403 с
  MinIO-admin-ответом vs 404 (отличает MinIO Admin API от чистого S3).
- Console (порт 9001 или обнаруженный): GET `/` → HTML/asset-fingerprint MinIO
  Console; корреляция с API endpoint.

**Классификация** (`MinioDetection.status`):
- `confirmed` — ≥2 сильных MinIO-специфичных сигнала (напр. health-live +
  S3-форма, или admin-плоскость + S3-форма).
- `probable` — S3-форма есть, но MinIO-специфичные сигналы недоступны (headers
  срезаны, health закрыт) — не утверждаем MinIO, но и не отбрасываем.
- `not_minio` — нет S3-формы, либо явно другой сервис.
- `transport_failure` — connect/TLS/timeout (по `transport.classify_failure_reason`).

**Evidence** — dict в JSON: какие сигналы проверены и что вернули (status-коды,
matched-признаки, api_endpoint, console_endpoint). В TXT неподтверждённые
(`not_minio`/`transport_failure`) не засоряют вывод — политика как у clickhouse
pre-detect-noise (`suppress_undetected_records_in_text`).

## Компонент: Anonymous (`actions`, фаза detect/auth)

После `confirmed` — анонимный (неподписанный) GET `/` (ListBuckets):
- `anonymous_list_ok` — 200 + ListAllMyBucketsResult.
- `authentication_required` — 403 `AccessDenied` без креды.
- Если bucket известен (из анон-list или задан пользователем — без агрессивной
  энумерации) — анонимный `list_objects_v2(max-keys=1)` / `head_bucket` →
  `anonymous_read_ok` / `access_denied` / `not_found`.
- `verification_unavailable` — сигнал не получить (transport/парсинг).

Классы взаимоисключающие; `403` сам по себе НЕ означает invalid credentials и НЕ
означает «не MinIO».

## Компонент: Explicit auth (`actions.verify_credential`) — крит.

username/password трактуются как access key/secret key (те же поля
`AuditCredentialRun.username/password`). `--session-token` — опция модуля,
прокидывается в signer как `x-amz-security-token` для всех подписанных вызовов
проверяемой credential-кандидатуры (общую `AuditCredentialRun` не расширяем,
т.к. session token пары с access/secret, а не самостоятельная credential).

Верификация — реальный подписанный вызов (GET `/` подписанный, при недоступности
— `admin_info`), состояние по S3 error-code:
- `SignatureDoesNotMatch` / `InvalidAccessKeyId` → **invalid**.
- Валидная подпись (2xx) → **valid**.
- Валидная подпись + `AccessDenied` на probe → **valid_but_restricted**
  (подпись принята сервером ⇒ креды валидны; ограничены правами) — НЕ invalid.
- Парсинг/сеть недоступны → **verification_unavailable** / **transient_failure**
  (по `transport.classify_failure_reason`).

Реализуется через `ModuleAuditSpec.auth` + `skip_credentials_without_verifier`
(если detect показал, что верификатор недоступен — не гоняем креды вслепую).
Ordering/dedup/приоритет explicit/redaction — из существующего runtime
(`merge_audit_credential_runs`, `sort_default_audit_credential_runs`).
Per-credential gate для stop-on-success — как grafana `_grafana_credential_gate`
(валидна ⇒ стоп; restricted тоже считается валидной кредой для стопа).

## Output и цвет

**TXT** (тег `MINIO`, маркеры `[*]/[+]/[!]`, стиль как grafana/clickhouse),
компактно на обычном скане:
- target, MinIO detected (+ status), API endpoint, Console endpoint (если),
  anonymous access, authentication requirement, successful credential + тип
  (access-key/session-token), (admin capability — Фаза 2).
- Сырые большие XML/JSON НЕ печатаются.

**JSON** — структурный `AuditRecord` (существующая модель/сериализатор):
`target`, `api_endpoint`, `console_endpoint`, `detection.status`,
`detection.evidence`, `anonymous`, `auth_required`, `credential_attempts/results`,
`identity` (access-key id, redacted secret), `credential_type`, `partial_reasons`,
`errors`, action/status-метаданные. Поля admin/buckets/objects/secrets —
объявлены как null/пустые в Фазе 1 (заполняются в Фазах 2–3).

**Цвет** — через существующий renderer (`render_colored_marker_line`,
`BooleanColorRule`, `CountColorRule`, span-хелперы). Никаких хардкод-ANSI.
`_render_colored_minio_line` красит семантику: service detected, anonymous
access, auth required, valid credential, invalid credential, restricted
credential, warning, error, partial. `--no-color` штатно отключает ANSI; ANSI не
попадает в JSON/файлы/логи. Golden-тест вывода.

## Обработка ошибок и классификация

- Transport-сбои → `transport_failure` (detect) / `transient_failure` (auth),
  через `transport.classify_failure_reason`.
- S3-ошибки классифицируются по `<Code>`, не по голому HTTP-статусу.
- `403` никогда не эквивалентно invalid/not-MinIO.
- Секреты (secret key, session token) редактируются в TXT/логах
  (`mask_secret`); полностью — только в JSON `identity` при явном контракте
  (в Фазе 1 secret всегда redacted, показывать полностью незачем).

## Тестирование (в коммит, `tests/`)

- **SigV4** (`tests/test_clients_s3_sigv4.py`): подпись по AWS SigV4 тест-векторам;
  session_token → `x-amz-security-token` в signed headers; детерминированность.
- **Detection** (`tests/test_minio_detection.py`): все 4 класса на синтетических
  ответах; false-positive resistance — generic S3 (не-MinIO) даёт `probable`/
  `not_minio`, НЕ `confirmed`; порт-fanout 9000/9001/80/443/10080/10443/19000/
  19001/20080/20443/29000/29001; evidence в JSON.
- **Anonymous**: классификация authreq/anon-list/anon-read/denied/not-found/
  unavailable; 403 ≠ invalid.
- **Auth** (`tests/test_minio_auth.py`): valid / invalid (SignatureDoesNotMatch,
  InvalidAccessKeyId) / valid_but_restricted (AccessDenied при валидной подписи) /
  verification_unavailable / transient; alias username↔access-key.
- **CLI** (`tests/test_cli_minio.py` или дополнение существующего): регистрация
  команды, парсинг флагов, дефолт-порты, `--no-color`, session-token.
- **Output**: JSON-сериализация структуры; renderer/цвета (golden); `--no-color`
  без ANSI; debug-redaction секретов.
- **Architecture guard**: MinIO присутствует в реестре/`AUDIT_MODULE_NAMES`
  (существующие guard-тесты не ослаблять).

## Global constraints

- Дефолт-порты: `9000, 9001, 80, 443, 10080, 10443, 19000, 19001, 20080, 20443,
  29000, 29001`; дефолт-порт спека = 9000.
- Один HTTP-клиент на target-lifecycle (переиспользование пула), не новый клиент
  на запрос; ответы читаются bounded (`response_size_cap`); responses закрываются
  (гарантируется `HttpSessionPool`).
- Никаких write/delete/PutObject/admin-mutations в Фазе 1.
- SigV4 региона `us-east-1`, сервис `s3`; session_token опционален.
- Никакой новой тяжёлой зависимости; SigV4 — стдлиб (`hmac`, `hashlib`).
- Каждое изменение кода завершать `ruff format` + `ruff check` + `mypy`;
  markdown-документация исключена из ruff (`docs/**` в extend-exclude).
- ANSI не попадает в JSON/output-files/logs.

## Открытые вопросы (для стадии реализации)

- Точный дефолт region — `us-east-1` (MinIO принимает любой при пустой
  конфигурации); подтвердить на lab в Фазе 4.
- Набор health-эндпоинтов, реально включённых в дефолтном MinIO
  (`/minio/health/live` гарантирован; `cluster`/`ready` — проверить на lab).
- Точная форма Console-fingerprint — стабилизировать по реальному образцу в
  Фазе 4; в Фазе 1 Console-сигнал опционален и не обязателен для `confirmed`.
