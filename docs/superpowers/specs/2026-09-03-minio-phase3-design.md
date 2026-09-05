# MinIO модуль — Фаза 3 (Bounded enumeration + Secret discovery)

Дата: 2026-09-03
Статус: дизайн, ожидает ревью

## Контекст

Продолжение MinIO-модуля (Фазы 1-2 = detection/anonymous/auth/defcreds/admin-
capability готовы). Фаза 3 добавляет bounded энумерацию buckets/objects и
secret discovery через существующий secret engine. Оригинальное ТЗ: разделы
9 (enumeration), 10 (secret discovery), 11 (bounded reading), 12 (scalability).

## Цель Фазы 3

По явным флагам: streaming-энумерация buckets/objects (с лимитами и пагинацией)
и двухэтапный secret discovery (приоритизация имён → bounded content-inspection →
существующий secret engine). Всё streaming/bounded — миллионы объектов не грузятся
в RAM. Без флагов ничего этого не происходит (дефолтный скан из Фаз 1-2).

## Границы Фазы 3

Вне scope: Docker-labs (Фаза 4), README (Фаза 5), активный `--probe-write`,
checkpoint/resume (архитектуру оставить пригодной, но не реализовывать).

## 1. CLI флаги (в стиле существующих `--show-*`)

`cli_modules/minio.py`, новая группа "Enumeration / Discovery":
- `--show-buckets` (store_true, dest show_buckets) — листинг buckets.
- `--bucket NAME` (dest bucket) — выбрать конкретный bucket.
- `--show-objects` (store_true, dest show_objects) — листинг objects.
- `--prefix P` (dest prefix) — фильтр по префиксу.
- `--limit N` (dest limit, int, default 100) — потолок выводимых buckets/objects.
- `--discover` (store_true, dest discover) — secret discovery (content-inspection).
- Bounded-reading бюджеты:
  - `--max-object-size BYTES` (dest max_object_size, default 10485760 = 10MiB) —
    объекты крупнее пропускаются (skipped by size).
  - `--max-read-bytes BYTES` (dest max_read_bytes, default 1048576 = 1MiB) —
    сколько байт читать из одного объекта (Range).
  - `--max-total-bytes BYTES` (dest max_total_bytes, default 67108864 = 64MiB) —
    суммарный байтовый бюджет discovery.
  - `--max-objects N` (dest max_objects, default 1000) — потолок объектов discovery.
  - `--discover-time BUDGET` (dest discover_time, float, default 30.0) — сек.

Policy: `--show-objects`/`--prefix` без `--bucket` (и без анонимного list) →
предупреждение/ошибка как в других модулях (нужен bucket-контекст).

## 2. Client: пагинация + Range read

`clients/minio_api.py`, расширить `MinioClient` (всё GET, bounded):
- `list_objects_v2(bucket, *, max_keys, prefix, continuation_token=None, signed)` —
  добавить `continuation-token` в query; ответ парсится вызывающей стороной.
- `get_object_range(bucket, key, *, start=0, length, signed) -> MinioResponse` —
  GET `/{bucket}/{key}` с заголовком `Range: bytes=start-(start+length-1)`,
  bounded `response_size_cap=length`. Ключ percent-encoded (закрывает deferred
  minor Фазы 1: object keys с пробелами/юникодом — `quote(key, safe="/")`).
- `head_object(bucket, key, *, signed) -> MinioResponse` — HEAD для metadata
  (size/etag/content-type/version) без чтения тела.

**Важно (SigV4 path):** `get_object_range`/`head_object` percent-кодируют key в
path ДО подписи (иначе подпись не совпадёт). Это активирует необходимость
корректного encoding из deferred-minor Фазы 1 — здесь и решается.

## 3. Streaming энумерация

`modules/minio/enumerate.py` (новый файл, чтобы actions.py не разрастался):
- `iter_buckets(client, *, limit) -> Iterator[BucketInfo]` — signed ListBuckets,
  парсит имена, yield до limit.
- `iter_objects(client, bucket, *, prefix, limit) -> Iterator[ObjectInfo]` —
  streaming пагинация ListObjectsV2: цикл по continuation-token, yield каждого
  объекта, СТОП по limit; НЕ накапливать весь список в памяти (генератор).
  Пагинация/limit применяются во время получения (не «получить всё → взять N»).
- `ObjectInfo`: bucket, key, size, last_modified, etag, version_id, content_type.
  version_id/content_type — из listing если есть, иначе None (без лишних HEAD).

## 4. Secret discovery (2 этапа)

`modules/minio/discover.py` (новый файл):

**Этап 1 — приоритизация имён.** `is_candidate_key(key) -> str | None` —
интересные по имени object keys → метка кандидата (не факт находки):
суффиксы/подстроки `.env`, `credentials`, `secret`, `config`, `backup`, `dump`,
`.pem`, `.key`, `.pfx`, `.p12`, `.jks`, `.kdbx`, `id_rsa`, `id_ed25519`,
`kubeconfig`, `.tfstate`, `.yaml`/`.yml`, `.json`, `.xml`, `.ini`, `.properties`,
`.sql`, архивы (`.zip`/`.tar`/`.gz`). Кандидат ≠ секрет (раздел 10 ТЗ).

**Этап 2 — bounded content-inspection.** `discover_secrets(client, bucket,
objects_iter, budgets) -> DiscoverResult`:
- Для каждого кандидата (streaming, не дожидаясь полного listing):
  - если size > max_object_size → skip (reason `object_too_large`).
  - если превышен max_objects / max_total_bytes / time budget → стоп (partial).
  - `get_object_range(bucket, key, length=min(max_read_bytes, max_total_remaining))`
    → bounded чтение; ошибки → partial reason (permission_denied/read_failure).
  - `secret_detection.scan_value(body_text, object_path="$", enabled=all)` →
    находки (тип, fingerprint, masked_value). Переиспользовать существующий engine,
    НЕ писать второй regex-scanner.
- `DiscoverResult`: findings (list: type/bucket/key/masked_value/fingerprint/
  object_path), candidates_seen, objects_scanned, bytes_read, partial_reasons
  (permission_denied/object_too_large/byte_budget_exhausted/object_limit/timeout/
  parse_failure), coverage_complete: bool.

**Bounded-reading абстракция:** легковесный `Budget` dataclass (max_object_size,
max_read_bytes, max_total_bytes, max_objects, deadline) с методами
`allow_object(size)`, `charge(bytes)`, `expired()`. Не MinIO-only костыль —
чистый reusable helper (в discover.py; при необходимости переиспользуем позже).

## 5. Wiring: `data` hook

`ModuleAuditSpec.data` (как grafana `_data`): выполняется после capabilities для
детектированного/аутентифицированного target. `actions.data_record(ctx, prior)`:
- Только если задан какой-либо из `--show-buckets/--show-objects/--discover`.
- Клиент из ctx.credential (или анонимный, если anonymous_list_ok).
- show_buckets → `record["buckets"] = list(iter_buckets(limit))`.
- show_objects (при bucket) → `record["objects"] = list(iter_objects(...))` (bounded).
- discover → `record["secret_candidates"]`, `record["secret_findings"]`,
  `record["discover_partial_reasons"]`, `record["discover_coverage"]`.
- streaming: discovery начинает обработку объектов не дожидаясь полного listing.

## 6. Output / JSON

**TXT:** дополнительные detail-строки (только при флагах), тег MINIO, маркеры:
- `[+] bucket <name>` (по одной на bucket при --show-buckets).
- `[+] object <bucket>/<key> (size:N) (mtime:...) (etag:...) (ctype:...)` при
  --show-objects (bounded по limit).
- `[+] secret <type> bucket=<b> key=<k> value=<masked> place=<path>` при --discover.
- `[!] Discover partial: <reasons>` если coverage не полное.
Сырые большие тела/XML НЕ печатаются. Secret value — masked (redact сохранён).

**JSON:** `buckets`, `objects` (с полями), `secret_candidates`, `secret_findings`,
`discover_partial_reasons`, `discover_coverage`. Через существующий AuditRecord.

## 7. Тесты (в коммит)

- Client: list_objects_v2 continuation-token в query; get_object_range Range-заголовок
  + percent-encoded key + bounded cap; head_object HEAD.
- SigV4 path-encoding: key с пробелом/юникодом подписывается закодированным path
  (регресс на deferred-minor Фазы 1).
- iter_objects: streaming пагинация — при 3 страницах и limit=2 останавливается
  на 2 объектах, НЕ читает 3-ю страницу целиком (мок пула считает вызовы).
- is_candidate_key: .env/id_rsa/.tfstate → кандидаты; neutral.txt → None.
- discover_secrets: bounded — object_too_large пропускается с reason; byte-budget/
  object-limit/timeout → partial + coverage_complete False; находки через
  secret engine (fake secret в теле → finding с masked value); binary object не
  падает; одинаковый секрет в 2 объектах.
- Большой synthetic listing (несколько тысяч ключей, мок) — pagination/limit/
  streaming/memory (не материализуется весь список).
- data hook wiring; флаги парсятся; policy (objects без bucket).
- render/JSON buckets/objects/secrets + partial; masked secret не течёт полным.
- architecture guards не ослаблены; полная сюита + CI (per-file ≥70%); matrix
  coverage для новых флагов.

## Global constraints

- Только GET/HEAD; никаких write/delete/PutObject/mutation.
- Энумерация и discovery — ТОЛЬКО по явным флагам; дефолтный скан не меняется.
- Streaming/bounded: пагинация и лимиты применяются во время получения; не
  материализовать полный inventory в RAM (генераторы).
- Bounded-reading бюджеты обязательны; partial coverage честно отражается в JSON
  (не заявлять full coverage при partial).
- Secret discovery — существующий `secret_detection.scan_value`, не второй scanner.
- Object keys percent-encoded до SigV4 (path и подпись согласованы).
- Secret value всегда masked в выводе/логах.
- `ruff format`+`check`+`mypy` чисто; per-file coverage ≥70%.

## Открытые вопросы (Фаза 4 lab)

- Точный формат ListObjectsV2 (NextContinuationToken, Contents/Key/Size/ETag/
  LastModified) — подтвердить на реальном MinIO.
- Content-type/version-id в listing vs требуется HEAD — откалибровать на lab.
