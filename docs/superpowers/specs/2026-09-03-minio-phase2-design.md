# MinIO модуль — Фаза 2 (Credentials вглубь + Admin capability)

Дата: 2026-09-03
Статус: дизайн, ожидает ревью

## Контекст

Продолжение MinIO-модуля (Фаза 1 = detection/anonymous/explicit-auth завершена).
Фаза 2 добавляет: `--defcreds` каталог, admin-capability детект,
permission-классификацию. Опирается на существующие абстракции и Фазу 1.
Оригинальное ТЗ: разделы 5 (default credentials), 7 (admin capabilities),
8 (permissions).

## Цель Фазы 2

После успешной authentication определить административные возможности identity
безопасными read-only Admin API probes. Плюс `--defcreds` — curated проверка
дефолтных credentials (включая `minioadmin:minioadmin`).

`redposture minio <target> --defcreds` → detection → anonymous → перебор curated
defcreds (stop-on-success) → для валидной креды admin-capability детект.
По-прежнему ничего не модифицирует.

## Границы Фазы 2

Вне scope: энумерация buckets/objects, secret discovery (Фаза 3), Docker-labs
(Фаза 4), README (Фаза 5), активный `--probe-write` (только заложить флаг-заглушку).

## 1. `--defcreds` каталог

**CLI:** добавить `--defcreds` (store_true, dest `defcreds`) в
`cli_modules/minio.py`, как у grafana/redis.

**Каталог** (`modules/minio/actions.py`), разделённый на реальные vs эвристику:
```python
# Реальный исторический дефолт MinIO.
_MINIO_REAL_DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("minioadmin", "minioadmin"),
)
# Курируемые service-specific кандидаты (эвристика), небольшой набор —
# НЕ generic brute-force wordlist.
_MINIO_HEURISTIC_DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("minio", "minio123"), ("minioadmin", "minio123"), ("minioadmin", "password"),
    ("admin", "admin"), ("admin", "minioadmin"), ("admin", "password"),
    ("root", "minioadmin"), ("root", "password"),
    ("minio", "minio"), ("access", "secret"),
)
_MINIO_DEFAULT_CREDENTIALS = _MINIO_REAL_DEFAULT_CREDENTIALS + _MINIO_HEURISTIC_DEFAULT_CREDENTIALS
```

**Candidate builder** `_build_credential_candidates(username, password, defcreds)`
по образцу grafana: provided-креда первой (приоритет), затем defcreds (при флаге),
stable dedup. Возвращает `list[tuple[access_key, secret_key, source]]`
(source ∈ provided/default).

**Wire в plan:** `build_minio_plan` строит `credential_runs` через
`merge_audit_credential_runs(provided_runs, plan.credential_runs, default_runs)`
+ `sort_default_audit_credential_runs` (как grafana). Каждая default-креда →
`AuditCredentialRun(username=ak, password=sk, source="default")`.

**Stop-on-success:** `credential_gate` (уже есть из Фазы 1) останавливает перебор
на первой валидной/restricted креде. defcreds-хит помечается `default_credentials`
в record. `continue_after_credential_error/success` = True только при `--defcreds`
(как grafana), чтобы перебрать каталог.

## 2. Admin capability detection

**Хук** `capabilities` в `ModuleAuditSpec` (как keeper/zookeeper): выполняется
после успешного auth для валидной креды.

**Реализация** `actions.capabilities_record(ctx, prior)`:
- Клиент с валидной кредой (из ctx.credential).
- Безопасные read-only Admin API v3 probes (SigV4, service s3, GET only):
  - `GET /minio/admin/v3/accountinfo` — политики/права вызывающей identity.
  - `GET /minio/admin/v3/list-users` — список IAM-пользователей (admin-only).
  - `GET /minio/admin/v3/list-canned-policies` — список политик (admin-only).
  - (`GET /minio/admin/v3/info` — server info, из Фазы 1.)
- НЕ выполнять: create/delete users, изменение policy/config, restart/stop.

**Классификация** `admin_capability` (в types `AdminCapability`):
- `confirmed` — ≥2 admin-only read-probe успешны (list-users + list-policies, или
  accountinfo показывает admin-политику + один list) → реальный admin.
- `partial` — часть admin-probe успешна, часть 403 (delegated с ограниченным
  admin-scope).
- `not_confirmed` — валидная креда, но все admin-probe → 403 (обычный S3-user).
- `unknown` — admin-плоскость недоступна/transient (parse/transport).

**Identity-тип** (`identity_kind`): различать по accountinfo-политике:
- `root` — accountinfo показывает встроенную политику `consoleAdmin` на встроенном
  root-аккаунте (AccountName совпадает с access key И политика consoleAdmin).
- `delegated_admin` — именованный пользователь с admin-эквивалентной политикой.
- `s3_user` — обычный пользователь без admin.
- `unknown` — не определить.
Не утверждать root только по широкому доступу к buckets (раздел 7 ТЗ).

Evidence (какие probe прошли, какие политики видны) → в JSON.

## 3. Permission classification

`permissions` (в types `PermissionSummary`), по безопасным read-only сигналам:
- `list_buckets`: ok/denied/unknown (по signed ListBuckets из auth).
- `list_objects`: unknown в Фазе 2 (энумерация — Фаза 3; probe только если bucket
  известен без агрессии) — по умолчанию `unknown`.
- `read_objects`: `unknown` (Фаза 3).
- `admin_plane`: из admin_capability.
- `write_objects`/`delete_objects`: **`unknown / not verified`** — активных
  write-probe нет. Заложить CLI-флаг `--probe-write` (store_true, dest
  `probe_write`) — в Фазе 2 он лишь помечает намерение (валидируется policy: без
  реального теста), реальный write-test НЕ реализуется.

## 4. Output / JSON

**TXT** (дополнение к Фазе-1 summary): при валидной креде добавить
`(admin:<capability>)` и `(identity:<kind>)` в summary-строку; `(default_creds:True)`
если defcreds-хит. Цвет: admin confirmed→red (высокий риск экспозиции),
partial→yellow, not_confirmed→green, unknown→yellow. default_creds→red.

**JSON:** добавить `admin_capability`, `admin_evidence` (probe-результаты, видимые
политики/пользователи — только имена/факты, без секретов), `identity_kind`,
`permissions`, `default_credentials`.

## 5. Тесты (в коммит)

- defcreds каталог: реальные vs эвристика разделены; `minioadmin:minioadmin`
  присутствует; builder — provided первым, dedup, source-метки.
- build_minio_plan: credential_runs включают provided+defcreds при `--defcreds`;
  порядок/приоритет.
- capabilities: confirmed (list-users+list-policies ok) / partial (часть 403) /
  not_confirmed (все 403) / unknown (transport); identity root vs delegated vs
  s3_user по accountinfo.
- Admin probe использует SigV4 (signed) и только GET; никаких mutate-вызовов.
- permissions: write/delete = unknown; `--probe-write` парсится, но не активен.
- render/JSON: admin/identity/default_creds поля + цвета; `--no-color`.
- stop-on-success: перебор останавливается на первой валидной креде.
- architecture guards не ослаблены; полная сюита + CI (coverage ≥70% per-file).

## Global constraints

- Только GET/HEAD Admin API; никаких user/policy/config-mutation, restart/stop.
- Admin API SigV4-signed (service s3, region us-east-1).
- defcreds — curated, НЕ generic brute-force; реальные и эвристические отделены.
- write/delete права = `unknown` без активного теста; `--probe-write` заложен, не
  активен.
- Не утверждать root по широкому bucket-доступу.
- Секреты не текут в вывод/логи (redaction сохранён из Фазы 1).
- `ruff format`+`ruff check`+`mypy` чисто; per-file coverage ≥70%.

## Открытые вопросы (валидация в Фазе 4 lab)

- Точные пути/формат ответов Admin API v3 (`accountinfo`/`list-users`/
  `list-canned-policies`) — подтвердить на реальном MinIO.
- Точная сигнатура «root» identity в accountinfo (built-in consoleAdmin) —
  откалибровать на lab.
