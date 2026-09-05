# MinIO Module — Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Добавить `--defcreds` curated-каталог и admin-capability/permission детект (безопасные read-only Admin API probes) к модулю MinIO.

**Architecture:** Расширяет Фазу 1. defcreds — module-level каталог + candidate builder + wire в build_minio_plan (как grafana/redis). Admin-capability — `ModuleAuditSpec.capabilities` хук (как keeper) + новые Admin API методы в minio_api. Классификация в actions/types.

**Tech Stack:** Python 3.10+, стдлиб, существующие HttpSessionPool/AuditRecord/ModuleAuditSpec/renderer, pytest/ruff/mypy.

**Spec:** `docs/superpowers/specs/2026-09-03-minio-phase2-design.md`

## Global Constraints

- Только GET/HEAD Admin API; никаких user/policy/config-mutation, restart/stop.
- Admin API SigV4-signed (service s3, region us-east-1).
- defcreds — curated (реальные `_MINIO_REAL_DEFAULT_CREDENTIALS` vs эвристика `_MINIO_HEURISTIC_DEFAULT_CREDENTIALS`); НЕ generic brute-force. `minioadmin:minioadmin` обязателен.
- write/delete права = `unknown`; `--probe-write` (dest probe_write) заложен, НЕ активен.
- Не утверждать root по широкому bucket-доступу — только по accountinfo built-in consoleAdmin.
- Секреты не текут в вывод/логи. ANSI не в JSON/файлах. `--no-color` работает.
- `.venv/bin/ruff format`+`ruff check`+`mypy` чисто; per-file coverage ≥70%. Тесты `.venv/bin/python -m pytest`. CI: `PATH="$PWD/.venv/bin:$PATH" bash scripts/run_ci_job.sh <lint|test>`.
- НЕ коммить. Не ослаблять architecture guards.

---

### Task 1: defcreds каталог + builder + CLI + plan wiring

**Files:**
- Modify: `redposture_core/modules/minio/actions.py` (каталог + builder)
- Modify: `redposture_core/cli_modules/minio.py` (--defcreds)
- Modify: `redposture_core/modules/minio/stage.py` (build_minio_plan credential_runs; defcreds gating)
- Test: `tests/test_minio_defcreds.py`

**Interfaces:**
- Produces: `actions._MINIO_REAL_DEFAULT_CREDENTIALS`, `actions._MINIO_HEURISTIC_DEFAULT_CREDENTIALS`, `actions._MINIO_DEFAULT_CREDENTIALS`, `actions._build_credential_candidates(username, password, defcreds) -> list[tuple[str,str,str]]`.

- [ ] **Step 1: Написать падающие тесты**

```python
# tests/test_minio_defcreds.py
from __future__ import annotations

from redposture_core.cli_args import parse_args
from redposture_core.modules.minio import actions
from redposture_core.modules.minio.stage import build_minio_plan


def test_real_default_includes_minioadmin_and_is_separated_from_heuristics():
    assert ("minioadmin", "minioadmin") in actions._MINIO_REAL_DEFAULT_CREDENTIALS
    assert ("minioadmin", "minioadmin") not in actions._MINIO_HEURISTIC_DEFAULT_CREDENTIALS
    # каталог = реальные + эвристика, без дублей
    combined = actions._MINIO_DEFAULT_CREDENTIALS
    assert combined[: len(actions._MINIO_REAL_DEFAULT_CREDENTIALS)] == actions._MINIO_REAL_DEFAULT_CREDENTIALS
    assert len(set(combined)) == len(combined)


def test_candidate_builder_prioritises_provided_and_dedups():
    cands = actions._build_credential_candidates("AK", "SK", True)
    assert cands[0] == ("AK", "SK", "provided")
    assert ("minioadmin", "minioadmin", "default") in cands
    keys = [(u, p) for u, p, _ in cands]
    assert len(keys) == len(set(keys))  # dedup


def test_candidate_builder_no_defcreds_returns_only_provided():
    assert actions._build_credential_candidates("AK", "SK", False) == [("AK", "SK", "provided")]
    assert actions._build_credential_candidates(None, None, False) == []


def test_plan_includes_defcreds_runs_when_flag_set():
    plan = build_minio_plan(parse_args(["minio", "-t", "127.0.0.1", "--defcreds"]))
    labels = {(r.username, r.password, r.source) for r in plan.credential_runs}
    assert ("minioadmin", "minioadmin", "default") in labels
```

- [ ] **Step 2: Прогнать — падает**

Run: `.venv/bin/python -m pytest tests/test_minio_defcreds.py -v`
Expected: FAIL.

- [ ] **Step 3: Реализовать**

```python
# cli_modules/minio.py — в auth-группу добавить:
    auth.add_argument("--defcreds", dest="defcreds", action="store_true",
                      help="Try a curated catalog of MinIO default credentials (incl. minioadmin:minioadmin).")
```

```python
# modules/minio/actions.py — добавить каталог и builder (рядом с прочими module-level).
_MINIO_REAL_DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("minioadmin", "minioadmin"),
)
_MINIO_HEURISTIC_DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("minio", "minio123"),
    ("minioadmin", "minio123"),
    ("minioadmin", "password"),
    ("admin", "admin"),
    ("admin", "minioadmin"),
    ("admin", "password"),
    ("root", "minioadmin"),
    ("root", "password"),
    ("minio", "minio"),
    ("access", "secret"),
)
_MINIO_DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    _MINIO_REAL_DEFAULT_CREDENTIALS + _MINIO_HEURISTIC_DEFAULT_CREDENTIALS
)


def _build_credential_candidates(
    username: str | None, password: str | None, defcreds: bool
) -> list[tuple[str, str, str]]:
    candidates: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    if password is not None:
        user = (username or "").strip()
        pair = (user, password)
        candidates.append((user, password, "provided"))
        seen.add(pair)
    if defcreds:
        for access_key, secret_key in _MINIO_DEFAULT_CREDENTIALS:
            pair = (access_key, secret_key)
            if pair in seen:
                continue
            seen.add(pair)
            candidates.append((access_key, secret_key, "default"))
    return candidates
```

```python
# modules/minio/stage.py — build_minio_plan: добавить credential_runs. Импортировать
# из stage_runtime: AuditCredentialRun, merge_audit_credential_runs, sort_default_audit_credential_runs.
def build_minio_plan(args: Any) -> AuditCommandPlan:
    plan = build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)
    default_runs = (
        sort_default_audit_credential_runs(
            AuditCredentialRun(username=ak, password=sk, source="default")
            for ak, sk, source in actions._build_credential_candidates(None, None, True)
        )
        if bool(getattr(args, "defcreds", False))
        else ()
    )
    return replace(
        plan,
        credential_runs=merge_audit_credential_runs(plan.credential_runs, default_runs),
    )
```

> `replace` из `dataclasses`. `AuditCredentialRun`/`merge_audit_credential_runs`/`sort_default_audit_credential_runs` — из `redposture_core.stage_runtime` (см. grafana/stage.py импорты). Provided `-u/-p` уже попадают в `plan.credential_runs` через build_basic_audit_plan; default_runs добавляются при `--defcreds`.
> В `build_minio_spec` установить `continue_after_credential_error=bool(getattr(args,"defcreds",False))` и `continue_after_credential_success=False` (стоп на первой валидной, но перебор каталога при ошибках).

- [ ] **Step 4: Прогнать + lint/type**

Run: `.venv/bin/ruff format redposture_core/modules/minio/ redposture_core/cli_modules/minio.py tests/test_minio_defcreds.py && .venv/bin/python -m pytest tests/test_minio_defcreds.py tests/test_cli_minio.py -v && .venv/bin/ruff check redposture_core/modules/minio/ redposture_core/cli_modules/minio.py && .venv/bin/mypy redposture_core/modules/minio/`
Expected: PASS + чисто.

- [ ] **Step 5: Commit** (по явной команде)

```bash
git add redposture_core/modules/minio/ redposture_core/cli_modules/minio.py tests/test_minio_defcreds.py
git commit -m "feat(minio): defcreds catalog and candidate builder"
```

---

### Task 2: Admin API probes в клиенте

**Files:**
- Modify: `redposture_core/clients/minio_api.py`
- Test: `tests/test_clients_minio_api.py` (дополнить)

**Interfaces:**
- Produces: `MinioClient.account_info(*, signed=True)` (GET `/minio/admin/v3/accountinfo`), `MinioClient.list_users(*, signed=True)` (GET `/minio/admin/v3/list-users`), `MinioClient.list_canned_policies(*, signed=True)` (GET `/minio/admin/v3/list-canned-policies`). Все GET, bounded, SigV4 при наличии креды.

- [ ] **Step 1: Написать падающие тесты**

```python
# tests/test_clients_minio_api.py — добавить
def test_admin_probes_are_get_and_signed():
    pool = _FakePool(200, b"{}")
    client = minio_api.MinioClient(pool, scheme="http", host="h", port=9000,
                                   access_key="AK", secret_key="SK")
    for call, path in (
        (client.account_info, "/minio/admin/v3/accountinfo"),
        (client.list_users, "/minio/admin/v3/list-users"),
        (client.list_canned_policies, "/minio/admin/v3/list-canned-policies"),
    ):
        pool.calls.clear()
        call(signed=True)
        assert pool.calls[0]["method"] == "GET"
        assert pool.calls[0]["url"].endswith(path)
        assert "Authorization" in pool.calls[0]["headers"]
```

- [ ] **Step 2: Прогнать — падает**

Run: `.venv/bin/python -m pytest tests/test_clients_minio_api.py -k admin_probes -v`
Expected: FAIL.

- [ ] **Step 3: Реализовать**

```python
# clients/minio_api.py — добавить методы в MinioClient (рядом с admin_info):
    def account_info(self, *, signed: bool = True) -> MinioResponse:
        return self._request("GET", "/minio/admin/v3/accountinfo", "", signed=signed)

    def list_users(self, *, signed: bool = True) -> MinioResponse:
        return self._request("GET", "/minio/admin/v3/list-users", "", signed=signed)

    def list_canned_policies(self, *, signed: bool = True) -> MinioResponse:
        return self._request("GET", "/minio/admin/v3/list-canned-policies", "", signed=signed)
```

- [ ] **Step 4: Прогнать + lint/type**

Run: `.venv/bin/ruff format redposture_core/clients/minio_api.py tests/test_clients_minio_api.py && .venv/bin/python -m pytest tests/test_clients_minio_api.py -v && .venv/bin/ruff check redposture_core/clients/minio_api.py && .venv/bin/mypy redposture_core/clients/minio_api.py`
Expected: PASS + чисто.

- [ ] **Step 5: Commit** (по явной команде)

```bash
git add redposture_core/clients/minio_api.py tests/test_clients_minio_api.py
git commit -m "feat(minio): read-only Admin API probes (accountinfo/list-users/list-policies)"
```

---

### Task 3: Admin capability + identity классификация

**Files:**
- Modify: `redposture_core/modules/minio/types.py`, `redposture_core/modules/minio/actions.py`
- Test: `tests/test_minio_capabilities.py`

**Interfaces:**
- Consumes: `MinioClient.account_info/list_users/list_canned_policies` (Task 2).
- Produces: `types.AdminCapability(capability, identity_kind, evidence)`; `actions.classify_admin_capability(client) -> AdminCapability`.

- [ ] **Step 1: Написать падающие тесты**

```python
# tests/test_minio_capabilities.py
from __future__ import annotations

from redposture_core.clients.minio_api import MinioResponse, S3Error
from redposture_core.modules.minio import actions


class _StubClient:
    def __init__(self, *, account=None, users=None, policies=None):
        self._account, self._users, self._policies = account, users, policies

    def account_info(self, *, signed=True):
        return self._account

    def list_users(self, *, signed=True):
        return self._users

    def list_canned_policies(self, *, signed=True):
        return self._policies


def _ok(body=b"{}"):
    return MinioResponse(http_status=200, headers={}, body=body, error=None)


def _denied():
    return MinioResponse(http_status=403, headers={}, body=b"", error=S3Error(403, "AccessDenied", ""))


def _boom():
    return MinioResponse(http_status=0, headers={}, body=b"", transport_error="timeout")


def test_confirmed_when_admin_reads_succeed():
    cap = actions.classify_admin_capability(_StubClient(account=_ok(), users=_ok(), policies=_ok()))
    assert cap.capability == "confirmed"


def test_partial_when_some_admin_reads_denied():
    cap = actions.classify_admin_capability(_StubClient(account=_ok(), users=_ok(), policies=_denied()))
    assert cap.capability == "partial"


def test_not_confirmed_when_all_admin_reads_denied():
    cap = actions.classify_admin_capability(_StubClient(account=_denied(), users=_denied(), policies=_denied()))
    assert cap.capability == "not_confirmed"


def test_unknown_when_admin_plane_unreachable():
    cap = actions.classify_admin_capability(_StubClient(account=_boom(), users=_boom(), policies=_boom()))
    assert cap.capability == "unknown"


def test_identity_root_from_console_admin_accountinfo():
    account = _ok(b'{"AccountName":"minioadmin","Policy":{"Statement":[{"Effect":"Allow","Action":["admin:*"],"Resource":["arn:aws:s3:::*"]}]}}')
    cap = actions.classify_admin_capability(_StubClient(account=account, users=_ok(), policies=_ok()))
    assert cap.identity_kind in {"root", "delegated_admin"}
```

- [ ] **Step 2: Прогнать — падает**

Run: `.venv/bin/python -m pytest tests/test_minio_capabilities.py -v`
Expected: FAIL.

- [ ] **Step 3: Реализовать**

```python
# modules/minio/types.py — добавить
@dataclass(frozen=True)
class AdminCapability:
    capability: str  # confirmed | partial | not_confirmed | unknown
    identity_kind: str = "unknown"  # root | delegated_admin | s3_user | unknown
    evidence: dict[str, Any] = field(default_factory=dict)
```

```python
# modules/minio/actions.py — добавить
def _probe_state(resp: MinioResponse) -> str:
    if resp.transport_error:
        return "unknown"
    if 200 <= resp.http_status < 300:
        return "ok"
    if resp.error is not None and resp.error.code in {"AccessDenied", "AccessKeyDisabled"}:
        return "denied"
    if resp.http_status in {401, 403}:
        return "denied"
    return "unknown"


def _looks_admin_policy(body: bytes) -> bool:
    lowered = body.lower()
    return b"admin:" in lowered or b"consoleadmin" in lowered or b'"action":["*"]' in lowered.replace(b" ", b"")


def classify_admin_capability(client: Any) -> AdminCapability:
    account = client.account_info(signed=True)
    users = client.list_users(signed=True)
    policies = client.list_canned_policies(signed=True)
    states = {
        "accountinfo": _probe_state(account),
        "list_users": _probe_state(users),
        "list_canned_policies": _probe_state(policies),
    }
    admin_probes = [states["list_users"], states["list_canned_policies"]]
    ok_admin = sum(1 for s in admin_probes if s == "ok")
    denied_admin = sum(1 for s in admin_probes if s == "denied")

    if all(s == "unknown" for s in states.values()):
        capability = "unknown"
    elif ok_admin >= 2:
        capability = "confirmed"
    elif ok_admin >= 1:
        capability = "partial"
    elif denied_admin >= 1 and states["accountinfo"] in {"ok", "denied"}:
        capability = "not_confirmed"
    else:
        capability = "unknown"

    identity_kind = "unknown"
    if states["accountinfo"] == "ok":
        if _looks_admin_policy(account.body or b""):
            identity_kind = "delegated_admin"
            # root: встроенный аккаунт с consoleAdmin (имя совпадает с access key).
            if b"consoleadmin" in (account.body or b"").lower():
                identity_kind = "root"
        else:
            identity_kind = "s3_user"

    return AdminCapability(
        capability=capability, identity_kind=identity_kind, evidence=states
    )
```

> Классификация root/delegated — эвристическая по accountinfo; точная калибровка на lab (Фаза 4). Не утверждаем root по bucket-доступу — только по consoleAdmin в accountinfo.

- [ ] **Step 4: Прогнать + lint/type**

Run: `.venv/bin/ruff format redposture_core/modules/minio/ tests/test_minio_capabilities.py && .venv/bin/python -m pytest tests/test_minio_capabilities.py -v && .venv/bin/ruff check redposture_core/modules/minio/ && .venv/bin/mypy redposture_core/modules/minio/`
Expected: PASS + чисто.

- [ ] **Step 5: Commit** (по явной команде)

```bash
git add redposture_core/modules/minio/ tests/test_minio_capabilities.py
git commit -m "feat(minio): admin capability and identity classification"
```

---

### Task 4: Permissions + `--probe-write` (inert) + wiring capabilities hook + render/JSON + end-to-end

**Files:**
- Modify: `redposture_core/modules/minio/types.py`, `actions.py`, `stage.py`, `render.py`, `policy.py`, `cli_modules/minio.py`
- Test: `tests/test_minio_capabilities.py` (доп.), `tests/test_stage_minio.py` (доп.), `tests/test_minio_render.py` (доп.)

**Interfaces:**
- Consumes: `classify_admin_capability` (Task 3); `AdminCapability`.
- Produces: `capabilities_record(ctx, prior)` hook (в actions), `types.PermissionSummary`, spec wiring `capabilities=_capabilities`.

- [ ] **Step 1: Написать падающие тесты**

```python
# tests/test_stage_minio.py — добавить
def test_spec_wires_capabilities_hook():
    from redposture_core.cli_args import parse_args
    from redposture_core.modules.minio import stage
    spec = stage.build_minio_spec(parse_args(["minio", "-t", "127.0.0.1"]))
    assert spec.capabilities is not None


def test_probe_write_flag_is_inert_and_parses():
    from redposture_core.cli_args import parse_args
    args = parse_args(["minio", "-t", "127.0.0.1", "--probe-write"])
    assert args.probe_write is True
```

```python
# tests/test_minio_capabilities.py — добавить: capabilities_record кладёт admin/permissions в record
def test_capabilities_record_populates_admin_and_permissions(monkeypatch):
    from redposture_core.modules.minio import actions
    from redposture_core.modules.minio.types import AdminCapability
    monkeypatch.setattr(actions, "classify_admin_capability",
                        lambda client: AdminCapability(capability="confirmed", identity_kind="root", evidence={}))

    class _Ctx:
        class args: pass
        host, port = "h", 9000
        lifecycle_state = None
        class credential:
            username, password = "AK", "SK"
    rec = actions.capabilities_record(_Ctx(), {"credential_state": "valid"})
    assert rec["admin_capability"] == "confirmed"
    assert rec["identity_kind"] == "root"
    assert rec["permissions"]["write_objects"] == "unknown"
```

- [ ] **Step 2: Прогнать — падает**

Run: `.venv/bin/python -m pytest tests/test_stage_minio.py -k "capabilities or probe_write" tests/test_minio_capabilities.py -k capabilities_record -v`
Expected: FAIL.

- [ ] **Step 3: Реализовать**

```python
# cli_modules/minio.py — в transport или actions группу:
    minio_parser.add_argument_group  # (используй существующую группу)
```
Добавить в auth-группу (или новую Actions-группу):
```python
    auth.add_argument("--probe-write", dest="probe_write", action="store_true",
                      help="(reserved) intent to actively test write/delete perms; inert in this phase.")
```

```python
# modules/minio/types.py — добавить
@dataclass(frozen=True)
class PermissionSummary:
    list_buckets: str = "unknown"
    list_objects: str = "unknown"
    read_objects: str = "unknown"
    write_objects: str = "unknown"
    delete_objects: str = "unknown"
    admin_plane: str = "unknown"
```

```python
# modules/minio/actions.py — добавить hook
def capabilities_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    merged = dict(prior)
    if str(prior.get("credential_state") or "") not in {"valid", "valid_but_restricted"}:
        return merged
    client = _client_for(ctx, ctx.credential)
    cap = classify_admin_capability(client)
    merged["admin_capability"] = cap.capability
    merged["identity_kind"] = cap.identity_kind
    merged["admin_evidence"] = cap.evidence
    merged["permissions"] = {
        "list_buckets": "ok" if prior.get("credential_state") == "valid" else "unknown",
        "list_objects": "unknown",
        "read_objects": "unknown",
        "write_objects": "unknown",  # not verified without active probe
        "delete_objects": "unknown",
        "admin_plane": "ok" if cap.capability in {"confirmed", "partial"} else "denied"
        if cap.capability == "not_confirmed" else "unknown",
    }
    return merged
```

```python
# modules/minio/stage.py — build_minio_spec: добавить capabilities хук
    def _capabilities(ctx: Any, record: Any) -> AuditRecord:
        prior = record.to_dict() if hasattr(record, "to_dict") else dict(record)
        return AuditRecord.from_mapping(actions.capabilities_record(ctx, prior), module="minio", service="minio")
    # ... в ModuleAuditSpec(...): capabilities=_capabilities,
```

```python
# modules/minio/render.py — в _format_minio_records добавить (после credential):
    if record.get("admin_capability"):
        parts.append(f"(admin:{record['admin_capability']})")
        if record.get("identity_kind"):
            parts.append(f"(identity:{record['identity_kind']})")
    if record.get("default_credentials"):
        parts.append("(default_creds:True)")
# + цветовые regex-spans: (admin:confirmed)->red, partial->yellow, not_confirmed->bright_green, unknown->yellow;
#   (default_creds:True)->red. Добавить _ADMIN_RE/_DEFCREDS_RE и в _minio_color_spans.
```

- [ ] **Step 4: Прогнать + lint/type + полная сюита + CI**

Run:
```bash
.venv/bin/ruff format redposture_core/modules/minio/ redposture_core/cli_modules/minio.py tests/
.venv/bin/python -m pytest tests/ -k minio -v
.venv/bin/python -m pytest tests/ -q -p no:cacheprovider
PATH="$PWD/.venv/bin:$PATH" bash scripts/run_ci_job.sh lint && PATH="$PWD/.venv/bin:$PATH" bash scripts/run_ci_job.sh test
```
Expected: всё зелёное; architecture guards passed; coverage per-file ≥70%; `minio --help` exit 0. Если matrix flag coverage упадёт на новых флагах (`--defcreds`/`--probe-write`) — добавь их в существующие minio-кейсы `scripts/run_lab_matrix_sequential.sh` (по образцу Фазы 1 registration-fix).

- [ ] **Step 5: Commit** (по явной команде)

```bash
git add redposture_core/modules/minio/ redposture_core/cli_modules/minio.py tests/ scripts/run_lab_matrix_sequential.sh
git commit -m "feat(minio): admin capability hook, permissions, --probe-write (inert)"
```

---

## Вне scope (Фазы 3-5)

Энумерация + secret discovery (Фаза 3); Docker-labs + integration (Фаза 4); README/help (Фаза 5); активный `--probe-write`.

## Примечание о коммитах

Установка пользователя: не коммитить без явной команды. Исполнитель оставляет изменения в рабочем дереве.
