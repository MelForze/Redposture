# Timeout Escalation By Attempt — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** На повторных попытках сетевого запроса поднимать таймаут по абсолютной лесенке `base → max(5,base) → max(7,base)`, при этом `connection refused` больше не ретраить, а базовый таймаут поднять с 1 c до 3 c.

**Architecture:** Общий фундамент (лесенка таймаутов + точный классификатор причины падения) добавляется в `redposture_core/clients/transport.py`. Его потребляют два HTTP retry-цикла (`HttpSessionPool.request`, `HttpApiClient.send`) и TCP-клиенты с уже существующими циклами попыток (ZooKeeper, Kafka). Дефолты таймаута правятся в CLI-парсерах. Прикладные ложные срабатывания на слове «timeout» чинятся точечно в модульных `fail_record`-проверках.

**Tech Stack:** Python 3.11+, стандартная библиотека (`socket`, `http.client`, `ssl`), pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-09-02-timeout-escalation-by-attempt-design.md`

## Global Constraints

- Лесенка таймаута: `ladder(base) = [base, max(5.0, base), max(7.0, base)]`; далее держит `max(7.0, base)`. Без множителей.
- Глобальный дефолт `--timeout` = `3.0`; `proxmox` = `5.0`; `zookeeper`/`keeper` = `5.0` (без изменений). Явный `--timeout N` задаёт `base` и уважается даже ниже 3 c.
- `connection refused` / `dns` / `network unreachable` / `tls verification failed` — терминальные причины: **не ретраить**.
- `connection timeout` / `reset` — эскалируемые причины: ретраить с ростом таймаута по лесенке.
- Число фактических попыток = `min(retries + 1, число ступеней лесенки)`; при `retries=0` — ровно одна попытка (лесенка не разворачивается).
- Серверные бюджеты (ClickHouse `send_receive_timeout`, Mongo `serverSelectionTimeoutMS`, ZK `session_timeout_ms`) на базовом таймауте — лесенку НЕ подхватывают.
- Каждое изменение кода завершать `ruff format` перед прогоном тестов.
- Точный классификатор `timeout` не должен матчить голое слово `timeout` (иначе прикладные `INVALID_SESSION_TIMEOUT`, `Timeout exceeded: max_execution_time` ложно считаются сетевыми).

---

### Task 1: Фундамент — лесенка таймаутов и точный классификатор причины

**Files:**
- Modify: `redposture_core/clients/transport.py`
- Test: `tests/test_clients_transport.py`

**Interfaces:**
- Consumes: ничего (фундамент).
- Produces:
  - `escalating_timeout(base: float, attempt_index: int) -> float` — `attempt_index` 0-based; `0→base`, `1→max(5,base)`, `2→max(7,base)`, `≥3→max(7,base)`.
  - `classify_failure_reason(value: Any) -> str` — один из `"refused" | "timeout" | "dns" | "network" | "tls" | "reset" | "other"`.
  - `is_terminal_reason(reason: str) -> bool` — `True` для `refused/dns/network/tls`.
  - `is_escalating_reason(reason: str) -> bool` — `True` для `timeout/reset`.

- [ ] **Step 1: Написать падающие тесты**

```python
# tests/test_clients_transport.py — добавить в конец файла
import redposture_core.clients.transport as transport


def test_escalating_timeout_ladder_default_base():
    assert [transport.escalating_timeout(3.0, i) for i in range(4)] == [3.0, 5.0, 7.0, 7.0]


def test_escalating_timeout_ladder_high_base_clamps_up():
    assert [transport.escalating_timeout(8.0, i) for i in range(3)] == [8.0, 8.0, 8.0]


def test_escalating_timeout_ladder_low_explicit_base():
    assert [transport.escalating_timeout(1.0, i) for i in range(3)] == [1.0, 5.0, 7.0]


def test_classify_failure_reason_buckets():
    assert transport.classify_failure_reason("[Errno 61] Connection refused") == "refused"
    assert transport.classify_failure_reason("connection timeout") == "timeout"
    assert transport.classify_failure_reason("Read timed out") == "timeout"
    assert transport.classify_failure_reason("Name or service not known") == "dns"
    assert transport.classify_failure_reason("No route to host") == "network"
    assert transport.classify_failure_reason("certificate verify failed") == "tls"
    assert transport.classify_failure_reason("Connection reset by peer") == "reset"


def test_classify_failure_reason_ignores_application_timeout_words():
    # Прикладные «timeout», не сетевые — не должны считаться timeout.
    assert transport.classify_failure_reason("INVALID_SESSION_TIMEOUT") == "other"
    assert transport.classify_failure_reason("Timeout exceeded: elapsed 10s, maximum: max_execution_time") == "other"


def test_reason_predicates():
    assert transport.is_terminal_reason("refused") is True
    assert transport.is_terminal_reason("dns") is True
    assert transport.is_terminal_reason("tls") is True
    assert transport.is_escalating_reason("timeout") is True
    assert transport.is_escalating_reason("reset") is True
    assert transport.is_escalating_reason("refused") is False
```

- [ ] **Step 2: Прогнать тесты — убедиться, что падают**

Run: `python3 -m pytest tests/test_clients_transport.py -k "escalating or classify or reason_predicates" -v`
Expected: FAIL — `AttributeError: module ... has no attribute 'escalating_timeout'`

- [ ] **Step 3: Реализовать фундамент**

```python
# redposture_core/clients/transport.py — добавить после is_connection_timeout_fail_record

_RESET_MARKERS = (
    "connection reset",
    "reset by peer",
    "broken pipe",
    "unexpected eof",
    "connection closed",
    "remote end closed",
    "server closed",
    "protocol closed before",
    "closed before",
)


def escalating_timeout(base: float, attempt_index: int) -> float:
    """Таймаут ступени `attempt_index` (0-based) по лесенке base → max(5,base) → max(7,base)."""
    base_value = max(0.1, float(base))
    floors = (base_value, max(5.0, base_value), max(7.0, base_value))
    idx = min(max(0, int(attempt_index)), len(floors) - 1)
    return floors[idx]


def classify_failure_reason(value: Any) -> str:
    """Классифицировать причину сетевого падения по нормализованному/сырому тексту.

    Приоритет refused → tls → timeout → dns → network → reset → other.
    Ветка timeout НЕ матчит голое слово ``timeout`` (только ``connection timeout`` /
    ``timed out`` / errno 60,110), иначе прикладные ``INVALID_SESSION_TIMEOUT`` и
    ``Timeout exceeded: ... max_execution_time`` ложно считались бы сетевыми.
    """
    text = str(value or "").strip().lower()
    if not text:
        return "other"
    if "connection refused" in text or "[errno 111]" in text or "[errno 61]" in text or "10061" in text:
        return "refused"
    if (
        "certificate verify failed" in text
        or "self signed certificate" in text
        or "tls verification failed" in text
        or "wrong version number" in text
    ):
        return "tls"
    if "connection timeout" in text or "timed out" in text or "[errno 60]" in text or "[errno 110]" in text:
        return "timeout"
    if (
        "name or service not known" in text
        or "nodename nor servname" in text
        or "getaddrinfo" in text
        or "dns lookup failed" in text
        or "temporary failure in name resolution" in text
    ):
        return "dns"
    if "no route to host" in text or "network is unreachable" in text or "network unreachable" in text:
        return "network"
    if any(marker in text for marker in _RESET_MARKERS):
        return "reset"
    return "other"


def is_terminal_reason(reason: str) -> bool:
    """True, если ретрай бесполезен: refused/dns/network/tls."""
    return reason in {"refused", "dns", "network", "tls"}


def is_escalating_reason(reason: str) -> bool:
    """True, если стоит ретраить с ростом таймаута: timeout/reset."""
    return reason in {"timeout", "reset"}
```

- [ ] **Step 4: Прогнать тесты — убедиться, что проходят**

Run: `ruff format redposture_core/clients/transport.py tests/test_clients_transport.py && python3 -m pytest tests/test_clients_transport.py -v`
Expected: PASS (включая существующие тесты файла).

- [ ] **Step 5: Commit** (только по явной команде пользователя — см. примечание в конце плана)

```bash
git add redposture_core/clients/transport.py tests/test_clients_transport.py
git commit -m "feat(transport): add timeout ladder and precise failure-reason classifier"
```

---

### Task 2: Поднять дефолты таймаута (глобальный 3.0, proxmox 5.0)

**Files:**
- Modify: `redposture_core/cli_args.py:330`
- Modify: `redposture_core/cli_modules/proxmox.py:25`
- Test: `tests/test_cli_args.py`

**Interfaces:**
- Consumes: ничего.
- Produces: изменённые дефолты парсера — потребляются во всех модулях через `args.timeout`.

- [ ] **Step 1: Написать падающие тесты**

```python
# tests/test_cli_args.py — добавить
from redposture_core.module_registry import build_parser  # используемый в файле билдер парсера


def test_global_timeout_default_is_three():
    parser = build_parser()
    args = parser.parse_args(["grafana", "-t", "127.0.0.1"])
    assert args.timeout == 3.0


def test_proxmox_timeout_default_is_five():
    parser = build_parser()
    args = parser.parse_args(["proxmox", "-t", "127.0.0.1"])
    assert args.timeout == 5.0


def test_zookeeper_timeout_default_unchanged():
    parser = build_parser()
    args = parser.parse_args(["zookeeper", "-t", "127.0.0.1"])
    assert args.timeout == 5.0
```

> Примечание для исполнителя: имя билдера парсера уточнить в `tests/test_cli_args.py` (существующие тесты уже строят парсер) и использовать тот же вызов.

- [ ] **Step 2: Прогнать тесты — убедиться, что падают**

Run: `python3 -m pytest tests/test_cli_args.py -k "timeout_default" -v`
Expected: FAIL — `assert 1.0 == 3.0` (global), `assert 3.0 == 5.0` (proxmox).

- [ ] **Step 3: Изменить дефолты**

```python
# redposture_core/cli_args.py:330 — было default=1.0
        default=3.0,
```

```python
# redposture_core/cli_modules/proxmox.py:25 — было parser.set_defaults(timeout=3.0)
    parser.set_defaults(timeout=5.0)
```

- [ ] **Step 4: Прогнать тесты — убедиться, что проходят**

Run: `ruff format redposture_core/cli_args.py redposture_core/cli_modules/proxmox.py tests/test_cli_args.py && python3 -m pytest tests/test_cli_args.py -v`
Expected: PASS.

- [ ] **Step 5: Проверить, что не сломались зависящие от дефолта тесты**

Run: `python3 -m pytest tests/ -k "timeout or default or cli_args or mass_profile" -q`
Expected: PASS; при падении из-за захардкоженного `1.0` в ассертах — обновить эти тесты на новый дефолт.

- [ ] **Step 6: Commit** (по явной команде)

```bash
git add redposture_core/cli_args.py redposture_core/cli_modules/proxmox.py tests/test_cli_args.py
git commit -m "feat(cli): raise default network timeout to 3s (proxmox 5s)"
```

---

### Task 3: Эскалация в HTTP retry-цикле `HttpSessionPool.request`

**Files:**
- Modify: `redposture_core/clients/http_session.py:321-338`
- Test: `tests/test_elastic_http_session.py`

**Interfaces:**
- Consumes: `transport.escalating_timeout`, `transport.classify_failure_reason`, `transport.is_terminal_reason`, `transport.is_escalating_reason` (Task 1).
- Produces: поведение — refused не ретраится; timeout/reset эскалируют таймаут по лесенке от `timeout_value` (base).

- [ ] **Step 1: Написать падающие тесты**

```python
# tests/test_elastic_http_session.py — добавить

import redposture_core.clients.http_session as http_session
from redposture_core.clients.http_session import HttpSessionPool


def _pool(retries):
    return HttpSessionPool(timeout=3.0, retries=retries)


def test_request_escalates_timeout_on_timeout(monkeypatch):
    seen_timeouts = []

    def fake_once(self, method, url, *, headers, body, timeout, response_size_cap):
        seen_timeouts.append(timeout)
        exc = TimeoutError("timed out")
        from redposture_core.clients.http_api import normalize_http_error
        return (http_session.HttpResponse(status=0, body=b"", headers={}, error=normalize_http_error(exc)), exc, False)

    monkeypatch.setattr(HttpSessionPool, "_request_once", fake_once)
    pool = _pool(retries=3)
    pool.request("GET", "http://127.0.0.1:9200/")
    assert seen_timeouts == [3.0, 5.0, 7.0]


def test_request_does_not_retry_on_refused(monkeypatch):
    calls = []

    def fake_once(self, method, url, *, headers, body, timeout, response_size_cap):
        calls.append(timeout)
        exc = ConnectionRefusedError("[Errno 61] Connection refused")
        from redposture_core.clients.http_api import normalize_http_error
        return (http_session.HttpResponse(status=0, body=b"", headers={}, error=normalize_http_error(exc)), exc, False)

    monkeypatch.setattr(HttpSessionPool, "_request_once", fake_once)
    pool = _pool(retries=3)
    pool.request("GET", "http://127.0.0.1:9200/")
    assert calls == [3.0]  # одна попытка, без ретраев
```

- [ ] **Step 2: Прогнать тесты — убедиться, что падают**

Run: `python3 -m pytest tests/test_elastic_http_session.py -k "escalates or refused" -v`
Expected: FAIL — `seen_timeouts == [3.0, 3.0, 3.0]` (фиксированный таймаут) и `calls == [3.0, 3.0, 3.0]` (refused ретраится).

- [ ] **Step 3: Переписать внутренний цикл попыток**

```python
# redposture_core/clients/http_session.py — заменить блок attempts-цикла (строки ~322-337)
        for _redirect in range(_MAX_REDIRECTS + 1):
            response: HttpResponse | None = None
            attempts = max(1, int(self.default_retries if retries is None else retries) + 1)
            for attempt in range(attempts):
                attempt_timeout = transport.escalating_timeout(timeout_value, attempt)
                response, request_error, _reused = self._request_once(
                    method_value,
                    current_url,
                    headers=headers_value,
                    body=body_value,
                    timeout=attempt_timeout,
                    response_size_cap=response_size_cap,
                )
                if request_error is None or not safe or attempt >= attempts - 1:
                    break
                reason = transport.classify_failure_reason(response.error)
                if not transport.is_escalating_reason(reason):
                    break  # refused/dns/network/tls/other — ретрай бесполезен
                with self._lock:
                    self._stats["retries"] += 1
                time.sleep(min(1.5, 0.2 * (2**attempt)))
            assert response is not None
```

> Добавить импорт `from . import transport` в шапку `http_session.py`, если его ещё нет. `timeout_value` (строка 314) остаётся `base` лесенки.

- [ ] **Step 4: Прогнать тесты — убедиться, что проходят**

Run: `ruff format redposture_core/clients/http_session.py tests/test_elastic_http_session.py && python3 -m pytest tests/test_elastic_http_session.py -v`
Expected: PASS.

- [ ] **Step 5: Регрессия по HTTP-модулям**

Run: `python3 -m pytest tests/ -k "http_session or elastic or grafana or consul or gitlab or kubeapi or qdrant or registry" -q`
Expected: PASS.

- [ ] **Step 6: Commit** (по явной команде)

```bash
git add redposture_core/clients/http_session.py tests/test_elastic_http_session.py
git commit -m "feat(http-session): escalate timeout per attempt, stop retrying refused"
```

---

### Task 4: Эскалация в HTTP retry-цикле `HttpApiClient.send`

**Files:**
- Modify: `redposture_core/clients/http_api.py:456-475`
- Test: `tests/test_clients_http_api.py`

**Interfaces:**
- Consumes: `transport.escalating_timeout`, `transport.classify_failure_reason`, `transport.is_escalating_reason` (Task 1).
- Produces: то же поведение эскалации/раннего выхода для второго HTTP-клиента (proxmox/grafana/elastic-детект).

- [ ] **Step 1: Написать падающие тесты**

```python
# tests/test_clients_http_api.py — добавить
from redposture_core.clients.http_api import HttpApiClient, HttpClientConfig, HttpRequest, HttpResponse


def test_send_escalates_timeout_on_timeout(monkeypatch):
    seen = []

    def fake_send_once(self, request, *, timeout=None):
        seen.append(timeout)
        return HttpResponse(status=0, body=b"", headers={}, error="connection timeout",
                            request_url=request.url, final_url=request.url)

    monkeypatch.setattr(HttpApiClient, "_send_once", fake_send_once)
    client = HttpApiClient(HttpClientConfig(timeout=3.0, retries=3))
    client.send(HttpRequest(method="GET", url="http://127.0.0.1/"))
    assert seen == [3.0, 5.0, 7.0]


def test_send_stops_on_refused(monkeypatch):
    seen = []

    def fake_send_once(self, request, *, timeout=None):
        seen.append(timeout)
        return HttpResponse(status=0, body=b"", headers={},
                            error="connection refused (service is not listening on target port)",
                            request_url=request.url, final_url=request.url)

    monkeypatch.setattr(HttpApiClient, "_send_once", fake_send_once)
    client = HttpApiClient(HttpClientConfig(timeout=3.0, retries=3))
    client.send(HttpRequest(method="GET", url="http://127.0.0.1/"))
    assert seen == [3.0]
```

> `_send_once` сейчас берёт таймаут из `timeout` аргумента `send`. После правки `send` должен передавать в `_send_once` эскалированный таймаут ступени явным `timeout=`.

- [ ] **Step 2: Прогнать тесты — убедиться, что падают**

Run: `python3 -m pytest tests/test_clients_http_api.py -k "escalates or refused" -v`
Expected: FAIL — `seen == [None, None, None]` / фиксированный таймаут; refused ретраится.

- [ ] **Step 3: Переписать `send`**

```python
# redposture_core/clients/http_api.py — метод send (строки ~456-475)
    def send(self, request: HttpRequest, *, timeout: float | None = None) -> HttpResponse:
        attempts = max(1, int(self.config.retries) + 1)
        base_timeout = self.config.timeout if timeout is None else float(timeout)
        last_error = ""
        for attempt in range(1, attempts + 1):
            attempt_timeout = transport.escalating_timeout(base_timeout, attempt - 1)
            response = self._send_once(request, timeout=attempt_timeout)
            if response.error is None:
                return response
            last_error = response.error
            if response.error.startswith("cross-origin redirect blocked:"):
                return response
            reason = transport.classify_failure_reason(response.error)
            if attempt < attempts and transport.is_escalating_reason(reason):
                time.sleep(max(0.0, float(self.config.backoff)) * attempt)
                continue
            break
        return HttpResponse(
            status=0,
            body=b"",
            headers={},
            error=last_error or "request failed",
            request_url=request.url,
            final_url=request.url,
        )
```

> Добавить `from . import transport` в шапку `http_api.py`, если отсутствует.

- [ ] **Step 4: Прогнать тесты — убедиться, что проходят**

Run: `ruff format redposture_core/clients/http_api.py tests/test_clients_http_api.py && python3 -m pytest tests/test_clients_http_api.py tests/test_http_api_lifecycle.py -v`
Expected: PASS.

- [ ] **Step 5: Commit** (по явной команде)

```bash
git add redposture_core/clients/http_api.py tests/test_clients_http_api.py
git commit -m "feat(http-api): escalate timeout per attempt, stop retrying refused"
```

---

### Task 5: Лесенка в TCP-клиенте ZooKeeper (stage2 attempt-таймауты)

**Files:**
- Modify: `redposture_core/modules/zookeeper/actions.py:2896,2916`
- Test: `tests/test_clients_zookeeper.py` (или существующий тест zookeeper actions — уточнить по расположению)

**Interfaces:**
- Consumes: `transport.escalating_timeout` (Task 1).
- Produces: `znode_count_attempt_timeouts` заполняется реальной лесенкой вместо `[timeout] * n`.

- [ ] **Step 1: Написать падающий тест**

```python
# добавить рядом с существующими тестами zookeeper stage2
from redposture_core.clients import transport


def test_zk_stage2_attempt_timeouts_use_ladder():
    base = 5.0
    stage2_attempts = 3
    expected = [transport.escalating_timeout(base, i) for i in range(stage2_attempts)]
    assert expected == [5.0, 5.0, 7.0]
```

> Этот тест фиксирует ожидаемую форму лесенки; интеграционную проверку заполнения `znode_count_attempt_timeouts` добавить по образцу существующих тестов stage2, если они есть.

- [ ] **Step 2: Прогнать — убедиться, что зелёный на хелпере, и найти места замены**

Run: `python3 -m pytest -k "stage2_attempt_timeouts" -v`
Expected: PASS (проверяет только форму). Далее — заменить построение списка.

- [ ] **Step 3: Заменить построение attempt-таймаутов на лесенку**

```python
# redposture_core/modules/zookeeper/actions.py — строки 2896 и 2916
# было: [float(timeout)] * stage2_attempts if _is_connection_timeout_error(...) else []
        merged["znode_count_attempt_timeouts"] = (
            [transport.escalating_timeout(float(timeout), i) for i in range(stage2_attempts)]
            if _is_connection_timeout_error(enum_error)
            else []
        )
```

```python
# второй сайт (строка ~2916)
    merged["znode_count_attempt_timeouts"] = (
        [transport.escalating_timeout(float(timeout), i) for i in range(stage2_attempts)]
        if _is_connection_timeout_error(stage2_error)
        else []
    )
```

> Убедиться, что `from redposture_core.clients import transport` (или существующий алиас) импортирован в `zookeeper/actions.py`.

- [ ] **Step 4: Прогнать тесты zookeeper**

Run: `ruff format redposture_core/modules/zookeeper/actions.py && python3 -m pytest tests/ -k "zookeeper or keeper" -q`
Expected: PASS.

- [ ] **Step 5: Commit** (по явной команде)

```bash
git add redposture_core/modules/zookeeper/actions.py tests/test_clients_zookeeper.py
git commit -m "feat(zookeeper): use timeout ladder for stage2 attempt timeouts"
```

---

### Task 6: Точный классификатор в модульных `fail_record`-проверках (ClickHouse)

**Files:**
- Modify: `redposture_core/modules/clickhouse/actions.py:371-374`
- Test: `tests/test_clickhouse_5173.py` (или существующий clickhouse-тест — уточнить)

**Interfaces:**
- Consumes: `transport.classify_failure_reason` (Task 1).
- Produces: ClickHouse retry-решение больше не считает серверный `Timeout exceeded: ... max_execution_time` сетевым timeout.

- [ ] **Step 1: Написать падающий тест**

```python
# добавить в clickhouse-тест
from redposture_core.clients import transport


def test_application_timeout_not_network_timeout():
    # серверный лимит выполнения запроса — не сетевой timeout
    assert transport.classify_failure_reason(
        "Timeout exceeded: elapsed 10s, maximum: max_execution_time"
    ) == "other"
    # настоящий сетевой timeout по-прежнему распознаётся
    assert transport.classify_failure_reason("connection timeout") == "timeout"
```

- [ ] **Step 2: Прогнать — убедиться, что зелёный (фундамент из Task 1 уже даёт нужное поведение)**

Run: `python3 -m pytest -k "application_timeout_not_network" -v`
Expected: PASS.

- [ ] **Step 3: Перевести ClickHouse retry-маркеры на точный классификатор**

```python
# redposture_core/modules/clickhouse/actions.py — блок retry-решения (~371-374)
# было: if _is_timeout_error(text) or _is_connection_refused_error(text) or any(marker in lower ...):
    reason = transport.classify_failure_reason(text)
    if (
        transport.is_escalating_reason(reason)
        or reason == "refused"
        or any(marker in lower for marker in retryable_markers)
    ):
```

> Сохранить исходную семантику «ретраить refused здесь тоже» (ClickHouse-специфика protocol-fallback), но перестать ловить прикладной серверный timeout. Убедиться, что `transport` импортирован (в файле уже есть `_is_timeout_error = transport.is_connection_timeout`).

- [ ] **Step 4: Прогнать тесты clickhouse**

Run: `ruff format redposture_core/modules/clickhouse/actions.py && python3 -m pytest tests/ -k "clickhouse" -q`
Expected: PASS.

- [ ] **Step 5: Commit** (по явной команде)

```bash
git add redposture_core/modules/clickhouse/actions.py tests/test_clickhouse_5173.py
git commit -m "fix(clickhouse): stop treating server max_execution_time as network timeout"
```

---

### Task 7: Elastic mass-profile — подтвердить отключение лесенки и пересмотреть floor

**Files:**
- Modify: `redposture_core/modules/elastic/stage.py:110-127`
- Test: `tests/test_elastic_mass_profile.py`

**Interfaces:**
- Consumes: поведение из Task 3 (при `retries=0` цикл делает одну попытку, лесенка не разворачивается).
- Produces: тест-гарантия, что mass-профиль не запускает эскалацию; решение по базовому таймауту mass-профиля.

- [ ] **Step 1: Написать тест-гарантию**

```python
# tests/test_elastic_mass_profile.py — добавить (paren fixtures как в соседних тестах)
def test_mass_profile_keeps_single_attempt_no_ladder() -> None:
    args = parse_args(["elastic", "-t", "10.0.0.0/18"])
    plan = elastic_stage.build_elastic_plan(args)
    assert plan.target_count >= 10_000
    # mass-профиль держит retries=0 → одна попытка → лесенка не разворачивается
    assert args.retries == 0
    # база mass-профиля остаётся сжатой ради throughput (не эскалирует)
    assert args.timeout == 1.0
```

- [ ] **Step 2: Прогнать — убедиться, что проходит (гарантия без изменения кода)**

Run: `python3 -m pytest tests/test_elastic_mass_profile.py -v`
Expected: PASS — включая новый тест. Если `assert args.timeout == 1.0` упадёт (решение поднять floor mass-профиля), синхронизировать с решением из Step 3.

- [ ] **Step 3: Решение по floor mass-профиля**

Открытый вопрос из спеки: при новом дефолте 3 c mass-профиль сейчас жмёт `timeout` к `1.0` (`stage.py:124`). Оставить `1.0` (throughput важнее на ≥10 000 эндпоинтов) — рекомендация. Изменение вносить ТОЛЬКО если продукт-решение иное; по умолчанию — оставить как есть, зафиксировав тестом.

- [ ] **Step 4: Прогнать тесты elastic**

Run: `ruff format redposture_core/modules/elastic/stage.py tests/test_elastic_mass_profile.py && python3 -m pytest tests/ -k "elastic" -q`
Expected: PASS.

- [ ] **Step 5: Commit** (по явной команде)

```bash
git add redposture_core/modules/elastic/stage.py tests/test_elastic_mass_profile.py
git commit -m "test(elastic): guarantee mass-profile keeps single attempt (no ladder)"
```

---

### Task 8: Полный прогон и архитектурные гварды

**Files:**
- Test: весь `tests/`

- [ ] **Step 1: Полный прогон**

Run: `ruff format redposture_core tests && python3 -m pytest tests/ -q`
Expected: PASS. Особое внимание — `tests/test_architecture_guards.py`, тесты с захардкоженным дефолтом `1.0` (обновить на `3.0`, если всплывут).

- [ ] **Step 1b: Guard-тест «op-бюджеты вне лесенки»**

Проверить, что серверные бюджеты остались на базовом таймауте, а не на ступени лесенки (задачи их код не трогали — это регрессионная страховка):

Run: `python3 -m pytest tests/ -k "clickhouse or mongodb or zookeeper" -q`
Expected: PASS — `send_receive_timeout`/`serverSelectionTimeoutMS`/`session_timeout_ms` считаются от `args.timeout`, не от `escalating_timeout`.

- [ ] **Step 2: Проверка `--help` дефолтов вручную**

Run: `python3 redposture.py grafana --help | grep -A1 -- '--timeout'; python3 redposture.py proxmox --help | grep -A1 -- '--timeout'`
Expected: grafana `default: 3.0`, proxmox `default: 5.0`.

- [ ] **Step 3: Commit финального прогона** (по явной команде)

```bash
git add -A
git commit -m "test: full suite green for timeout escalation"
```

---

## Вне scope этого плана (следующая фаза)

Спека упоминает слой TCP-connect и для одноразовых клиентов (`oracle`, `mongodb`, `docker_engine`), а также `kafka`, у которых сейчас нет единого attempt-цикла для эскалации connect-таймаута. Их интеграция с `escalating_timeout` требует введения ретрай-цикла на уровне connect и оформляется отдельным планом, чтобы не дублировать разнородный код клиентов здесь. Эскалация в этой фазе покрывает оба HTTP-слоя (большинство модулей) и ZooKeeper stage2.

Поле записи `attempt_timeouts` для HTTP-слоёв (обобщение ZK-паттерна на `HttpResponse`/`AuditRecord`) вынесено в ту же следующую фазу: базовая ценность (эскалация + отказ ретраить refused) от него не зависит.

## Примечание о коммитах

Шаги `git commit` в задачах — часть стандартного TDD-ритма плана. В этом репозитории действует установка пользователя: не выполнять `git commit`/`push` без явной команды в том же запросе. Исполнитель прогоняет тесты и оставляет изменения в рабочем дереве; коммитит только когда пользователь прямо об этом просит.
