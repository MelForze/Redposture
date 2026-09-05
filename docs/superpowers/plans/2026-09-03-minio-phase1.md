# MinIO Module — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Добавить безопасный read-only модуль `redposture minio` (Фаза 1): обнаружение MinIO, anonymous checks, верификация явных credentials, TXT/JSON/цветной вывод.

**Architecture:** Модуль строится по паттерну `modules/grafana` через `ModuleAuditSpec` + `run_basic_host_audit` (общие targeting/output/progress не переписываются). Доступ к S3/Admin API — собственный SigV4-signer (`clients/s3_sigv4.py`) поверх существующего `HttpSessionPool`, без внешних SDK.

**Tech Stack:** Python 3.10+, стандартная библиотека (`hmac`, `hashlib`, `xml.etree`), существующие `HttpSessionPool`, `AuditRecord`, `ModuleAuditSpec`, renderer, pytest, ruff, mypy.

**Spec:** `docs/superpowers/specs/2026-09-03-minio-phase1-design.md`

## Global Constraints

- Дефолт-порты: `9000, 9001, 80, 443, 10080, 10443, 19000, 19001, 20080, 20443, 29000, 29001`; дефолт-порт спека = `9000`.
- Доступ к S3/Admin — собственный SigV4 (region `us-east-1`, service `s3`), session_token опционален (`x-amz-security-token`). Никаких MinIO/boto3 SDK; SigV4 на стдлибе.
- Никаких write/delete/PutObject/admin-mutations в Фазе 1. Только GET/HEAD.
- username/password = access key/secret key (те же поля `AuditCredentialRun`). `--session-token` — опция модуля, применяется ко всем подписанным вызовам.
- Верификация креды — по S3 error-code: `SignatureDoesNotMatch`/`InvalidAccessKeyId` → invalid; валидная подпись + `AccessDenied` → valid_but_restricted (НЕ invalid); `403` никогда не эквивалентен invalid/not-MinIO.
- Классификация detection: `confirmed` (≥2 сильных MinIO-специфичных сигнала) / `probable` / `not_minio` / `transport_failure`. Detection-evidence → в JSON; неподтверждённое не засоряет TXT.
- Один HTTP-клиент на target-lifecycle (переиспользование пула), bounded чтение (`response_size_cap`).
- ANSI не попадает в JSON/output-files/logs; `--no-color` полностью отключает цвет; цвет только через существующий renderer, без хардкод-ANSI.
- Каждое изменение кода завершать `.venv/bin/ruff format` + `.venv/bin/ruff check` + `.venv/bin/mypy`. Тесты — `.venv/bin/python -m pytest`. Не ослаблять существующие architecture-guard тесты.
- `docs/**` исключён из ruff (уже в extend-exclude).

---

### Task 1: SigV4 signer (`clients/s3_sigv4.py`)

**Files:**
- Create: `redposture_core/clients/s3_sigv4.py`
- Test: `tests/test_clients_s3_sigv4.py`

**Interfaces:**
- Consumes: ничего (стдлиб).
- Produces:
  - `sign_request(*, method: str, host: str, path: str, query: str = "", headers: dict[str, str] | None = None, payload_hash: str, access_key: str, secret_key: str, region: str = "us-east-1", service: str = "s3", session_token: str | None = None, timestamp: datetime.datetime | None = None) -> dict[str, str]` — возвращает заголовки для добавления к запросу: `Authorization`, `x-amz-date`, `x-amz-content-sha256`, и `x-amz-security-token` при наличии session_token.
  - `EMPTY_PAYLOAD_HASH: str` — sha256 пустого тела (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).

- [ ] **Step 1: Написать падающий тест (авторитетный AWS SigV4 S3 GET vector)**

```python
# tests/test_clients_s3_sigv4.py
from __future__ import annotations

import datetime

from redposture_core.clients import s3_sigv4


def test_sign_request_matches_aws_s3_get_reference_vector():
    # Публичный AWS SigV4 reference (S3 GET Object, single-chunk payload).
    headers = s3_sigv4.sign_request(
        method="GET",
        host="examplebucket.s3.amazonaws.com",
        path="/test.txt",
        query="",
        headers={"Range": "bytes=0-9"},
        payload_hash=s3_sigv4.EMPTY_PAYLOAD_HASH,
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="s3",
        timestamp=datetime.datetime(2013, 5, 24, 0, 0, 0, tzinfo=datetime.timezone.utc),
    )
    assert headers["x-amz-date"] == "20130524T000000Z"
    assert headers["x-amz-content-sha256"] == s3_sigv4.EMPTY_PAYLOAD_HASH
    assert headers["Authorization"] == (
        "AWS4-HMAC-SHA256 "
        "Credential=AKIDEXAMPLE/20130524/us-east-1/s3/aws4_request, "
        "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, "
        "Signature=67fe34c8530db585abddc51067328adfedb6e42487d2566dc7d927d6e2722900"
    )
    assert "x-amz-security-token" not in headers


def test_sign_request_includes_session_token_in_signed_headers():
    headers = s3_sigv4.sign_request(
        method="GET",
        host="minio.example:9000",
        path="/",
        payload_hash=s3_sigv4.EMPTY_PAYLOAD_HASH,
        access_key="AKID",
        secret_key="SECRET",
        session_token="SESSIONTOKEN123",
        timestamp=datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc),
    )
    assert headers["x-amz-security-token"] == "SESSIONTOKEN123"
    # security token участвует в подписи (входит в SignedHeaders).
    signed = headers["Authorization"].split("SignedHeaders=", 1)[1].split(",", 1)[0]
    assert "x-amz-security-token" in signed
```

- [ ] **Step 2: Прогнать — убедиться, что падает**

Run: `.venv/bin/python -m pytest tests/test_clients_s3_sigv4.py -v`
Expected: FAIL — `ModuleNotFoundError`/`AttributeError` (модуля нет).

- [ ] **Step 3: Реализовать signer**

```python
# redposture_core/clients/s3_sigv4.py
"""AWS Signature Version 4 signer for S3 / MinIO Admin API requests.

Pure, dependency-free (stdlib hmac/hashlib). MinIO signs both S3 and Admin API
requests with SigV4, service "s3". Only the header-based signing flow is
implemented (no presigned URLs, no chunked payloads).
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
from urllib.parse import quote

EMPTY_PAYLOAD_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

_ALGORITHM = "AWS4-HMAC-SHA256"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _hmac(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


def _canonical_query(query: str) -> str:
    if not query:
        return ""
    pairs: list[tuple[str, str]] = []
    for part in query.split("&"):
        if not part:
            continue
        name, _, value = part.partition("=")
        pairs.append((quote(name, safe="-_.~"), quote(value, safe="-_.~")))
    pairs.sort()
    return "&".join(f"{name}={value}" for name, value in pairs)


def sign_request(
    *,
    method: str,
    host: str,
    path: str,
    query: str = "",
    headers: dict[str, str] | None = None,
    payload_hash: str,
    access_key: str,
    secret_key: str,
    region: str = "us-east-1",
    service: str = "s3",
    session_token: str | None = None,
    timestamp: datetime.datetime | None = None,
) -> dict[str, str]:
    """Return the SigV4 auth headers to merge into the outgoing request."""
    now = timestamp or datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    signed_headers_map: dict[str, str] = {}
    for name, value in (headers or {}).items():
        signed_headers_map[name.lower()] = str(value).strip()
    signed_headers_map["host"] = host
    signed_headers_map["x-amz-content-sha256"] = payload_hash
    signed_headers_map["x-amz-date"] = amz_date
    if session_token:
        signed_headers_map["x-amz-security-token"] = session_token

    sorted_names = sorted(signed_headers_map)
    canonical_headers = "".join(f"{name}:{signed_headers_map[name]}\n" for name in sorted_names)
    signed_headers = ";".join(sorted_names)

    canonical_request = "\n".join(
        [
            method.upper(),
            path or "/",
            _canonical_query(query),
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [_ALGORITHM, amz_date, credential_scope, _sha256_hex(canonical_request.encode("utf-8"))]
    )
    signature = hmac.new(
        _signing_key(secret_key, date_stamp, region, service),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    authorization = (
        f"{_ALGORITHM} Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    result = {
        "Authorization": authorization,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
    }
    if session_token:
        result["x-amz-security-token"] = session_token
    return result


__all__ = ["sign_request", "EMPTY_PAYLOAD_HASH"]
```

- [ ] **Step 4: Прогнать — убедиться, что проходит**

Run: `.venv/bin/ruff format redposture_core/clients/s3_sigv4.py tests/test_clients_s3_sigv4.py && .venv/bin/python -m pytest tests/test_clients_s3_sigv4.py -v`
Expected: PASS (оба теста).

- [ ] **Step 5: Lint/type**

Run: `.venv/bin/ruff check redposture_core/clients/s3_sigv4.py && .venv/bin/mypy redposture_core/clients/s3_sigv4.py`
Expected: чисто.

- [ ] **Step 6: Commit** (по явной команде пользователя — см. примечание в конце)

```bash
git add redposture_core/clients/s3_sigv4.py tests/test_clients_s3_sigv4.py
git commit -m "feat(minio): add stdlib SigV4 signer"
```

---

### Task 2: MinIO S3/Admin client (`clients/minio_api.py`)

**Files:**
- Create: `redposture_core/clients/minio_api.py`
- Test: `tests/test_clients_minio_api.py`

**Interfaces:**
- Consumes: `s3_sigv4.sign_request`, `s3_sigv4.EMPTY_PAYLOAD_HASH` (Task 1); `HttpSessionPool` (existing).
- Produces:
  - `S3Error` dataclass: `http_status: int`, `code: str`, `message: str`.
  - `MinioResponse` dataclass: `http_status: int`, `headers: dict[str, str]`, `body: bytes`, `error: S3Error | None`, `transport_error: str | None`.
  - `MinioClient(pool: HttpSessionPool, *, scheme: str, host: str, port: int, access_key: str | None = None, secret_key: str | None = None, session_token: str | None = None)`.
  - методы (все GET/HEAD, bounded): `get_service_root(*, signed: bool) -> MinioResponse` (GET `/`), `head_bucket(bucket, *, signed) -> MinioResponse`, `list_objects_v2(bucket, *, max_keys=1, prefix="", signed) -> MinioResponse` (GET `/{bucket}?list-type=2&...`), `health(kind: str) -> MinioResponse` (GET `/minio/health/{kind}`), `admin_info(*, signed=True) -> MinioResponse` (GET `/minio/admin/v3/info`).
  - `base_url` property → `f"{scheme}://{host}:{port}"`.

- [ ] **Step 1: Написать падающие тесты (мокнутый пул)**

```python
# tests/test_clients_minio_api.py
from __future__ import annotations

from redposture_core.clients import minio_api


class _FakePool:
    def __init__(self, status, body, headers=None):
        self._status = status
        self._body = body
        self._headers = headers or {}
        self.calls = []

    def request(self, method, url, *, headers=None, body=None, timeout=None, response_size_cap=10 * 1024 * 1024):
        self.calls.append({"method": method, "url": url, "headers": headers or {}})
        return _FakeResponse(self._status, self._body, self._headers)


class _FakeResponse:
    def __init__(self, status, body, headers):
        self.status = status
        self.body = body
        self.headers = headers
        self.error = None


_ACCESS_DENIED_XML = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b"<Error><Code>AccessDenied</Code><Message>Access Denied.</Message></Error>"
)


def test_get_service_root_parses_s3_error_code():
    pool = _FakePool(403, _ACCESS_DENIED_XML, {"Server": "MinIO"})
    client = minio_api.MinioClient(pool, scheme="http", host="10.0.0.5", port=9000)
    resp = client.get_service_root(signed=False)
    assert resp.http_status == 403
    assert resp.error is not None
    assert resp.error.code == "AccessDenied"
    assert pool.calls[0]["url"] == "http://10.0.0.5:9000/"


def test_signed_request_attaches_authorization_header():
    pool = _FakePool(200, b"<ListAllMyBucketsResult></ListAllMyBucketsResult>")
    client = minio_api.MinioClient(
        pool, scheme="http", host="h", port=9000, access_key="AKID", secret_key="SECRET"
    )
    client.get_service_root(signed=True)
    sent = pool.calls[0]["headers"]
    assert "Authorization" in sent
    assert sent["Authorization"].startswith("AWS4-HMAC-SHA256 ")
    assert "x-amz-date" in sent


def test_list_objects_v2_builds_bounded_query():
    pool = _FakePool(200, b"<ListBucketResult></ListBucketResult>")
    client = minio_api.MinioClient(pool, scheme="https", host="h", port=443)
    client.list_objects_v2("mybucket", max_keys=1, prefix="a/", signed=False)
    url = pool.calls[0]["url"]
    assert url.startswith("https://h:443/mybucket?")
    assert "list-type=2" in url
    assert "max-keys=1" in url
    assert "prefix=a%2F" in url


def test_transport_exception_becomes_transport_error():
    class _BoomPool:
        def request(self, *a, **k):
            raise OSError("connection refused")

    client = minio_api.MinioClient(_BoomPool(), scheme="http", host="h", port=9000)
    resp = client.health("live")
    assert resp.transport_error is not None
    assert resp.http_status == 0
```

- [ ] **Step 2: Прогнать — убедиться, что падает**

Run: `.venv/bin/python -m pytest tests/test_clients_minio_api.py -v`
Expected: FAIL (модуля нет).

- [ ] **Step 3: Реализовать клиент**

```python
# redposture_core/clients/minio_api.py
"""Thin S3 / MinIO Admin API client over the shared HttpSessionPool.

GET/HEAD only (read-only). Parses S3 error XML into a typed (code, message).
No third-party SDK; requests are SigV4-signed with clients.s3_sigv4 when
credentials are present.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote, urlencode
from xml.etree import ElementTree

from . import s3_sigv4

_RESPONSE_CAP = 5 * 1024 * 1024


@dataclass(frozen=True)
class S3Error:
    http_status: int
    code: str
    message: str


@dataclass(frozen=True)
class MinioResponse:
    http_status: int
    headers: dict[str, str]
    body: bytes
    error: S3Error | None = None
    transport_error: str | None = None


def _parse_s3_error(status: int, body: bytes) -> S3Error | None:
    if status < 400 or not body:
        return None
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return S3Error(http_status=status, code="", message="")
    if root.tag.split("}")[-1] != "Error":
        return None
    code = ""
    message = ""
    for child in root:
        tag = child.tag.split("}")[-1]
        if tag == "Code":
            code = (child.text or "").strip()
        elif tag == "Message":
            message = (child.text or "").strip()
    return S3Error(http_status=status, code=code, message=message)


class MinioClient:
    def __init__(
        self,
        pool: object,
        *,
        scheme: str,
        host: str,
        port: int,
        access_key: str | None = None,
        secret_key: str | None = None,
        session_token: str | None = None,
    ) -> None:
        self._pool = pool
        self.scheme = scheme
        self.host = host
        self.port = int(port)
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def _host_header(self) -> str:
        return f"{self.host}:{self.port}"

    def _request(self, method: str, path: str, query: str, *, signed: bool) -> MinioResponse:
        url = f"{self.base_url}{path}"
        if query:
            url = f"{url}?{query}"
        headers: dict[str, str] = {}
        if signed and self.access_key and self.secret_key:
            headers.update(
                s3_sigv4.sign_request(
                    method=method,
                    host=self._host_header,
                    path=path,
                    query=query,
                    payload_hash=s3_sigv4.EMPTY_PAYLOAD_HASH,
                    access_key=self.access_key,
                    secret_key=self.secret_key,
                    session_token=self.session_token,
                )
            )
        try:
            resp = self._pool.request(method, url, headers=headers, response_size_cap=_RESPONSE_CAP)
        except Exception as exc:  # noqa: BLE001 - transport errors normalized for callers
            return MinioResponse(http_status=0, headers={}, body=b"", transport_error=str(exc))
        if getattr(resp, "error", None):
            return MinioResponse(http_status=0, headers={}, body=b"", transport_error=str(resp.error))
        status = int(resp.status)
        body = resp.body or b""
        return MinioResponse(
            http_status=status,
            headers=dict(resp.headers or {}),
            body=body,
            error=_parse_s3_error(status, body),
        )

    def get_service_root(self, *, signed: bool) -> MinioResponse:
        return self._request("GET", "/", "", signed=signed)

    def head_bucket(self, bucket: str, *, signed: bool) -> MinioResponse:
        return self._request("HEAD", f"/{quote(bucket)}", "", signed=signed)

    def list_objects_v2(
        self, bucket: str, *, max_keys: int = 1, prefix: str = "", signed: bool
    ) -> MinioResponse:
        params = {"list-type": "2", "max-keys": str(max(1, int(max_keys)))}
        if prefix:
            params["prefix"] = prefix
        return self._request("GET", f"/{quote(bucket)}", urlencode(params), signed=signed)

    def health(self, kind: str) -> MinioResponse:
        return self._request("GET", f"/minio/health/{kind}", "", signed=False)

    def admin_info(self, *, signed: bool = True) -> MinioResponse:
        return self._request("GET", "/minio/admin/v3/info", "", signed=signed)


__all__ = ["MinioClient", "MinioResponse", "S3Error"]
```

> Примечание для исполнителя: `urlencode` квотит значения (`a/` → `a%2F`), что удовлетворяет тесту `prefix=a%2F`. Порядок ключей в `urlencode` стабилен (insertion order dict) — тест проверяет подстроки, не полный порядок.

- [ ] **Step 4: Прогнать + lint/type**

Run: `.venv/bin/ruff format redposture_core/clients/minio_api.py tests/test_clients_minio_api.py && .venv/bin/python -m pytest tests/test_clients_minio_api.py -v && .venv/bin/ruff check redposture_core/clients/minio_api.py && .venv/bin/mypy redposture_core/clients/minio_api.py`
Expected: PASS + чисто.

- [ ] **Step 5: Commit** (по явной команде)

```bash
git add redposture_core/clients/minio_api.py tests/test_clients_minio_api.py
git commit -m "feat(minio): add S3/Admin API client over HttpSessionPool"
```

---

### Task 3: Типы и detection (`modules/minio/types.py`, `modules/minio/actions.py::detect_minio`)

**Files:**
- Create: `redposture_core/modules/minio/__init__.py` (пустой докстринг-модуль)
- Create: `redposture_core/modules/minio/types.py`
- Create: `redposture_core/modules/minio/actions.py`
- Test: `tests/test_minio_detection.py`

**Interfaces:**
- Consumes: `MinioClient`, `MinioResponse`, `S3Error` (Task 2); `transport.classify_failure_reason` (existing).
- Produces:
  - `types.MinioDetection`: `status: str` (`confirmed|probable|not_minio|transport_failure`), `api_endpoint: str | None`, `console_endpoint: str | None`, `evidence: dict[str, Any]`.
  - `actions.detect_minio(client: MinioClient) -> MinioDetection` — детект по одному endpoint (client уже указывает на host:port).
  - `actions._SIGNAL_*` — helper-функции классификации (S3-форма, health, admin-plane).

- [ ] **Step 1: Написать падающие тесты**

```python
# tests/test_minio_detection.py
from __future__ import annotations

from redposture_core.clients.minio_api import MinioResponse, S3Error
from redposture_core.modules.minio import actions


class _StubClient:
    """Client double returning canned responses per method."""

    def __init__(self, *, root=None, health=None, admin=None):
        self._root = root
        self._health = health
        self._admin = admin
        self.scheme = "http"
        self.host = "10.0.0.5"
        self.port = 9000

    @property
    def base_url(self):
        return f"{self.scheme}://{self.host}:{self.port}"

    def get_service_root(self, *, signed):
        return self._root

    def health(self, kind):
        return self._health

    def admin_info(self, *, signed=True):
        return self._admin


def _resp(status, body=b"", headers=None, error=None):
    return MinioResponse(http_status=status, headers=headers or {}, body=body, error=error)


def test_confirmed_when_health_live_and_s3_shape():
    client = _StubClient(
        root=_resp(403, b"<Error><Code>AccessDenied</Code></Error>", {"Server": "MinIO"},
                   S3Error(403, "AccessDenied", "")),
        health=_resp(200, b""),
        admin=_resp(403, b"<Error><Code>AccessDenied</Code></Error>", error=S3Error(403, "AccessDenied", "")),
    )
    det = actions.detect_minio(client)
    assert det.status == "confirmed"
    assert det.api_endpoint == "http://10.0.0.5:9000"
    assert det.evidence["health_live"] is True
    assert det.evidence["s3_shape"] is True


def test_probable_when_only_s3_shape_no_minio_specific_signals():
    # Generic S3-совместимый (не MinIO): S3 XML есть, но health/admin/Server отсутствуют.
    client = _StubClient(
        root=_resp(200, b"<ListAllMyBucketsResult></ListAllMyBucketsResult>"),
        health=_resp(404, b""),
        admin=_resp(404, b""),
    )
    det = actions.detect_minio(client)
    assert det.status == "probable"


def test_not_minio_when_no_s3_shape():
    client = _StubClient(
        root=_resp(200, b"<html><title>nginx</title></html>"),
        health=_resp(404, b""),
        admin=_resp(404, b""),
    )
    det = actions.detect_minio(client)
    assert det.status == "not_minio"


def test_transport_failure_bubbles_up():
    boom = MinioResponse(http_status=0, headers={}, body=b"", transport_error="connection refused")
    client = _StubClient(root=boom, health=boom, admin=boom)
    det = actions.detect_minio(client)
    assert det.status == "transport_failure"
    assert "refused" in det.evidence.get("transport_error", "")
```

- [ ] **Step 2: Прогнать — убедиться, что падает**

Run: `.venv/bin/python -m pytest tests/test_minio_detection.py -v`
Expected: FAIL (модуля нет).

- [ ] **Step 3: Реализовать types.py и detect_minio**

```python
# redposture_core/modules/minio/__init__.py
"""MinIO audit module (Phase 1: detection, anonymous, explicit auth)."""
```

```python
# redposture_core/modules/minio/types.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class MinioDetection:
    status: str  # confirmed | probable | not_minio | transport_failure
    api_endpoint: str | None = None
    console_endpoint: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
```

```python
# redposture_core/modules/minio/actions.py
"""MinIO detection / anonymous / auth-verification actions."""

from __future__ import annotations

from ...clients.minio_api import MinioClient, MinioResponse
from .types import MinioDetection

_S3_MARKERS = (b"ListAllMyBucketsResult", b"ListBucketResult", b"<Error>", b"<Code>")


def _has_s3_shape(resp: MinioResponse) -> bool:
    if resp.transport_error:
        return False
    if resp.error is not None and resp.error.code:
        return True
    body = resp.body or b""
    return any(marker in body for marker in _S3_MARKERS)


def _server_is_minio(resp: MinioResponse) -> bool:
    server = str(resp.headers.get("Server") or resp.headers.get("server") or "")
    return "minio" in server.lower()


def _health_live(resp: MinioResponse) -> bool:
    return not resp.transport_error and resp.http_status in {200, 204}


def _admin_plane(resp: MinioResponse) -> bool:
    # Admin API present when the admin path answers with an S3/MinIO error
    # (403/AccessDenied) rather than a plain 404.
    if resp.transport_error:
        return False
    if resp.http_status == 404:
        return False
    return resp.http_status in {401, 403} or (resp.error is not None and bool(resp.error.code))


def detect_minio(client: MinioClient) -> MinioDetection:
    root = client.get_service_root(signed=False)
    if root.transport_error:
        return MinioDetection(
            status="transport_failure",
            api_endpoint=client.base_url,
            evidence={"transport_error": root.transport_error},
        )
    health = client.health("live")
    admin = client.admin_info(signed=False)

    s3_shape = _has_s3_shape(root)
    server_minio = _server_is_minio(root)
    health_ok = _health_live(health)
    admin_ok = _admin_plane(admin)

    evidence = {
        "s3_shape": s3_shape,
        "server_minio": server_minio,
        "health_live": health_ok,
        "admin_plane": admin_ok,
        "root_status": root.http_status,
    }

    strong_signals = sum(1 for flag in (health_ok, admin_ok, server_minio) if flag)
    if s3_shape and strong_signals >= 1 and (health_ok or admin_ok or (server_minio and strong_signals >= 2)):
        status = "confirmed"
    elif s3_shape:
        status = "probable"
    else:
        status = "not_minio"

    return MinioDetection(status=status, api_endpoint=client.base_url, evidence=evidence)
```

> Логика `confirmed`: S3-форма плюс минимум один MinIO-специфичный сигнал уровня плоскости (health или admin), либо `Server: MinIO` вместе со вторым сигналом. Один только `Server` без health/admin даёт `probable` (reverse-proxy мог его подделать/срезать — не единственный признак). Generic-S3 без MinIO-сигналов → `probable`, никогда `confirmed`.

- [ ] **Step 4: Прогнать + lint/type**

Run: `.venv/bin/ruff format redposture_core/modules/minio/ tests/test_minio_detection.py && .venv/bin/python -m pytest tests/test_minio_detection.py -v && .venv/bin/ruff check redposture_core/modules/minio/ && .venv/bin/mypy redposture_core/modules/minio/`
Expected: PASS + чисто.

- [ ] **Step 5: Commit** (по явной команде)

```bash
git add redposture_core/modules/minio/__init__.py redposture_core/modules/minio/types.py redposture_core/modules/minio/actions.py tests/test_minio_detection.py
git commit -m "feat(minio): multi-signal MinIO detection"
```

---

### Task 4: Anonymous классификация (`modules/minio/actions.py::classify_anonymous`)

**Files:**
- Modify: `redposture_core/modules/minio/actions.py`, `redposture_core/modules/minio/types.py`
- Test: `tests/test_minio_anonymous.py`

**Interfaces:**
- Consumes: `MinioClient`, `MinioResponse` (Task 2).
- Produces:
  - `types.AnonymousResult`: `api_reachable: bool`, `classification: str` (`anonymous_list_ok|authentication_required|access_denied|not_found|verification_unavailable`), `buckets: tuple[str, ...]`, `read_probe: str | None`.
  - `actions.classify_anonymous(client: MinioClient, *, known_bucket: str | None = None) -> AnonymousResult`.

- [ ] **Step 1: Написать падающие тесты**

```python
# tests/test_minio_anonymous.py
from __future__ import annotations

from redposture_core.clients.minio_api import MinioResponse, S3Error
from redposture_core.modules.minio import actions


class _StubClient:
    def __init__(self, *, root=None, listing=None):
        self._root = root
        self._listing = listing
        self.scheme, self.host, self.port = "http", "h", 9000

    @property
    def base_url(self):
        return "http://h:9000"

    def get_service_root(self, *, signed):
        return self._root

    def list_objects_v2(self, bucket, *, max_keys=1, prefix="", signed):
        return self._listing


def _resp(status, body=b"", error=None):
    return MinioResponse(http_status=status, headers={}, body=body, error=error)


def test_authentication_required_on_access_denied_root():
    client = _StubClient(root=_resp(403, error=S3Error(403, "AccessDenied", "")))
    result = actions.classify_anonymous(client)
    assert result.classification == "authentication_required"
    assert result.api_reachable is True


def test_anonymous_list_ok_lists_buckets():
    body = (
        b"<ListAllMyBucketsResult><Buckets>"
        b"<Bucket><Name>public</Name></Bucket><Bucket><Name>logs</Name></Bucket>"
        b"</Buckets></ListAllMyBucketsResult>"
    )
    client = _StubClient(root=_resp(200, body))
    result = actions.classify_anonymous(client)
    assert result.classification == "anonymous_list_ok"
    assert result.buckets == ("public", "logs")


def test_known_bucket_anonymous_read_probe():
    client = _StubClient(
        root=_resp(403, error=S3Error(403, "AccessDenied", "")),
        listing=_resp(200, b"<ListBucketResult></ListBucketResult>"),
    )
    result = actions.classify_anonymous(client, known_bucket="reports")
    assert result.read_probe == "anonymous_read_ok"


def test_verification_unavailable_on_transport_error():
    boom = MinioResponse(http_status=0, headers={}, body=b"", transport_error="timeout")
    client = _StubClient(root=boom)
    result = actions.classify_anonymous(client)
    assert result.classification == "verification_unavailable"
    assert result.api_reachable is False
```

- [ ] **Step 2: Прогнать — убедиться, что падает**

Run: `.venv/bin/python -m pytest tests/test_minio_anonymous.py -v`
Expected: FAIL.

- [ ] **Step 3: Реализовать**

```python
# redposture_core/modules/minio/types.py — добавить
@dataclass(frozen=True)
class AnonymousResult:
    api_reachable: bool
    classification: str
    buckets: tuple[str, ...] = ()
    read_probe: str | None = None
```

```python
# redposture_core/modules/minio/actions.py — добавить импорт AnonymousResult из .types
# и функции ниже.
from xml.etree import ElementTree


def _parse_bucket_names(body: bytes) -> tuple[str, ...]:
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return ()
    names: list[str] = []
    for elem in root.iter():
        if elem.tag.split("}")[-1] == "Name" and (elem.text or "").strip():
            names.append(elem.text.strip())
    return tuple(names)


def classify_anonymous(client: MinioClient, *, known_bucket: str | None = None) -> AnonymousResult:
    root = client.get_service_root(signed=False)
    if root.transport_error:
        return AnonymousResult(api_reachable=False, classification="verification_unavailable")

    if root.http_status == 200 and b"ListAllMyBucketsResult" in (root.body or b""):
        buckets = _parse_bucket_names(root.body or b"")
        return AnonymousResult(api_reachable=True, classification="anonymous_list_ok", buckets=buckets)

    if root.error is not None and root.error.code in {"AccessDenied", "InvalidAccessKeyId"}:
        classification = "authentication_required"
    elif root.http_status in {401, 403}:
        classification = "authentication_required"
    elif root.http_status == 404 or (root.error is not None and root.error.code in {"NoSuchBucket", "NoSuchKey"}):
        classification = "not_found"
    else:
        classification = "access_denied" if root.http_status >= 400 else "verification_unavailable"

    read_probe: str | None = None
    if known_bucket:
        listing = client.list_objects_v2(known_bucket, max_keys=1, signed=False)
        if listing.transport_error:
            read_probe = None
        elif listing.http_status == 200:
            read_probe = "anonymous_read_ok"
        elif listing.error is not None and listing.error.code in {"NoSuchBucket", "NoSuchKey"}:
            read_probe = "not_found"
        elif listing.http_status in {401, 403}:
            read_probe = "access_denied"

    return AnonymousResult(
        api_reachable=True, classification=classification, read_probe=read_probe
    )
```

- [ ] **Step 4: Прогнать + lint/type**

Run: `.venv/bin/ruff format redposture_core/modules/minio/ tests/test_minio_anonymous.py && .venv/bin/python -m pytest tests/test_minio_anonymous.py -v && .venv/bin/ruff check redposture_core/modules/minio/ && .venv/bin/mypy redposture_core/modules/minio/`
Expected: PASS + чисто.

- [ ] **Step 5: Commit** (по явной команде)

```bash
git add redposture_core/modules/minio/ tests/test_minio_anonymous.py
git commit -m "feat(minio): anonymous access classification"
```

---

### Task 5: Верификация explicit-креды (`modules/minio/actions.py::verify_credential`)

**Files:**
- Modify: `redposture_core/modules/minio/actions.py`, `redposture_core/modules/minio/types.py`
- Test: `tests/test_minio_auth.py`

**Interfaces:**
- Consumes: `MinioClient`, `MinioResponse`, `S3Error` (Task 2).
- Produces:
  - `types.CredentialResult`: `state: str` (`valid|invalid|valid_but_restricted|verification_unavailable|transient_failure`), `access_key: str | None`, `error_code: str | None`.
  - `actions.verify_credential(client: MinioClient) -> CredentialResult` — client уже сконфигурирован access/secret/session; шлёт подписанный GET `/`.

- [ ] **Step 1: Написать падающие тесты**

```python
# tests/test_minio_auth.py
from __future__ import annotations

from redposture_core.clients.minio_api import MinioResponse, S3Error
from redposture_core.modules.minio import actions


class _StubClient:
    def __init__(self, response, access_key="AKID"):
        self._response = response
        self.access_key = access_key
        self.scheme, self.host, self.port = "http", "h", 9000

    @property
    def base_url(self):
        return "http://h:9000"

    def get_service_root(self, *, signed):
        assert signed is True
        return self._response


def _resp(status, error=None, transport_error=None):
    return MinioResponse(http_status=status, headers={}, body=b"", error=error, transport_error=transport_error)


def test_valid_credentials_on_2xx():
    result = actions.verify_credential(_StubClient(_resp(200)))
    assert result.state == "valid"
    assert result.access_key == "AKID"


def test_invalid_on_signature_mismatch():
    result = actions.verify_credential(_StubClient(_resp(403, S3Error(403, "SignatureDoesNotMatch", ""))))
    assert result.state == "invalid"
    assert result.error_code == "SignatureDoesNotMatch"


def test_invalid_on_unknown_access_key():
    result = actions.verify_credential(_StubClient(_resp(403, S3Error(403, "InvalidAccessKeyId", ""))))
    assert result.state == "invalid"


def test_valid_but_restricted_on_access_denied():
    # Валидная подпись, но нет прав на ListBuckets -> креды валидны, ограничены.
    result = actions.verify_credential(_StubClient(_resp(403, S3Error(403, "AccessDenied", ""))))
    assert result.state == "valid_but_restricted"


def test_transient_on_transport_error():
    result = actions.verify_credential(_StubClient(_resp(0, transport_error="connection reset")))
    assert result.state == "transient_failure"


def test_verification_unavailable_on_unparseable():
    result = actions.verify_credential(_StubClient(_resp(500)))
    assert result.state == "verification_unavailable"
```

- [ ] **Step 2: Прогнать — убедиться, что падает**

Run: `.venv/bin/python -m pytest tests/test_minio_auth.py -v`
Expected: FAIL.

- [ ] **Step 3: Реализовать**

```python
# redposture_core/modules/minio/types.py — добавить
@dataclass(frozen=True)
class CredentialResult:
    state: str  # valid | invalid | valid_but_restricted | verification_unavailable | transient_failure
    access_key: str | None = None
    error_code: str | None = None
```

```python
# redposture_core/modules/minio/actions.py — добавить импорт CredentialResult и функцию.
_INVALID_CRED_CODES = {"SignatureDoesNotMatch", "InvalidAccessKeyId", "AccessKeyDisabled"}


def verify_credential(client: MinioClient) -> CredentialResult:
    resp = client.get_service_root(signed=True)
    access_key = getattr(client, "access_key", None)
    if resp.transport_error:
        return CredentialResult(state="transient_failure", access_key=access_key)
    if 200 <= resp.http_status < 300:
        return CredentialResult(state="valid", access_key=access_key)
    code = resp.error.code if resp.error is not None else ""
    if code in _INVALID_CRED_CODES:
        return CredentialResult(state="invalid", access_key=access_key, error_code=code)
    if code == "AccessDenied":
        # Подпись принята сервером (иначе был бы SignatureDoesNotMatch) -> креды
        # валидны, просто нет прав на пробную операцию.
        return CredentialResult(state="valid_but_restricted", access_key=access_key, error_code=code)
    return CredentialResult(state="verification_unavailable", access_key=access_key, error_code=code or None)
```

- [ ] **Step 4: Прогнать + lint/type**

Run: `.venv/bin/ruff format redposture_core/modules/minio/ tests/test_minio_auth.py && .venv/bin/python -m pytest tests/test_minio_auth.py -v && .venv/bin/ruff check redposture_core/modules/minio/ && .venv/bin/mypy redposture_core/modules/minio/`
Expected: PASS + чисто.

- [ ] **Step 5: Commit** (по явной команде)

```bash
git add redposture_core/modules/minio/ tests/test_minio_auth.py
git commit -m "feat(minio): credential verification by S3 error-code"
```

---

### Task 6: CLI parser + policy (`cli_modules/minio.py`, `modules/minio/policy.py`)

**Files:**
- Create: `redposture_core/cli_modules/minio.py`
- Create: `redposture_core/modules/minio/policy.py`
- Test: `tests/test_cli_minio.py`

**Interfaces:**
- Consumes: `ParserHelperSet`-style helpers (передаются в `configure_minio_parser`, как у grafana: `add_output_flags`, `add_log_flag`, `add_scan_host_flags`, `add_multi_ports_flag`, `add_save_flag`, `port_type`).
- Produces:
  - `configure_minio_parser(parser, *, add_output_flags, add_log_flag, add_scan_host_flags, add_multi_ports_flag, add_save_flag, port_type)` — регистрирует Common/Auth-группы, `--port`, `-u/--username`, `-p/--password`, `--session-token`, TLS-флаги (через `add_scan_host_flags`/существующие).
  - `policy.validate_args(args, console) -> int | None`.

> Точную сигнатуру helper-набора взять из `redposture_core/cli_modules/grafana.py::configure_grafana_parser` (тот же `_HTTP_MODULE_HELPERS`). MinIO не имеет SSRF-группы — только Common + Auth.

- [ ] **Step 1: Написать падающие тесты**

```python
# tests/test_cli_minio.py
from __future__ import annotations

from redposture_core.cli_args import parse_args


def test_minio_registered_and_parses_bare_host():
    args = parse_args(["minio", "-t", "127.0.0.1"])
    assert args.command == "minio"
    assert args.targets == "127.0.0.1"


def test_minio_default_ports_include_offsets():
    from redposture_core.modules.minio.stage import build_minio_plan

    plan = build_minio_plan(parse_args(["minio", "-t", "127.0.0.1"]))
    assert plan.ports == (9000, 9001, 80, 443, 10080, 10443, 19000, 19001, 20080, 20443, 29000, 29001)


def test_minio_credentials_and_session_token_parse():
    args = parse_args(
        ["minio", "-t", "127.0.0.1", "-u", "AKID", "-p", "SECRET", "--session-token", "TOK"]
    )
    assert args.username == "AKID"
    assert args.password == "SECRET"
    assert args.session_token == "TOK"


def test_minio_no_color_flag():
    args = parse_args(["minio", "-t", "127.0.0.1", "--no-color"])
    assert args.no_color is True
```

> Примечание: имя атрибута для `--no-color`/`--session-token`/`command` уточнить по существующим модулям (`grep no_color`, `dest=` в cli_args helpers). Тест `build_minio_plan` зависит от Task 8 — этот подтест можно временно пометить `xfail`, сняв метку в Task 8; остальные подтесты Task 6 самостоятельны.

- [ ] **Step 2: Прогнать — убедиться, что падает**

Run: `.venv/bin/python -m pytest tests/test_cli_minio.py -k "credentials or no_color or bare_host" -v`
Expected: FAIL — `minio` не зарегистрирован (`invalid choice`).

- [ ] **Step 3: Реализовать CLI-парсер и policy**

```python
# redposture_core/cli_modules/minio.py
"""MinIO CLI parser builder."""

from __future__ import annotations

import argparse
from collections.abc import Callable


def configure_minio_parser(
    minio_parser: argparse.ArgumentParser,
    *,
    add_output_flags: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_scan_host_flags: Callable[..., None],
    add_multi_ports_flag: Callable[..., None],
    add_save_flag: Callable[..., None],
    port_type: Callable[[str], int],
) -> None:
    common = minio_parser.add_argument_group("Common")
    auth = minio_parser.add_argument_group("Auth")
    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=None,
        metavar="port",
        help=(
            "MinIO port spec: single port, list/range, or file. If omitted, scans "
            "9000,9001,80,443,10080,10443,19000,19001,20080,20443,29000,29001."
        ),
    )
    add_multi_ports_flag(common)
    auth.add_argument("-u", "--username", dest="username", default=None, metavar="access-key",
                      help="Access key (username == access key).")
    auth.add_argument("-p", "--password", dest="password", default=None, metavar="secret-key",
                      help="Secret key (password == secret key).")
    auth.add_argument("--session-token", dest="session_token", default=None, metavar="token",
                      help="Optional STS session token (x-amz-security-token).")
    # TLS flags are per-module (мирроринг kubeapi: они НЕ входят в общие helpers).
    transport = minio_parser.add_argument_group("Transport")
    transport.add_argument("--https", dest="https", action="store_true",
                           help="Force HTTPS for MinIO endpoints (otherwise inferred from port/scheme).")
    transport.add_argument("--insecure", dest="insecure", action="store_true",
                           help="Skip TLS certificate verification.")
    transport.add_argument("--ca-file", dest="ca_file", default=None, metavar="path",
                           help="Custom CA bundle for TLS verification.")
```

> Общий набор Common-флагов (targets, out-target, timeout, workers, retries, proxy, output, log, debug, no-color) приходит через `add_output_flags`/`add_scan_host_flags`/`add_multi_ports_flag` — как у `configure_grafana_parser`. TLS-флаги объявлены явно выше (в общих helpers их нет — см. `cli_modules/kubeapi.py:41-53`). НЕ добавлять SSRF/apitoken/defcreds (defcreds — Фаза 2). Точные dests TLS: `https`/`insecure`/`ca_file` — совпадают с тем, что читает `_client_for` в Task 8 и `MinioLifecycleState`.

```python
# redposture_core/modules/minio/policy.py
"""Argument validation for the MinIO module."""

from __future__ import annotations

from typing import Any


def validate_args(args: Any, console: Any) -> int | None:
    port = getattr(args, "port", None)
    if isinstance(port, int) and port <= 0:
        console.error("--port must be > 0")
        return 2
    if getattr(args, "session_token", None) and not (
        getattr(args, "username", None) and getattr(args, "password", None)
    ):
        console.error("--session-token requires -u/--username and -p/--password")
        return 2
    return None
```

- [ ] **Step 4: Зарегистрировать в module_registry (нужно для парсинга) — см. Task 8 Step 3 частично**

Чтобы тест `test_cli_minio` (кроме `default_ports`) прошёл, MinIO должен быть зарегистрирован. Регистрацию делаем здесь минимально (импорт + COMMAND + CommandSpec), а stage-wiring — в Task 8. Добавить в `redposture_core/module_registry.py`:

```python
# рядом с другими импортами cli_modules
from .cli_modules.minio import configure_minio_parser
# рядом с COMMAND_*
COMMAND_MINIO = "minio"
# в _STAGE_RUNNER_MODULES
COMMAND_MINIO: "redposture_core.modules.minio.stage",
# в COMMAND_SPECS (кортеж)
CommandSpec(
    name=COMMAND_MINIO,
    help="Audit MinIO exposure: detection, anonymous access, credential verification.",
    runner_attr="run_minio_stage",
    configure_parser=_make_configurator(configure_minio_parser, _HTTP_MODULE_HELPERS),
),
```

> `run_minio_stage` появится в Task 8; до этого CLI-парсинг и `parse_args` работают (runner резолвится лениво). Подтесты Task 6 (кроме default_ports) пройдут.

- [ ] **Step 5: Прогнать + lint/type**

Run: `.venv/bin/ruff format redposture_core/cli_modules/minio.py redposture_core/modules/minio/policy.py redposture_core/module_registry.py tests/test_cli_minio.py && .venv/bin/python -m pytest tests/test_cli_minio.py -k "credentials or no_color or bare_host" -v && .venv/bin/ruff check redposture_core/cli_modules/minio.py redposture_core/modules/minio/policy.py && .venv/bin/mypy redposture_core/cli_modules/minio.py redposture_core/modules/minio/policy.py`
Expected: три подтеста PASS + чисто.

- [ ] **Step 6: Commit** (по явной команде)

```bash
git add redposture_core/cli_modules/minio.py redposture_core/modules/minio/policy.py redposture_core/module_registry.py tests/test_cli_minio.py
git commit -m "feat(minio): CLI parser, policy, command registration"
```

---

### Task 7: Render (`modules/minio/render.py`) — TXT/JSON detail + цвет

**Files:**
- Create: `redposture_core/modules/minio/render.py`
- Test: `tests/test_minio_render.py`

**Interfaces:**
- Consumes: `AuditRecord`-подобный dict/record с ключами, которые кладёт stage (Task 8): `detection_status`, `api_endpoint`, `console_endpoint`, `anonymous`, `auth_required`, `credential_state`, `credential_type`. Renderer работает по dict (`record.to_dict()`), как `_format_discover_detail_records`.
- Produces:
  - `_format_minio_record(record, output_format) -> list[str]` — TXT-строки (тег `MINIO`, маркеры), пусто для json.
  - `_render_colored_minio_line(console, line) -> bool` — раскраска через `render_colored_marker_line`.

> Точную форму записи и имена ключей согласовать с Task 8 (что кладёт detect/auth в `AuditRecord`). Renderer читает те же ключи. Цвет — через `redposture_core.rendering.render_colored_marker_line` (см. `_render_colored_clickhouse_line` как образец): booleans/counts/spans, без хардкод-ANSI.

- [ ] **Step 1: Написать падающие тесты**

```python
# tests/test_minio_render.py
from __future__ import annotations

from redposture_core.modules.minio import render


def _record(**over):
    base = {
        "host": "10.0.0.5",
        "port": 9000,
        "detection_status": "confirmed",
        "api_endpoint": "http://10.0.0.5:9000",
        "console_endpoint": "http://10.0.0.5:9001",
        "anonymous": "authentication_required",
        "auth_required": True,
        "credential_state": "valid",
        "credential_type": "access-key",
    }
    base.update(over)
    return base


def test_txt_summary_compact_and_tagged():
    lines = render._format_minio_record(_record(), "txt")
    summary = next(line for line in lines if "MinIO" in line)
    assert summary.startswith("MINIO\t10.0.0.5\t9000\t")
    assert "(detection:confirmed)" in summary
    assert "(anonymous:authentication_required)" in summary
    assert "(credential:valid)" in summary


def test_json_format_emits_no_txt():
    assert render._format_minio_record(_record(), "json") == []


def test_not_minio_suppressed_in_txt():
    lines = render._format_minio_record(_record(detection_status="not_minio"), "txt")
    assert lines == []


def test_colorized_summary_paints_valid_credential_green():
    class _Console:
        def __init__(self):
            self.lines = []

        def _paint(self, text, color, _s):
            return f"<{color}>{text}</{color}>"

        def plain(self, line):
            self.lines.append(line)

    line = render._format_minio_record(_record(), "txt")[0]
    console = _Console()
    assert render._render_colored_minio_line(console, line) is True
    assert "<bright_green>credential:valid</bright_green>" in console.lines[0]
```

- [ ] **Step 2: Прогнать — убедиться, что падает**

Run: `.venv/bin/python -m pytest tests/test_minio_render.py -v`
Expected: FAIL.

- [ ] **Step 3: Реализовать render**

```python
# redposture_core/modules/minio/render.py
"""TXT/JSON rendering and terminal coloring for the MinIO module."""

from __future__ import annotations

import re
from typing import Any

from ...console import Console
from ...rendering import render_colored_marker_line, render_tagged_detail_line

_DETECTION_COLOR = {"confirmed": "bright_green", "probable": "yellow"}
_CRED_COLOR = {
    "valid": "bright_green",
    "valid_but_restricted": "yellow",
    "invalid": "red",
    "transient_failure": "yellow",
    "verification_unavailable": "yellow",
}


def _format_minio_record(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return []
    status = str(record.get("detection_status") or "")
    if status in {"not_minio", "transport_failure", ""}:
        return []  # не засоряем TXT неподтверждённым
    host = str(record.get("host") or "?")
    port = int(record.get("port") or 0)
    prefix = f"MINIO\t{host}\t{port}\t"
    parts = [f"(detection:{status})"]
    if record.get("api_endpoint"):
        parts.append(f"(api:{record['api_endpoint']})")
    if record.get("console_endpoint"):
        parts.append(f"(console:{record['console_endpoint']})")
    if record.get("anonymous"):
        parts.append(f"(anonymous:{record['anonymous']})")
    parts.append(f"(auth_required:{bool(record.get('auth_required'))})")
    if record.get("credential_state"):
        parts.append(f"(credential:{record['credential_state']})")
        if record.get("credential_type"):
            parts.append(f"(type:{record['credential_type']})")
    return [f"{prefix} [*] MinIO {' '.join(parts)}"]


_DETECTION_RE = re.compile(r"\(detection:([a-z_]+)\)")
_CRED_RE = re.compile(r"\(credential:([a-z_]+)\)")
_ANON_RE = re.compile(r"\(anonymous:([a-z_]+)\)")


def _minio_color_spans(_marker: str, payload: str) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for regex, table, default in (
        (_DETECTION_RE, _DETECTION_COLOR, "red"),
        (_CRED_RE, _CRED_COLOR, "red"),
    ):
        m = regex.search(payload)
        if m:
            spans.append((m.start(), m.end(), table.get(m.group(1), default)))
    m = _ANON_RE.search(payload)
    if m:
        color = "red" if m.group(1) in {"anonymous_list_ok", "anonymous_read_ok"} else "yellow"
        spans.append((m.start(), m.end(), color))
    return spans


def _render_colored_minio_line(console: Console, line: str) -> bool:
    if render_colored_marker_line(console, line, tag="MINIO", extra_spans=_minio_color_spans):
        return True
    if line.startswith("MINIO") and "\t" in line:
        return render_tagged_detail_line(console, line, tag="MINIO", default_color="white")
    return False


__all__ = ["_format_minio_record", "_render_colored_minio_line"]
```

> Anonymous открытый доступ (`anonymous_list_ok`/`anonymous_read_ok`) красится красным (это экспозиция), прочие anonymous-классы — жёлтым. Detection/credential — по таблицам. `colorize_spans` снимает внешние скобки, красит внутренность (как в clickhouse).

- [ ] **Step 4: Прогнать + lint/type**

Run: `.venv/bin/ruff format redposture_core/modules/minio/render.py tests/test_minio_render.py && .venv/bin/python -m pytest tests/test_minio_render.py -v && .venv/bin/ruff check redposture_core/modules/minio/render.py && .venv/bin/mypy redposture_core/modules/minio/render.py`
Expected: PASS + чисто.

- [ ] **Step 5: Commit** (по явной команде)

```bash
git add redposture_core/modules/minio/render.py tests/test_minio_render.py
git commit -m "feat(minio): TXT/JSON rendering and terminal coloring"
```

---

### Task 8: Stage wiring + интеграция (`modules/minio/stage.py`) + сквозной прогон

**Files:**
- Create: `redposture_core/modules/minio/stage.py`
- Modify: `redposture_core/modules/minio/actions.py` (добавить `host_stage_lifecycle` — сборка record из detect/anonymous/auth), `tests/test_cli_minio.py` (снять xfail с `default_ports`)
- Test: `tests/test_stage_minio.py`

**Interfaces:**
- Consumes: `build_basic_audit_plan`, `run_basic_host_audit`, `ModuleAuditSpec`, `AuditRecord`, `AuditConfig`, `Console`, `HttpSessionPool` (existing); `detect_minio`, `classify_anonymous`, `verify_credential` (Tasks 3–5); `render` (Task 7); `policy.validate_args` (Task 6).
- Produces:
  - `build_minio_plan(args) -> AuditCommandPlan`.
  - `build_minio_spec(args) -> ModuleAuditSpec`.
  - `run_minio_stage(args, logger) -> int`.
  - Detect/auth хуки строят `AuditRecord` с ключами, которые читает render (`detection_status`, `api_endpoint`, `console_endpoint`, `anonymous`, `auth_required`, `credential_state`, `credential_type`, `detection` evidence, `credential_attempts`).

- [ ] **Step 1: Написать падающий тест (сборка plan + spec + запись detect)**

```python
# tests/test_stage_minio.py
from __future__ import annotations

from redposture_core.cli_args import parse_args
from redposture_core.modules.minio import stage


def test_build_minio_plan_default_ports():
    plan = stage.build_minio_plan(parse_args(["minio", "-t", "127.0.0.1"]))
    assert plan.ports == (9000, 9001, 80, 443, 10080, 10443, 19000, 19001, 20080, 20443, 29000, 29001)


def test_build_minio_spec_wires_hooks():
    spec = stage.build_minio_spec(parse_args(["minio", "-t", "127.0.0.1"]))
    assert spec.module == "minio"
    assert spec.label == "MINIO"
    assert spec.detect is not None
    assert spec.auth is not None
    assert spec.colorize is not None
    assert spec.skip_credentials_without_verifier is True
```

- [ ] **Step 2: Прогнать — убедиться, что падает**

Run: `.venv/bin/python -m pytest tests/test_stage_minio.py -v`
Expected: FAIL (модуля stage нет).

- [ ] **Step 3: Реализовать stage.py + lifecycle-хуки в actions**

```python
# redposture_core/modules/minio/actions.py — добавить lifecycle state и хуки-обёртки.
from ...clients.http_session import HttpSessionPool

# Модуль использует detect/auth хуки, а не монолитный host_stage. Значение None
# корректно (runner в stage_runtime.py при host_stage=None + detect/auth идёт по
# staged-пути), и наличие имени `host_stage = ` удовлетворяет architecture-guard
# (tests/test_architecture_guards.py::test_module_actions_are_typed_hook_facades).
host_stage = None


class MinioLifecycleState:
    """Holds one HttpSessionPool per target lifecycle (pool reuse)."""

    def __init__(self, args: Any) -> None:
        self.pool = HttpSessionPool(
            timeout=float(getattr(args, "timeout", 5.0) or 5.0),
            insecure=bool(getattr(args, "insecure", False)),
            ca_file=getattr(args, "ca_file", None),
            retries=int(getattr(args, "retries", 0) or 0),
        )

    def close(self) -> None:
        self.pool.close()


def minio_lifecycle_state_factory(ctx: Any) -> MinioLifecycleState:
    return MinioLifecycleState(ctx.args)


def _client_for(ctx: Any, credential: Any) -> MinioClient:
    scheme = "https" if bool(getattr(ctx.args, "https", False)) or int(ctx.port) in {443, 10443, 20443} else "http"
    pool = ctx.lifecycle_state.pool if isinstance(ctx.lifecycle_state, MinioLifecycleState) else HttpSessionPool(
        timeout=float(getattr(ctx.args, "timeout", 5.0) or 5.0)
    )
    return MinioClient(
        pool,
        scheme=scheme,
        host=str(ctx.host),
        port=int(ctx.port),
        access_key=getattr(credential, "username", None),
        secret_key=getattr(credential, "password", None),
        session_token=getattr(ctx.args, "session_token", None),
    )


def detect_record(ctx: Any) -> dict[str, Any]:
    client = _client_for(ctx, ctx.credential)
    detection = detect_minio(client)
    anon = classify_anonymous(client) if detection.status == "confirmed" else None
    verification_status = "available" if detection.status == "confirmed" else "unavailable"
    status_word = {
        "confirmed": "detected",
        "probable": "probable",
        "not_minio": "not_service",
        "transport_failure": "fail",
    }[detection.status]
    record: dict[str, Any] = {
        "host": str(ctx.host),
        "port": int(ctx.port),
        "status": status_word,
        "detection_status": detection.status,
        "api_endpoint": detection.api_endpoint,
        "console_endpoint": detection.console_endpoint,
        "detection": detection.evidence,
        "credential_verification_status": verification_status,
    }
    if anon is not None:
        record["anonymous"] = anon.classification
        record["auth_required"] = anon.classification == "authentication_required"
        record["buckets"] = list(anon.buckets)
    return record


def auth_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    credential = ctx.credential
    if not (getattr(credential, "username", None) and getattr(credential, "password", None)):
        return dict(prior)
    client = _client_for(ctx, credential)
    result = verify_credential(client)
    merged = dict(prior)
    merged["credential_state"] = result.state
    merged["credential_type"] = "session-token" if getattr(ctx.args, "session_token", None) else "access-key"
    merged["credential_attempts"] = [
        {"access_key": result.access_key, "state": result.state, "error_code": result.error_code}
    ]
    merged["provided_credentials_ok"] = result.state in {"valid", "valid_but_restricted"}
    return merged
```

```python
# redposture_core/modules/minio/stage.py
"""Runtime entrypoint for the minio audit module."""

from __future__ import annotations

from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    ModuleAuditSpec,
    build_basic_audit_plan,
    run_basic_host_audit,
)
from . import actions, policy, render

_DEFAULT_PORT = 9000
_DEFAULT_PORTS: tuple[int, ...] = (9000, 9001, 80, 443, 10080, 10443, 19000, 19001, 20080, 20443, 29000, 29001)


def build_minio_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def _minio_credential_gate(credential: Any, record: AuditRecord) -> tuple[bool, str]:
    ok = record.extra.get("provided_credentials_ok") is True
    return ok, "minio credential verified" if ok else "minio credential rejected"


def build_minio_spec(args: Any) -> ModuleAuditSpec:
    def _detect(ctx: Any) -> AuditRecord:
        return AuditRecord.from_mapping(actions.detect_record(ctx), module="minio", service="minio")

    def _auth(ctx: Any, record: Any) -> AuditRecord:
        prior = record.to_dict() if hasattr(record, "to_dict") else dict(record)
        return AuditRecord.from_mapping(actions.auth_record(ctx, prior), module="minio", service="minio")

    return ModuleAuditSpec(
        module="minio",
        label="MINIO",
        default_port=_DEFAULT_PORT,
        detect=_detect,
        auth=_auth,
        lifecycle_state_factory=actions.minio_lifecycle_state_factory,
        lifecycle_state_close=lambda state: state.close(),
        render_module=render,
        colorize=render._render_colored_minio_line,
        credential_gate=_minio_credential_gate,
        skip_credentials_without_verifier=True,
    )


def run_minio_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    return run_basic_host_audit(
        args,
        logger,
        console=console,
        label="MINIO",
        validate=policy.validate_args,
        build_plan=build_minio_plan,
        build_spec=build_minio_spec,
    )


__all__ = ["build_minio_plan", "build_minio_spec", "run_minio_stage"]
```

> Точные имена полей `ModuleAuditSpec` (`credential_gate`, `render_module`, `colorize`, `lifecycle_state_factory/close`, `skip_credentials_without_verifier`) и `AuditRecord.from_mapping`/`.to_dict()`/`.extra` — сверить с `modules/grafana/stage.py` и `stage_runtime.py`; при расхождении имён использовать фактические. Если `AuditRecord.from_mapping` требует `status` в определённом наборе — использовать значения как в grafana (`detected`/`not_service`/`fail`).

- [ ] **Step 4: Снять xfail с default_ports-теста и прогнать stage+cli тесты**

Run: `.venv/bin/ruff format redposture_core/modules/minio/ tests/test_stage_minio.py tests/test_cli_minio.py && .venv/bin/python -m pytest tests/test_stage_minio.py tests/test_cli_minio.py -v && .venv/bin/mypy redposture_core/modules/minio/`
Expected: PASS + чисто.

- [ ] **Step 5: Architecture-guard + полный прогон + smoke**

Run:
```bash
.venv/bin/python -m pytest tests/ -k "minio or architecture or module_registry or cli_args" -q
.venv/bin/python redposture.py minio --help
```
Expected: PASS; `minio --help` печатает группы флагов без ошибок. Если guard-тест перечисляет модули и ждёт MinIO — он проходит (модуль зарегистрирован). Если что-то в guard требует дополнительного (напр. README-список) — учесть в Task 9/Фазе 5.

- [ ] **Step 6: Полный CI-эквивалент**

Run: `PATH="$PWD/.venv/bin:$PATH" bash scripts/run_ci_job.sh lint && PATH="$PWD/.venv/bin:$PATH" bash scripts/run_ci_job.sh test`
Expected: lint (ruff+format+mypy+help) зелёный; test (pytest+coverage per-file ≥70%) зелёный. Если новый файл < 70% покрытия — добить тестами (SigV4/client/detection/auth уже покрыты; render/stage — добить edge-тестами).

- [ ] **Step 7: Commit** (по явной команде)

```bash
git add redposture_core/modules/minio/ tests/test_stage_minio.py tests/test_cli_minio.py
git commit -m "feat(minio): stage wiring, lifecycle, end-to-end Phase 1"
```

---

## Вне scope этого плана (следующие фазы)

- Фаза 2: `--defcreds` каталог (`minioadmin:minioadmin` + curated, real vs heuristic), credential files/ordering в каталоге, stop-on-success поверх каталога, admin-capability детект (Admin API read-only probes → confirmed/partial/not_confirmed/unknown; root vs delegated vs S3-user), permission-классификация (`--probe-write` заложен, не активен).
- Фаза 3: `--show-buckets/--bucket/--show-objects/--prefix` streaming-пагинация + лимиты; secret discovery (приоритизация имён + bounded content-inspection → существующий secret engine); бюджеты + partial-reasons.
- Фаза 4: Docker-labs (gitignored `lab/`), fixtures, synthetic dataset на тысячи объектов, integration `lab_tests/`.
- Фаза 5: README/help финализация, полный self-review, финальный CI.

## Примечание о коммитах

Шаги `git commit` — часть TDD-ритма плана. В этом репозитории действует установка пользователя: не выполнять `git commit`/`push` без явной команды в том же запросе. Исполнитель прогоняет тесты и оставляет изменения в рабочем дереве; коммитит только когда пользователь прямо просит.
