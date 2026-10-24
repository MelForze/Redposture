"""Small deterministic contracts for the seven UI surfaces."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core import web_panels
from redposture_core.audit_models import AuditRecord
from redposture_core.clients.http_api import HttpResponse
from redposture_core.cve import resolve_products
from redposture_core.stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
    AuditHookContext,
    ModuleAuditSpec,
)
from redposture_core.stage_spray import Candidate, _supported
from redposture_core.targeting import ScanTargetSpec


def _response(
    status: int,
    payload: object,
    *,
    headers: dict[str, str] | None = None,
    final_url: str | None = None,
) -> HttpResponse:
    body = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
    return HttpResponse(status=status, body=body, headers=headers or {}, final_url=final_url)


_FIXTURES: dict[str, dict[str, HttpResponse]] = {
    "portainer": {
        "/api/system/status": _response(200, {"Version": "2.45.2", "InstanceID": "qa"}),
        "/": _response(200, "<title>Portainer</title>"),
    },
    "mongodb": {
        "/": _response(200, '<title>Home - Mongo Express</title><img src="/public/img/mongo-express-logo.png">'),
        "/public/img/mongo-express-logo.png": _response(200, "PNG", headers={"Content-Type": "image/png"}),
    },
    "elastic_kibana": {
        "/api/status": _response(200, {"version": {"number": "8.13.4"}}, headers={"kbn-name": "qa"}),
        "/api/spaces/space": _response(200, [{"id": "default", "name": "Default"}], headers={"kbn-name": "qa"}),
    },
    "elastic_osd": {
        "/api/status": _response(200, {"version": {"number": "2.14.0"}}, headers={"osd-name": "qa"}),
        "/api/spaces/space": _response(404, {}),
        "/api/saved_objects/_find?type=dashboard&per_page=1": _response(
            200, {"saved_objects": []}, headers={"osd-name": "qa"}
        ),
    },
    "redis": {
        "/": _response(200, "<title>Redis Insight</title>"),
        "/api/info": _response(200, {"appVersion": "2.68.0", "appType": "DOCKER", "buildType": "DOCKER_ON_PREMISE"}),
    },
    "postgres": {
        "/login": _response(200, "<title>pgAdmin 4</title>"),
        "/misc/ping": _response(200, "PING"),
    },
    "minio": {
        "/": _response(200, "<title>MinIO Console</title>"),
        "/api/v1/session": _response(403, {"message": "invalid session"}, headers={"Server": "MinIO Console"}),
    },
}


@pytest.mark.parametrize(
    ("fixture", "module", "product"),
    [
        ("portainer", "portainer", "portainer"),
        ("mongodb", "mongodb", "mongo_express"),
        ("elastic_kibana", "elastic", "kibana"),
        ("elastic_osd", "elastic", "opensearch_dashboards"),
        ("redis", "redis", "redis_insight"),
        ("postgres", "postgres", "pgadmin"),
        ("minio", "minio", "minio_console"),
    ],
)
def test_ui_fingerprints_require_product_answers(
    monkeypatch: pytest.MonkeyPatch, fixture: str, module: str, product: str
) -> None:
    answers = _FIXTURES[fixture]
    monkeypatch.setattr(
        web_panels,
        "_get",
        lambda _pool, _base, path, **_kw: answers.get(path, _response(404, {})),
    )
    result = web_panels._fingerprints(module, object(), "http://qa")
    assert result is not None
    assert result[0] == product
    assert len(result[2]) >= 2


@pytest.mark.parametrize("module", tuple(web_panels.MODULE_PRODUCTS))
def test_generic_http_and_broken_product_signals_do_not_confirm(monkeypatch: pytest.MonkeyPatch, module: str) -> None:
    monkeypatch.setattr(
        web_panels,
        "_get",
        lambda _pool, _base, _path, **_kw: _response(200, {"version": "1.0"}),
    )
    assert web_panels._fingerprints(module, object(), "http://qa") is None


def test_explicit_url_preserves_ui_prefix_and_strips_known_api_suffix() -> None:
    ctx = SimpleNamespace(host="qa.example", port=443, target=SimpleNamespace(path="/tenant/api/status"))
    assert web_panels._base(ctx, "https") == "https://qa.example:443/tenant"


def test_protected_opensearch_dashboard_has_two_product_signals(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = {
        "/api/status": _response(401, {"message": "Authentication required"}, headers={"osd-name": "qa"}),
        "/app/login": _response(200, "<title>OpenSearch Dashboards</title>", headers={"osd-name": "qa"}),
    }
    monkeypatch.setattr(web_panels, "_get", lambda _pool, _base, path, **_kw: answers.get(path, _response(404, {})))
    assert web_panels._fingerprints("elastic", object(), "http://qa") == (
        "opensearch_dashboards",
        None,
        ["opensearch_auth_challenge", "opensearch_login_page"],
    )
    answers["/app/login"] = _response(200, "<title>Unrelated SSO</title>", headers={"osd-name": "qa"})
    assert web_panels._fingerprints("elastic", object(), "http://qa") is None


def test_mongo_express_uses_real_database_route_for_access(monkeypatch: pytest.MonkeyPatch) -> None:
    home = '<title>Home - Mongo Express</title><img src="/public/img/mongo-express-logo.png"><a href="/db/qa/">qa</a>'
    answers = {
        "/": _response(200, home),
        "/public/img/mongo-express-logo.png": _response(200, "PNG", headers={"Content-Type": "image/png"}),
        "/db/qa/": _response(401, "Unauthorized", headers={"WWW-Authenticate": 'Basic realm="db"'}),
    }
    requested: list[str] = []

    def get(_pool: object, _base: str, path: str, **_kw: object) -> HttpResponse:
        requested.append(path)
        return answers.get(path, _response(404, {}))

    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(
        host="qa",
        port=8081,
        target=SimpleNamespace(path="", scheme="http", explicit_port=8081),
        args=SimpleNamespace(timeout=1, secure=False, _proxy_config=None),
    )
    result = web_panels.detect_panel("mongodb", ctx)
    assert result is not None
    assert result["auth_required"] is True
    assert result["ui"]["credential_probe_path"] == "/db/qa/"
    assert "/db/" not in requested


@pytest.mark.parametrize(
    ("target", "expected_order"),
    [
        (ScanTargetSpec(host="qa", scheme="https", explicit_port=9443), ["ui", "backend"]),
        (ScanTargetSpec(host="qa", explicit_port=2375), ["backend", "ui"]),
    ],
)
def test_explicit_origin_runs_ui_and_backend_as_separate_records(
    monkeypatch: pytest.MonkeyPatch, target: ScanTargetSpec, expected_order: list[str]
) -> None:
    surfaces: list[str] = []

    def detect_backend(ctx: AuditHookContext) -> AuditRecord:
        surfaces.append("backend")
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="mongodb",
            service="mongodb",
            status="open_no_auth",
            extra={"is_mongodb": True},
        )

    def detect_ui(_module: str, _ctx: object) -> dict[str, object]:
        surfaces.append("ui")
        return {
            "host": "qa",
            "port": target.explicit_port,
            "module": "mongodb",
            "service": "mongodb",
            "status": "open_no_auth",
            "auth_required": False,
            "surface": "ui",
            "is_ui": True,
            "ui_product": "mongo_express",
            "ui": {"endpoint": "https://qa:9443", "auth_required": False, "inventory": {}},
            "detection_status": "confirmed",
            "detection_signals": ["mongo_express_page", "mongo_express_system_status"],
        }

    monkeypatch.setattr(web_panels, "detect_panel", detect_ui)
    spec = ModuleAuditSpec(
        module="mongodb",
        label="MONGODB",
        default_port=2375,
        detect=detect_backend,
        is_detected=lambda record: record.extra.get("is_mongodb") is True,
        render=lambda record: [f"MONGODB {record.status}"],
    )
    plan = AuditCommandPlan(
        target_specs_by_port={int(target.explicit_port or 0): (target,)}, output_format="json", workers=1
    )
    result = AuditCommandRunner(args=SimpleNamespace(debug=False), spec=spec, emit_line=lambda _line: None).run_plan(
        plan
    )
    assert surfaces == expected_order
    assert result.record_count == 2
    assert {record.get("surface", "backend") for record in result.records} == {"ui", "backend"}


@pytest.mark.parametrize("scheme", ["http", None])
def test_minio_console_never_counts_as_backend_on_same_origin(
    monkeypatch: pytest.MonkeyPatch, scheme: str | None
) -> None:
    def detect_backend(ctx: AuditHookContext) -> AuditRecord:
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="minio",
            service="minio",
            status="detected",
            extra={"is_minio": True, "detection_status": "console"},
        )

    monkeypatch.setattr(
        web_panels,
        "detect_panel",
        lambda _module, _ctx: {
            "host": "qa",
            "port": 19001,
            "module": "minio",
            "service": "minio",
            "status": "auth_required",
            "auth_required": True,
            "surface": "ui",
            "is_ui": True,
            "ui_product": "minio_console",
            "ui": {"endpoint": "http://qa:19001", "auth_required": True},
        },
    )
    spec = ModuleAuditSpec(
        module="minio",
        label="MINIO",
        default_port=9000,
        detect=detect_backend,
        is_detected=lambda record: record.extra.get("is_minio") is True,
        render=lambda record: [f"MINIO {record.status}"],
    )
    target = ScanTargetSpec(host="qa", scheme=scheme, explicit_port=19001)
    plan = AuditCommandPlan(target_specs_by_port={19001: (target,)}, output_format="json", workers=1)
    result = AuditCommandRunner(args=SimpleNamespace(debug=False), spec=spec, emit_line=lambda _line: None).run_plan(
        plan
    )
    assert result.record_count == 1
    assert result.records[0]["surface"] == "ui"


def test_docker_engine_does_not_receive_portainer_password_candidates() -> None:
    seen: list[bool] = []

    def host_stage(
        host: str, port: int, timeout: float, retries: int, run_deep_checks: bool = True
    ) -> dict[str, object]:
        seen.append(run_deep_checks)
        return {"host": host, "port": port, "status": "open_no_auth", "is_docker": True}

    spec = ModuleAuditSpec(
        module="docker",
        label="DOCKER",
        default_port=2375,
        host_stage=host_stage,
        is_detected=lambda record: record.extra.get("is_docker") is True,
        keep_anonymous_open_no_auth=True,
        continue_after_credential_success=True,
    )
    runner = AuditCommandRunner(args=SimpleNamespace(defcreds=True), spec=spec, emit_line=lambda _line: None)
    detected = AuditRecord(
        host="qa", port=2375, module="docker", service="docker", status="open_no_auth", extra={"is_docker": True}
    )
    runner._run_monolithic_deep_lifecycle(
        "qa",
        2375,
        None,
        detected,
        (AuditCredentialRun("admin", "admin"), AuditCredentialRun("root", "root")),
        None,
        None,
    )
    assert seen == [True]


@pytest.mark.parametrize("fixture", tuple(_FIXTURES))
@pytest.mark.parametrize("module", tuple(web_panels.MODULE_PRODUCTS))
def test_foreign_ui_does_not_confirm_as_another_product(
    monkeypatch: pytest.MonkeyPatch, fixture: str, module: str
) -> None:
    own_module = fixture.split("_", 1)[0]
    if module == own_module:
        return
    answers = _FIXTURES[fixture]
    monkeypatch.setattr(web_panels, "_get", lambda _pool, _base, path, **_kw: answers.get(path, _response(404, {})))
    assert web_panels._fingerprints(module, object(), "http://qa") is None


def test_portainer_422_invalid_credentials_and_identity_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    record = {"ui_product": "portainer", "ui": {"endpoint": "http://qa"}}
    ctx = SimpleNamespace(
        credential=AuditCredentialRun(username="admin", password="wrong"),
        args=SimpleNamespace(timeout=1, secure=False, _proxy_config=None),
    )
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(
        web_panels,
        "_post",
        lambda *_args, **_kw: _response(422, {"message": "Invalid credentials"}),
    )
    assert web_panels.authenticate_panel(ctx, record)["credential_state"] == "invalid"
    monkeypatch.setattr(
        web_panels,
        "_post",
        lambda *_args, **_kw: _response(200, {"jwt": "qa-token"}),
    )
    monkeypatch.setattr(
        web_panels,
        "_get",
        lambda *_args, **_kw: _response(200, {"Id": 1, "Username": "admin", "Role": 1}),
    )
    assert web_panels.authenticate_panel(ctx, record)["credential_state"] == "valid"
    monkeypatch.setattr(web_panels, "_post", lambda *_args, **_kw: _response(429, {"message": "too many requests"}))
    assert web_panels.authenticate_panel(ctx, record)["credential_state"] == "rate_limited"


def test_opensearch_dashboard_auth_uses_matching_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    record = {"ui_product": "opensearch_dashboards", "ui": {"endpoint": "http://qa", "version": None}}
    ctx = SimpleNamespace(
        credential=AuditCredentialRun(username="admin", password="right"),
        args=SimpleNamespace(timeout=1, secure=False, _proxy_config=None),
    )
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))
    seen: list[dict[str, str]] = []

    def get(_pool: object, _base: str, path: str, *, headers: dict[str, str]) -> HttpResponse:
        seen.append(headers)
        if path == "/api/v1/configuration/account":
            return _response(200, {"data": {"user_name": "admin"}})
        return _response(200, {"version": {"number": "2.14.0"}})

    monkeypatch.setattr(web_panels, "_get", get)
    result = web_panels.authenticate_panel(ctx, record)
    assert result["credential_state"] == "valid"
    assert result["ui"]["version"] == "2.14.0"
    assert all(value.get("Authorization", "").startswith("Basic ") for value in seen)
    monkeypatch.setattr(
        web_panels, "_get", lambda *_args, **_kw: _response(401, {"message": "Authentication Exception"})
    )
    assert web_panels.authenticate_panel(ctx, record)["credential_state"] == "invalid"


def test_minio_empty_bucket_dict_is_zero_not_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(
        web_panels,
        "_get",
        lambda *_args, **_kw: _response(200, {"buckets": []}),
    )
    ctx = SimpleNamespace(
        args=SimpleNamespace(show_buckets=True, show_objects=False, timeout=1, secure=False, _proxy_config=None)
    )
    result = web_panels.enumerate_panel(
        ctx, {"ui_product": "minio_console", "ui": {"endpoint": "http://qa", "inventory": {}}}
    )
    assert result["ui"]["inventory"]["show_buckets"] == {"count": 0, "items": [], "records": [], "partial": False}


def test_minio_object_names_are_bounded_and_are_not_downloaded(monkeypatch: pytest.MonkeyPatch) -> None:
    paths: list[str] = []
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))

    def get(_pool: object, _base: str, path: str, **_kw: object) -> HttpResponse:
        paths.append(path)
        if path == "/api/v1/buckets":
            return _response(200, {"buckets": [{"name": "qa"}]})
        return _response(200, {"objects": [{"name": "notes.txt"}, {"name": "image.png"}]})

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(
        args=SimpleNamespace(show_buckets=True, show_objects=True, timeout=1, secure=False, _proxy_config=None)
    )
    result = web_panels.enumerate_panel(
        ctx, {"ui_product": "minio_console", "ui": {"endpoint": "http://qa", "inventory": {}}}
    )
    assert result["ui"]["inventory"]["show_objects"] == {
        "count": 2,
        "items": ["qa/notes.txt", "qa/image.png"],
        "partial": False,
    }
    assert paths == ["/api/v1/buckets", "/api/v1/buckets/qa/objects?limit=10001"]


@pytest.mark.parametrize("batched_response", [False, True])
def test_redis_insight_key_cursor_is_read_only_and_bounded(
    monkeypatch: pytest.MonkeyPatch, batched_response: bool
) -> None:
    requests: list[tuple[str, str, object]] = []
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(
        web_panels,
        "_get",
        lambda _pool, _base, path, **_kw: _response(200, [{"id": "qa-id", "name": "qa-redis"}]),
    )

    def post(_pool: object, _base: str, path: str, body: bytes, _headers: object, **_kw: object) -> HttpResponse:
        requests.append(("POST", path, json.loads(body)))
        page = {"cursor": 0, "keys": [{"name": "qa-key"}, {"name": "qa-second"}, {"name": "qa-excess"}]}
        return _response(200, [page] if batched_response else page)

    monkeypatch.setattr(web_panels, "_post", post)
    ctx = SimpleNamespace(args=SimpleNamespace(show_keys=2, timeout=1, secure=False, _proxy_config=None))
    result = web_panels.enumerate_panel(
        ctx, {"ui_product": "redis_insight", "ui": {"endpoint": "http://qa", "inventory": {}}}
    )
    assert result["ui"]["inventory"]["show_keys"] == {
        "count": 2,
        "items": ["qa-redis/qa-key", "qa-redis/qa-second"],
        "partial": True,
    }
    assert requests == [
        ("POST", "/api/databases/qa-id/keys?encoding=utf8", {"cursor": "0", "count": 2, "keysInfo": False})
    ]


def test_redis_insight_basic_only_proves_reverse_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))

    def get(_pool: object, _base: str, _path: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        return (
            _response(200, [{"id": "qa"}]) if (headers or {}).get("Authorization") else _response(401, "Basic required")
        )

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(
        credential=AuditCredentialRun(username="admin", password="secret"),
        args=SimpleNamespace(timeout=1, secure=False, _proxy_config=None),
    )
    result = web_panels.authenticate_panel(ctx, {"ui_product": "redis_insight", "ui": {"endpoint": "http://qa"}})
    assert result["credential_state"] == "valid"
    assert result["ui"]["auth_boundary"] == "reverse_proxy"
    assert result.get("is_redis") is not True


def test_mongo_express_query_reads_each_document_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))
    requested: list[str] = []

    def get(_pool: object, _base: str, path: str, **_kw: object) -> HttpResponse:
        requested.append(path)
        if path == "/":
            return _response(200, '<title>Mongo Express</title><a href="/db/qa/">qa</a>')
        if path == "/db/qa/":
            return _response(200, '<a href="/db/qa/widgets">widgets</a>')
        if path.startswith("/db/qa/widgets?"):
            return _response(
                200,
                "<tr onclick=\"loadDocument('/db/qa/widgets/%22id%22?skip=0')\">"
                "<button onclick=\"loadDocument('/db/qa/widgets/%22id%22')\">",
            )
        if path == "/db/qa/widgets/%22id%22":
            return _response(200, '<textarea id="document">{label: &#39;sample&#39;}</textarea>')
        return _response(404, {})

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(
        args=SimpleNamespace(
            database="qa",
            collections=["widgets"],
            dump=5,
            query='{"label":"sample"}',
            timeout=1,
            secure=False,
            _proxy_config=None,
        )
    )
    inventory = web_panels.enumerate_panel(ctx, {"ui_product": "mongo_express", "ui": {"endpoint": "http://qa"}})["ui"][
        "inventory"
    ]
    assert inventory["dump"]["count"] == 1
    assert inventory["query"]["records"][0]["content"] == "{label: 'sample'}"
    assert requested.count("/db/qa/widgets/%22id%22") == 1


def test_mongo_express_dump_walks_every_collection_page(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))
    paths: list[str] = []

    def get(_pool: object, _base: str, path: str, **_kw: object) -> HttpResponse:
        paths.append(path)
        if path == "/":
            return _response(200, '<title>Mongo Express</title><a href="/db/qa/">qa</a>')
        if path == "/db/qa/":
            return _response(200, '<a href="/db/qa/first">first</a><a href="/db/qa/second">second</a>')
        if path in {"/db/qa/first", "/db/qa/first?skip=1", "/db/qa/second"}:
            name = "first2" if "skip=1" in path else path.rsplit("/", 1)[-1]
            count = 2 if "first" in path else 1
            return _response(
                200,
                f"limit: '1', totalPages: Math.round('{count}' / '1') loadDocument('/db/qa/{name}/doc')",
            )
        if path.endswith("/doc"):
            return _response(200, f'<textarea id="document">{{"path":"{path}"}}</textarea>')
        return _response(404, {})

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(args=SimpleNamespace(dump=True, timeout=1, secure=False, _proxy_config=None))
    result = web_panels.enumerate_panel(ctx, {"ui_product": "mongo_express", "ui": {"endpoint": "http://qa"}})
    dump = result["ui"]["inventory"]["dump"]
    assert dump["count"] == 3
    assert dump["partial"] is False
    assert "/db/qa/first?skip=1" in paths


def test_mongo_express_dump_marks_partial_at_document_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_panels, "_DUMP_ITEMS", 1)
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))

    def get(_pool: object, _base: str, path: str, **_kw: object) -> HttpResponse:
        if path == "/":
            return _response(200, '<title>Mongo Express</title><a href="/db/qa/">qa</a>')
        if path == "/db/qa/":
            return _response(200, '<a href="/db/qa/items">items</a>')
        if path == "/db/qa/items":
            return _response(200, "limit: '1', totalPages: Math.round('2' / '1') loadDocument('/db/qa/items/a')")
        if path == "/db/qa/items/a":
            return _response(200, '<textarea id="document">{"value":1}</textarea>')
        return _response(404, {})

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(args=SimpleNamespace(dump=True, timeout=1, secure=False, _proxy_config=None))
    dump = web_panels.enumerate_panel(ctx, {"ui_product": "mongo_express", "ui": {"endpoint": "http://qa"}})["ui"][
        "inventory"
    ]["dump"]
    assert dump["count"] == 1
    assert dump["partial"] is True


def test_mongo_express_show_indexes_exceeds_old_first_twenty_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))

    def get(_pool: object, _base: str, path: str, **_kw: object) -> HttpResponse:
        if path == "/":
            return _response(200, '<title>Mongo Express</title><a href="/db/qa/">qa</a>')
        if path == "/db/qa/":
            return _response(200, '<a href="/db/qa/items">items</a>')
        if path == "/db/qa/items":
            links = "".join(f'<a href="/db/qa/items/dropIndex/x?name=index{number}">x</a>' for number in range(30))
            return _response(200, links)
        return _response(404, {})

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(args=SimpleNamespace(show_indexes=True, timeout=1, secure=False, _proxy_config=None))
    indexes = web_panels.enumerate_panel(ctx, {"ui_product": "mongo_express", "ui": {"endpoint": "http://qa"}})["ui"][
        "inventory"
    ]["show_indexes"]
    assert indexes["count"] == 30
    assert "qa/items/index29" in indexes["items"]
    assert indexes["partial"] is False


def test_redis_insight_cursor_and_typed_dump_stay_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(web_panels, "_get", lambda *_args, **_kw: _response(200, [{"id": "0", "name": "qa"}]))
    requests: list[tuple[str, dict[str, object]]] = []

    def post(_pool: object, _base: str, path: str, body: bytes, _headers: object, **_kw: object) -> HttpResponse:
        payload = json.loads(body)
        requests.append((path, payload))
        if path.endswith("/keys?encoding=utf8"):
            if payload["cursor"] == "0":
                return _response(200, [{"cursor": 3, "keys": [{"name": "first", "type": "string"}]}])
            return _response(200, [{"cursor": 0, "keys": [{"name": "second", "type": "string"}]}])
        return _response(200, {"value": "secret", "keyName": payload["keyName"]})

    monkeypatch.setattr(web_panels, "_post", post)
    ctx = SimpleNamespace(args=SimpleNamespace(show_keys=10, dump=1, timeout=1, secure=False, _proxy_config=None))
    inventory = web_panels.enumerate_panel(ctx, {"ui_product": "redis_insight", "ui": {"endpoint": "http://qa"}})["ui"][
        "inventory"
    ]
    assert inventory["show_keys"]["items"] == ["qa/first", "qa/second"]
    assert inventory["dump"]["count"] == 1
    assert inventory["dump"]["records"][0]["value"]["value"] == "secret"
    assert [entry[1]["cursor"] for entry in requests if entry[0].endswith("/keys?encoding=utf8")] == ["0", "3"]
    assert all("/cli" not in path for path, _ in requests)


def test_minio_console_dump_reads_explicit_object_without_file_write(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))
    paths: list[str] = []

    def get(_pool: object, _base: str, path: str, **_kw: object) -> HttpResponse:
        paths.append(path)
        if path == "/api/v1/buckets":
            return _response(200, {"buckets": [{"name": "qa"}]})
        if path.endswith("objects?limit=10001"):
            return _response(200, {"objects": [{"name": "secret.env"}]})
        if path.endswith("objects/download?prefix=secret.env"):
            return _response(200, "TOKEN=fixture")
        return _response(404, {})

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(
        args=SimpleNamespace(
            object="qa/secret.env", dump=True, download=False, timeout=1, secure=False, _proxy_config=None
        )
    )
    inventory = web_panels.enumerate_panel(ctx, {"ui_product": "minio_console", "ui": {"endpoint": "http://qa"}})["ui"][
        "inventory"
    ]
    assert inventory["dump"]["records"] == [{"object": "qa/secret.env", "content": "TOKEN=fixture"}]
    assert paths.count("/api/v1/buckets/qa/objects/download?prefix=secret.env") == 1
    assert "download" not in inventory


def test_minio_object_read_does_not_require_bucket_listing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))
    paths: list[str] = []

    def get(_pool: object, _base: str, path: str, **_kw: object) -> HttpResponse:
        paths.append(path)
        if path == "/api/v1/buckets":
            return _response(403, {"message": "list denied"})
        return _response(200, "readable object")

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(
        args=SimpleNamespace(object="qa/readable.txt", dump=True, timeout=1, secure=False, _proxy_config=None)
    )
    inventory = web_panels.enumerate_panel(ctx, {"ui_product": "minio_console", "ui": {"endpoint": "http://qa"}})["ui"][
        "inventory"
    ]
    assert inventory["dump"]["records"] == [{"object": "qa/readable.txt", "content": "readable object"}]
    assert len(paths) == 2
    assert all("objects?limit" not in path for path in paths)


def test_minio_console_dump_walks_all_buckets_and_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))
    paths: list[str] = []

    def get(_pool: object, _base: str, path: str, **_kw: object) -> HttpResponse:
        paths.append(path)
        if path == "/api/v1/buckets":
            return _response(200, {"buckets": [{"name": "one"}, {"name": "two"}]})
        if path == "/api/v1/buckets/one/objects?limit=10001":
            return _response(200, {"objects": [{"name": "a"}], "nextMarker": "a", "isTruncated": True})
        if path == "/api/v1/buckets/one/objects?limit=10001&marker=a":
            return _response(200, {"objects": [{"name": "b"}], "isTruncated": False})
        if path == "/api/v1/buckets/two/objects?limit=10001":
            return _response(200, {"objects": [{"name": "c"}]})
        if "/objects/download?" in path:
            return _response(200, path)
        return _response(404, {})

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(args=SimpleNamespace(dump=True, timeout=1, secure=False, _proxy_config=None))
    result = web_panels.enumerate_panel(ctx, {"ui_product": "minio_console", "ui": {"endpoint": "http://qa"}})
    dump = result["ui"]["inventory"]["dump"]
    assert [item["object"] for item in dump["records"]] == ["one/a", "one/b", "two/c"]
    assert dump["partial"] is False
    assert "/api/v1/buckets/one/objects?limit=10001&marker=a" in paths


def test_minio_console_dump_descends_into_directory_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))
    paths: list[str] = []

    def get(_pool: object, _base: str, path: str, **_kw: object) -> HttpResponse:
        paths.append(path)
        if path == "/api/v1/buckets":
            return _response(200, {"buckets": [{"name": "qa"}]})
        if path == "/api/v1/buckets/qa/objects?limit=10001":
            return _response(200, {"objects": [{"name": "nested/"}]})
        if path == "/api/v1/buckets/qa/objects?limit=10001&prefix=nested%2F":
            return _response(200, {"objects": [{"name": "nested/a.txt", "size": 4, "etag": "qa"}]})
        if "/objects/download?" in path:
            return _response(200, "body")
        return _response(404, {})

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(args=SimpleNamespace(dump=True, timeout=1, secure=False, _proxy_config=None))
    inventory = web_panels.enumerate_panel(ctx, {"ui_product": "minio_console", "ui": {"endpoint": "http://qa"}})["ui"][
        "inventory"
    ]
    assert inventory["dump"]["records"] == [{"object": "qa/nested/a.txt", "content": "body"}]
    assert inventory["dump"]["partial"] is False
    assert "/api/v1/buckets/qa/objects?limit=10001&prefix=nested%2F" in paths


def test_minio_console_empty_bucket_null_objects_is_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))

    def get(_pool: object, _base: str, path: str, **_kw: object) -> HttpResponse:
        if path == "/api/v1/buckets":
            return _response(200, {"buckets": [{"name": "empty"}]})
        return _response(200, {"objects": None})

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(args=SimpleNamespace(dump=True, timeout=1, secure=False, _proxy_config=None))
    inventory = web_panels.enumerate_panel(ctx, {"ui_product": "minio_console", "ui": {"endpoint": "http://qa"}})["ui"][
        "inventory"
    ]
    assert inventory["dump"]["count"] == 0
    assert inventory["dump"]["partial"] is False


def test_minio_console_dump_reports_partial_at_object_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_panels, "_DUMP_ITEMS", 2)
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))

    def get(_pool: object, _base: str, path: str, **_kw: object) -> HttpResponse:
        if path == "/api/v1/buckets":
            return _response(200, {"buckets": [{"name": "qa"}]})
        if "/objects?" in path:
            return _response(200, {"objects": [{"name": name} for name in ("a", "b", "c")]})
        return _response(200, "body")

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(args=SimpleNamespace(dump=True, timeout=1, secure=False, _proxy_config=None))
    dump = web_panels.enumerate_panel(ctx, {"ui_product": "minio_console", "ui": {"endpoint": "http://qa"}})["ui"][
        "inventory"
    ]["dump"]
    assert dump["count"] == 2
    assert dump["partial"] is True


def test_ui_txt_dump_includes_every_record_and_full_content() -> None:
    body = "x" * 1500
    record = {
        "host": "qa",
        "port": 9001,
        "ui_product": "minio_console",
        "ui": {
            "auth_required": False,
            "inventory": {
                "dump": {
                    "count": 201,
                    "items": ["truncated"],
                    "records": [{"object": f"bucket/{index}", "content": body} for index in range(201)],
                    "partial": False,
                }
            },
        },
    }
    lines = web_panels.render_panel(record, "MINIO")
    dump_lines = [line for line in lines if " [+] bucket/" in line]
    assert len(dump_lines) == 201
    assert body in dump_lines[-1]
    assert all("\x1b[" not in line for line in lines)


def test_ui_txt_dump_labels_binary_base64() -> None:
    record = {
        "host": "qa",
        "port": 9001,
        "ui_product": "minio_console",
        "ui": {"inventory": {"dump": {"count": 1, "records": [{"object": "bucket/blob", "base64": "/wA="}]}}},
    }
    assert any("bucket/blob base64:/wA=" in line for line in web_panels.render_panel(record, "MINIO"))


def test_portainer_system_keeps_info_and_disk_usage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))
    paths: list[str] = []

    def get(_pool: object, _base: str, path: str, **_kw: object) -> HttpResponse:
        paths.append(path)
        if path.startswith("/api/endpoints?"):
            return _response(200, [{"Id": 2, "Name": "qa"}])
        if path.endswith("/info"):
            return _response(200, {"ServerVersion": "27.0", "Driver": "overlay2"})
        if path.endswith("/system/df"):
            return _response(200, {"LayersSize": 123})
        return _response(404, {})

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(args=SimpleNamespace(system=True, timeout=1, secure=False, _proxy_config=None))
    system = web_panels.enumerate_panel(ctx, {"ui_product": "portainer", "ui": {"endpoint": "http://qa"}})["ui"][
        "inventory"
    ]["system"]
    assert system["records"][0]["info"]["Driver"] == "overlay2"
    assert system["records"][0]["disk_usage"]["LayersSize"] == 123
    assert all("/docker/" in path for path in paths[1:])


def test_dashboards_fixed_inventory_uses_upstream_gets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))
    requests: list[tuple[str, bytes]] = []

    def post(_pool: object, _base: str, path: str, body: bytes, _headers: object, **_kw: object) -> HttpResponse:
        requests.append((path, body))
        if "_cat%2Findices" in path:
            return _response(200, [{"index": "qa"}])
        if "_search" in path:
            return _response(200, {"hits": {"hits": [{"_id": "1", "_source": {"name": "qa"}}]}})
        return _response(200, {"status": "bright_green"})

    monkeypatch.setattr(web_panels, "_post", post)
    ctx = SimpleNamespace(args=SimpleNamespace(cluster=True, timeout=1, secure=False, _proxy_config=None))
    inventory = web_panels.enumerate_panel(ctx, {"ui_product": "kibana", "ui": {"endpoint": "http://qa"}})["ui"][
        "inventory"
    ]
    assert inventory["cluster"]["records"]["status"] == "bright_green"
    assert all("method=GET" in path and body == b"" for path, body in requests)


def test_dashboards_does_not_count_proxy_errors_or_prioritize_internal_indices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))
    requested: list[str] = []

    def post(_pool: object, _base: str, path: str, _body: bytes, _headers: object, **_kw: object) -> HttpResponse:
        requested.append(path)
        if "_security%2Fuser" in path:
            return _response(200, {"error": "method not allowed", "status": 405})
        if "_cat%2Findices" in path:
            return _response(200, [{"index": f".internal-{index}"} for index in range(15)] + [{"index": "qa"}])
        if "qa%2F_search" in path:
            return _response(200, {"hits": {"hits": [{"_id": "1", "_source": {"name": "qa"}}]}})
        return _response(404, {})

    monkeypatch.setattr(web_panels, "_post", post)
    ctx = SimpleNamespace(args=SimpleNamespace(user=True, discover=True, timeout=1, secure=False, _proxy_config=None))
    inventory = web_panels.enumerate_panel(ctx, {"ui_product": "kibana", "ui": {"endpoint": "http://qa"}})["ui"][
        "inventory"
    ]
    assert inventory["user"]["status"] == "unavailable"
    assert inventory["discover"]["count"] == 0
    assert inventory["discover"]["partial"] is True


def test_pgadmin_view_rows_uses_read_only_cursor_and_closes_session(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []

    def post(_pool: object, _base: str, path: str, body: bytes, _headers: object) -> HttpResponse:
        calls.append(("POST", path))
        assert "/3/table/1/2/3/4" in path
        assert json.loads(body) == {"server_cursor": True}
        return _response(200, {"success": 1, "data": {"conn_id": "1"}})

    def get(_pool: object, _base: str, path: str, **_kw: object) -> HttpResponse:
        calls.append(("GET", path))
        if "/poll/" in path:
            return _response(200, {"success": 1, "data": {"status": "Success", "result": [[1, "qa"]]}})
        return _response(200, {"success": 1, "data": {"status": True}})

    class Pool:
        def request_once(self, method: str, url: str, **_kw: object) -> HttpResponse:
            calls.append((method, url))
            return _response(200, {})

    monkeypatch.setattr(web_panels, "_post", post)
    monkeypatch.setattr(web_panels, "_get", get)
    value = web_panels._pgadmin_view_rows(Pool(), "http://qa", {}, 1, 2, 3, 4, limit=5)
    assert value["records"] == [[1, "qa"]]
    assert [method for method, _ in calls] == ["POST", "GET", "GET", "DELETE"]


def test_pgadmin_view_rows_fetches_following_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(web_panels, "_post", lambda *_args, **_kw: _response(200, {"success": 1}))

    def get(_pool: object, _base: str, path: str, **_kw: object) -> HttpResponse:
        calls.append(path)
        if "/poll/" in path:
            return _response(
                200,
                {"data": {"status": "Success", "result": [[1], [2]], "pagination": {"next_page": 1}}},
            )
        if "/fetch_window/" in path:
            next_page = 1 if path.endswith("/3/10") else 0
            row = [3] if next_page else [4]
            return _response(
                200, {"data": {"status": "Success", "result": [row], "pagination": {"next_page": next_page}}}
            )
        return _response(200, {"success": 1})

    class Pool:
        def request_once(self, _method: str, _url: str, **_kw: object) -> HttpResponse:
            return _response(200, {})

    monkeypatch.setattr(web_panels, "_get", get)
    result = web_panels._pgadmin_view_rows(Pool(), "http://qa", {}, 1, 2, 3, 4, limit=10)
    assert result["records"] == [[1], [2], [3], [4]]
    assert result["partial"] is False
    assert any("/fetch_window/" in path and path.endswith("/3/10") for path in calls)
    assert any("/fetch_window/" in path and path.endswith("/4/10") for path in calls)


def test_pgadmin_view_rows_marks_byte_budget_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_panels, "_post", lambda *_args, **_kw: _response(200, {"success": 1}))

    def get(_pool: object, _base: str, path: str, **_kw: object) -> HttpResponse:
        data = {"status": "Success", "result": [["small"], ["large-value"]], "pagination": {"next_page": 0}}
        return _response(200, {"data": data} if "/poll/" in path else {"success": 1})

    class Pool:
        def request_once(self, _method: str, _url: str, **_kw: object) -> HttpResponse:
            return _response(200, {})

    monkeypatch.setattr(web_panels, "_get", get)
    result = web_panels._pgadmin_view_rows(Pool(), "http://qa", {}, 1, 2, 3, 4, limit=10, max_bytes=12)
    assert result["records"] == [["small"]]
    assert result["partial"] is True


@pytest.mark.parametrize("sequence_ok", [True, False])
def test_pgadmin_backend_connection_does_not_save_password(monkeypatch: pytest.MonkeyPatch, sequence_ok: bool) -> None:
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))
    posts: list[dict[str, object]] = []

    def get(_pool: object, _base: str, path: str, **_kw: object) -> HttpResponse:
        if path == "/browser/js/utils.js":
            return _response(200, "csrf_token_header'] = 'X-Test'; csrf_token'] = 'token'")
        if path == "/browser/nodes/":
            return _response(200, {"success": 1, "data": [{"_type": "server_group", "_id": "1"}]})
        if path == "/browser/server/nodes/1/":
            return _response(200, {"success": 1, "data": [{"_type": "server", "_id": "2", "label": "qa"}]})
        if path == "/browser/role/obj/1/2/":
            return _response(
                200,
                [
                    {
                        "rolname": "qa_user",
                        "rolsuper": False,
                        "rolcreaterole": True,
                        "rolcreatedb": False,
                        "rolmembership": [{"role": "reader", "admin": False}],
                        "rolpassword": "must-not-leak",
                    }
                ],
            )
        if path == "/browser/database/nodes/1/2/":
            return _response(
                200, {"success": 1, "data": [{"_type": "database", "_id": 4, "label": "qa_db", "connected": True}]}
            )
        if path == "/browser/database/obj/1/2/4":
            return _response(200, {"acl": None, "tblacl": ""})
        if path == "/browser/schema/nodes/1/2/4/":
            return _response(200, {"success": 1, "data": [{"_type": "schema", "_id": 5, "label": "public"}]})
        if path == "/browser/schema/obj/1/2/4/5":
            return _response(
                200,
                {
                    "nspacl": [{"grantee": "reader", "privileges": [{"privilege_type": "U"}]}],
                    "deftblacl": [{"grantee": "reader", "privileges": ["r"]}],
                },
            )
        if path == "/browser/sequence/nodes/1/2/4/5/":
            if not sequence_ok:
                return _response(403, {})
            return _response(200, {"success": 1, "data": [{"_type": "sequence", "_id": 7, "label": "order_seq"}]})
        if path == "/browser/sequence/obj/1/2/4/5/7":
            return _response(200, {"relacl": [{"grantee": "reader", "privileges": ["U", "r"]}]})
        if path == "/browser/function/nodes/1/2/4/5/":
            return _response(200, {"success": 1, "data": [{"_type": "function", "_id": 8, "label": "secret_fn()"}]})
        if path == "/browser/function/obj/1/2/4/5/8":
            return _response(200, {"proacl": [{"grantee": "reader", "privileges": ["X"]}]})
        if path == "/browser/table/nodes/1/2/4/5/":
            return _response(200, {"success": 1, "data": [{"_type": "table", "_id": 6, "label": "orders"}]})
        if path == "/browser/table/obj/1/2/4/5/6":
            return _response(200, {"relacl_str": ["reader=r/owner"], "acl": [{"grantee": "reader"}]})
        if path == "/browser/column/nodes/1/2/4/5/6/":
            return _response(
                200,
                {
                    "success": 1,
                    "data": [
                        {"_type": "column", "_id": 9, "label": "email"},
                        {"_type": "column", "_id": 10, "label": "id"},
                    ],
                },
            )
        if path == "/browser/column/obj/1/2/4/5/6/9":
            return _response(200, {"attacl": [{"grantee": "reader", "privileges": ["r"]}]})
        if path == "/browser/column/obj/1/2/4/5/6/10":
            return _response(200, {"name": "id"})
        return _response(404, {})

    def post(_pool: object, _base: str, _path: str, body: bytes, _headers: object) -> HttpResponse:
        posts.append(json.loads(body))
        return _response(200, {"data": {"user": {"name": "qa_user", "is_superuser": False}}})

    monkeypatch.setattr(web_panels, "_get", get)
    monkeypatch.setattr(web_panels, "_post", post)
    ctx = SimpleNamespace(
        args=SimpleNamespace(
            show_databases=True,
            privesc_check=True,
            pgadmin_server_password="db-secret",
            timeout=1,
            secure=False,
            _proxy_config=None,
        )
    )
    inventory = web_panels.enumerate_panel(ctx, {"ui_product": "pgadmin", "ui": {"endpoint": "http://qa"}})["ui"][
        "inventory"
    ]
    assert inventory["show_databases"]["items"] == ["qa/qa_db"]
    assert inventory["privesc_check"]["records"][0]["is_superuser"] is False
    assert inventory["privesc_check"]["records"][1]["rolmembership"] == [{"role": "reader", "admin": False}]
    assert any(
        entry.get("object_type") == "table" and entry["acl_fields"]["relacl_str"] == ["reader=r/owner"]
        for entry in inventory["privesc_check"]["records"]
    )
    kinds = {entry.get("object_type") for entry in inventory["privesc_check"]["records"]}
    assert kinds >= {"function", "column"}
    assert ("sequence" in kinds) is sequence_ok
    assert any("deftblacl" in entry.get("acl_fields", {}) for entry in inventory["privesc_check"]["records"])
    assert inventory["privesc_check"]["partial"] is not sequence_ok
    assert posts == [{"password": "db-secret", "save_password": False}]
    assert "db-secret" not in json.dumps(inventory)
    assert "must-not-leak" not in json.dumps(inventory)


def test_pgadmin_nodes_accepts_result_and_data_lists() -> None:
    node = {"_type": "server", "_id": "1", "label": "qa-postgres"}
    assert web_panels._pgadmin_nodes(_response(200, {"success": 1, "result": [node], "data": None})) == [node]
    assert web_panels._pgadmin_nodes(_response(200, {"success": 1, "result": None, "data": [node]})) == [node]
    assert web_panels._pgadmin_nodes(_response(401, {"success": 0, "result": [node]})) is None


def test_portainer_walks_paginated_environments(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))
    paths: list[str] = []

    def get(_pool: object, _base: str, path: str, **_kw: object) -> HttpResponse:
        paths.append(path)
        if path == "/api/endpoints?start=0&limit=100":
            return _response(200, [{"Id": number, "Name": f"env-{number}"} for number in range(1, 101)])
        if path == "/api/endpoints?start=100&limit=100":
            return _response(200, [{"Id": 101, "Name": "env-101"}])
        return _response(404, {})

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(args=SimpleNamespace(containers=True, timeout=1, secure=False, _proxy_config=None))
    inventory = web_panels.enumerate_panel(ctx, {"ui_product": "portainer", "ui": {"endpoint": "http://qa"}})["ui"][
        "inventory"
    ]
    assert inventory["environments"]["count"] == 101
    assert inventory["environments"]["partial"] is False
    assert "/api/endpoints?start=100&limit=100" in paths
    assert inventory["containers"]["partial"] is True


def test_dashboard_discovery_forwards_search_bodies_cleanup_and_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core.modules.elastic import discover

    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))
    requests = []

    def post(_pool, _base, path, body, headers, **kwargs):
        requests.append((parse_qs(urlsplit(path).query), body, headers))
        return HttpResponse(200, b"{}", {}, truncated=True)

    monkeypatch.setattr(web_panels, "_post", post)

    def run(request, **kwargs):
        options = kwargs["options"]
        assert options.max_source_bytes == 17 and options.max_seconds == 0.001
        result = request(
            discover.DiscoverRequest("POST", "/qa/_search", {"Content-Type": "application/json"}, b'{"size":1}')
        )
        assert result.truncated
        request(discover.DiscoverRequest("DELETE", "/_pit", body=b'{"id":"context"}'))
        coverage = discover.DiscoverCoverage(truncated=True)
        return discover.DiscoverReport([], coverage, [])

    monkeypatch.setattr(discover, "run_discovery", run)
    ctx = SimpleNamespace(args=SimpleNamespace(discover=True, discover_max_bytes=17, discover_time=0.001))
    inventory = web_panels.enumerate_panel(ctx, {"ui_product": "kibana", "ui": {"endpoint": "http://qa"}})["ui"][
        "inventory"
    ]
    assert inventory["discover"]["partial"]
    assert requests[0][0] == {"path": ["/qa/_search"], "method": ["POST"]}
    assert requests[0][1] == b'{"size":1}' and requests[0][2]["kbn-xsrf"] == "redposture"
    assert requests[1][0]["method"] == ["DELETE"]


def test_redis_insight_typed_hash_pages_and_repeated_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[object] = []

    def post(_pool: object, _base: str, _path: str, body: bytes, _headers: object, **_kw: object) -> HttpResponse:
        payload = json.loads(body)
        seen.append(payload["cursor"])
        if len(seen) == 1:
            return _response(200, {"fields": [{"field": "one", "value": "a"}], "cursor": 2})
        return _response(200, {"fields": [{"field": "two", "value": "b"}], "cursor": 2})

    monkeypatch.setattr(web_panels, "_post", post)
    data, error, _, partial = web_panels._redis_insight_value(
        object(),
        "http://qa",
        {},
        {"database_id": "qa", "key": "hash", "type": "hash"},
        byte_budget=1024 * 1024,
        deadline=web_panels.time.monotonic() + 10,
    )
    assert [page["fields"][0]["field"] for page in data] == ["one", "two"]
    assert seen == [0, 2]
    assert error == "repeated_cursor"
    assert partial is True


def test_redis_insight_stream_reads_following_page(monkeypatch: pytest.MonkeyPatch) -> None:
    starts: list[str | None] = []

    def post(_pool: object, _base: str, _path: str, body: bytes, _headers: object, **_kw: object) -> HttpResponse:
        payload = json.loads(body)
        starts.append(payload.get("start"))
        if len(starts) == 1:
            return _response(200, {"total": 2, "entries": [{"id": "1-0", "fields": {"a": "one"}}]})
        return _response(200, {"total": 2, "entries": [{"id": "2-0", "fields": {"a": "two"}}]})

    monkeypatch.setattr(web_panels, "_post", post)
    data, error, _, partial = web_panels._redis_insight_value(
        object(),
        "http://qa",
        {},
        {"database_id": "qa", "key": "events", "type": "stream"},
        byte_budget=1024 * 1024,
        deadline=web_panels.time.monotonic() + 10,
    )
    assert starts == [None, "(1-0"]
    assert [page["entries"][0]["id"] for page in data] == ["1-0", "2-0"]
    assert error is None
    assert partial is False


def test_minio_console_download_without_bucket_reads_all_accessible(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))

    def get(_pool: object, _base: str, path: str, **_kw: object) -> HttpResponse:
        if path == "/api/v1/buckets":
            return _response(200, {"buckets": [{"name": "one"}, {"name": "two"}]})
        if path.endswith("/objects?limit=10001"):
            return _response(200, {"objects": [{"name": "a.txt"}]})
        if "/objects/download?" in path:
            return _response(200, path)
        return _response(404, {})

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(args=SimpleNamespace(download=True, timeout=1, secure=False, _proxy_config=None))
    inventory = web_panels.enumerate_panel(ctx, {"ui_product": "minio_console", "ui": {"endpoint": "http://qa"}})["ui"][
        "inventory"
    ]
    assert inventory["download"]["count"] == 2
    assert inventory["download"]["partial"] is False
    assert all(Path(row["path"]).exists() for row in inventory["download"]["records"])
    assert len(set(inventory["download"]["items"])) == 2


def test_ui_rendering_uses_airflow_palette_and_has_no_ansi() -> None:
    class PaintConsole:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []
            self.lines: list[str] = []

        def _paint(self, value: str, color: str, _stream: object) -> str:
            self.calls.append((value, color))
            return value

        def plain(self, value: str) -> None:
            self.lines.append(value)

    console = PaintConsole()
    detection = "MINIO\t127.0.0.1\t9001\t [*] MinIO Console (auth required:True) (version:2026.1)"
    assert web_panels.colorize_panel_line(console, detection, "MINIO") is True
    assert any("version:2026.1" in value and color == "white" for value, color in console.calls)
    assert any("auth required:True" in value and color == "bright_green" for value, color in console.calls)
    for count, color in ((0, "bright_green"), (3, "true_red")):
        console.calls.clear()
        assert (
            web_panels.colorize_panel_line(
                console, f"MINIO\t127.0.0.1\t9001\t [*] Show Objects Enumeration (count:{count})", "MINIO"
            )
            is True
        )
        assert any(f"count:{count}" in value and painted == color for value, painted in console.calls)
    console.calls.clear()
    assert web_panels.colorize_panel_line(console, "MINIO\t127.0.0.1\t9001\t [+] user:secret (UI)", "MINIO")
    assert any("user:secret" in value and color == "true_red" for value, color in console.calls)
    assert any(value == "UI" and color == "white" for value, color in console.calls)
    console.calls.clear()
    assert web_panels.colorize_panel_line(console, "MINIO\t127.0.0.1\t9001\t [-] user:wrong (UI)", "MINIO")
    assert not any("user:wrong" in value and color == "true_red" for value, color in console.calls)
    console.calls.clear()
    assert web_panels.colorize_panel_line(console, "MINIO\t127.0.0.1\t9001\t [*] dump coverage:partial", "MINIO")
    assert any("coverage:partial" in value and color == "orange" for value, color in console.calls)
    console.calls.clear()
    assert web_panels.colorize_panel_line(console, "MINIO\t127.0.0.1\t9001\t [+] qa/file TOKEN=fixture", "MINIO")
    assert any("qa/file" in value and color == "true_red" for value, color in console.calls)
    record = {
        "host": "127.0.0.1",
        "port": 9001,
        "ui_product": "minio_console",
        "ui": {"version": None, "auth_required": True, "inventory": {"show_objects": {"count": 0, "items": []}}},
    }
    assert all("\x1b" not in line for line in web_panels.render_panel(record, "MINIO"))
    record["ui"]["inventory"] = {
        "export": {"count": 10_050, "items": ["/tmp/qa.jsonl"], "partial": True, "reason": "HTTP 429"}
    }
    export_lines = web_panels.render_panel(record, "MINIO")
    assert any("Export Enumeration (count:10050)" in line for line in export_lines)
    assert any("export coverage:partial" in line for line in export_lines)
    assert all("\x1b" not in line for line in export_lines)
    console.calls.clear()
    assert web_panels.colorize_panel_line(
        console, next(line for line in export_lines if "Export Enumeration" in line), "MINIO"
    )
    assert any("count:10050" in value and color == "true_red" for value, color in console.calls)
    record["ui"]["inventory"] = {"export": {"status": "unavailable", "partial": True, "reason": "HTTP 403"}}
    unavailable = web_panels.render_panel(record, "MINIO")[-1]
    assert "[-] export unavailable (reason:HTTP 403)" in unavailable
    console.calls.clear()
    assert web_panels.colorize_panel_line(console, unavailable, "MINIO")
    assert any("reason:HTTP 403" in value and color == "orange" for value, color in console.calls)


def test_ui_cve_route_never_uses_backend_version() -> None:
    products = resolve_products(
        "postgres",
        {"surface": "ui", "ui_product": "pgadmin", "server_version": "16.0", "ui": {"version": "9.1"}},
    )
    assert [(item.product_key, item.version) for item in products] == [("pgadmin", "9.1")]


@pytest.mark.parametrize("product", tuple(web_panels.UI_PRODUCTS))
def test_every_ui_product_has_own_cve_key(product: str) -> None:
    products = resolve_products("elastic", {"surface": "ui", "ui_product": product, "ui": {"version": "1.2.3"}})
    assert [(item.product_key, item.version) for item in products] == [(product, "1.2.3")]


def test_spray_refuses_redis_insight_without_product_login() -> None:
    record = AuditRecord.from_mapping(
        {
            "host": "127.0.0.1",
            "port": 5540,
            "module": "redis",
            "service": "redis",
            "status": "open_no_auth",
            "surface": "ui",
            "ui_product": "redis_insight",
            "credential_verification_status": "unavailable",
        },
        module="redis",
        service="redis",
    )
    candidate = Candidate(kind="pair", username="admin", password="admin", token=None)
    assert _supported("redis", candidate, record) is False
    token = Candidate(kind="token", username=None, password=None, token="secret")
    assert _supported("redis", token, record) is False
