"""Malformed UI reads, identity proof and direct HTTP framing contracts."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs

import pytest

from redposture_core import web_panels as wp
from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.elastic import async_detect as direct


def response(value: Any, status: int = 200, **kwargs: Any) -> HttpResponse:
    body = value.encode() if isinstance(value, str) else json.dumps(value).encode()
    return HttpResponse(status=status, body=body, headers=kwargs.pop("headers", {}), **kwargs)


@pytest.mark.parametrize(
    ("kind", "value", "reason"),
    [
        ("json", {"downloaded": False}, "json_not_downloaded"),
        ("json", {"data": {}}, "invalid_json_response"),
        ("string", {"value": 4}, "invalid_string_response"),
        ("hash", {"fields": {}}, "invalid_hash_response"),
        ("set", {"members": {}}, "invalid_set_response"),
        ("set", {"members": []}, "missing_cursor"),
        ("list", {"elements": [], "total": 3}, "stalled_page"),
        ("list", {"elements": [0] * 100}, "unknown_next_page"),
        ("stream", {"entries": [], "total": 3}, "stalled_page"),
        ("stream", {"entries": [{}], "total": 3}, "missing_stream_id"),
        ("stream", {"entries": [{}] * 100}, "unknown_next_page"),
    ],
)
def test_redis_typed_routes_reject_missing_completion_proof(
    monkeypatch: pytest.MonkeyPatch, kind: str, value: Any, reason: str
) -> None:
    requests: list[tuple[str, dict[str, Any]]] = []

    def post(_pool: Any, _base: str, path: str, body: bytes, headers: Any, **kwargs: Any) -> HttpResponse:
        requests.append((path, json.loads(body)))
        assert headers == {"Content-Type": "application/json", "Cookie": "sid=1"}
        assert kwargs["response_size_cap"] == 4096
        return response(value)

    monkeypatch.setattr(wp, "_post", post)
    data, error, used, partial = wp._redis_insight_value(
        object(),
        "http://panel",
        {"Cookie": "sid=1"},
        {"database_id": "db/1", "key": "secret", "type": kind},
        byte_budget=4096,
        deadline=float("inf"),
    )
    assert (data, error, used, partial) == ([value], reason, len(json.dumps(value).encode()), True)
    assert len(requests) == 1
    assert requests[0][0].startswith("/api/databases/db%2F1/")
    assert requests[0][0].endswith("?encoding=utf8")
    assert requests[0][1]["keyName"] == "secret"


@pytest.mark.parametrize("budget", [0, 1])
def test_redis_value_budget_exhaustion_does_not_issue_request(monkeypatch: pytest.MonkeyPatch, budget: int) -> None:
    def unexpected(*_args: Any, **_kwargs: Any) -> None:
        pytest.fail("expired reads must not issue a request")

    monkeypatch.setattr(wp, "_post", unexpected)
    assert wp._redis_insight_value(
        object(), "http://panel", {}, {"database_id": "db", "key": "k", "type": "hash"}, byte_budget=budget, deadline=0
    ) == ([], "budget_reached", 0, True)


@pytest.mark.parametrize("status", [401, 500])
def test_redis_value_reports_denied_or_unavailable_with_bytes(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    monkeypatch.setattr(wp, "_post", lambda *_args, **_kwargs: response("denied", status))
    value, reason, used, partial = wp._redis_insight_value(
        object(),
        "http://panel",
        {},
        {"database_id": "db", "key": "k", "type": "string"},
        byte_budget=100,
        deadline=float("inf"),
    )
    assert (value, reason, used, partial) == ([], "access_denied" if status == 401 else "unavailable", 6, True)


@pytest.mark.parametrize("kind", ["string", "list", "zset"])
def test_redis_typed_values_advance_read_windows(monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    pages: list[dict[str, Any]]
    if kind == "string":
        pages = [{"value": "x" * 4096}, {"value": "end"}]
        route = "string/get-value"
        windows = [{"start": 0, "end": 4095}, {"start": 4096, "end": 8191}]
    else:
        pages = [{"elements": ["a", "b"], "total": 3}, {"elements": ["c"], "total": 3}]
        route = "list/get-elements" if kind == "list" else "zSet/get-members"
        windows = [{"offset": 0, "count": 100}, {"offset": 2, "count": 100}]
    requests: list[dict[str, Any]] = []
    answers = iter(pages)

    def post(_pool: Any, _base: str, path: str, body: bytes, _headers: Any, **_kwargs: Any) -> HttpResponse:
        assert path == f"/api/databases/db/{route}?encoding=utf8"
        requests.append(json.loads(body))
        return response(next(answers))

    monkeypatch.setattr(wp, "_post", post)
    value, reason, used, partial = wp._redis_insight_value(
        object(),
        "http://panel",
        {},
        {"database_id": "db", "key": "k", "type": kind},
        byte_budget=20000,
        deadline=float("inf"),
    )
    assert (value, reason, partial) == (pages, None, False)
    assert used == sum(len(json.dumps(page).encode()) for page in pages)
    extra = {"sortOrder": "ASC"} if kind == "zset" else {}
    assert requests == [{"keyName": "k", **window, **extra} for window in windows]


@pytest.mark.parametrize(
    ("product", "answers", "expected"),
    [
        ("minio_console", [response({}, 429)], "rate_limited"),
        ("minio_console", [response({}, 401)], "invalid"),
        (
            "minio_console",
            [response({}, headers={"Set-Cookie": "sid=1; HttpOnly"}), response({"accessKey": "user"})],
            "valid",
        ),
        (
            "minio_console",
            [response({}, headers={"Set-Cookie": "sid=1"}), response({"accessKey": "other"})],
            "unverified",
        ),
        ("mongo_express", [response({}, 429)], "rate_limited"),
        ("mongo_express", [response({}, 401, headers={"WWW-Authenticate": "Basic realm=ui"})], "invalid"),
        ("mongo_express", [response("mongo express /public/img/mongo-express-logo.png"), response({}, 401)], "valid"),
        (
            "mongo_express",
            [
                response("mongo express /public/img/mongo-express-logo.png"),
                response("mongo express /public/img/mongo-express-logo.png"),
            ],
            "unverified",
        ),
        ("kibana", [response({}, 429)], "rate_limited"),
        ("kibana", [response("authentication exception", 401)], "invalid"),
    ],
)
def test_product_auth_distinguishes_challenge_identity_and_public_access(
    monkeypatch: pytest.MonkeyPatch, product: str, answers: list[HttpResponse], expected: str
) -> None:
    requests: list[tuple[str, str, Any]] = []
    pending = iter(answers)

    class Pool:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def close(self) -> None:
            pass

    def get(_pool: Any, base: str, path: str, **kwargs: Any) -> HttpResponse:
        assert base == "http://panel"
        requests.append(("GET", path, kwargs))
        return next(pending)

    def post(_pool: Any, base: str, path: str, body: bytes, headers: Any) -> HttpResponse:
        assert base == "http://panel"
        assert json.loads(body) == {"accessKey": "user", "secretKey": "pass"}
        requests.append(("POST", path, headers))
        return next(pending)

    monkeypatch.setattr(wp, "HttpSessionPool", Pool)
    monkeypatch.setattr(wp, "_get", get)
    monkeypatch.setattr(wp, "_post", post)
    original = {"ui_product": product, "ui": {"endpoint": "http://panel", "credential_probe_path": "/db/qa/"}}
    result = wp.authenticate_panel(
        SimpleNamespace(args=SimpleNamespace(), credential=SimpleNamespace(username="user", password="pass")), original
    )
    assert result["credential_state"] == expected
    assert result["provided_credentials_ok"] is (
        True if expected == "valid" else False if expected == "invalid" else None
    )
    assert "credential_state" not in original
    assert len(requests) == len(answers)
    assert requests[0][:2] == (
        ("POST", "/api/v1/login")
        if product == "minio_console"
        else ("GET", "/db/qa/")
        if product == "mongo_express"
        else ("GET", "/api/security/v1/me")
    )
    if product == "mongo_express":
        assert requests[0][2]["headers"]["Authorization"] == "Basic dXNlcjpwYXNz"
        if len(requests) == 2:
            assert requests[1][2] == {}
    if product == "minio_console" and len(requests) == 2:
        assert requests[1] == ("GET", "/api/v1/session", {"headers": {"Cookie": "sid=1"}})


@pytest.mark.parametrize("accepted", [True, False])
def test_pgadmin_login_escapes_csrf_and_proves_browser_identity(
    monkeypatch: pytest.MonkeyPatch, accepted: bool
) -> None:
    requests: list[str] = []

    class Pool:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def close(self) -> None:
            pass

    def get(_pool: Any, _base: str, path: str, **kwargs: Any) -> HttpResponse:
        requests.append(path)
        if path == "/login":
            return response('<input name="csrf_token" value="a&amp;b">', headers={"Set-Cookie": "pre=1; Path=/"})
        assert kwargs == {"headers": {"Cookie": "session=2"}}
        return response("pgadmin.browser" if accepted else "login_user", final_url="http://panel/browser/")

    def post(_pool: Any, _base: str, path: str, body: bytes, headers: Any) -> HttpResponse:
        requests.append(path)
        assert parse_qs(body.decode()) == {
            "email": ["user"],
            "password": ["pass"],
            "csrf_token": ["a&b"],
            "language": ["en"],
            "internal_button": ["Login"],
        }
        assert headers["Cookie"] == "pre=1"
        return response(
            {}, status=302, headers={"Set-Cookie": "session=2", "Location": "/browser/" if accepted else "/login"}
        )

    monkeypatch.setattr(wp, "HttpSessionPool", Pool)
    monkeypatch.setattr(wp, "_get", get)
    monkeypatch.setattr(wp, "_post", post)
    result = wp.authenticate_panel(
        SimpleNamespace(args=SimpleNamespace(), credential=SimpleNamespace(username="user", password="pass")),
        {"ui_product": "pgadmin", "ui": {"endpoint": "http://panel"}},
    )
    assert result["credential_state"] == ("valid" if accepted else "invalid")
    assert requests == ["/login", "/authenticate/login", "/browser/"]
    if accepted:
        assert result["ui"]["session_cookie"] == "session=2"


async def read_http(wire: bytes) -> direct.AsyncProbe:
    reader = asyncio.StreamReader(limit=200000)
    reader.feed_data(wire)
    reader.feed_eof()
    return await direct._read_http_response(reader, "/fingerprint")


@pytest.mark.parametrize(
    ("wire", "reason"),
    [
        (b"NOTHTTP 200 OK\r\n\r\n", "invalid HTTP status"),
        (b"HTTP/1.1 200 OK\r\nmalformed\r\n\r\n", "invalid HTTP response header"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n", "negative HTTP content length"),
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "invalid chunk size"),
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\naXX", "invalid chunk delimiter"),
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n", "invalid chunk trailer"),
    ],
)
def test_direct_http_rejects_malformed_framing(wire: bytes, reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        asyncio.run(read_http(wire))


@pytest.mark.parametrize(
    "wire",
    [
        b"HTTP/1.1 100 Continue\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\noops",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10001\r\n",
        b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 65537,
    ],
)
def test_direct_http_requests_shared_transport_fallback_for_unverifiable_bodies(wire: bytes) -> None:
    assert asyncio.run(read_http(wire)) == direct.AsyncProbe(path="/fingerprint", fallback=True)


@pytest.mark.parametrize("chunked", [True, False])
def test_direct_http_reads_eof_and_chunk_extensions_with_trailers(chunked: bool) -> None:
    body = (
        b"Transfer-Encoding: chunked\r\n\r\n3;ext=1\r\nabc\r\n0\r\nX-Trace: value\r\n\r\n"
        if chunked
        else b"X-Product: Elastic\r\n\r\nabc"
    )
    answer = asyncio.run(read_http(b"HTTP/1.1 200 OK\r\n" + body))
    assert (answer.path, answer.status, answer.payload, answer.fallback, answer.error) == (
        "/fingerprint",
        200,
        b"abc",
        False,
        None,
    )


def test_direct_transport_returns_none_inside_event_loop_and_skips_non_ascii_path() -> None:
    async def run() -> None:
        assert direct.probe_direct_paths("127.0.0.1", 80, ("/",), "http", 1, None) is None
        assert await direct._probe_one("127.0.0.1", 80, "/é", "http", 1, None) == direct.AsyncProbe(
            path="/é", fallback=True
        )

    asyncio.run(run())


def test_direct_header_budget_and_chunk_line_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(direct, "_MAX_HEADER", 16)
    with pytest.raises(ValueError, match="headers exceed limit"):
        asyncio.run(read_http(b"HTTP/1.1 200 OK\r\nX: long\r\n\r\n"))

    async def read_chunk(wire: bytes) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(wire)
        reader.feed_eof()
        await direct._read_chunked(reader)

    with pytest.raises(ValueError, match="chunk size line"):
        asyncio.run(read_chunk(b"1" * 129 + b"\r\n"))
    with pytest.raises(ValueError, match="chunk trailer"):
        asyncio.run(read_chunk(b"0\r\n" + b"X" * 17 + b"\r\n"))


def test_direct_probe_closes_writer_releases_slot_and_formats_ipv6_default_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    written: list[bytes] = []
    lifecycle: list[str] = []

    class Slots:
        def acquire(self, *, blocking: bool) -> bool:
            assert blocking is False
            return True

        def release(self) -> None:
            lifecycle.append("release")

    class Writer:
        def write(self, data: bytes) -> None:
            written.append(data)

        async def drain(self) -> None:
            lifecycle.append("drain")

        def close(self) -> None:
            lifecycle.append("close")

    async def connect(host: str, port: int, **kwargs: Any) -> tuple[asyncio.StreamReader, Writer]:
        assert (host, port) == ("::1", 80)
        assert kwargs["ssl"] is None
        reader = asyncio.StreamReader()
        reader.feed_data(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        reader.feed_eof()
        return reader, Writer()

    monkeypatch.setattr(direct, "_DIRECT_CONNECTIONS", Slots())
    monkeypatch.setattr(direct.asyncio, "open_connection", connect)
    result = asyncio.run(direct._probe_one("[::1]", 80, "/status", "http", 1, None))
    assert (result.status, result.payload) == (200, b"ok")
    assert written == [
        b"GET /status HTTP/1.1\r\nHost: [::1]\r\nUser-Agent: RedPosture/1.0\r\nConnection: close\r\n\r\n"
    ]
    assert lifecycle == ["drain", "close", "release"]


def test_direct_probe_waits_for_slot_and_falls_back_on_connect_error(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = iter([False, True])
    events: list[Any] = []

    class Slots:
        def acquire(self, *, blocking: bool) -> bool:
            assert blocking is False
            return next(attempts)

        def release(self) -> None:
            events.append("release")

    async def sleep(seconds: float) -> None:
        events.append(seconds)

    async def connect(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("connection refused")

    monkeypatch.setattr(direct, "_DIRECT_CONNECTIONS", Slots())
    monkeypatch.setattr(direct.asyncio, "sleep", sleep)
    monkeypatch.setattr(direct.asyncio, "open_connection", connect)
    assert asyncio.run(direct._probe_one("localhost", 80, "/", "http", 1, None)) == direct.AsyncProbe(
        path="/", fallback=True
    )
    assert events == [0.01, "release"]


@pytest.mark.parametrize(
    "product", ["portainer", "mongo_express", "kibana", "pgadmin", "minio_console", "redis_insight"]
)
def test_missing_credentials_never_start_product_login(monkeypatch: pytest.MonkeyPatch, product: str) -> None:
    def unexpected(**_kwargs: Any) -> None:
        pytest.fail("missing credential must not initialize HTTP session")

    monkeypatch.setattr(wp, "HttpSessionPool", unexpected)
    original = {"ui_product": product, "ui": {"endpoint": "http://panel"}}
    result = wp.authenticate_panel(
        SimpleNamespace(credential=SimpleNamespace(username=None, password="pass")), original
    )
    assert result is original


def test_redis_value_unsupported_type_and_page_limit_are_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    entry = {"database_id": "db", "key": "k", "type": "module-type"}
    assert wp._redis_insight_value(object(), "http://panel", {}, entry, byte_budget=100, deadline=float("inf")) == (
        None,
        "unsupported_type",
        0,
        True,
    )
    monkeypatch.setattr(wp, "_DUMP_ITEMS", 1)
    monkeypatch.setattr(wp, "_post", lambda *_args, **_kwargs: response({"fields": [], "cursor": 2}))
    value, error, used, partial = wp._redis_insight_value(
        object(), "http://panel", {}, {**entry, "type": "hash"}, byte_budget=100, deadline=float("inf")
    )
    assert (value, error, partial) == ([{"fields": [], "cursor": 2}], "page_limit_reached", True)
    assert used == len(json.dumps(value[0]).encode())


def test_download_write_failure_is_reported_without_a_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core import download_paths

    def fail(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(download_paths, "write_unique_file", fail)
    assert wp._write_ui_object("bucket", "key", b"value", endpoint="http://panel") is None


@pytest.mark.parametrize(
    "product,flags",
    [
        ("redis_insight", ["show_keys", "dump"]),
        ("minio_console", ["show_buckets", "show_objects", "dump", "download", "discover"]),
        ("pgadmin", ["show_databases", "show_tables", "show_columns", "dump", "privesc_check"]),
    ],
)
@pytest.mark.parametrize("status", [403, 500])
def test_inventory_root_denials_propagate_to_each_requested_operation(
    monkeypatch: pytest.MonkeyPatch, product: str, flags: list[str], status: int
) -> None:
    paths: list[str] = []
    monkeypatch.setattr(wp, "HttpSessionPool", lambda **_kwargs: SimpleNamespace(close=lambda: None))

    def get(_pool: Any, _base: str, path: str, **_kwargs: Any) -> HttpResponse:
        paths.append(path)
        return response({}, status)

    monkeypatch.setattr(wp, "_get", get)
    args = SimpleNamespace(**dict.fromkeys(flags, True))
    result = wp.enumerate_panel(
        SimpleNamespace(args=args), {"ui_product": product, "ui": {"endpoint": "http://panel"}}
    )["ui"]["inventory"]
    expected = {"status": "access_denied" if status == 403 else "unavailable"}
    assert all(result[flag] == expected for flag in flags)
    assert (
        paths
        == (
            {
                "redis_insight": ["/api/databases"],
                "minio_console": ["/api/v1/buckets"],
                "pgadmin": ["/browser/js/utils.js", "/browser/nodes/"],
            }[product]
        )
    )


@pytest.mark.parametrize("bad_page", [[], [None], {"keys": None}])
def test_redis_inventory_invalid_key_pages_do_not_become_zero_keys(
    monkeypatch: pytest.MonkeyPatch, bad_page: Any
) -> None:
    monkeypatch.setattr(wp, "HttpSessionPool", lambda **_kwargs: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(wp, "_get", lambda *_args, **_kwargs: response([{"id": "db", "name": "qa"}]))
    calls: list[Any] = []

    def post(_pool: Any, _base: str, path: str, body: bytes, _headers: Any, **_kwargs: Any) -> HttpResponse:
        calls.append((path, json.loads(body)))
        return response(bad_page)

    monkeypatch.setattr(wp, "_post", post)
    result = wp.enumerate_panel(
        SimpleNamespace(args=SimpleNamespace(show_keys=True, dump=True)),
        {"ui_product": "redis_insight", "ui": {"endpoint": "http://panel"}},
    )["ui"]["inventory"]
    assert result["show_keys"] == {"status": "unavailable"}
    assert result["dump"] == {"count": 0, "items": [], "records": [], "partial": True}
    assert calls == [("/api/databases/db/keys?encoding=utf8", {"cursor": "0", "count": 100, "keysInfo": True})]


def test_redis_inventory_skips_invalid_connections_and_marks_value_failures_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(wp, "HttpSessionPool", lambda **_kwargs: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(wp, "_get", lambda *_args, **_kwargs: response([None, {"id": 4}, {"id": "db"}]))
    monkeypatch.setattr(
        wp,
        "_post",
        lambda *_args, **_kwargs: response({"keys": [None, {"name": "key", "type": "module-type"}], "cursor": "0"}),
    )
    result = wp.enumerate_panel(
        SimpleNamespace(args=SimpleNamespace(show_keys=True, dump=True)),
        {"ui_product": "redis_insight", "ui": {"endpoint": "http://panel"}},
    )["ui"]["inventory"]
    assert result["show_keys"] == {"count": 1, "items": ["db/key"], "partial": True}
    assert result["dump"] == {
        "count": 1,
        "items": ["key (unsupported_type)"],
        "records": [
            {"database_id": "db", "key": "key", "type": "module-type", "status": "unsupported_type", "partial": True}
        ],
        "partial": True,
    }


@pytest.mark.parametrize("failed_stage", ["database", "schema", "table", "column", "disconnected"])
def test_pgadmin_inventory_distinguishes_inaccessible_backend_from_empty_tables(
    monkeypatch: pytest.MonkeyPatch, failed_stage: str
) -> None:
    monkeypatch.setattr(wp, "HttpSessionPool", lambda **_kwargs: SimpleNamespace(close=lambda: None))
    pages = {
        "/browser/nodes/": [
            {"_type": "other"},
            {"_type": "server_group", "_id": "x"},
            {"_type": "server_group", "_id": 1},
        ],
        "/browser/server/nodes/1/": [
            {"_type": "server", "_id": "bad"},
            {"_type": "server", "_id": 2, "label": "backend"},
        ],
        "/browser/database/nodes/1/2/": [
            {"_type": "other"},
            {"_type": "database", "_id": 3, "label": "qa", "connected": failed_stage != "disconnected"},
        ],
        "/browser/schema/nodes/1/2/3/": [{"_type": "other"}, {"_type": "schema", "_id": 4, "label": "public"}],
        "/browser/table/nodes/1/2/3/4/": [{"_type": "other"}, {"_type": "table", "_id": 5, "label": "orders"}],
        "/browser/column/nodes/1/2/3/4/5/": [],
    }
    paths: list[str] = []

    def get(_pool: Any, _base: str, path: str, **_kwargs: Any) -> HttpResponse:
        paths.append(path)
        if path == "/browser/js/utils.js":
            return response("")
        if path.startswith(f"/browser/{failed_stage}/nodes/"):
            return response({}, 403)
        return response({"success": 1, "data": pages[path]})

    monkeypatch.setattr(wp, "_get", get)
    monkeypatch.setattr(wp, "_pgadmin_view_rows", lambda *_args, **_kwargs: {"status": "access_denied"})
    inventory = wp.enumerate_panel(
        SimpleNamespace(args=SimpleNamespace(show_databases=True, show_tables=True, show_columns=True, dump=True)),
        {"ui_product": "pgadmin", "ui": {"endpoint": "http://panel"}},
    )["ui"]["inventory"]
    assert inventory["servers"] == {"count": 2, "items": ["backend"]}
    if failed_stage == "database":
        assert inventory["show_databases"] == {"status": "backend_not_connected"}
    else:
        assert inventory["show_databases"] == {"count": 1, "items": ["backend/qa"]}
    if failed_stage in {"database", "disconnected"}:
        assert inventory["show_tables"] == {"status": "backend_not_connected"}
        assert inventory["dump"] == {"status": "backend_not_connected"}
    else:
        assert inventory["dump"] == {"count": 0, "items": [], "records": [], "partial": True}
        assert inventory["show_tables"]["count"] == (1 if failed_stage == "column" else 0)
    assert inventory["show_columns"] == (
        {"status": "backend_not_connected"}
        if failed_stage in {"database", "disconnected"}
        else {"count": 0, "items": []}
    )
    assert paths[-1] == (
        "/browser/database/nodes/1/2/"
        if failed_stage in {"database", "disconnected"}
        else f"/browser/{failed_stage}/nodes/"
        + {"schema": "1/2/3/", "table": "1/2/3/4/", "column": "1/2/3/4/5/"}[failed_stage]
    )


@pytest.mark.parametrize(
    ("product", "child_key", "parent_key", "entry", "expected"),
    [
        (
            "mongo_express",
            "show_collections",
            "show_databases",
            {"collection": "qa/orders", "content": '{"id":1}'},
            'qa/orders "{\\"id\\":1}"',
        ),
        (
            "pgadmin",
            "show_tables",
            "show_databases",
            {"table": "qa/orders", "row": [1, "paid"]},
            'qa/orders [1, "paid"]',
        ),
        (
            "redis_insight",
            "show_keys",
            None,
            {"key": "orders", "value": {"value": "secret"}},
            'orders = {"value": "secret"}',
        ),
        (
            "redis_insight",
            "show_keys",
            None,
            {"key": "orders", "status": "unsupported_type"},
            "orders (unsupported_type)",
        ),
        (
            "minio_console",
            "show_objects",
            "show_buckets",
            {"object": "qa/orders", "base64": "AP8="},
            "qa/orders base64:AP8=",
        ),
    ],
)
def test_grouped_render_preserves_values_unmatched_rows_partial_reasons_and_no_ansi(
    product: str, child_key: str, parent_key: str | None, entry: Any, expected: str
) -> None:
    inventory: dict[str, Any] = {
        child_key: {
            "count": 2,
            "items": ["qa/orders", "unmatched/child"],
            "partial": True,
            "reason": "denied\nnext\x1b[31m",
        },
        "dump": {"count": 2, "records": [None, entry], "partial": True},
    }
    if parent_key:
        inventory[parent_key] = {"count": 2, "items": ["qa", "empty"]}
    lines, consumed = wp._render_grouped_panel_inventory("MODULE\thost\t1\t", product, inventory)
    assert consumed == {child_key, "dump"} | ({parent_key} if parent_key else set())
    shown = "\n".join(lines)
    assert expected in shown
    assert "unmatched/child" in shown
    assert shown.count(expected) == 1
    assert "coverage:partial (reason:denied\\nnext)" in shown
    assert "\x1b" not in shown
    assert len([line for line in lines if "Enumeration (count:" in line]) == len(consumed)


@pytest.mark.parametrize(
    "inventory",
    [
        {"show_keys": {}},
        {"show_keys": {"count": 1, "items": []}},
        {"show_keys": {"count": 1, "items": []}, "connections": {}},
        {"show_tables": {"count": 0, "items": []}, "show_databases": {"status": "unavailable"}},
    ],
)
def test_grouped_render_falls_back_when_hierarchy_cannot_be_proven(inventory: Any) -> None:
    product = "pgadmin" if "show_tables" in inventory else "redis_insight"
    lines, consumed = wp._render_grouped_panel_inventory("prefix", product, inventory)
    if product == "pgadmin":
        assert consumed == {"show_tables"}
        assert lines == ["prefix [*] Show Tables Enumeration (count:0)"]
    else:
        assert (lines, consumed) == ([], set())


def test_render_credential_attempts_deduplicate_and_show_lockout_once() -> None:
    attempts = [
        None,
        {"username": "user", "password": "pass", "credential_state": "valid"},
        {"username": "user", "password": "pass", "credential_state": "valid"},
        {"username": "other", "password": "wrong", "credential_state": "invalid"},
        {"username": "skip", "credential_state": "unverified"},
        {"credential_state": "account_locked"},
        {"credential_state": "captcha"},
    ]
    rows = wp.render_panel(
        {
            "host": "host",
            "port": 1,
            "ui_product": "postgrest",
            "ui": {"anonymous_read": True},
            "attempted_credentials": attempts,
        },
        "POSTGRES",
    )
    assert rows == [
        "POSTGRES\thost\t1\t [*] PostgREST (auth required:unknown) (version:unknown) (UI)",
        "POSTGRES\thost\t1\t [+] Anonymous READ available through PostgREST",
        "POSTGRES\thost\t1\t [+] user:pass (UI)",
        "POSTGRES\thost\t1\t [-] other:wrong (UI)",
        "POSTGRES\thost\t1\t [!] Credential attempts stopped: panel rate limit or lockout",
    ]


@pytest.mark.parametrize(
    "line",
    [
        "MOD\thost\t1\t [+] user:pass",
        "MOD\thost\t1\t [+] apikey auth",
        "MOD\thost\t1\t [+] token auth",
        "MOD\thost\t1\t [*] unrelated",
    ],
)
def test_panel_colorizer_leaves_backend_credentials_to_backend(line: str) -> None:
    assert wp.colorize_panel_line(object(), line, "MOD") is False


@pytest.mark.parametrize("answer", [response({}, 500), response({"jwt": "token"}), response({}, 429)])
def test_portainer_login_token_needs_verified_matching_identity(
    monkeypatch: pytest.MonkeyPatch, answer: HttpResponse
) -> None:
    monkeypatch.setattr(wp, "HttpSessionPool", lambda **_kwargs: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(wp, "_post", lambda *_args: response({"jwt": "token"}))
    calls: list[Any] = []

    def get(_pool: Any, _base: str, path: str, **kwargs: Any) -> HttpResponse:
        calls.append((path, kwargs))
        return answer

    monkeypatch.setattr(wp, "_get", get)
    result = wp.authenticate_panel(
        SimpleNamespace(args=SimpleNamespace(), credential=SimpleNamespace(username="user", password="pass")),
        {"ui_product": "portainer", "ui": {"endpoint": "http://panel"}},
    )
    assert result["credential_state"] == ("rate_limited" if answer.status == 429 else "unverified")
    assert calls == [("/api/users/me", {"headers": {"Authorization": "Bearer token"}})]
    assert "session_token" not in result["ui"]


@pytest.mark.parametrize("token", ["", "bad token", "é", "bad\x7f", "x" * 16385])
def test_portainer_token_validation_does_not_send_malformed_authorization(
    monkeypatch: pytest.MonkeyPatch, token: str
) -> None:
    def unexpected(**_kwargs: Any) -> None:
        pytest.fail("invalid token must not initialize HTTP session")

    monkeypatch.setattr(wp, "HttpSessionPool", unexpected)
    result = wp.authenticate_portainer_token(SimpleNamespace(), {"ui": {"endpoint": "http://panel"}}, token)
    assert result["credential_state"] == "unverified"
    assert result["ui"]["credential_proof"] == "Portainer token format is invalid"


@pytest.mark.parametrize(
    "bad_list",
    [
        {},
        {"objects": [None, {}, {"name": ""}]},
        {"objects": [], "isTruncated": True},
        {"objects": [{"name": "a"}], "nextMarker": "same"},
    ],
)
def test_minio_bounded_listing_marks_malformed_or_stalled_pages_partial(
    monkeypatch: pytest.MonkeyPatch, bad_list: Any
) -> None:
    monkeypatch.setattr(wp, "HttpSessionPool", lambda **_kwargs: SimpleNamespace(close=lambda: None))
    paths: list[str] = []

    def get(_pool: Any, _base: str, path: str, **_kwargs: Any) -> HttpResponse:
        paths.append(path)
        return response({"buckets": [{"name": "qa"}]}) if path == "/api/v1/buckets" else response(bad_list)

    monkeypatch.setattr(wp, "_get", get)
    result = wp.enumerate_panel(
        SimpleNamespace(args=SimpleNamespace(show_objects=True, dump=True)),
        {"ui_product": "minio_console", "ui": {"endpoint": "http://panel"}},
    )["ui"]["inventory"]
    assert result["dump"]["partial"] is True
    if "nextMarker" in bad_list:
        assert paths[2] == "/api/v1/buckets/qa/objects?limit=10001&marker=same"
        assert result["show_objects"] == {"count": 1, "items": ["qa/a"], "partial": True}
    else:
        assert result["show_objects"] == {"status": "unavailable"}
        assert result["dump"]["count"] == 0


@pytest.mark.parametrize("listing_failed", [True, False])
def test_minio_discovery_adapter_forwards_range_and_preserves_partial_listing(
    monkeypatch: pytest.MonkeyPatch, listing_failed: bool
) -> None:
    from redposture_core.modules.minio import discover

    monkeypatch.setattr(wp, "HttpSessionPool", lambda **_kwargs: SimpleNamespace(close=lambda: None))
    requests: list[Any] = []

    def get(_pool: Any, _base: str, path: str, **kwargs: Any) -> HttpResponse:
        requests.append((path, kwargs))
        if path == "/api/v1/buckets":
            return response({"buckets": [{"name": "qa"}]})
        if "/objects?" in path:
            return response({"objects": [{"name": "secret.env", "size": 8}, *([None] if listing_failed else [])]})
        assert path == "/api/v1/buckets/qa/objects/download?prefix=secret.env"
        return HttpResponse(status=200, body=b"content", headers={"Content-Type": "text/plain"})

    def scan(reader: Any, objects: Any, *, budget: Any) -> Any:
        targets = list(objects)
        assert [(obj.bucket, obj.key) for obj in targets] == [("qa", "secret.env")]
        assert budget.max_total_bytes == 123
        first = reader.get_object_range("qa", "secret.env", start=0, length=4)
        second = reader.get_object_range("qa", "secret.env", start=4, length=4)
        assert first.transport_error is None
        assert second.transport_error == "Console ignored object range"
        assert (second.http_status, second.body) == (200, b"content")
        return discover.DiscoverResult(
            findings=[{"bucket": "qa", "key": "secret.env", "type": "password", "masked_value": "se***"}],
            objects_scanned=1,
            bytes_read=7,
        )

    monkeypatch.setattr(wp, "_get", get)
    monkeypatch.setattr(discover, "discover_secrets", scan)
    result = wp.enumerate_panel(
        SimpleNamespace(args=SimpleNamespace(discover=True, discover_max_bytes=123)),
        {"ui_product": "minio_console", "ui": {"endpoint": "http://panel", "session_cookie": "sid=1"}},
    )["ui"]["inventory"]["discover"]
    assert result["count"] == 1
    assert result["items"] == ["qa/secret.env password se***"]
    assert (result["bytes_read"], result["objects_scanned"], result["partial"]) == (7, 1, listing_failed)
    assert result["partial_reasons"] == (["listing_incomplete"] if listing_failed else [])
    assert requests[-2][1] == {"headers": {"Cookie": "sid=1", "Range": "bytes=0-3"}, "response_size_cap": 4}
    assert requests[-1][1] == {"headers": {"Cookie": "sid=1", "Range": "bytes=4-7"}, "response_size_cap": 4}


@pytest.mark.parametrize("mode", ["failed-download", "binary-download", "failed-write", "budget"])
def test_minio_dump_and_download_outcomes_keep_binary_content_and_failures_explicit(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    monkeypatch.setattr(wp, "HttpSessionPool", lambda **_kwargs: SimpleNamespace(close=lambda: None))
    calls: list[str] = []

    def get(_pool: Any, _base: str, path: str, **_kwargs: Any) -> HttpResponse:
        calls.append(path)
        if path == "/api/v1/buckets":
            return response({"buckets": [{"name": "qa"}]})
        if "/objects?" in path:
            return response({"objects": [{"name": "file", "size": 2}]})
        return HttpResponse(status=403 if mode == "failed-download" else 200, body=b"\x00\xff", headers={})

    writes: list[Any] = []

    def write(*args: Any, **kwargs: Any) -> str | None:
        writes.append((args, kwargs))
        return None if mode == "failed-write" else "saved.bin"

    monkeypatch.setattr(wp, "_get", get)
    monkeypatch.setattr(wp, "_write_ui_object", write)
    if mode == "budget":
        monkeypatch.setattr(wp, "_DUMP_BYTES", 0)
    inventory = wp.enumerate_panel(
        SimpleNamespace(args=SimpleNamespace(dump=True, download=True)),
        {"ui_product": "minio_console", "ui": {"endpoint": "http://panel"}},
    )["ui"]["inventory"]
    assert inventory["dump"]["partial"] is (mode != "binary-download")
    assert inventory["download"]["partial"] is (mode != "binary-download")
    assert inventory["dump"]["records"] == (
        [] if mode in {"failed-download", "budget"} else [{"object": "qa/file", "base64": "AP8="}]
    )
    assert inventory["download"]["records"] == (
        [{"object": "qa/file", "path": "saved.bin", "size": 2}] if mode == "binary-download" else []
    )
    assert len(writes) == (1 if mode in {"binary-download", "failed-write"} else 0)
    assert len(calls) == (2 if mode == "budget" else 3)


@pytest.mark.parametrize(
    "mode", ["start", "poll-malformed", "poll-error", "poll-busy", "window-malformed", "window-empty"]
)
def test_pgadmin_bounded_cursor_handles_read_failure_and_always_closes(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    monkeypatch.setattr(wp.secrets, "randbelow", lambda _limit: 9)
    monkeypatch.setattr(wp, "_post", lambda *_args: response({"success": 1}))
    sleeps: list[float] = []
    monkeypatch.setattr(wp.time, "sleep", sleeps.append)
    paths: list[str] = []

    def get(_pool: Any, _base: str, path: str, **_kwargs: Any) -> HttpResponse:
        paths.append(path)
        if "/start/" in path:
            return response({"success": 0 if mode == "start" else 1})
        if "/fetch_window/" in path:
            return response({"data": {"result": []}} if mode == "window-empty" else {})
        return response(
            {}
            if mode == "poll-malformed"
            else {
                "data": {
                    "status": "Error" if mode == "poll-error" else "Busy" if mode == "poll-busy" else "Success",
                    "result": [[1]],
                    "pagination": {"next_page": True},
                }
            }
        )

    class Pool:
        def request_once(self, method: str, url: str, **kwargs: Any) -> None:
            assert (method, url) == ("DELETE", "http://panel/sqleditor/close/10")
            assert kwargs == {"headers": {}, "response_size_cap": 4096}
            paths.append("closed")
            raise OSError("cleanup unavailable")

    monkeypatch.setattr(wp, "_get", get)
    result = wp._pgadmin_view_rows(Pool(), "http://panel", {}, 1, 2, 3, 4, limit=5)
    if mode.startswith("window-"):
        assert result == {"count": 1, "items": ["[1]"], "records": [[1]], "partial": True, "bytes_read": 3}
        assert paths[-2] == "/sqleditor/fetch_window/10/2/5"
    else:
        assert result == {"status": "timeout" if mode == "poll-busy" else "unavailable"}
    assert paths[-1] == "closed"
    assert len(sleeps) == (10 if mode == "poll-busy" else 0)
