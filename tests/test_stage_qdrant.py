from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from types import SimpleNamespace

import pytest

from redposture_core import stage_qdrant as qdrant


def test_inline_and_json_compact_helpers() -> None:
    assert qdrant._normalize_inline_text("a\n  b\t c") == "a b c"
    assert qdrant._json_compact({"a": 1, "b": 2}) == '{"a":1,"b":2}'


def test_qdrant_headers_and_version_extraction() -> None:
    assert qdrant._qdrant_headers(None) is None
    assert qdrant._qdrant_headers(" key ") == {"api-key": "key"}

    assert qdrant._qdrant_extract_version({"version": "1.15.0"}) == "1.15.0"
    assert qdrant._qdrant_extract_version({"result": {"version": "1.14.0"}}) == "1.14.0"
    assert qdrant._qdrant_extract_version({}) is None


@pytest.mark.parametrize(
    ("raw", "parsed"),
    [
        ("1.15.2", (1, 15, 2)),
        ("v1.9.3", (1, 9, 3)),
        ("bad", None),
    ],
)
def test_parse_semver_triplet(raw: str, parsed: tuple[int, int, int] | None) -> None:
    assert qdrant._parse_semver_triplet(raw) == parsed


def test_semver_in_half_open_range() -> None:
    assert qdrant._semver_in_half_open_range((1, 10, 0), min_incl=(1, 9, 3), max_excl=(1, 15, 6)) is True
    assert qdrant._semver_in_half_open_range((1, 15, 6), min_incl=(1, 9, 3), max_excl=(1, 15, 6)) is False
    assert qdrant._semver_in_half_open_range(None, min_incl=(1, 9, 3), max_excl=(1, 15, 6)) is None


def test_qdrant_payload_helpers() -> None:
    assert qdrant._qdrant_is_root_payload({"title": "Qdrant - Vector DB"}) is True
    assert qdrant._qdrant_is_root_payload({"version": "1.0", "result": {}}) is True
    assert qdrant._qdrant_is_root_payload({"hello": "world"}) is False

    assert qdrant._qdrant_error_text({"status": {"error": " failed  reason "}}) == "failed reason"
    assert qdrant._qdrant_error_text("  timeout \n now ") == "timeout now"
    assert qdrant._qdrant_error_text(None, fallback_status=500) == "status=500"


def test_qdrant_collections_from_payload_deduplicates() -> None:
    payload = {"result": {"collections": [{"name": "a"}, {"name": "a"}, {"name": "b"}]}}
    assert qdrant._qdrant_collections_from_payload(payload) == ["a", "b"]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/a/b?x=1", ("/a/b", "x=1")),
        ("a/b", ("/a/b", "")),
        ("http://host/x?y=2", ("/x", "y=2")),
    ],
)
def test_normalize_ssrf_path(raw: str, expected: tuple[str, str]) -> None:
    assert qdrant._normalize_ssrf_path(raw) == expected


def test_normalize_ssrf_urls_builds_expected_urls() -> None:
    urls = qdrant._normalize_ssrf_urls("127.0.0.1", "6333,6334", "/metrics?x=1")
    assert urls == [
        "http://127.0.0.1:6333/metrics?x=1",
        "http://127.0.0.1:6334/metrics?x=1",
    ]


def test_normalize_ssrf_urls_returns_empty_on_invalid_path() -> None:
    assert qdrant._normalize_ssrf_urls("127.0.0.1", "6333", "http://[::1") == []


def test_format_detect_and_summary_records() -> None:
    detect = qdrant._format_detect_record(
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "host": "127.0.0.1",
            "port": 6333,
            "is_qdrant": True,
            "version": "1.15.0",
            "auth_required": False,
            "anonymous_access": True,
        },
        "txt",
    )
    assert "[*] Qdrant API" in detect
    assert "(auth required:False)" in detect

    open_line = qdrant._format_record(
        {
            "host": "127.0.0.1",
            "port": 6333,
            "status": "open_no_auth",
            "collections_count": 2,
            "edit_probe": {"source": "anonymous", "ok": True},
            "ghsa_f632_vm87_2m2f": {"assessment": "potentially_vulnerable"},
        },
        "txt",
    )
    assert "[+] anonymous access" in open_line
    assert "RCE!" in open_line

    auth_line = qdrant._format_record(
        {
            "host": "127.0.0.1",
            "port": 6333,
            "status": "auth_required",
            "collections_list_error": "forbidden",
        },
        "txt",
    )
    assert "[-] authentication required for collections" in auth_line
    assert "err=forbidden" in auth_line

    fail_line = qdrant._format_record(
        {"host": "127.0.0.1", "port": 6333, "status": "fail", "error": "connection timeout"},
        "txt",
    )
    assert "[!] connection failed" in fail_line


def test_audit_qdrant_host_open_access_dump_and_ssrf(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        qdrant,
        "_qdrant_get_root_info",
        lambda *_args, **_kwargs: (200, {"title": "Qdrant - Vector Search Engine", "version": "1.15.2"}, None),
    )
    monkeypatch.setattr(
        qdrant,
        "_qdrant_get_collections",
        lambda *_args, **_kwargs: (
            200,
            {"status": "ok", "result": {"collections": [{"name": "alpha"}, {"name": "beta"}]}},
            None,
        ),
    )
    monkeypatch.setattr(
        qdrant,
        "_qdrant_get_collection_info",
        lambda *_args, **_kwargs: (200, {"result": {"vectors_count": 10}}, None),
    )
    monkeypatch.setattr(
        qdrant,
        "_qdrant_edit_probe_empty_patch",
        lambda *_args, **_kwargs: {"ok": True, "collection": "alpha", "status": 200},
    )
    monkeypatch.setattr(
        qdrant,
        "_qdrant_logger_endpoint_probe",
        lambda *_args, **_kwargs: {"ok": True, "status": 200, "response_raw": '{"result":"ok"}'},
    )
    monkeypatch.setattr(
        qdrant,
        "_qdrant_assess_ghsa_f632_vm87_2m2f",
        lambda **_kwargs: {
            "marker": "[!]",
            "assessment": "potentially_vulnerable",
            "version_affected": True,
            "logger_reachable": True,
            "logger_status": 200,
        },
    )
    monkeypatch.setattr(
        qdrant,
        "_qdrant_ssrf_snapshot_recover_probe",
        lambda *_args, **_kwargs: {
            "target_url": _args[4],
            "ok": True,
            "status": 200,
            "response_raw": '{"snapshot":"ok"}',
        },
    )

    record = qdrant._audit_qdrant_host(
        "127.0.0.1",
        6333,
        1.0,
        0,
        api_key=None,
        show_collections=True,
        dump_requested=True,
        collection_name="alpha",
        ssrf_urls=["http://127.0.0.1:9100/metrics"],
    )

    assert record["status"] == "open_no_auth"
    assert record["collections_count"] == 2
    assert record["collections_source"] == "anonymous"
    assert record["collection_dump_items"][0]["ok"] is True
    assert record["edit_probe"]["source"] == "anonymous"
    assert record["ghsa_f632_vm87_2m2f"]["assessment"] == "potentially_vulnerable"
    assert record["ssrf_results"][0]["ok"] is True

    text_lines = qdrant._format_detail_records(record, "txt", debug=True)
    text = "\n".join(text_lines)
    assert "[*] Collections (count:2) (source:anonymous)" in text
    assert "[*] Collections Dump (name:alpha)" in text
    assert "[+] update probe accepted" in text
    assert "GHSA-f632-vm87-2m2f" in text
    assert "[*] Snapshot-recover SSRF" in text

    json_payloads = [json.loads(item) for item in qdrant._format_detail_records(record, "json", debug=True)]
    assert {item["type"] for item in json_payloads} == {
        "collections_list",
        "collections_dump",
        "edit_probe",
        "vuln_check",
        "ssrf_snapshot_recover",
    }


def test_audit_qdrant_host_uses_api_key_when_anonymous_is_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_root(*_args, headers=None, **_kwargs):  # type: ignore[no-untyped-def]
        if headers is None:
            return 401, {"status": {"error": "forbidden"}}, None
        return 200, {"version": "1.16.0"}, None

    def fake_collections(*_args, headers=None, **_kwargs):  # type: ignore[no-untyped-def]
        if headers is None:
            return 403, {"status": {"error": "forbidden"}}, None
        return 200, {"result": {"collections": [{"name": "secret"}]}}, None

    monkeypatch.setattr(qdrant, "_qdrant_get_root_info", fake_root)
    monkeypatch.setattr(qdrant, "_qdrant_get_collections", fake_collections)
    monkeypatch.setattr(
        qdrant,
        "_qdrant_edit_probe_empty_patch",
        lambda *_args, **_kwargs: {"ok": False, "validation_only": True, "collection": "secret", "status": 400},
    )
    monkeypatch.setattr(
        qdrant,
        "_qdrant_logger_endpoint_probe",
        lambda *_args, **_kwargs: {"ok": False, "status": 403, "response_raw": ""},
    )
    monkeypatch.setattr(
        qdrant,
        "_qdrant_assess_ghsa_f632_vm87_2m2f",
        lambda **_kwargs: {
            "marker": "[*]",
            "assessment": "not_affected",
            "version_affected": False,
            "logger_reachable": False,
        },
    )

    record = qdrant._audit_qdrant_host(
        "127.0.0.1",
        6333,
        1.0,
        0,
        api_key="secret-key",
        show_collections=True,
        dump_requested=False,
        collection_name=None,
        ssrf_urls=None,
    )

    assert record["status"] == "open_auth"
    assert record["auth_required"] is True
    assert record["api_key_access"] is True
    assert record["collections_source"] == "api_key"
    assert record["edit_probe"]["source"] == "api_key"
    text = "\n".join(qdrant._format_detail_records(record, "txt", debug=True))
    assert "(source:api_key)" in text
    assert "update probe reached endpoint" in text


def test_audit_qdrant_host_marks_non_qdrant_services(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(qdrant, "_qdrant_get_root_info", lambda *_args, **_kwargs: (200, {"hello": "world"}, None))
    monkeypatch.setattr(qdrant, "_qdrant_get_collections", lambda *_args, **_kwargs: (200, {"hello": "world"}, None))

    record = qdrant._audit_qdrant_host(
        "127.0.0.1",
        6333,
        1.0,
        0,
        api_key=None,
        show_collections=False,
        dump_requested=False,
        collection_name=None,
        ssrf_urls=None,
    )

    assert record["is_qdrant"] is False
    assert record["error"] == "service is not qdrant"


def test_audit_qdrant_host_retries_and_returns_fail_record(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        qdrant,
        "_qdrant_get_root_info",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("connection refused")),
    )
    monkeypatch.setattr(qdrant, "_retry_delay", lambda _attempt: 0.0)

    record = qdrant._audit_qdrant_host(
        "127.0.0.1",
        6333,
        1.0,
        1,
        api_key=None,
        show_collections=False,
        dump_requested=False,
        collection_name=None,
        ssrf_urls=None,
    )

    assert record["status"] == "fail"
    assert "connection refused" in str(record["error"])


def test_http_json_request_handles_success_http_error_and_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeResponse:
        def __init__(self, status: int, body: bytes) -> None:
            self.status = status
            self._body = body

        def read(self) -> bytes:
            return self._body

        def __enter__(self) -> _FakeResponse:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(urllib.request, "urlopen", lambda *_args, **_kwargs: _FakeResponse(200, b'{"ok":1}'))
    status, payload, error = qdrant._http_json_request("127.0.0.1", 6333, "GET", "/", 1.0)
    assert (status, payload, error) == (200, {"ok": 1}, None)

    monkeypatch.setattr(urllib.request, "urlopen", lambda *_args, **_kwargs: _FakeResponse(200, b"plain text"))
    status, payload, error = qdrant._http_json_request("127.0.0.1", 6333, "GET", "/", 1.0)
    assert (status, payload, error) == (200, "plain text", None)

    def _raise_http_error(*_args: object, **_kwargs: object) -> object:
        raise urllib.error.HTTPError(
            "http://127.0.0.1:6333/",
            403,
            "forbidden",
            {},
            io.BytesIO(b'{"error":"forbidden"}'),
        )

    monkeypatch.setattr(urllib.request, "urlopen", _raise_http_error)
    status, payload, error = qdrant._http_json_request("127.0.0.1", 6333, "GET", "/", 1.0)
    assert (status, payload, error) == (403, {"error": "forbidden"}, None)

    monkeypatch.setattr(urllib.request, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError()))
    status, payload, error = qdrant._http_json_request("127.0.0.1", 6333, "GET", "/", 1.0)
    assert status == 0
    assert payload is None
    assert "connection timeout" in str(error)


def test_qdrant_probe_helpers_and_root_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []

    def fake_http_json_request(
        host: str,
        port: int,
        method: str,
        path: str,
        timeout: float,
        *,
        headers: dict[str, str] | None = None,
        payload: dict[str, object] | None = None,
    ) -> tuple[int, object, str | None]:
        calls.append((method, path))
        _ = (host, port, timeout, headers, payload)
        if path == "/":
            return 404, {"status": {"error": "not found"}}, None
        if path == "/service/info":
            return 200, {"version": "1.15.0", "result": {}}, None
        if path == "/collections/demo":
            return 200, {"result": {"name": "demo"}}, None
        if path == "/collections/demo%2Fprod":
            return 200, {"result": {"name": "demo/prod"}}, None
        return 500, {"error": "unexpected"}, None

    monkeypatch.setattr(qdrant, "_http_json_request", fake_http_json_request)

    status, payload, error = qdrant._qdrant_get_root_info("127.0.0.1", 6333, 1.0)
    assert (status, payload, error) == (200, {"version": "1.15.0", "result": {}}, None)
    assert calls[:2] == [("GET", "/"), ("GET", "/service/info")]

    qdrant._qdrant_get_collection_info("127.0.0.1", 6333, 1.0, "demo")
    qdrant._qdrant_get_collection_info("127.0.0.1", 6333, 1.0, "demo/prod")
    assert ("GET", "/collections/demo") in calls
    assert ("GET", "/collections/demo%2Fprod") in calls


def test_qdrant_edit_logger_ssrf_and_assessment_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        qdrant,
        "_http_json_request",
        lambda *_args, **_kwargs: (422, {"status": {"error": "invalid payload"}}, None),
    )
    edit_result = qdrant._qdrant_edit_probe_empty_patch("127.0.0.1", 6333, 1.0, "demo")
    assert edit_result["reachable"] is True
    assert edit_result["validation_only"] is True
    assert edit_result["error"] == "invalid payload"

    monkeypatch.setattr(
        qdrant,
        "_http_json_request",
        lambda *_args, **_kwargs: (403, {"error": "forbidden"}, None),
    )
    logger_result = qdrant._qdrant_logger_endpoint_probe("127.0.0.1", 6333, 1.0)
    assert logger_result["blocked"] is True
    assert logger_result["ok"] is False
    assert logger_result["error"] == "forbidden"

    monkeypatch.setattr(
        qdrant,
        "_http_json_request",
        lambda *_args, **_kwargs: (200, {"result": "ok"}, None),
    )
    ssrf_result = qdrant._qdrant_ssrf_snapshot_recover_probe(
        "127.0.0.1",
        6333,
        1.0,
        "demo",
        "http://127.0.0.1:9100/metrics",
    )
    assert ssrf_result["ok"] is True
    assert ssrf_result["status"] == 200

    not_affected = qdrant._qdrant_assess_ghsa_f632_vm87_2m2f(version="1.15.6", logger_probe=None)
    assert not_affected["assessment"] == "not_affected_version"
    assert not_affected["marker"] == "[*]"

    vulnerable = qdrant._qdrant_assess_ghsa_f632_vm87_2m2f(
        version="1.15.5",
        logger_probe={"reachable": True, "blocked": False, "status": 200},
    )
    assert vulnerable["assessment"] == "potentially_vulnerable"
    assert vulnerable["marker"] == "[+]"

    blocked = qdrant._qdrant_assess_ghsa_f632_vm87_2m2f(
        version="1.15.5",
        logger_probe={"reachable": False, "blocked": True, "status": 403, "error": "forbidden"},
    )
    assert blocked["assessment"] == "logger_endpoint_blocked"
    assert blocked["marker"] == "[-]"


def test_qdrant_ssrf_capture_listener_records_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeServer:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self.server_address = ("127.0.0.1", 19000)
            self.closed = False
            self.stopped = False

        def serve_forever(self) -> None:
            return

        def shutdown(self) -> None:
            self.stopped = True

        def server_close(self) -> None:
            self.closed = True

    class _FakeThread:
        def __init__(self, target: object, daemon: bool, name: str) -> None:
            self.target = target
            self.daemon = daemon
            self.name = name
            self.started = False
            self.joined = False

        def start(self) -> None:
            self.started = True

        def join(self, timeout: float | None = None) -> None:
            _ = timeout
            self.joined = True

    monkeypatch.setattr(qdrant, "_QdrantSsrfCaptureServer", _FakeServer)
    monkeypatch.setattr(qdrant.threading, "Thread", _FakeThread)

    listener = qdrant._start_qdrant_ssrf_capture_listener(19000)
    assert listener["started"] is True
    server = listener["server"]
    assert server is not None
    listener["hits"].append({"method": "GET", "path": "/debug/vars?full=1"})
    hits = qdrant._qdrant_ssrf_capture_hits(listener)
    assert hits == [{"method": "GET", "path": "/debug/vars?full=1"}]
    qdrant._stop_qdrant_ssrf_capture_listener(listener)
    assert server.stopped is True
    assert server.closed is True
    assert listener["thread"].joined is True


def test_audit_qdrant_targets_and_run_stage_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory
) -> None:
    emitted: list[str] = []
    logged: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def fake_audit(
        host: str,
        port: int,
        timeout: float,
        retries: int,
        *,
        api_key: str | None,
        show_collections: bool,
        dump_requested: bool,
        collection_name: str | None,
        ssrf_urls: list[str] | None,
    ) -> dict[str, object]:
        _ = (timeout, retries, api_key, show_collections, dump_requested, collection_name, ssrf_urls)
        if host == "127.0.0.1":
            return {
                "timestamp": "2026-03-27T00:00:00Z",
                "host": host,
                "port": port,
                "is_qdrant": True,
                "status": "open_no_auth",
                "auth_required": False,
                "anonymous_access": True,
                "version": "1.15.0",
                "collections_count": 1,
                "show_collections": False,
                "dump": False,
                "error": None,
            }
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": host,
            "port": port,
            "is_qdrant": False,
            "status": "fail",
            "auth_required": None,
            "anonymous_access": None,
            "version": None,
            "collections_count": None,
            "show_collections": False,
            "dump": False,
            "error": "connection timeout",
        }

    monkeypatch.setattr(qdrant, "_audit_qdrant_host", fake_audit)
    output_path = tmp_path / "qdrant.txt"
    totals = qdrant.audit_qdrant_targets(
        hosts=["127.0.0.1", "127.0.0.2"],
        port=6333,
        timeout=1.0,
        retries=0,
        workers=2,
        api_key=None,
        show_collections=False,
        dump_requested=False,
        collection_name=None,
        ssrf_urls=None,
        output_path=str(output_path),
        output_format="txt",
        debug=False,
        emit_line=emitted.append,
        logger=SimpleNamespace(log=lambda *a, **k: logged.append((a, k))),
        suppress_timeout_status_lines=True,
    )
    assert totals == (2, 1, 0, 0, 1)
    assert any("Qdrant API" in line for line in emitted)
    assert not any("connection failed" in line for line in emitted)
    assert output_path.read_text(encoding="utf-8")
    assert len(logged) == 2

    class _FakeConsole:
        def __init__(self, debug: bool = False) -> None:
            self.debug = debug
            self.errors: list[str] = []
            self.warns: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

        def warn(self, message: str) -> None:
            self.warns.append(message)

        def info(self, _message: str) -> None:
            return

        def plain(self, _message: str, color: str | None = None) -> None:
            _ = color
            return

        def render_tagged_payload_line(self, *_args: object, **_kwargs: object) -> bool:
            return False

    fake_console = _FakeConsole()
    monkeypatch.setattr(qdrant, "Console", lambda debug=False: fake_console)
    monkeypatch.setattr(qdrant, "collect_scan_ports", lambda *_args, **_kwargs: [6333])
    monkeypatch.setattr(qdrant, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

    base_args = dict(
        debug=False,
        timeout=1.0,
        retries=0,
        workers=1,
        output=None,
        output_format="txt",
        port=6333,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        show_collections=False,
        dump=False,
        collection=None,
        ssrf_target=None,
        ssrf_port=None,
        ssrf_path=None,
        ssrf_listen=False,
        api_key=None,
    )

    rc = qdrant.run_qdrant_stage(
        SimpleNamespace(**{**base_args, "ssrf_listen": True}), logger=SimpleNamespace(log=lambda *_a, **_k: None)
    )
    assert rc == 2
    assert any("--listen requires --ssrf-target" in message for message in fake_console.errors)

    fake_console.errors.clear()
    rc = qdrant.run_qdrant_stage(
        SimpleNamespace(**{**base_args, "ssrf_target": "127.0.0.1", "ssrf_port": "9100"}),
        logger=SimpleNamespace(log=lambda *_a, **_k: None),
    )
    assert rc == 2
    assert any("requires --collection" in message for message in fake_console.errors)
