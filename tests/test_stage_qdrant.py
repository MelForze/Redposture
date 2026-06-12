from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

from redposture_core import stage_qdrant as qdrant
from tests.stage_runtime_helpers import patch_runner_for_legacy_target_fake, run_module_targets_for_test


def test_inline_and_json_compact_helpers() -> None:
    assert qdrant._normalize_inline_text("a\n  b\t c") == "a b c"
    assert qdrant._json_compact({"a": 1, "b": 2}) == '{"a":1,"b":2}'


def test_clip_retry_and_timeout_fail_record_helpers() -> None:
    assert qdrant._clip("abcdef", 3) == "abc"
    assert qdrant._retry_delay(0) == pytest.approx(0.20)
    assert qdrant._retry_delay(12) == pytest.approx(1.50)

    assert qdrant._is_connection_timeout_fail_record({"status": "fail", "error": "connection timeout"})
    assert qdrant._is_connection_timeout_fail_record(
        {
            "status": "fail",
            "error": "connection refused (service is not listening on target port)",
        }
    )
    assert not qdrant._is_connection_timeout_fail_record({"status": "open_no_auth", "error": "connection timeout"})


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("[Errno 111] Connection refused", "connection refused (service is not listening on target port)"),
        ("timed out", "connection timeout"),
        ("Name or service not known", "dns lookup failed"),
        ("Temporary failure in name resolution", "dns lookup temporary failure"),
        ("operation not permitted", "operation not permitted by local environment"),
    ],
)
def test_friendly_error_text_mappings(raw: str, expected: str) -> None:
    assert qdrant._friendly_error_text(raw) == expected


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


def test_qdrant_error_and_response_helpers_cover_extra_shapes() -> None:
    assert qdrant._qdrant_error_text({"message": "  bad\tmessage  "}) == "bad message"
    assert qdrant._qdrant_error_text([{"a": 1}]) == '[{"a":1}]'
    assert qdrant._qdrant_error_text("", fallback_status=404) is None

    assert qdrant._qdrant_looks_like_response({"result": {}, "status": "ok"}) is True
    assert qdrant._qdrant_looks_like_response({"status": {"error": "forbidden"}}) is True
    assert qdrant._qdrant_looks_like_response({"hello": "world"}) is False


def test_qdrant_collections_from_payload_deduplicates() -> None:
    payload = {"result": {"collections": [{"name": "a"}, {"name": "a"}, {"name": "b"}]}}
    assert qdrant._qdrant_collections_from_payload(payload) == ["a", "b"]


def test_qdrant_lab_seed_is_fail_fast_and_verifies_collections(lab_full_compose_path: Path) -> None:
    compose = lab_full_compose_path.read_text(encoding="utf-8")
    seed_block = compose.split("  qdrant-seed:", 1)[1].split("  elastic-open:", 1)[0]

    assert ">/dev/null || true" not in seed_block
    assert "redposture-qdrant-seed-ready" in seed_block
    assert "require_points" in seed_block
    assert 'require_collection "demo_vectors"' in seed_block
    assert 'require_collection "audit_logs"' in seed_block
    assert 'require_collection "service_inventory"' in seed_block
    assert 'require_points "demo_vectors"' in seed_block
    assert 'require_points "audit_logs"' in seed_block
    assert 'require_points "service_inventory"' in seed_block


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
    def fake_root(*_args, headers=None, **_kwargs):
        if headers is None:
            return 401, {"status": {"error": "forbidden"}}, None
        return 200, {"version": "1.16.0"}, None

    def fake_collections(*_args, headers=None, **_kwargs):
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


def test_qdrant_ssrf_capture_listener_start_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FailServer:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise OSError("address already in use")

    monkeypatch.setattr(qdrant, "_QdrantSsrfCaptureServer", _FailServer)
    listener = qdrant._start_qdrant_ssrf_capture_listener(19001)
    assert listener["started"] is False
    assert "address already in use" in str(listener["error"])


def test_format_detail_records_error_and_ssrf_failure_paths() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 6333,
        "show_collections": True,
        "dump": True,
        "collection_name": "alpha",
        "collections_source": "anonymous",
        "collections_count": None,
        "collections": None,
        "collections_list_error": "forbidden",
        "collection_dump_items": [{"name": "alpha", "ok": False, "status": 403, "error": "forbidden"}],
        "collection_dump_error": "dump blocked",
        "ssrf_requested": True,
        "ssrf_collection": "alpha",
        "ssrf_error": "listener unavailable",
        "ssrf_results": None,
        "edit_probe": None,
        "ghsa_f632_vm87_2m2f": None,
        "logger_probe": None,
    }
    lines = qdrant._format_detail_records(record, "txt", debug=False)
    text = "\n".join(lines)
    assert "collections unavailable err=forbidden" in text
    assert "dump unavailable err=dump blocked" in text
    assert "collection dump failed name=alpha status=403 err=forbidden" in text
    assert "ssrf probe unavailable err=listener unavailable" in text

    json_lines = qdrant._format_detail_records(record, "json", debug=False)
    payload_types = {json.loads(line).get("type") for line in json_lines}
    assert {"collections_list", "collections_dump", "ssrf_snapshot_recover"} <= payload_types


def test_merge_stage2_record_merges_debug_and_stage_metadata() -> None:
    detect = {
        "status": "open_no_auth",
        "debug_events": ["d1"],
        "debug_events_streamed": False,
        "stages": [{"stage_name": "detect_protocol", "result": "ok"}],
        "stage_durations_ms": {"detect_protocol": 5},
        "stage_attempts": {"detect_protocol": 2},
        "stage_failed_at": None,
    }
    deep = {
        "collections_count": 1,
        "debug_events": ["d2"],
        "debug_events_streamed": True,
        "stages": [{"stage_name": "data", "result": "ok"}],
        "stage_durations_ms": {"data": 12},
        "stage_attempts": {"data": 2},
        "stage_failed_at": "data",
    }
    merged = qdrant._merge_stage2_record(detect, deep)
    assert merged["collections_count"] == 1
    assert merged["debug_events"] == ["d1", "d2"]
    assert merged["debug_events_streamed"] is True
    assert merged["stage_durations_ms"] == {"detect_protocol": 5, "data": 12}
    assert merged["stage_attempts"] == {"detect_protocol": 2, "data": 2}
    assert merged["stage_failed_at"] == "data"


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
    totals = run_module_targets_for_test(
        "qdrant",
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


def test_audit_qdrant_targets_emits_stage_debug_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, bool, bool, str | None, tuple[str, ...] | None]] = []

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
        _ = (port, timeout, retries, api_key)
        calls.append((host, show_collections, dump_requested, collection_name, tuple(ssrf_urls or [])))
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": host,
            "port": 6333,
            "is_qdrant": True,
            "status": "open_no_auth",
            "auth_required": False,
            "anonymous_access": True,
            "version": "1.15.0",
            "collections_count": 0,
            "show_collections": show_collections,
            "dump": dump_requested,
            "collections": [],
            "error": None,
        }

    monkeypatch.setattr(qdrant, "_audit_qdrant_host", fake_audit)
    debug_lines: list[str] = []
    totals = run_module_targets_for_test(
        "qdrant",
        hosts=["127.0.0.1"],
        port=6333,
        timeout=1.0,
        retries=0,
        workers=1,
        api_key=None,
        show_collections=True,
        dump_requested=True,
        collection_name="metrics",
        ssrf_urls=["http://127.0.0.1:18080/hit"],
        output_path=None,
        output_format="txt",
        debug=True,
        emit_line=None,
        logger=None,
        append_output=False,
        suppress_timeout_status_lines=False,
        debug_emit=debug_lines.append,
        show_progress=False,
    )
    assert totals == (1, 1, 0, 0, 0)
    assert calls == [
        ("127.0.0.1", False, False, None, ()),
        ("127.0.0.1", True, True, "metrics", ("http://127.0.0.1:18080/hit",)),
    ]
    assert any(line.startswith("pass=1 detect start total=1") for line in debug_lines)
    assert any("stage2_gate=run reason=status=open_no_auth" in line for line in debug_lines)
    assert any("pass=2 deep complete processed=1" in line for line in debug_lines)


def test_render_colored_qdrant_line_covers_marker_spans() -> None:
    class _FakeConsole:
        def __init__(self) -> None:
            self.lines: list[str] = []

        def _paint(self, text: str, color: str, _stream) -> str:
            return f"<{color}>{text}</{color}>"

        def plain(self, message: str) -> None:
            self.lines.append(message)

    console = _FakeConsole()
    assert qdrant._render_colored_qdrant_line(console, "hello") is False
    line = "QDRANT  \t127.0.0.1\t6333\t [+] anonymous access (auth required:False) (collections:3) (idor:true) RCE!"
    assert qdrant._render_colored_qdrant_line(console, line) is True
    assert console.lines
    rendered = console.lines[-1]
    assert "<white>anonymous access (</white><red>auth required:False</red>" in rendered
    assert "<red>collections:3</red>" in rendered
    assert "<red>idor:true</red>" in rendered
    assert "<orange>RCE!</orange>" in rendered


def test_call_audit_qdrant_host_with_stage_debug_fail_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        qdrant,
        "_audit_qdrant_host",
        lambda *_args, **_kwargs: {
            "timestamp": "2026-01-01T00:00:00Z",
            "host": "127.0.0.1",
            "port": 6333,
            "is_qdrant": False,
            "status": "fail",
            "error": "connection timeout",
        },
    )
    events: list[str] = []
    record = qdrant._call_audit_qdrant_host_with_stage_debug(
        "127.0.0.1",
        6333,
        1.0,
        1,
        api_key=None,
        show_collections=False,
        dump_requested=False,
        collection_name=None,
        ssrf_urls=None,
        run_deep_checks=False,
        debug=True,
        debug_emit=events.append,
    )
    assert record["stage_failed_at"] == "detect_protocol"
    assert record["debug_events_streamed"] is True
    assert isinstance(record.get("stages"), list) and record["stages"]
    assert any("retry_decision stage=detect_protocol" in item for item in events)
    assert any("stage_timing_summary status=fail" in item for item in events)


def test_run_qdrant_stage_ssrf_listener_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeConsole:
        def __init__(self, debug: bool = False) -> None:
            self.debug = debug
            self.errors: list[str] = []
            self.warns: list[str] = []
            self.infos: list[str] = []
            self.lines: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

        def warn(self, message: str) -> None:
            self.warns.append(message)

        def info(self, message: str) -> None:
            self.infos.append(message)

        def plain(self, message: str, color: str | None = None) -> None:
            _ = color
            self.lines.append(message)

        def _paint(self, text: str, _color: str, _stream) -> str:
            return text

        def render_tagged_payload_line(self, *_args: object, **_kwargs: object) -> bool:
            return False

    fake_console = _FakeConsole(debug=True)
    monkeypatch.setattr(qdrant, "Console", lambda debug=False: fake_console)
    monkeypatch.setattr(
        qdrant,
        "collect_scan_ports",
        lambda raw=None: [18080] if str(raw or "") == "18080" else [6333],
    )
    monkeypatch.setattr(
        qdrant,
        "collect_scan_target_specs",
        lambda *_args, **_kwargs: [SimpleNamespace(host="127.0.0.1", scheme=None, explicit_port=None)],
    )
    monkeypatch.setattr(
        qdrant,
        "build_scan_execution_groups",
        lambda *_args, **_kwargs: [SimpleNamespace(hosts=["127.0.0.1"], port=6333)],
    )
    monkeypatch.setattr(
        qdrant,
        "_normalize_ssrf_urls",
        lambda *_args, **_kwargs: ["http://127.0.0.1:18080/debug/vars"],
    )
    patch_runner_for_legacy_target_fake(
        monkeypatch,
        "qdrant",
        lambda *_args, **_kwargs: (1, 1, 0, 0, 0),
    )
    monkeypatch.setattr(
        qdrant,
        "_start_qdrant_ssrf_capture_listener",
        lambda port: {"started": True, "port": int(port), "server": object(), "thread": object(), "hits": []},
    )
    monkeypatch.setattr(qdrant, "_stop_qdrant_ssrf_capture_listener", lambda _listener: None)
    monkeypatch.setattr(
        qdrant,
        "_qdrant_ssrf_capture_hits",
        lambda _listener: [
            {
                "method": "GET",
                "path": "/debug/vars",
                "client_host": "127.0.0.1",
                "client_port": 1111,
                "host": "127.0.0.1:18080",
                "user_agent": "curl/8.0",
                "content_length": 12,
                "body_preview": "probe=1",
                "raw_request": "GET /debug/vars HTTP/1.1\nHost: 127.0.0.1:18080",
            }
        ],
    )

    args = SimpleNamespace(
        debug=True,
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
        collection="metrics",
        ssrf_target="127.0.0.1",
        ssrf_port="18080",
        ssrf_path="/debug/vars",
        ssrf_listen=True,
        api_key=None,
    )
    rc = qdrant.run_qdrant_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 0
    assert not fake_console.errors
    assert any("local SSRF listener started" in item for item in fake_console.infos)
    assert any("qdrant audit complete:" in item for item in fake_console.infos)


def test_run_qdrant_stage_multi_instance_uses_single_global_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeConsole:
        def __init__(self, debug: bool = False) -> None:
            self.debug = debug
            self.errors: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

        def warn(self, _message: str) -> None:
            return

        def info(self, _message: str) -> None:
            return

        def plain(self, _message: str, color: str | None = None) -> None:
            _ = color
            return

        def _paint(self, text: str, _color: str, _stream) -> str:
            return text

        def render_tagged_payload_line(self, *_args: object, **_kwargs: object) -> bool:
            return False

    fake_console = _FakeConsole()
    monkeypatch.setattr(qdrant, "Console", lambda debug=False: fake_console)
    monkeypatch.setattr(qdrant, "collect_scan_ports", lambda *_a, **_k: [6333, 26333, 26334])
    monkeypatch.setattr(
        qdrant,
        "collect_scan_target_specs",
        lambda *_a, **_k: [SimpleNamespace(host="127.0.0.1", scheme=None, explicit_port=None)],
    )
    monkeypatch.setattr(
        qdrant,
        "build_scan_execution_groups",
        lambda *_a, **_k: [
            SimpleNamespace(hosts=["127.0.0.1"], port=6333, scheme_hint=None),
            SimpleNamespace(hosts=["127.0.0.1"], port=26333, scheme_hint=None),
            SimpleNamespace(hosts=["127.0.0.1"], port=26334, scheme_hint=None),
        ],
    )

    calls: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):
        calls.append(kwargs)
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        kwargs["emit_line"]("QDRANT\t127.0.0.1\t6333\t[*] Qdrant Service")
        return (1, 1, 0, 0, 0)

    patch_runner_for_legacy_target_fake(monkeypatch, "qdrant", fake_audit_targets)

    args = SimpleNamespace(
        debug=False,
        timeout=1.0,
        retries=0,
        workers=1,
        output=None,
        output_format="txt",
        port=6333,
        ports="6333,26333,26334",
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        show_collections=True,
        dump=False,
        collection=None,
        ssrf_target=None,
        ssrf_port=None,
        ssrf_path=None,
        ssrf_listen=False,
        api_key=None,
    )
    rc = qdrant.run_qdrant_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 0
    assert not fake_console.errors
    assert [bool(call["show_progress"]) for call in calls] == [False, False, False]


def test_run_qdrant_stage_ssrf_url_parse_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeConsole:
        def __init__(self, debug: bool = False) -> None:
            self.debug = debug
            self.errors: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

        def warn(self, _message: str) -> None:
            return

        def info(self, _message: str) -> None:
            return

        def plain(self, _message: str, color: str | None = None) -> None:
            _ = color
            return

        def render_tagged_payload_line(self, *_args: object, **_kwargs: object) -> bool:
            return False

    fake_console = _FakeConsole()
    monkeypatch.setattr(qdrant, "Console", lambda debug=False: fake_console)
    monkeypatch.setattr(qdrant, "collect_scan_ports", lambda *_a, **_k: [6333])
    monkeypatch.setattr(
        qdrant,
        "collect_scan_target_specs",
        lambda *_a, **_k: [SimpleNamespace(host="127.0.0.1", scheme=None, explicit_port=None)],
    )
    monkeypatch.setattr(
        qdrant,
        "build_scan_execution_groups",
        lambda *_a, **_k: [SimpleNamespace(hosts=["127.0.0.1"], port=6333)],
    )

    args = SimpleNamespace(
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
        collection="metrics",
        ssrf_target="127.0.0.1",
        ssrf_port="18080",
        ssrf_path="/debug/vars",
        ssrf_listen=False,
        api_key=None,
    )

    monkeypatch.setattr(qdrant, "_normalize_ssrf_urls", lambda *_a, **_k: (_ for _ in ()).throw(ValueError("bad")))
    rc = qdrant.run_qdrant_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 2
    assert any("failed to parse SSRF targets/ports: bad" in item for item in fake_console.errors)

    fake_console.errors.clear()
    monkeypatch.setattr(qdrant, "_normalize_ssrf_urls", lambda *_a, **_k: [])
    rc = qdrant.run_qdrant_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 2
    assert any("failed to build SSRF URLs" in item for item in fake_console.errors)


def test_run_qdrant_stage_rejects_https_url_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeConsole:
        def __init__(self, debug: bool = False) -> None:
            _ = debug
            self.errors: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

        def warn(self, _message: str) -> None:
            return

        def info(self, _message: str) -> None:
            return

        def plain(self, _message: str, color: str | None = None) -> None:
            _ = color
            return

        def render_tagged_payload_line(self, *_args: object, **_kwargs: object) -> bool:
            return False

    fake_console = _FakeConsole()
    monkeypatch.setattr(qdrant, "Console", lambda debug=False: fake_console)
    monkeypatch.setattr(qdrant, "collect_scan_ports", lambda *_a, **_k: [6333])
    monkeypatch.setattr(
        qdrant,
        "collect_scan_target_specs",
        lambda *_a, **_k: [SimpleNamespace(host="api.example.local", scheme="https", explicit_port=6333)],
    )

    args = SimpleNamespace(
        timeout=1.0,
        retries=0,
        workers=1,
        output=None,
        output_format="txt",
        port=6333,
        ports=None,
        targets="https://api.example.local:6333",
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
        debug=False,
    )

    rc = qdrant.run_qdrant_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 2
    assert any("accepts only http:// URL targets" in msg for msg in fake_console.errors)
