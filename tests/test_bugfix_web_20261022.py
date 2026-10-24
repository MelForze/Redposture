"""Regressions for malformed UI export pages and Consul Basic evidence."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core import web_panel_export as export
from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.consul import actions as consul
from redposture_core.modules.consul.stage import _build_consul_host_stage_options
from redposture_core.ui_export import UIExport


def _response(value: Any) -> HttpResponse:
    return HttpResponse(status=200, body=json.dumps(value).encode(), headers={})


def _export_context(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Any, list[UIExport], list[str]]:
    monkeypatch.chdir(tmp_path)
    writers: list[UIExport] = []
    closed: list[str] = []

    def writer(*args: Any, **kwargs: Any) -> UIExport:
        result = UIExport(*args, **kwargs)
        writers.append(result)
        return result

    monkeypatch.setattr(export, "UIExport", writer)
    monkeypatch.setattr(export, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: closed.append("pool")))
    return SimpleNamespace(args=SimpleNamespace()), writers, closed


@pytest.mark.parametrize("product", ["kibana", "opensearch_dashboards"])
@pytest.mark.parametrize("bad", [None, False, 7, "hit", {}])
def test_elastic_malformed_tail_saves_valid_prefix_and_closes_export(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, product: str, bad: Any
) -> None:
    ctx, writers, closed = _export_context(monkeypatch, tmp_path)
    answers = iter(
        [
            _response([{"index": "orders"}]),
            _response({"_scroll_id": "first", "hits": {"hits": [{"_id": "1", "_source": {"name": "saved"}}]}}),
            _response({"_scroll_id": "second", "hits": {"hits": [{"_id": "2"}, bad]}}),
        ]
    )
    monkeypatch.setattr(export.wp, "_post", lambda *a, **kw: next(answers))
    result = export.export_panel(ctx, {"ui_product": product, "ui": {"endpoint": "http://qa"}}, {"documents"})
    outcome = result["ui"]["inventory"]["export"]
    assert outcome["partial"] is True and "invalid hit" in outcome["reason"]
    rows = [json.loads(line) for line in Path(outcome["path"]).read_text().splitlines()]
    assert outcome["count"] == 3
    assert [row["value"]["hit"]["_id"] for row in rows if row["collection"] == "documents"] == ["1", "2"]
    assert closed == ["pool"]
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        writers[0].connection.execute("SELECT 1")
    assert "\x1b" not in Path(outcome["path"]).read_text()
    answers = iter(
        [
            _response([{"index": "orders"}]),
            _response({"_scroll_id": "retry", "hits": {"hits": [{"_id": "1"}, {"_id": "2"}, {"_id": "3"}]}}),
            _response({"_scroll_id": "done", "hits": {"hits": []}}),
        ]
    )
    resumed = export.export_panel(ctx, {"ui_product": product, "ui": {"endpoint": "http://qa"}}, {"documents"})
    complete = resumed["ui"]["inventory"]["export"]
    assert complete["partial"] is False and complete["count"] == 4
    assert complete["path"] == outcome["path"]
    assert closed == ["pool", "pool"]


@pytest.mark.parametrize("empty", [None, []])
def test_minio_empty_bucket_preserves_earlier_data_and_completes_later_bucket(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, empty: Any
) -> None:
    ctx, writers, closed = _export_context(monkeypatch, tmp_path)

    def get(_pool: Any, _base: str, path: str, _headers: Any) -> HttpResponse:
        if path == "/api/v1/buckets":
            return _response({"buckets": [{"name": "before"}, {"name": "empty"}, {"name": "after"}]})
        if "/empty/" in path:
            return _response({"objects": empty})
        assert "/before/" in path or "/after/" in path
        return _response({"objects": [{"name": "report.json", "size": 1}]})

    monkeypatch.setattr(export, "_get", get)
    result = export.export_panel(ctx, {"ui_product": "minio_console", "ui": {"endpoint": "http://qa"}}, {"objects"})
    outcome = result["ui"]["inventory"]["export"]
    assert outcome["partial"] is False and outcome["reason"] is None
    rows = [json.loads(line) for line in Path(outcome["path"]).read_text().splitlines()]
    assert outcome["count"] == 5
    assert [row["value"]["object"] for row in rows if row["collection"] == "objects"] == [
        "before/report.json",
        "after/report.json",
    ]
    assert closed == ["pool"]
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        writers[0].connection.execute("SELECT 1")
    assert "\x1b" not in Path(outcome["path"]).read_text()


@pytest.mark.parametrize("probe", ["scope", "self"])
@pytest.mark.parametrize(
    ("response", "expected_ok", "expected_verdict"),
    [
        ((0, None, "timeout", False, False), None, None),
        ((503, None, None, False, False), None, None),
        ((200, None, None, False, False), None, None),
        ((401, None, "truncated response", False, False), None, None),
        ((401, None, None, False, False), False, True),
        ((403, None, None, False, False), False, True),
        ((200, {}, None, False, False), True, None),
    ],
)
def test_consul_basic_requires_explicit_denial_and_never_invents_invalidity(
    monkeypatch: pytest.MonkeyPatch, probe: str, response: tuple[Any, ...], expected_ok: Any, expected_verdict: Any
) -> None:
    monkeypatch.setattr(consul._THREAD_LOCAL_LIFECYCLE, "state", None, raising=False)
    monkeypatch.setattr(consul, "_consul_get_json_any", lambda *a, **kw: response)
    if probe == "scope":
        baseline = consul._scope_probe(
            "qa", 8500, "/v1/catalog/services", 1, scheme="http", insecure=False, count_fn=consul._count_services
        )
    else:
        baseline = consul._agent_self_probe("qa", 8500, 1, scheme="http", insecure=False)
    assert baseline["ok"] is expected_ok
    success = {"ok": True, "status": 200, "count": 0}
    for authenticated in [success, {"ok": False, "status": 403}, {"ok": None, "status": 503}]:
        verdict = (
            consul._basic_credential_verdict({"services": baseline}, {"services": authenticated}, {}, {})
            if probe == "scope"
            else consul._basic_credential_verdict({}, {}, baseline, authenticated)
        )
        assert verdict is (expected_verdict if authenticated is success else None)


@pytest.mark.parametrize("baseline", [{"ok": False}, {"ok": False, "status": 503}, {"ok": None, "status": 403}])
def test_consul_basic_unknown_or_missing_denial_proof_remains_unverified(baseline: dict[str, Any]) -> None:
    assert consul._basic_credential_verdict({"kv": baseline}, {"kv": {"ok": True}}, baseline, {"ok": True}) is None


@pytest.mark.parametrize("anonymous", ["timeout", "server", "malformed", "public", "denied"])
def test_consul_lifecycle_recovery_only_confirms_basic_after_denial(
    monkeypatch: pytest.MonkeyPatch, anonymous: str
) -> None:
    monkeypatch.setattr(consul, "_probe_consul_scheme", lambda *a, **kw: (True, "http", False, False, "leader", None))

    def request(_host: str, _port: int, path: str, _timeout: float, **kwargs: Any) -> Any:
        if not kwargs.get("headers") and anonymous != "public":
            return {
                "timeout": (0, None, "timeout", False, False),
                "server": (503, None, None, False, False),
                "malformed": (200, None, None, False, False),
                "denied": (403, None, None, False, False),
            }[anonymous]
        return (200, {} if path in {"/v1/catalog/services", "/v1/agent/self"} else [], None, False, False)

    monkeypatch.setattr(consul, "_consul_get_json_any", request)
    state = consul.ConsulLifecycleState()
    ctx = SimpleNamespace(
        host="qa",
        port=8500,
        args=SimpleNamespace(timeout=0.1, retries=0),
        target=None,
        lifecycle_state=state,
        debug_emit=None,
        credential=SimpleNamespace(username="ignored", password="pair", token=None, source="provided"),
    )
    options = _build_consul_host_stage_options(ctx.args)
    detected = consul.detect_consul(ctx, options)
    record = consul.authenticate_consul(ctx, detected, options)
    assert record["auth_valid"] is (True if anonymous == "denied" else None)
    assert record["status"] == ("valid_credentials" if anonymous == "denied" else "unknown_auth")
    if anonymous != "denied":
        assert "unverified" in consul._auth_summary_line(record)
        assert "failed" not in consul._auth_summary_line(record)
    state.close()
