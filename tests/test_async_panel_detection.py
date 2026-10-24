"""UI fingerprints/access probes share their decision tree with native async."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from redposture_core import web_panels
from redposture_core.detection_steps import run_async_requests
from tests.test_web_panels import _FIXTURES, _response


@pytest.mark.parametrize("fixture", list(_FIXTURES) + ["kubeapi"])
@pytest.mark.parametrize("denied", [False, True])
def test_panel_record_and_request_options_match(monkeypatch, fixture, denied):
    module = "elastic" if fixture.startswith("elastic_") else fixture
    routes = _FIXTURES.get(fixture, {"/": _response(200, "<title>Kubernetes Dashboard</title><kd-root></kd-root>")})
    calls = []

    def get(_pool, base, path, **options):
        calls.append((base, path, options))
        return routes.get(path, _response(401 if denied else 200, []))

    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(
        host="127.0.0.1",
        port=8080,
        args=SimpleNamespace(timeout=2),
        target=SimpleNamespace(scheme="http", path="/tenant", explicit_port=8080),
    )
    expected = web_panels.detect_panel(module, ctx, report_failure=True)
    expected_calls = calls[:]
    calls.clear()

    async def send(base, path, options=None):
        return get(None, base, path, **(options or {}))

    got = asyncio.run(run_async_requests(web_panels.panel_requests(module, ctx, report_failure=True), send))
    assert got == expected
    assert calls == expected_calls
    assert got["is_ui"] is True
    assert got["ui"]["endpoint"] == "http://127.0.0.1:8080/tenant"


@pytest.mark.parametrize("hint", [None, "ui", "backend"])
@pytest.mark.parametrize("backend_hit", [False, True])
@pytest.mark.parametrize("panel_hit", [False, True])
def test_runtime_surface_order_is_shared(monkeypatch, hint, backend_hit, panel_hit):
    from redposture_core.audit_models import AuditRecord
    from redposture_core.stage_runtime import AuditCommandRunner, ModuleAuditSpec

    calls = []
    backend = AuditRecord(
        host="127.0.0.1",
        port=9200,
        service="elastic",
        module="elastic",
        status="open_no_auth" if backend_hit else "not_service",
        extra={"is_elastic": backend_hit},
    )
    panel = (
        {
            "host": "127.0.0.1",
            "port": 9200,
            "service": "elastic",
            "status": "open_no_auth",
            "surface": "ui",
            "is_ui": True,
        }
        if panel_hit
        else None
    )

    def sync(ctx):
        calls.append("backend")
        return backend

    async def native(ctx, http):
        calls.append("backend")
        return backend

    def ui(module, ctx):
        calls.append("panel")
        return panel

    async def ui_native(module, ctx, http):
        return ui(module, ctx)

    monkeypatch.setattr(web_panels, "detect_panel", ui)
    monkeypatch.setattr(web_panels, "detect_panel_async", ui_native, raising=False)
    runner = AuditCommandRunner(
        args=SimpleNamespace(),
        spec=ModuleAuditSpec(module="elastic", label="ELASTIC", default_port=9200, detect=sync, detect_async=native),
        emit_line=lambda _: None,
    )
    ctx = SimpleNamespace(host="127.0.0.1", port=9200, target=SimpleNamespace(surface_hint=hint, scheme="http"))
    expected = runner._detect(ctx)
    expected_calls = calls[:]
    calls.clear()
    got = asyncio.run(runner._detect_async(ctx, object()))
    assert got == expected
    assert calls == expected_calls


@pytest.mark.parametrize("hint", [None, "ui", "backend"])
@pytest.mark.parametrize("backend_hit", [False, True])
@pytest.mark.parametrize("panel_hit", [False, True])
def test_host_stage_only_specs_preserve_surface_order_and_monolithic_batching(
    monkeypatch, hint, backend_hit, panel_hit
):
    from redposture_core.audit_models import AuditRecord
    from redposture_core.stage_runtime import AuditCommandRunner, AuditCredentialRun, AuditHookContext, ModuleAuditSpec

    calls = []
    backend = AuditRecord(
        host="127.0.0.1",
        port=27017,
        module="mongodb",
        service="mongodb",
        status="open_no_auth" if backend_hit else "not_service",
        extra={"is_mongodb": backend_hit},
    )
    panel = (
        {
            "host": "127.0.0.1",
            "port": 27017,
            "service": "mongodb",
            "status": "unknown_auth",
            "surface": "ui",
            "is_ui": True,
            "ui": {"product": "mongo_express"},
        }
        if panel_hit
        else None
    )

    def host_stage(host, port, timeout, run_deep_checks=False):
        calls.append("backend")
        return backend

    async def native(ctx, http):
        calls.append("backend")
        return backend

    def ui(module, ctx):
        calls.append("panel")
        return None if panel is None else {**panel, "ui": dict(panel["ui"])}

    async def async_ui(module, ctx, http):
        return ui(module, ctx)

    monkeypatch.setattr(web_panels, "detect_panel", ui)
    monkeypatch.setattr(web_panels, "detect_panel_async", async_ui)
    spec = ModuleAuditSpec(
        module="mongodb",
        label="MONGODB",
        default_port=27017,
        host_stage=host_stage,
        detect_async=native,
        is_detected=lambda r: r.extra.get("is_mongodb") is True,
    )
    args = SimpleNamespace(timeout=1, retries=0)
    runner = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _: None)
    assert runner._host_stage_is_monolithic
    ctx = AuditHookContext(
        args=args,
        host="127.0.0.1",
        port=27017,
        logger=None,
        credential=AuditCredentialRun(source="anonymous"),
        target=SimpleNamespace(surface_hint=hint, scheme="http"),
    )
    expected = runner._detect(ctx)
    expected_calls = calls[:]
    calls.clear()
    got = asyncio.run(runner._detect_async(ctx, object()))
    assert got == expected
    assert calls == expected_calls
