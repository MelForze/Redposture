"""Stored dashboard/config exports are not datasource queries or alert tests."""

from types import SimpleNamespace
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core.modules.grafana import actions, discover
from tests.test_docker_discover import Pool


@pytest.fixture
def context(monkeypatch):
    Pool.calls = []
    Pool.routes = {
        "/api/search": (200, [{"uid": "qa"}]),
        "/api/dashboards/uid/qa": (200, {"dashboard": {"description": "password=inactive-dashboard!42"}}),
        "/api/datasources": (
            200,
            [{"uid": "ds1", "secureJsonFields": {"basicAuthPassword": True}, "jsonData": {"oauthPassThru": False}}],
        ),
        "/api/v1/provisioning/contact-points/export": (
            200,
            {"contactPoints": [{"receivers": [{"settings": {"password": "inactive-contact!42"}}]}]},
        ),
        "/api/v1/provisioning/alert-rules": (200, []),
    }
    state = actions.GrafanaLifecycleState(
        http=cast(Any, Pool()), auth_header="Basic fixture", host="qa.invalid", port=3000, scheme="http"
    )
    monkeypatch.setattr(actions._THREAD_LOCAL_HTTP, "state", state, raising=False)
    return SimpleNamespace(
        host="qa.invalid", port=3000, lifecycle_state=state, args=SimpleNamespace(timeout=1, discover_time=30)
    )


def run(ctx):
    return discover.discover(ctx, {"status": "valid_credentials", "provided_credentials_ok": True})


def test_dashboard_and_contact_export_no_masked_datasource_value(context):
    report = run(context)
    assert report["status"] == "complete" and report["scope"] == "current organization"
    assert {str(f["value"]) for f in report["findings"]} == {"inactive-dashboard!42", "inactive-contact!42"}
    assert all(s["read"] and s["complete"] for s in report["sources"])
    assert not any("/query" in path or "/test" in path for path in Pool.calls)


def test_viewer_keeps_dashboard_findings_but_reports_denied_contact_secrets(context):
    Pool.routes["/api/v1/provisioning/contact-points/export"] = (403, {"password": "not-readable-error"})
    report = run(context)
    assert report["status"] == "partial"
    assert {str(f["value"]) for f in report["findings"]} == {"inactive-dashboard!42"}
    assert next(s for s in report["sources"] if s["id"] == "grafana.contact_points")["denied"] == 1


@pytest.mark.parametrize("repeat", [False, True])
def test_dashboard_catalog_pagination_and_repeated_page(context, monkeypatch, repeat):
    monkeypatch.setattr(discover, "_PAGE_SIZE", 2)
    original = context.lifecycle_state.http.request_stream
    pages = []

    def request(method, url, **kwargs):
        if urlsplit(url).path == "/api/search":
            page = int(parse_qs(urlsplit(url).query)["page"][0])
            pages.append(page)
            Pool.routes["/api/search"] = (200, [{"uid": "qa"}, {"uid": "two"}] if page == 1 or repeat else [])
        return original(method, url, **kwargs)

    context.lifecycle_state.http.request_stream = request
    Pool.routes["/api/dashboards/uid/two"] = (200, {"dashboard": {"title": "Public dashboard"}})
    report = run(context)
    assert pages == [1, 2]
    assert report["status"] == ("partial" if repeat else "complete")
    assert Pool.calls.count("/api/dashboards/uid/qa") == Pool.calls.count("/api/dashboards/uid/two") == 1


def test_unverified_access_never_reads_configuration(context):
    report = discover.discover(context, {"status": "detected"})
    assert report["status"] == "partial" and not report["findings"] and not Pool.calls


def test_discovery_does_not_first_materialize_capped_datasource_inventory(context, monkeypatch):
    context.args.discover = True
    calls = []
    context.emit_ready_inventory = lambda record: calls.append("enum")
    monkeypatch.setattr(actions, "_fetch_datasources", lambda *a, **kw: pytest.fail("capped duplicate source read"))
    real = discover.discover

    def checked(ctx, record):
        calls.append("discover")
        return real(ctx, record)

    monkeypatch.setattr(discover, "discover", checked)
    result = actions.collect_grafana_data(
        context,
        {"status": "valid_credentials", "provided_credentials_ok": True},
        {"show_datasources": False, "check_urls": []},
    )
    assert result["content_discovery"]["status"] == "complete"
    assert calls == ["enum", "discover"]
