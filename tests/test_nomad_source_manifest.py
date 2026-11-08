"""Nomad job catalogs and full job specifications have independent ACLs."""

from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.nomad import actions


@pytest.mark.parametrize("denied", [None, "catalog", "spec"])
def test_catalog_and_selected_job_content_report_actual_access(denied):
    calls = []

    class Pool:
        def request(self, method, url, **kwargs):
            assert method == "GET"
            path = urlsplit(url).path
            calls.append(path)
            kind = "catalog" if path == "/v1/jobs" else "spec"
            data = (
                [{"ID": "app", "Namespace": "default"}]
                if kind == "catalog"
                else {"ID": "app", "Meta": {"password": "inactive-spec!42"}}
            )
            return HttpResponse(403 if kind == denied else 200, json.dumps(data).encode(), {})

    ctx = SimpleNamespace(
        host="qa",
        port=4646,
        args=SimpleNamespace(discover=True, discover_time=30),
        credential=None,
        lifecycle_state=SimpleNamespace(http=Pool()),
    )
    result = actions.data_record(ctx, {"api_endpoint": "http://qa", "status": "open_no_auth"})["content_discovery"]
    rows = {r["id"]: r for r in result["sources"]}
    if denied != "catalog":
        assert rows["nomad.job_catalog_pages"]["read"] == 1
        assert rows["nomad.job_specs"]["read"] == int(denied is None)
        assert rows["nomad.job_specs"]["complete"] == (denied is None)
    if denied:
        row = rows["nomad.job_catalog_pages" if denied == "catalog" else "nomad.job_specs"]
        assert row["denied"] == 1 and row["read"] == 0 and not row["complete"]
        assert not result["findings"]
    else:
        assert result["status"] == "complete" and all(r["complete"] for r in rows.values())
        assert [f["value"] for f in result["findings"]] == ["inactive-spec!42"]
    assert calls == (["/v1/jobs"] if denied == "catalog" else ["/v1/jobs", "/v1/job/app"])
