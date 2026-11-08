"""Panel metadata and actual OCI/assets contents have separate access evidence."""

from __future__ import annotations

import io
import json
import tarfile
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.modules.registry import actions
from redposture_core.storage_discovery import DiscoveryCollector, discover_registry_sources


def run(monkeypatch, product, *, denied=None, malformed=False, selected=False, invalid_descriptor=False):
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as tar:
        body = b'password="inactive-layer!42"'
        item = tarfile.TarInfo("app.env")
        item.size = len(body)
        tar.addfile(item, io.BytesIO(body))
    routes: dict[str, tuple[str, Any]] = {
        "/v2/_catalog?n=100": ("repository_catalog_pages", {"repositories": ["qa/app"]}),
        "/v2/qa/app/tags/list?n=100": ("tag_catalog_pages", {"tags": ["latest"]}),
        "/v2/qa/app/manifests/latest": (
            "oci_manifests",
            {
                "config": {"digest": "sha256:cfg"},
                "layers": [{"digest": "sha256:layer", "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}],
            },
        ),
        "/v2/qa/app/blobs/sha256:cfg": ("oci_config", {"password": "inactive-config!42"}),
        "/v2/qa/app/blobs/sha256:layer": ("oci_layer", b"invalid gzip" if malformed else archive.getvalue()),
        "/api/v2.0/projects?page_size=100&page=1": ("project_catalog_pages", [{"name": "qa"}]),
        "/api/v2.0/projects/qa/repositories?page_size=100&page=1": ("repository_catalog_pages", [{"name": "qa/app"}]),
        "/service/rest/v1/repositories": ("repository_catalog_pages", [{"name": "raw"}]),
        "/service/rest/v1/components?repository=raw": (
            "component_catalog_pages",
            {"items": [{"assets": [{"path": "app.env", "downloadUrl": "/repository/raw/app.env"}]}]},
        ),
        "/repository/raw/app.env": ("asset_contents", b'password="inactive-asset!42"'),
    }
    if invalid_descriptor:
        routes["/v2/qa/app/manifests/latest"] = ("oci_manifests", {"layers": [{}]})
    calls = []

    def request(host, port, method, path, timeout, **kwargs):
        assert method == "GET"
        calls.append(path)
        kind, data = routes[path]
        if kind == denied:
            return 403, b'password="not-a-source!42"', {}, None
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
        return 200, body, {}, None

    monkeypatch.setattr(actions, "_http_request", request)
    ctx = SimpleNamespace(
        host="qa",
        port=5000,
        args=SimpleNamespace(discover_time=30, timeout=1, image="qa/app:latest" if selected else None),
        credential=SimpleNamespace(username=None, password=None, token=None),
    )
    prior = {
        "status": "open_no_auth",
        "is_registry": True,
        **({"is_nexus": True, "probe_status": 404} if product == "nexus" else {}),
    }
    c = DiscoveryCollector(product, ctx, prior)
    discover_registry_sources(ctx, prior, c, product)
    return c.result(), calls


@pytest.mark.parametrize("product", ["docker-registry", "harbor", "nexus"])
def test_manifest_reports_actual_payload_reads_and_panel_backend_boundary(monkeypatch, product):
    result, _ = run(monkeypatch, product)
    assert result["status"] == "complete", result["partial_reasons"]
    rows = {r["id"].removeprefix(product + "."): r for r in result["sources"]}
    for source in (
        ["repository_catalog_pages", "component_catalog_pages", "asset_contents"]
        if product == "nexus"
        else ["repository_catalog_pages", "tag_catalog_pages", "oci_manifests", "oci_config", "oci_layer"]
    ):
        assert rows[source]["read"] == 1 and rows[source]["complete"], rows[source]
    assert {f["value"] for f in result["findings"]} == (
        {"inactive-asset!42"} if product == "nexus" else {"inactive-config!42", "inactive-layer!42"}
    )
    if product == "nexus":
        assert rows["oci_endpoint"]["unsupported"] and rows["oci_endpoint"]["read"] == 0


@pytest.mark.parametrize(
    "product,kind", [("docker-registry", "oci_config"), ("harbor", "oci_layer"), ("nexus", "asset_contents")]
)
def test_denied_payload_is_not_counted_as_read_or_parsed(monkeypatch, product, kind):
    result, _ = run(monkeypatch, product, denied=kind)
    assert result["status"] in {"partial", "unavailable"}
    row = next(r for r in result["sources"] if r["id"] == product + "." + kind)
    assert row["denied"] == 1 and row["read"] == 0 and not row["complete"]
    assert all(f["value"] != "not-a-source!42" for f in result["findings"])


def test_image_selector_does_not_claim_catalog_was_read(monkeypatch):
    result, calls = run(monkeypatch, "docker-registry", selected=True)
    rows = {r["id"]: r for r in result["sources"]}
    assert result["status"] == "complete"
    assert rows["docker-registry.repository_catalog_pages"]["requested"] == 0
    assert not any("_catalog" in p or "tags/list" in p for p in calls)


def test_invalid_descriptor_cannot_leave_manifest_source_complete(monkeypatch):
    result, _ = run(monkeypatch, "docker-registry", selected=True, invalid_descriptor=True)
    assert result["status"] == "partial"
    row = next(r for r in result["sources"] if r["id"] == "docker-registry.oci_manifests")
    assert not row["complete"]


@pytest.mark.parametrize("mode", ["repositories", "tags", "harbor_projects", "harbor_repositories", "nexus_components"])
def test_repeated_page_marks_only_its_catalog_walk_incomplete(mode):
    from redposture_core import storage_discovery as s

    product = "harbor" if mode.startswith("harbor") else "nexus" if mode.startswith("nexus") else "docker-registry"
    ctx = SimpleNamespace(host="qa", port=80, args=SimpleNamespace(discover_time=30, repository=None, asset=None))
    c = DiscoveryCollector(product, ctx, {"status": "open_no_auth"})

    def get(path, cap):
        value: Any
        if mode == "repositories":
            value = {"repositories": ["app"] * 100}
        elif mode == "tags":
            value = {"tags": ["latest"] * 100}
        elif mode.startswith("harbor"):
            if "/repositories?" in path:
                value = [{"name": "qa/app"}] * 100 if mode == "harbor_repositories" else []
            else:
                value = [{"name": "qa"}] * (100 if mode == "harbor_projects" else 1)
        else:
            value = [{"name": "raw"}] if path.endswith("/repositories") else {"items": [], "continuationToken": "same"}
        return 200, json.dumps(value).encode(), {}, None

    if mode == "repositories":
        s._registry_catalog(c, get)
    elif mode == "tags":
        s._registry_tags(c, get, "app")
    elif mode.startswith("harbor"):
        s._harbor_repositories(c, get)
    else:
        s._discover_nexus_assets(c, get, ctx)
    result = c.result()
    assert result["status"] == "partial"
    kind = (
        "tag_catalog_pages"
        if mode == "tags"
        else "project_catalog_pages"
        if mode == "harbor_projects"
        else "component_catalog_pages"
        if mode == "nexus_components"
        else "repository_catalog_pages"
    )
    rows = {row["id"]: row for row in result["sources"]}
    assert rows[product + "." + kind]["read"] > 0 and not rows[product + "." + kind]["complete"]
    if mode == "harbor_repositories":
        assert rows["harbor.project_catalog_pages"]["complete"], (
            "repository paging failure must not invalidate finished project catalog"
        )
