import json
from itertools import islice
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core import web_panel_export as we
from redposture_core import web_panels as wp
from redposture_core.clients.http_api import HttpResponse
from redposture_core.clients.minio_api import MinioResponse
from redposture_core.modules.gitlab import actions as ga
from redposture_core.modules.minio import actions as ma
from redposture_core.modules.minio import enumerate as me
from redposture_core.modules.registry import actions as ra


def _page(keys, token=None):
    items = "".join(f"<Contents><Key>{key}</Key><Size>1</Size></Contents>" for key in keys)
    cursor = f"<NextContinuationToken>{token}</NextContinuationToken>" if token else ""
    return f"<ListBucketResult>{items}{cursor}</ListBucketResult>".encode()


def test_minio_preserves_exact_keys_and_explicit_reference():
    client = NS(list_objects_v2=lambda *a, **k: MinioResponse(200, {}, _page([" report.txt ", "report.txt", " "])))
    assert [o.key for o in me.iter_objects(client, "bucket")] == [" report.txt ", "report.txt", " "]
    assert ma._split_object_ref("bucket/ report.txt ") == ("bucket", " report.txt ")


@pytest.mark.parametrize(
    "reply",
    [
        MinioResponse(500, {}, b"<Error/>"),
        MinioResponse(200, {}, b"<ListBucketResult><Contents>", truncated=True),
        MinioResponse(200, {}, b"<Error/>"),
        MinioResponse(200, {}, b"<ListBucketResult/>", truncated=True),
    ],
)
def test_minio_listing_failure_is_partial_discovery(reply):
    ctx = NS(args=NS(discover=True, bucket="bucket", output_format="json"), credential=NS(), host="qa", port=9000)
    client = NS(list_objects_v2=lambda *a, **k: reply)
    with patch.object(ma, "_client_for", return_value=client):
        out = ma.data_record(ctx, {"credential_state": "valid"})
    assert out["discover_coverage"] == "partial"
    assert out["discover_coverage_percent"] is None
    assert out["discover_partial_reasons"]


def test_minio_repeated_cursor_stops_before_duplicate_page():
    calls, errors = [], []

    def page(*args, **kwargs):
        calls.append(kwargs["continuation_token"])
        return MinioResponse(200, {}, _page(["item"], "same"))

    rows = list(islice(me.iter_objects(NS(list_objects_v2=page), "bucket", on_error=errors.append), 5))
    assert [row.key for row in rows] == ["item"]
    assert calls == [None, "same"]
    assert errors and "continuation" in errors[0].lower()


def test_minio_multi_endpoint_and_existing_downloads_preserved(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    reports = []
    for endpoint, value in [
        ("http://same:9000/a", b"first"),
        ("https://same:9000/a", b"second"),
        ("http://same:9001/a", b"third"),
        ("http://same:9000/b", b"fourth"),
        ("http://same:9000/a", b"repeat"),
    ]:
        result = {}
        client = NS(base_url=endpoint, get_object=lambda *a, value=value, **k: MinioResponse(200, {}, value))
        ma._run_object_op(
            client,
            result,
            object_ref="bucket/file.txt",
            bucket=None,
            want_dump=False,
            want_download=True,
            max_bytes=100,
        )
        reports.append((result["object_downloads"][0]["path"], value))
    assert len({path for path, _ in reports}) == 5
    assert all(Path(path).read_bytes() == value for path, value in reports)


def test_registry_download_follows_lifecycle_route_and_transport_policy(tmp_path):
    urls, configs = [], []

    class Client:
        def __init__(self, config):
            configs.append(config)

        def download_to_file(self, url, path, **kwargs):
            urls.append(url)
            Path(path).write_bytes(b"blob")
            return 200, 4, None

    state = ra.RegistryLifecycleState(
        http=NS(proxy="http://proxy:3128", insecure=True),
        scheme="https",
        host="effective.example",
        port=5443,
        base_path="/mounted",
    )
    ra._activate_registry_transport(state)
    try:
        with (
            patch.object(ra, "resolve_http_scheme", side_effect=AssertionError("must reuse resolved route")),
            patch.object(ra, "HttpApiClient", Client),
        ):
            for index in range(2):
                assert ra._http_download(
                    "original.example", 5000, "/v2/repo/blobs/sha256:abc", 1, str(tmp_path / str(index))
                ) == (200, 4, None)
        assert urls == ["https://effective.example:5443/mounted/v2/repo/blobs/sha256:abc"] * 2
        assert len(configs) == 1 and configs[0].proxy == "http://proxy:3128"
    finally:
        del ra._THREAD_LOCAL_HTTP.state


def test_registry_download_endpoint_and_reference_identity(tmp_path):
    reports = []

    def download(host, port, path, timeout, out_path, **kwargs):
        Path(out_path).write_text(f"{host}:{port}")
        return 200, 1, None

    with patch.object(ra, "_http_download", download):
        for host, port, image in [
            ("same", 5000, "repo:a/b"),
            ("same", 5001, "repo:a/b"),
            ("same", 5000, "repo:a_b"),
            ("same", 5000, "repo:a/b"),
        ]:
            reports.append(
                ra._download_image(
                    host,
                    port,
                    1,
                    headers={},
                    inspect_data=dict(
                        image=image, repository="repo", config_digest="sha256:abc", layers=[], total_size=1
                    ),
                    download_dir=str(tmp_path),
                    console=NS(),
                )
            )
    assert len({r["path"] for r in reports}) == 4
    assert [Path(r["path"], "sha256_abc.blob").read_text() for r in reports] == [
        "same:5000",
        "same:5001",
        "same:5000",
        "same:5000",
    ]


def test_gitlab_resolves_every_unlisted_explicit_clone_ref():
    state = ga.GitLabLifecycleState()
    ctx = NS(
        lifecycle_state=state, args=NS(timeout=1), host="qa", port=80, credential=NS(token=None), nested_scheduler=None
    )
    options = dict(
        project_filters=["group/one", "group/two", "group/missing"],
        clone=True,
        clone_dir="unused",
        show_repositories=True,
    )
    calls = []

    def fetch(*args, **kwargs):
        calls.append(kwargs["project_ref"])
        return (
            ({"id": 2, "path_with_namespace": "group/two"}, None)
            if kwargs["project_ref"] == "group/two"
            else (None, "not found")
        )

    with (
        patch.object(ga, "_http_request", return_value=(200, b"", {}, None)),
        patch.object(
            ga, "_paginate_projects", return_value=([{"id": 1, "path_with_namespace": "group/one"}], "partial listing")
        ),
        patch.object(ga, "_fetch_project_by_ref", fetch),
        patch.object(
            ga,
            "_clone_project",
            side_effect=lambda project, *a, **k: {"project": project["path_with_namespace"], "status": "cloned"},
        ),
    ):
        result = ga.collect_gitlab_data(ctx, {"status": "detected"}, options)
    assert calls == ["group/two", "group/missing"]
    assert {r["project"]: r["status"] for r in result["clone_results"]} == {
        "group/one": "cloned",
        "group/two": "cloned",
        "group/missing": "failed",
    }


def _json_response(value):
    return HttpResponse(200, json.dumps(value).encode(), {})


@pytest.mark.parametrize(
    "flags,remaining",
    [(dict(show_buckets=True, download=True), "download"), (dict(show_objects=True, discover=True), "discover")],
)
def test_ui_standard_export_keeps_other_requested_actions(tmp_path, monkeypatch, flags, remaining):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(wp, "HttpSessionPool", lambda **kw: NS(close=lambda: None))

    def get(pool, base, path, **kwargs):
        if path == "/api/v1/buckets":
            return _json_response({"buckets": [{"name": "qa"}]})
        if "/objects?" in path:
            return _json_response({"objects": [{"name": "secret.env", "size": 30}]})
        return HttpResponse(200, b"password=RealProofValue123!", {})

    monkeypatch.setattr(wp, "_get", get)

    def export(ctx, record, categories):
        return {**record, "ui": {**record["ui"], "inventory": {"export": {"status": "complete"}}}}

    monkeypatch.setattr(we, "export_panel", export)
    ctx = NS(args=NS(_ui_standard_export=True, **flags))
    result = wp.enumerate_panel(ctx, {"ui_product": "minio_console", "ui": {"endpoint": "http://qa"}})["ui"][
        "inventory"
    ]
    assert "export" in result and remaining in result
    assert result[remaining]["count"] >= 1


@pytest.mark.parametrize("product", ["kibana", "opensearch_dashboards"])
def test_ui_discovery_uses_secret_engine_and_keeps_cluster(product, monkeypatch):
    monkeypatch.setattr(wp, "HttpSessionPool", lambda **kw: NS(close=lambda: None))

    def post(pool, base, path, body, headers, **kwargs):
        upstream = parse_qs(urlsplit(path).query)["path"][0]
        if "_cluster/health" in upstream:
            return _json_response({"status": "green"})
        if "_cluster/settings" in upstream:
            return _json_response({"persistent": {"service": {"password": "RealProofValue123!"}}})
        if "_resolve/index" in upstream:
            return _json_response({"indices": [], "aliases": [], "data_streams": []})
        if "_cat/indices" in upstream:
            return _json_response([])
        return _json_response({})

    monkeypatch.setattr(wp, "_post", post)
    ctx = NS(args=NS(_ui_standard_export=True, discover=True, cluster=True, discover_max_bytes=1024, discover_time=1))
    result = wp.enumerate_panel(ctx, {"ui_product": product, "ui": {"endpoint": "http://qa"}})["ui"]["inventory"]
    assert result["cluster"]["records"]["status"] == "green"
    assert result["discover"]["count"] >= 1
    assert any("RealProofValue123!" in json.dumps(row) for row in result["discover"]["records"])
    assert result["discover"]["coverage"]["source_bytes_scanned"] <= 1024


def test_portainer_exports_running_and_stopped_containers(monkeypatch):
    def get(pool, base, path, headers):
        if "/api/endpoints?" in path:
            return _json_response([{"Id": 1}])
        return _json_response([{"Id": "running"}] + ([{"Id": "stopped"}] if "all=1" in path else []))

    monkeypatch.setattr(we, "_get", get)
    assert [row[2]["Id"] for row in we._portainer(None, "http://qa", {}, {"containers"}) if row[1] == "containers"] == [
        "running",
        "stopped",
    ]


@pytest.mark.parametrize(
    "reply",
    [
        MinioResponse(500, {}, b"<Error/>"),
        MinioResponse(200, {}, b"<Error/>"),
        MinioResponse(200, {}, b"<ListAllMyBucketsResult/>", truncated=True),
    ],
)
def test_minio_bucket_errors_propagate_to_inventory_and_discovery(reply):
    ctx = NS(args=NS(show_buckets=True, discover=True, output_format="json"), credential=NS(), host="qa", port=9000)
    with patch.object(ma, "_client_for", return_value=NS(get_service_root=lambda **kw: reply)):
        result = ma.data_record(ctx, {"credential_state": "valid"})
    assert result["inventory_coverage"] == "partial" and result["listing_errors"]
    assert result["discover_coverage"] == "partial" and result["discover_coverage_percent"] is None


def test_minio_distinct_exact_keys_have_distinct_downloads(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    paths = []
    for key in ["a/b", "a_b", "a//b", "a/./b", " file ", " "]:
        result = {}
        ma._run_object_op(
            NS(base_url="http://qa:9000", get_object=lambda *a, **k: MinioResponse(200, {}, b"proof")),
            result,
            object_ref="bucket/" + key,
            bucket=None,
            want_dump=False,
            want_download=True,
            max_bytes=100,
        )
        paths.append(result["object_downloads"][0]["path"])
    assert len(set(paths)) == len(paths)


@pytest.mark.parametrize("combined", [False, True])
def test_console_discovery_budget_applies_alongside_dump(combined, monkeypatch):
    monkeypatch.setattr(wp, "HttpSessionPool", lambda **kw: NS(close=lambda: None))

    def get(pool, base, path, **kwargs):
        if path == "/api/v1/buckets":
            return _json_response({"buckets": [{"name": "qa"}]})
        if "/objects?" in path:
            return _json_response({"objects": [{"name": "secret.env", "size": 64}]})
        cap = kwargs["response_size_cap"]
        value = b"password=RealProofValue123!"
        return HttpResponse(200, value[:cap], {}, truncated=len(value) > cap)

    monkeypatch.setattr(wp, "_get", get)
    ctx = NS(args=NS(discover=True, dump=combined, discover_max_bytes=1, discover_time=1))
    result = wp.enumerate_panel(ctx, {"ui_product": "minio_console", "ui": {"endpoint": "http://qa"}})["ui"][
        "inventory"
    ]
    assert result["discover"]["bytes_read"] <= 1 and result["discover"]["partial"]
    assert result["discover"]["count"] == 0
    if combined:
        assert result["dump"]["records"][0]["content"] == "password=RealProofValue123!"


def test_console_discovery_zero_time_does_not_read_objects(monkeypatch):
    monkeypatch.setattr(wp, "HttpSessionPool", lambda **kw: NS(close=lambda: None))
    paths = []

    def get(pool, base, path, **kwargs):
        paths.append(path)
        return _json_response({"buckets": [{"name": "qa"}]})

    monkeypatch.setattr(wp, "_get", get)
    ctx = NS(args=NS(discover=True, discover_time=0, discover_max_bytes=50))
    result = wp.enumerate_panel(ctx, {"ui_product": "minio_console", "ui": {"endpoint": "http://qa"}})["ui"][
        "inventory"
    ]["discover"]
    assert result["partial"] and result["bytes_read"] == 0
    assert paths == ["/api/v1/buckets"]


def test_portainer_bounded_inventory_also_requests_stopped(monkeypatch):
    monkeypatch.setattr(wp, "HttpSessionPool", lambda **kw: NS(close=lambda: None))

    def get(pool, base, path, **kwargs):
        if "/api/endpoints?" in path:
            return _json_response([{"Id": 1}])
        assert "containers/json?all=1" in path
        return _json_response([{"Id": "stopped", "Names": ["/stopped"], "State": "exited"}])

    monkeypatch.setattr(wp, "_get", get)
    result = wp.enumerate_panel(
        NS(args=NS(containers=True)), {"ui_product": "portainer", "ui": {"endpoint": "http://qa"}}
    )["ui"]["inventory"]
    assert result["containers"]["count"] == 1


def test_minio_partial_inventory_and_unknown_coverage_colors_and_saved_output():
    from redposture_core.modules.minio import render

    record = dict(
        host="qa",
        port=9000,
        detection_status="confirmed",
        listing_errors=["ListObjects: invalid XML"],
        discover_requested=True,
        discover_coverage="partial",
        discover_coverage_percent=None,
    )
    lines = render._format_minio_detail_records(record, "txt")
    assert any("(coverage:unknown)" in line for line in lines)
    assert all("\x1b[" not in line for line in lines)
    assert "\\u001b" not in json.dumps(record)
    assert render._minio_extra_spans("[!]", "inventory partial: ListObjects: invalid XML") == [
        (0, len("inventory partial: ListObjects: invalid XML"), "orange")
    ]
