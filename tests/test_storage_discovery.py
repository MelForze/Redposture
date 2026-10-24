from __future__ import annotations

import tarfile
from io import BytesIO
from types import SimpleNamespace
from typing import Any
from zipfile import ZipFile

from redposture_core.cli_args import parse_args
from redposture_core.data_discovery import render_discovery
from redposture_core.storage_discovery import DiscoveryCollector, merge_discovery_results


def test_storage_modules_expose_discover_without_running_other_actions() -> None:
    for module in ("gitlab", "portainer", "harbor", "nexus", "docker-registry"):
        args = parse_args(
            [module, "-t", "127.0.0.1", "--discover", "--discover-time", "30", "--discover-max-bytes", "4096"]
        )
        assert args.discover is True
        assert args.discover_time == 30
        assert args.discover_max_bytes == 4096
        assert getattr(args, "execute", None) is None
        assert getattr(args, "download", False) is False


def test_collector_streams_masked_findings_and_preserves_partial_reason() -> None:
    emitted: list[str] = []
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=1000, discover_time=30),
        host="127.0.0.1",
        port=8080,
        live_emit=lambda lines: emitted.extend(lines),
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    collector.add("project/demo/file/.env", "API_TOKEN=glpat-abcdefghijklmnopqrst")
    collector.partial("project/demo/history", "diff truncated")
    result = collector.result()
    assert result["status"] == "partial"
    assert result["findings"][0]["object_path"].startswith("$.project/demo/file/.env")
    assert "glpat-abcdefghijklmnopqrst" not in str(result)
    assert emitted and "glpat-abcdefghijklmnopqrst" not in "".join(emitted)
    assert result["partial_reasons"] == ["project/demo/history: diff truncated"]


def test_discovery_server_path_cannot_put_ansi_in_saved_or_live_output() -> None:
    emitted: list[str] = []
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=1000, discover_time=30),
        host="qa",
        port=80,
        live_emit=lambda lines: emitted.extend(lines),
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
    collector.add("project/\x1b[31mevil.env", "API_TOKEN=glpat-abcdefghijklmnopqrst")
    assert collector.result()["findings"]
    rendered = str(collector.result()) + "".join(emitted)
    assert "\x1b" not in rendered
    assert "glpat-abcdefghijklmnopqrst" not in rendered


def test_collector_counts_downloaded_bytes_and_stops_at_budget() -> None:
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=4, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("nexus", ctx, {"status": "open_no_auth"})
    assert collector.charge(3) is True
    assert collector.charge(2) is False
    assert collector.result()["status"] == "partial"
    assert collector.result()["bytes_read"] == 3


def test_expired_discovery_time_stops_before_another_network_request(monkeypatch) -> None:
    from redposture_core import storage_discovery

    now = [100.0]
    monkeypatch.setattr(storage_discovery, "time", SimpleNamespace(monotonic=lambda: now[0]))
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=1000, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
    now[0] = 131.0

    def forbidden_request(_path, _cap):
        raise AssertionError("expired discovery must not start a request")

    assert collector.read(forbidden_request, "/api/v4/projects", "projects") is None
    assert collector.result()["status"] == "partial"
    assert "discover_time" in collector.result()["partial_reasons"]


def test_only_empty_inventory_and_denied_resources_is_unavailable() -> None:
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=1000, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("portainer", ctx, {"status": "valid_credentials"})
    collector.add("portainer/inventory/environments", [])
    collector.partial("portainer/environments", "access_denied")
    assert collector.result()["status"] == "unavailable"


def test_live_findings_are_not_rendered_twice_in_txt() -> None:
    record = {
        "host": "qa",
        "port": 80,
        "content_discovery": {
            "status": "complete",
            "source": "anonymous",
            "live_emitted": True,
            "findings": [{"type": "gitlab_token", "confidence": "high", "value": "masked", "object_path": "$.file"}],
            "partial_reasons": ["project/demo: access_denied"],
        },
    }
    lines = render_discovery("gitlab", record)
    assert len(lines) == 1
    assert "Discover Secrets" in lines[0]
    assert "project/demo: access_denied" in lines[0]


def test_gitlab_web_and_registry_discovery_share_one_summary_without_losing_findings() -> None:
    web = {
        "status": "complete",
        "source": "authenticated",
        "bytes_read": 12,
        "bytes_inspected": 8,
        "findings": [{"type": "token", "fingerprint": "web", "object_path": "$.project/7/file"}],
        "partial_reasons": [],
        "live_emitted": True,
    }
    registry = {
        "status": "partial",
        "source": "anonymous",
        "bytes_read": 24,
        "bytes_inspected": 16,
        "findings": [{"type": "secret", "fingerprint": "registry", "object_path": "$.registry/layer"}],
        "partial_reasons": ["registry/layer: response_truncated"],
        "live_emitted": False,
    }
    merged = merge_discovery_results(web, registry)
    assert merged["status"] == "partial"
    assert merged["source"] == "mixed"
    assert merged["bytes_read"] == 36
    assert len(merged["findings"]) == 2
    assert merged["partial_reasons"] == ["registry/layer: response_truncated"]
    # A finding emitted only on one surface must still be present in the saved TXT.
    assert len(render_discovery("gitlab", {"host": "qa", "port": 80, "content_discovery": merged})) == 2


def test_storage_discover_summary_colors_match_airflow() -> None:
    from redposture_core.modules.gitlab import render as gitlab_render
    from redposture_core.modules.portainer import render as portainer_render
    from redposture_core.modules.registry import product_render

    class PaintConsole:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def _paint(self, value: str, color: str, _stream: object) -> str:
            self.calls.append((value, color))
            return value

        def plain(self, _value: str) -> None:
            return None

    for module, colorize in (
        ("GITLAB", gitlab_render._render_colored_gitlab_line),
        ("PORTAINER", portainer_render.colorize),
        ("HARBOR", product_render._render_colored_registry_line),
        ("NEXUS", product_render._render_colored_registry_line),
        ("DOCKER-REGISTRY", product_render._render_colored_registry_line),
    ):
        console = PaintConsole()
        assert colorize(
            console, f"{module}\tqa\t80\t [*] Discover Secrets (status:complete) (findings:1) (source:anonymous)"
        )
        assert any("status:complete" in value and color == "bright_green" for value, color in console.calls)
        assert any("findings:1" in value and color == "true_red" for value, color in console.calls)


def test_runtime_preserves_precomputed_streaming_discovery(tmp_path) -> None:
    from redposture_core.audit_models import AuditRecord
    from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, ModuleAuditSpec

    record = AuditRecord.from_mapping(
        {
            "host": "qa",
            "port": 8080,
            "status": "open_no_auth",
            "content_discovery": {"status": "complete", "bytes_inspected": 42, "source": "anonymous", "findings": []},
        },
        module="gitlab",
    )
    args = SimpleNamespace(command="gitlab", discover=True, discover_max_bytes=1, debug=False)
    runner = AuditCommandRunner(
        args=args,
        spec=ModuleAuditSpec(
            module="gitlab",
            label="GITLAB",
            default_port=8080,
            detect=lambda _ctx: record,
            data=lambda _ctx, prior: prior,
            is_detected=lambda _record: True,
            render=lambda _record: [],
        ),
        emit_line=lambda _line: None,
    )
    output = tmp_path / "out.json"
    runner.run_plan(
        AuditCommandPlan(targets_by_port={8080: ("qa",)}, output_path=str(output), output_format="json", workers=1)
    )
    saved = __import__("json").loads(output.read_text())
    assert saved["content_discovery"]["status"] == "complete"
    assert saved["content_discovery"]["bytes_inspected"] == 42


def test_public_registry_discover_can_probe_after_root_auth_challenge() -> None:
    from redposture_core.audit_models import AuditRecord
    from redposture_core.stage_runtime import AuditCommandRunner, ModuleAuditSpec

    spec = ModuleAuditSpec(
        module="harbor",
        label="HARBOR",
        default_port=80,
        discover_public_on_auth_required=True,
    )
    record = AuditRecord.from_mapping(
        {"host": "qa", "port": 80, "status": "auth_required", "is_registry": True, "provided_credentials": False},
        module="harbor",
    )
    runner = AuditCommandRunner(args=SimpleNamespace(discover=True), spec=spec, emit_line=lambda _line: None)
    assert runner._deep_gate(record)[0] is True
    assert (
        AuditCommandRunner(args=SimpleNamespace(discover=False), spec=spec, emit_line=lambda _line: None)._deep_gate(
            record
        )[0]
        is False
    )
    supplied = AuditRecord.from_mapping(
        {"host": "qa", "port": 80, "status": "auth_required", "is_registry": True, "provided_credentials": True},
        module="harbor",
    )
    assert runner._deep_gate(supplied)[0] is False


def test_collector_marks_truncated_transport_and_keeps_prefix_finding() -> None:
    body: Any
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=1000, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
    body = collector.read(
        lambda _path, _cap: (200, b"API_TOKEN=glpat-abcdefghijklmnopqrst", {"x-redposture-truncated": "true"}, None),
        "/file",
        "project/demo/file",
    )
    assert body is not None
    collector.add("project/demo/file", body.decode(), charge=False)
    assert collector.result()["status"] == "partial"
    assert collector.result()["findings"]


def test_zip_archive_inspects_file_path_without_extracting_to_disk() -> None:
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=10000, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
    output = BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr("vars/.env", "API_TOKEN=glpat-abcdefghijklmnopqrst")
    collector.scan_archive("project/demo/job/7/artifacts", output.getvalue(), "zip")
    assert "vars/.env" in collector.result()["findings"][0]["object_path"]


def test_archive_member_larger_than_remaining_budget_is_partial_without_decompression() -> None:
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=256, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("harbor", ctx, {"status": "open_no_auth"})
    output = BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr("large/.env", "API_TOKEN=glpat-abcdefghijklmnopqrst\n" * 100)
    collector.scan_archive("image/qa/layer", output.getvalue(), "zip")
    assert collector.result()["status"] == "partial"
    assert collector.result()["findings"] == []
    assert any("member_too_large" in reason for reason in collector.result()["partial_reasons"])


def test_streaming_tar_stops_before_skipping_an_oversized_member() -> None:
    archive_bytes = BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w:gz") as archive:
        oversized = b"x" * 100_000
        first = tarfile.TarInfo("large.bin")
        first.size = len(oversized)
        archive.addfile(first, BytesIO(oversized))
        secret = b"API_TOKEN=glpat-abcdefghijklmnopqrst"
        second = tarfile.TarInfo("later.env")
        second.size = len(secret)
        archive.addfile(second, BytesIO(secret))
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=50, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("docker-registry", ctx, {"status": "open_no_auth"})
    collector.scan_archive("image/qa/layer", archive_bytes.getvalue(), "tar")
    assert collector.result()["status"] == "partial"
    assert any("member_too_large:large.bin" in reason for reason in collector.result()["partial_reasons"])
    assert not collector.result()["findings"]


def test_corrupt_archive_marks_partial_instead_of_complete() -> None:
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=1000, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
    collector.scan_archive("project/7/artifacts", b"not a zip", "zip")
    assert collector.result()["status"] == "partial"
    assert "archive_error" in collector.result()["partial_reasons"][0]


def test_portainer_discovery_ignores_runtime_paths_and_public_swarm_trust_root() -> None:
    value: Any
    from redposture_core.storage_discovery import _portainer_discovery_view

    value = {
        "GraphDriver": {"Data": {"UpperDir": "/var/lib/docker/overlay2/abcdefghijklmnopqrstuv/diff"}},
        "HostnamePath": "/var/lib/docker/containers/abcdefghijklmnopqrstuv/hostname",
        "Config": {"Env": ["API_TOKEN=glpat-abcdefghijklmnopqrst"]},
        "Swarm": {
            "Cluster": {"TLSInfo": {"TrustRoot": "-----BEGIN CERTIFICATE-----\nPUBLICDATA\n-----END CERTIFICATE-----"}}
        },
    }
    cleaned = _portainer_discovery_view(value)
    assert "GraphDriver" not in cleaned
    assert "HostnamePath" not in cleaned
    assert "TrustRoot" not in cleaned["Swarm"]["Cluster"]["TLSInfo"]
    assert cleaned["Config"]["Env"] == value["Config"]["Env"]


def test_gitlab_discover_reads_repository_history_variables_and_job_logs(monkeypatch) -> None:
    from redposture_core.modules.gitlab import actions
    from redposture_core.storage_discovery import discover_gitlab_sources

    calls: list[str] = []
    responses = {
        "/api/v4/projects/7/repository/branches?per_page=100&page=1": [{"name": "main", "commit": {"id": "c2"}}],
        "/api/v4/projects/7/repository/tree?recursive=true&ref=main&per_page=100&page=1": [
            {"type": "blob", "path": ".env"}
        ],
        "/api/v4/projects/7/repository/commits?all=true&per_page=100&page=1": [{"id": "c1", "parent_ids": []}],
        "/api/v4/projects/7/repository/commits/c1/diff?per_page=100&page=1": [
            {"new_path": "old.env", "old_path": "old.env", "new_file": True}
        ],
        "/api/v4/projects/7/variables?per_page=100&page=1": [
            {"key": "API_TOKEN", "value": "glpat-abcdefghijklmnopqrst"}
        ],
        "/api/v4/groups/4/variables?per_page=100&page=1": [],
        "/api/v4/groups/4": {"id": 4, "parent_id": None},
        "/api/v4/projects/7/jobs?per_page=100&page=1": [{"id": 9, "artifacts_file": {"filename": ""}}],
    }

    def fake_request(_host, _port, _method, path, _timeout, **_kwargs):
        calls.append(path)
        if path.endswith("/repository/files/.env/raw?ref=main&lfs=true"):
            return 200, b"password=from-current", {}, None
        if path.endswith("/repository/files/old.env/raw?ref=c1&lfs=true"):
            return 200, b"API_TOKEN=glpat-abcdefghijklmnopqrst", {}, None
        if path.endswith("/jobs/9/trace"):
            return 200, b"password=from-log", {}, None
        if path in responses:
            return 200, __import__("json").dumps(responses[path]).encode(), {}, None
        raise AssertionError(path)

    monkeypatch.setattr(actions, "_http_request", fake_request)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=10000, discover_time=30, timeout=1),
        host="qa",
        port=80,
        credential=SimpleNamespace(token="tok"),
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    discover_gitlab_sources(
        ctx,
        {
            "https": False,
            "token_valid": True,
            "token_projects": [{"id": 7, "path_with_namespace": "team/app", "namespace": {"id": 4}}],
        },
        collector,
    )
    result = collector.result()
    assert result["status"] == "complete"
    assert any("old.env" in finding["object_path"] for finding in result["findings"])
    assert any("API_TOKEN" in path for path in calls) is False
    assert "/api/v4/projects/7/jobs/9/trace" in calls
    assert "/api/v4/groups/4" in calls


def test_gitlab_discover_preserves_project_pagination_error(monkeypatch) -> None:
    from redposture_core.modules.gitlab import actions
    from redposture_core.storage_discovery import discover_gitlab_sources

    monkeypatch.setattr(
        actions,
        "_http_request",
        lambda *_args, **_kwargs: (200, b"[]", {}, None),
    )
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=10000, discover_time=30, timeout=1),
        host="qa",
        port=80,
        credential=SimpleNamespace(token="tok"),
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    discover_gitlab_sources(
        ctx,
        {
            "token_valid": True,
            "token_projects": [{"id": 7, "path_with_namespace": "team/app"}],
            "token_projects_error": "partial: GitLab pagination limit exceeded",
        },
        collector,
    )
    assert collector.result()["status"] == "partial"
    assert "pagination limit" in " ".join(collector.result()["partial_reasons"])


def test_gitlab_discover_lists_projects_with_its_own_network_budget(monkeypatch) -> None:
    from redposture_core.modules.gitlab import actions
    from redposture_core.storage_discovery import discover_gitlab_sources

    calls: list[tuple[str, int]] = []
    responses = {
        "/api/v4/projects?per_page=100&page=1&simple=true&order_by=id&sort=asc": [
            {"id": 7, "path_with_namespace": "team/app"}
        ],
        "/api/v4/projects/7/repository/branches?per_page=100&page=1": [],
        "/api/v4/projects/7/repository/commits?all=true&per_page=100&page=1": [],
        "/api/v4/projects/7/variables?per_page=100&page=1": [],
        "/api/v4/projects/7/jobs?per_page=100&page=1": [],
    }

    def fake(_host, _port, _method, path, _timeout, **kwargs):
        body: Any
        cap = kwargs["response_size_cap"]
        calls.append((path, cap))
        body = __import__("json").dumps(responses[path]).encode()
        assert len(body) <= cap
        return 200, body, {}, None

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=2000, discover_time=30, timeout=1),
        host="qa",
        port=80,
        credential=SimpleNamespace(token="tok"),
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    discover_gitlab_sources(ctx, {"token_valid": True, "token_projects": None, "project_filters": []}, collector)
    result = collector.result()
    assert result["status"] == "complete"
    assert calls[0][0].startswith("/api/v4/projects?")
    assert calls[0][1] == 2000
    assert result["bytes_read"] <= 2000


def test_gitlab_discover_marks_repeated_project_page_partial(monkeypatch) -> None:
    from redposture_core.modules.gitlab import actions
    from redposture_core.storage_discovery import discover_gitlab_sources

    pages: list[str] = []

    def fake(_host, _port, _method, path, _timeout, **_kwargs):
        if path.startswith("/api/v4/projects?"):
            pages.append(path)
            return 200, b'[{"id":7,"path_with_namespace":"team/app"}]', {"x-next-page": "2"}, None
        assert path.startswith("/api/v4/projects/7/")
        return 200, b"[]", {}, None

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=10000, discover_time=30, timeout=1),
        host="qa",
        port=80,
        credential=SimpleNamespace(token="tok"),
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    discover_gitlab_sources(ctx, {"token_valid": True, "token_projects": None, "project_filters": []}, collector)
    assert len(pages) == 2
    assert collector.result()["status"] == "partial"
    assert any("repeated_page" in reason for reason in collector.result()["partial_reasons"])


def test_gitlab_denied_project_listing_is_unavailable(monkeypatch) -> None:
    from redposture_core.modules.gitlab import actions
    from redposture_core.storage_discovery import discover_gitlab_sources

    def denied(_host, _port, _method, path, _timeout, **_kwargs):
        assert path.startswith("/api/v4/projects?")
        return 403, b"", {}, None

    monkeypatch.setattr(actions, "_http_request", denied)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=10000, discover_time=30, timeout=1),
        host="qa",
        port=80,
        credential=SimpleNamespace(token="tok"),
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    discover_gitlab_sources(ctx, {"token_valid": True, "token_projects": None, "project_filters": []}, collector)
    assert collector.result()["status"] == "unavailable"
    assert collector.result()["partial_reasons"] == ["projects/list: access_denied"]


def test_gitlab_discover_only_skips_unbounded_preinventory(monkeypatch) -> None:
    from redposture_core.audit_models import AuditRecord
    from redposture_core.modules.gitlab import actions, stage
    from redposture_core.modules.registry import actions as registry_actions

    def no_preinventory(*_args, **_kwargs):
        raise AssertionError("ordinary GitLab inventory must not precede bounded --discover")

    def discover(_ctx, record, collector):
        assert record["public_projects"] is None
        collector.add("project/team/app/file/.env", "API_TOKEN=glpat-abcdefghijklmnopqrst")

    monkeypatch.setattr(actions, "collect_gitlab_data", no_preinventory)
    monkeypatch.setattr(stage, "discover_gitlab_sources", discover)
    args = SimpleNamespace(discover=True, images=False, clone=False, discover_max_bytes=1000, discover_time=30)
    spec = stage.build_gitlab_spec(args)
    ctx = SimpleNamespace(
        args=args,
        host="qa",
        port=80,
        target=SimpleNamespace(scheme="http", path=""),
        credential=SimpleNamespace(username=None, password=None, token=None, source="anonymous"),
        lifecycle_state=stage.GitLabCombinedState(
            actions.GitLabLifecycleState(), registry_actions.RegistryLifecycleState()
        ),
    )
    record = AuditRecord.from_mapping(
        {"status": "detected", "is_gitlab": True, "gitlab_surface": "web", "public_projects": []},
        module="gitlab",
        service="gitlab",
    )
    assert spec.data is not None
    result = spec.data(ctx, record).to_dict()
    assert result["content_discovery"]["status"] == "complete"
    assert result["content_discovery"]["findings"]


def test_gitlab_discover_resolves_selected_project_missing_from_list(monkeypatch) -> None:
    from redposture_core.modules.gitlab import actions
    from redposture_core.storage_discovery import discover_gitlab_sources

    paths: list[str] = []

    def fake(_host, _port, _method, path, _timeout, **_kwargs):
        value: Any
        paths.append(path)
        if path == "/api/v4/projects/team%2Fapp":
            value = {"id": 7, "path_with_namespace": "team/app"}
        elif path == "/api/v4/projects/7/repository/branches?per_page=100&page=1":
            value = [{"name": "main"}]
        elif path == "/api/v4/projects/7/repository/tree?recursive=true&ref=main&per_page=100&page=1":
            value = [{"type": "blob", "path": ".env"}]
        elif path == "/api/v4/projects/7/repository/files/.env/raw?ref=main&lfs=true":
            return 200, b"API_TOKEN=glpat-abcdefghijklmnopqrst", {}, None
        elif path.endswith("per_page=100&page=1"):
            value = []
        else:
            raise AssertionError(path)
        return 200, __import__("json").dumps(value).encode(), {}, None

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=10000, discover_time=30, timeout=1),
        host="qa",
        port=80,
        credential=SimpleNamespace(token="tok"),
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    discover_gitlab_sources(
        ctx,
        {"token_valid": True, "token_projects": [], "project_filters": ["team/app"]},
        collector,
    )
    assert collector.result()["status"] == "complete"
    assert any("team/app" in item["object_path"] for item in collector.result()["findings"])
    assert "/api/v4/projects/team%2Fapp" in paths


def test_docker_registry_discover_scans_config_and_layer(monkeypatch) -> None:
    data: Any
    from redposture_core.modules.registry import actions
    from redposture_core.storage_discovery import discover_registry_sources

    layer = BytesIO()
    data = b"API_TOKEN=glpat-zyxwvutsrqponmlkjihg"
    with tarfile.open(fileobj=layer, mode="w:gz") as archive:
        info = tarfile.TarInfo("app/.env")
        info.size = len(data)
        archive.addfile(info, BytesIO(data))
    bodies = {
        "/v2/_catalog?n=100": {"repositories": ["team/app"]},
        "/v2/team/app/tags/list?n=100": {"tags": ["latest"]},
        "/v2/team/app/manifests/latest": {
            "config": {"digest": "sha256:cfg"},
            "layers": [{"digest": "sha256:layer", "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}],
        },
        "/v2/team/app/blobs/sha256:cfg": {"config": {"Env": ["API_TOKEN=glpat-abcdefghijklmnopqrst"]}},
    }

    def fake(_host, _port, _method, path, _timeout, **_kwargs):
        if "/manifests/" in path:
            assert "application/vnd.oci.image.manifest.v1+json" in _kwargs["headers"].get("Accept", "")
        if path.endswith("/blobs/sha256:layer"):
            return 200, layer.getvalue(), {}, None
        if path in bodies:
            return 200, __import__("json").dumps(bodies[path]).encode(), {}, None
        raise AssertionError(path)

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(
            discover_max_bytes=100000, discover_time=30, timeout=1, repository=None, image=None, tag=None, asset=None
        ),
        host="qa",
        port=5000,
        credential=SimpleNamespace(username=None, password=None, token=None),
    )
    collector = DiscoveryCollector("docker-registry", ctx, {"status": "open_no_auth"})
    discover_registry_sources(ctx, {"status": "open_no_auth", "is_registry": True}, collector, "docker-registry")
    result = collector.result()
    assert result["status"] == "complete"
    assert any("app/.env" in finding["object_path"] for finding in result["findings"])


def test_nexus_discover_scans_asset_and_respects_asset_selector(monkeypatch) -> None:
    from redposture_core.modules.registry import actions
    from redposture_core.storage_discovery import discover_registry_sources

    paths: list[str] = []

    def fake(_host, _port, _method, path, _timeout, **_kwargs):
        value: Any
        paths.append(path)
        if path == "/service/rest/v1/repositories":
            value = [{"name": "raw-hosted", "format": "raw", "type": "hosted"}]
        elif path == "/service/rest/v1/components?repository=raw-hosted":
            value = {
                "items": [
                    {
                        "assets": [
                            {
                                "path": "builds/2026.02/release-metadata.json",
                                "downloadUrl": "http://qa:8081/repository/raw-hosted/builds/2026.02/release-metadata.json",
                            },
                            {"path": "skip.env", "downloadUrl": "http://qa:8081/repository/raw-hosted/skip.env"},
                        ]
                    }
                ],
                "continuationToken": None,
            }
        elif path == "/repository/raw-hosted/builds/2026.02/release-metadata.json":
            return 200, b"API_TOKEN=glpat-abcdefghijklmnopqrst", {}, None
        else:
            raise AssertionError(path)
        return 200, __import__("json").dumps(value).encode(), {}, None

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(
            discover_max_bytes=100000,
            discover_time=30,
            timeout=1,
            repository=None,
            image=None,
            tag=None,
            asset="builds/2026.02/release-metadata.json",
        ),
        host="qa",
        port=8081,
        credential=SimpleNamespace(username=None, password=None, token=None),
    )
    collector = DiscoveryCollector("nexus", ctx, {"status": "open_no_auth"})
    discover_registry_sources(
        ctx, {"status": "open_no_auth", "is_nexus": True, "is_registry": True, "probe_status": 404}, collector, "nexus"
    )
    findings = collector.result()["findings"]
    assert findings
    assert all("downloadUrl" not in finding["object_path"] for finding in findings)
    assert all("//builds/2026.02" not in finding["object_path"] for finding in findings)
    assert "/repository/raw-hosted/skip.env" not in paths
    assert not any(path.startswith("/v2/") for path in paths)


def test_nexus_asset_advertised_internal_host_reads_through_selected_proxy(monkeypatch) -> None:
    from redposture_core.modules.registry import actions
    from redposture_core.storage_discovery import discover_registry_sources

    paths: list[str] = []

    def fake(host, port, _method, path, _timeout, **_kwargs):
        value: Any
        assert (host, port) == ("proxy.qa", 18081)
        paths.append(path)
        if path == "/service/rest/v1/repositories":
            value = [{"name": "raw-hosted"}]
        elif path == "/service/rest/v1/components?repository=raw-hosted":
            value = {
                "items": [
                    {
                        "assets": [
                            {"path": "qa.env", "downloadUrl": "http://nexus-internal:8081/repository/raw-hosted/qa.env"}
                        ]
                    }
                ]
            }
        elif path == "/repository/raw-hosted/qa.env":
            return 200, b"API_TOKEN=glpat-abcdefghijklmnopqrst", {}, None
        else:
            raise AssertionError(path)
        return 200, __import__("json").dumps(value).encode(), {}, None

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(
            discover_max_bytes=100000, discover_time=30, timeout=1, repository=None, asset=None, image=None, tag=None
        ),
        host="proxy.qa",
        port=18081,
        credential=SimpleNamespace(username=None, password=None, token=None),
    )
    collector = DiscoveryCollector("nexus", ctx, {"status": "open_no_auth"})
    discover_registry_sources(
        ctx, {"status": "open_no_auth", "is_nexus": True, "is_registry": True, "probe_status": 404}, collector, "nexus"
    )
    assert collector.result()["status"] == "complete"
    assert collector.result()["findings"]
    assert "/repository/raw-hosted/qa.env" in paths


def test_nexus_asset_selector_excludes_other_component_metadata(monkeypatch) -> None:
    from redposture_core.modules.registry import actions
    from redposture_core.storage_discovery import discover_registry_sources

    def fake(_host, _port, _method, path, _timeout, **_kwargs):
        value: Any
        if path == "/service/rest/v1/repositories":
            value = [{"name": "raw-hosted"}]
        elif path == "/service/rest/v1/components?repository=raw-hosted":
            value = {
                "items": [
                    {
                        "name": "selected",
                        "assets": [
                            {"path": "selected.env", "downloadUrl": "http://qa:8081/repository/raw-hosted/selected.env"}
                        ],
                    },
                    {
                        "name": "API_TOKEN=glpat-abcdefghijklmnopqrst",
                        "assets": [
                            {"path": "other.env", "downloadUrl": "http://qa:8081/repository/raw-hosted/other.env"}
                        ],
                    },
                ]
            }
        elif path == "/repository/raw-hosted/selected.env":
            return 200, b"API_TOKEN=glpat-zyxwvutsrqponmlkjihg", {}, None
        else:
            raise AssertionError(path)
        return 200, __import__("json").dumps(value).encode(), {}, None

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(
            discover_max_bytes=100000,
            discover_time=30,
            timeout=1,
            repository=None,
            asset="selected.env",
            image=None,
            tag=None,
        ),
        host="qa",
        port=8081,
        credential=SimpleNamespace(username=None, password=None, token=None),
    )
    collector = DiscoveryCollector("nexus", ctx, {"status": "open_no_auth"})
    discover_registry_sources(
        ctx, {"status": "open_no_auth", "is_nexus": True, "probe_status": 404}, collector, "nexus"
    )
    assert collector.result()["findings"]
    assert all(item["value"].endswith("jihg") for item in collector.result()["findings"])


def test_harbor_discover_uses_project_repository_when_catalog_is_unavailable(monkeypatch) -> None:
    from redposture_core.modules.registry import actions
    from redposture_core.storage_discovery import discover_registry_sources

    paths: list[str] = []
    payloads = {
        "/api/v2.0/projects?page_size=100&page=1": [{"name": "team"}],
        "/api/v2.0/projects/team/repositories?page_size=100&page=1": [{"name": "team/app"}],
        "/v2/team/app/tags/list?n=100": {"tags": ["v1"]},
        "/v2/team/app/manifests/v1": {"config": {"digest": "sha256:cfg"}, "layers": []},
        "/v2/team/app/blobs/sha256:cfg": {"config": {"Env": ["API_TOKEN=glpat-abcdefghijklmnopqrst"]}},
    }

    def fake(_host, _port, _method, path, _timeout, **_kwargs):
        paths.append(path)
        if path in payloads:
            return 200, __import__("json").dumps(payloads[path]).encode(), {}, None
        raise AssertionError(path)

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(
            discover_max_bytes=100000, discover_time=30, timeout=1, repository=None, image=None, tag=None, asset=None
        ),
        host="qa",
        port=80,
        credential=SimpleNamespace(username=None, password=None, token=None),
    )
    collector = DiscoveryCollector("harbor", ctx, {"status": "open_no_auth"})
    discover_registry_sources(
        ctx, {"status": "open_no_auth", "is_registry": True, "is_harbor": True}, collector, "harbor"
    )
    assert collector.result()["status"] == "complete"
    assert collector.result()["findings"]
    assert "/v2/_catalog?n=100" not in paths


def test_portainer_discover_reads_stack_container_and_config_without_secret_values(monkeypatch) -> None:
    from redposture_core import web_panels
    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.storage_discovery import discover_portainer_sources

    calls: list[str] = []
    responses = {
        "/api/stacks": [{"Id": 11, "Name": "app"}],
        "/api/stacks/11/file": {"StackFileContent": "API_TOKEN=glpat-abcdefghijklmnopqrst"},
        "/api/endpoints/2/docker/containers/abc/json": {"Config": {"Env": ["API_TOKEN=glpat-zyxwvutsrqponmlkjihg"]}},
        "/api/endpoints/2/docker/configs": [{"ID": "cfg"}],
        "/api/endpoints/2/docker/configs/cfg": {"Spec": {"Data": "QVBJX1RPS0VOPWdscGF0LWFiY2RlZmdoaWprbG1ub3BxcnN0"}},
        "/api/endpoints/2/docker/secrets": [{"ID": "secret", "Spec": {"Name": "only-metadata"}}],
    }

    def fake_get(_pool, _base, path, **_kwargs):
        calls.append(path)
        assert path in responses
        return HttpResponse(200, __import__("json").dumps(responses[path]).encode(), {})

    monkeypatch.setattr(web_panels, "_get", fake_get)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=100000, discover_time=30, timeout=1, endpoint="2", secure=False),
        host="qa",
        port=9000,
    )
    record = {"status": "valid_credentials", "ui": {"endpoint": "http://qa:9000", "session_token": "token"}}
    inventory = {
        "environments": {"records": [{"Id": 2, "Name": "local"}]},
        "containers": {"records": [{"environment": 2, "Id": "abc"}]},
    }
    collector = DiscoveryCollector("portainer", ctx, record)
    discover_portainer_sources(ctx, record, inventory, collector)
    findings = collector.result()["findings"]
    assert any("stack/11" in item["object_path"] for item in findings)
    assert any("container/abc" in item["object_path"] for item in findings)
    assert "/api/endpoints/2/docker/secrets/secret" not in calls


def test_portainer_discover_without_accessible_environments_is_unavailable(monkeypatch) -> None:
    from redposture_core import web_panels
    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.storage_discovery import discover_portainer_sources

    paths: list[str] = []

    def fake_get(_pool, _base, path, **_kwargs):
        paths.append(path)
        assert path == "/api/stacks"
        return HttpResponse(200, b"[]", {})

    monkeypatch.setattr(web_panels, "_get", fake_get)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=100000, discover_time=30, timeout=1, endpoint=None, secure=False),
        host="qa",
        port=9000,
    )
    record = {"status": "valid_credentials", "ui": {"endpoint": "http://qa:9000", "session_token": "token"}}
    inventory = {"environments": {"records": []}}
    collector = DiscoveryCollector("portainer", ctx, record)
    discover_portainer_sources(ctx, record, inventory, collector)
    result = collector.result()
    assert result["status"] == "unavailable"
    assert any("no_accessible_environments" in reason for reason in result["partial_reasons"])
    assert paths == ["/api/stacks"]
