from __future__ import annotations

import base64
import hashlib
import json
import tarfile
from io import BytesIO
from types import SimpleNamespace
from typing import Any
from zipfile import ZipFile

import pytest

from redposture_core import storage_discovery as storage
from redposture_core.cli_args import parse_args
from redposture_core.data_discovery import render_discovery
from redposture_core.discovery_spool import SpoolingFindings
from redposture_core.discovery_values import DiskBackedText
from redposture_core.storage_discovery import (
    DiscoveryCollector,
    _harbor_repositories,
    _registry_catalog,
    merge_discovery_results,
)


def test_collector_spools_large_total_values_before_count_threshold() -> None:
    context = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("gitlab", context, {"status": "open_no_auth"})
    expected = [f"real-{index}-" + "q" * 120_000 for index in range(3)]
    for index, value in enumerate(expected):
        assert collector.add(f"source-{index}", {"password": value})
    report = collector.result()
    assert isinstance(report["findings"], SpoolingFindings)
    actual = [finding["value"] for finding in report["findings"]]
    assert all(isinstance(value, DiskBackedText) for value in actual)
    assert ["".join(value.iter_text_chunks()) for value in actual] == expected
    assert report["status"] == "complete"


def test_registry_catalog_continues_after_one_hundred_pages() -> None:
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=4096, discover_time=30), host="qa", port=5000)
    collector = DiscoveryCollector("docker-registry", ctx, {"status": "open_no_auth"})
    calls = 0

    def get(_path: str, _cap: int):
        nonlocal calls
        calls += 1
        names = [f"repo-{calls:03d}-{index:02d}" for index in range(100)] if calls <= 101 else []
        return 200, json.dumps({"repositories": names}).encode(), {}, None

    repositories = _registry_catalog(collector, get)
    assert calls == 102
    assert len(repositories) == 10_100
    assert collector.result()["partial_reasons"] == []


def test_harbor_repository_list_continues_after_one_hundred_pages() -> None:
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=4096, discover_time=30), host="qa", port=8080)
    collector = DiscoveryCollector("harbor", ctx, {"status": "open_no_auth"})
    repo_calls = 0

    def get(path: str, _cap: int):
        nonlocal repo_calls
        if path.startswith("/api/v2.0/projects?"):
            return 200, json.dumps([{"name": "qa"}]).encode(), {}, None
        repo_calls += 1
        names = [{"name": f"qa/repo-{repo_calls:03d}-{index:02d}"} for index in range(100)] if repo_calls <= 101 else []
        return 200, json.dumps(names).encode(), {}, None

    repositories = _harbor_repositories(collector, get)
    assert repo_calls == 102
    assert len(repositories) == 10_100
    assert collector.result()["partial_reasons"] == []


def test_storage_modules_expose_discover_without_running_other_actions() -> None:
    for module in ("gitlab", "portainer", "harbor", "nexus", "docker-registry"):
        args = parse_args([module, "-t", "127.0.0.1", "--discover", "--discover-time", "30"])
        assert args.discover is True
        assert args.discover_time == 30
        assert not hasattr(args, "discover_max_bytes")
        assert getattr(args, "execute", None) is None
        assert getattr(args, "download", False) is False


def test_collector_streams_full_findings_and_preserves_partial_reason() -> None:
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
    assert result["findings"][0]["value"] == "glpat-abcdefghijklmnopqrst"
    assert emitted and 'Value="glpat-abcdefghijklmnopqrst"' in "".join(emitted)
    assert result["partial_reasons"] == ["project/demo/history: diff truncated"]


def test_storage_collector_keeps_disk_backed_value_for_final_stream(tmp_path) -> None:
    emitted: list[str] = []
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30), host="qa", port=80, live_emit=lambda lines: emitted.extend(lines)
    )
    with DiskBackedText(directory=tmp_path) as value:
        value.append_text("glpat-" + "Ab0" * 400_000)
        value.finish()
        collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
        collector.add("project/env", {"api_token": value})
        result = collector.result()
        assert result["status"] == "complete"
        assert isinstance(result["findings"], SpoolingFindings)
        restored = result["findings"][0]["value"]
        assert isinstance(restored, DiskBackedText)
        assert (restored.byte_length, restored.digest) == (value.byte_length, value.digest)
        assert "".join(restored.iter_text_chunks()) == "glpat-" + "Ab0" * 400_000
        assert emitted == []


def test_storage_collector_emits_full_disk_value_live_once(tmp_path) -> None:
    emitted: list[str] = []

    def disk_emit(_module, _host, _port, *, finding_type, value, place) -> None:
        emitted.append(f"{finding_type}:{place}:{''.join(value.iter_text_chunks())}")

    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30),
        host="qa",
        port=80,
        live_emit=lambda _lines: None,
        live_discovery_value=disk_emit,
    )
    with DiskBackedText(directory=tmp_path) as value:
        token = "glpat-" + "Ab0" * 40_000
        value.append_text(token)
        value.finish()
        collector = DiscoveryCollector("qdrant", ctx, {"status": "open_no_auth"})
        collector.add("collection.app.point.0", {"api_token": value})
        result = collector.result()
        assert len(emitted) == 1 and emitted[0].endswith(token)
        assert result["live_emitted"] is True
        assert not list(result["findings"].iter_unemitted())


def test_collector_bounds_distinct_partial_reports_without_losing_unavailable_status() -> None:
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
    for index in range(10_000):
        collector.partial(f"project/{index}", "access_denied")
    result = collector.result()
    assert result["status"] == "unavailable"
    assert len(result["partial_reasons"]) <= 65
    assert "additional_partial_reports:9936" in result["partial_reasons"]
    collector.partial("project/10001", "malformed_json")
    assert collector.result()["status"] == "partial"


def test_collector_spools_many_findings_without_losing_list_or_json_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(storage, "FINDING_SPOOL_THRESHOLD", 2)
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
    for index in range(3):
        collector.add(f"object/{index}", f"glpat-{index:020d}")
    collector.add("duplicate", "glpat-00000000000000000000")
    result = collector.result()
    assert isinstance(result["findings"], list)
    assert len(result["findings"]) == 3
    assert bool(result["findings"])
    assert len(json.loads(json.dumps(result))["findings"]) == 3
    assert all(item["value"] == f"glpat-{index:020d}" for index, item in enumerate(result["findings"]))


def test_spooled_live_findings_are_not_rendered_twice(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(storage, "FINDING_SPOOL_THRESHOLD", 2)
    emitted: list[str] = []
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30),
        host="qa",
        port=80,
        live_emit=lambda lines: emitted.extend(lines),
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
    for index in range(3):
        collector.add(f"object/{index}", f"glpat-{index:020d}")
    result = collector.result()
    lines = render_discovery("gitlab", {"host": "qa", "port": 80, "content_discovery": result})
    assert len(emitted) == 3
    assert len(result["emitted_fingerprints"]) == 3
    assert len(lines) == 1
    assert "findings:3" in lines[0]


def test_merge_spooled_and_in_memory_findings_preserves_emission_and_dedup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(storage, "FINDING_SPOOL_THRESHOLD", 1)
    emitted: list[str] = []
    live_ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30), host="qa", port=80, live_emit=lambda lines: emitted.extend(lines)
    )
    live = DiscoveryCollector("gitlab", live_ctx, {"status": "open_no_auth"})
    live.add("one", "glpat-00000000000000000001")
    live.add("two", "glpat-00000000000000000002")
    ordinary_ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=80)
    ordinary = DiscoveryCollector("gitlab", ordinary_ctx, {"status": "open_no_auth"})
    ordinary.add("duplicate", "glpat-00000000000000000001")
    ordinary.add("three", "glpat-00000000000000000003")
    merged = merge_discovery_results(live.result(), ordinary.result())
    assert merged is not None
    assert len(merged["findings"]) == 3
    lines = render_discovery("gitlab", {"host": "qa", "port": 80, "content_discovery": merged})
    assert len(emitted) == 2
    assert len(lines) == 2  # one new finding plus the summary
    assert "findings:3" in lines[-1]


def test_spooled_finding_stays_pending_when_live_output_callback_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(storage, "FINDING_SPOOL_THRESHOLD", 2)
    emitted: list[str] = []

    def live_emit(lines: list[str]) -> None:
        if len(emitted) >= 2:
            raise RuntimeError("output interrupted")
        emitted.extend(lines)

    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=80, live_emit=live_emit)
    collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
    for index in range(2):
        collector.add(f"object/{index}", f"glpat-{index:020d}")
    with pytest.raises(RuntimeError, match="output interrupted"):
        collector.add("object/2", "glpat-00000000000000000002")
    result = collector.result()
    lines = render_discovery("gitlab", {"host": "qa", "port": 80, "content_discovery": result})
    assert len(emitted) == 2
    assert len(lines) == 2
    assert "object/2" in lines[0]


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
    assert 'Value="glpat-abcdefghijklmnopqrst"' in rendered


def test_collector_counts_downloaded_bytes_across_portions() -> None:
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=4, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("nexus", ctx, {"status": "open_no_auth"})
    assert collector.charge(3) is True
    assert collector.charge(2) is True
    assert collector.result()["bytes_read"] == 5
    assert collector.charge(5) is False  # One response still exceeds its portion bound.
    assert collector.result()["status"] == "partial"


def test_default_collector_has_no_300_mb_cumulative_limit() -> None:
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("nexus", ctx, {"status": "open_no_auth"})
    assert collector.charge(200_000_000)
    assert collector.charge(200_000_000)
    assert collector.cap() == 10 * 1024 * 1024
    assert collector.result()["bytes_read"] == 400_000_000
    assert collector.result()["status"] != "partial"


def test_collector_keeps_valid_http_prefix_when_source_times_out() -> None:
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30, discover_max_bytes=1024), host="h", port=1)
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    prefix = b"API_TOKEN=glpat-abcdefghijklmnopqrst\n"
    body = collector.read(
        lambda _path, _cap: (200, prefix, {}, "HTTP response timeout budget exhausted"),
        "/qa/file",
        "project/qa/file",
    )
    assert body == prefix
    collector.add("project/qa/file", body.decode(), charge=False)
    result = collector.result()
    assert result["status"] == "partial"
    assert result["findings"]


def test_collector_scans_downloaded_prefix_after_target_deadline_expires() -> None:
    import time

    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30, discover_max_bytes=1024), host="h", port=1)
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    prefix = b"API_TOKEN=glpat-abcdefghijklmnopqrst\n"

    def timed_out(_path, _cap):
        collector.deadline = time.monotonic() - 1
        return 200, prefix, {}, "HTTP response timeout budget exhausted"

    body = collector.read(timed_out, "/qa/file", "project/qa/file")
    assert body == prefix
    collector.add("project/qa/file", body.decode(), charge=False)
    assert collector.result()["findings"]
    assert collector.result()["status"] == "partial"


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


def test_collector_counts_target_detect_and_auth_time_in_deadline(monkeypatch) -> None:
    from redposture_core import storage_discovery

    monkeypatch.setattr(storage_discovery, "time", SimpleNamespace(monotonic=lambda: 105.0))
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=1000, discover_time=4),
        host="qa",
        port=80,
        discovery_started_at=100.0,
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    assert collector.allowed() is False
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


def test_collector_marks_truncated_transport_and_keeps_only_complete_prefix_finding() -> None:
    body: Any
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=1000, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
    body = collector.read(
        lambda _path, _cap: (
            200,
            b"API_TOKEN=glpat-abcdefghijklmnopqrst\nAPI_TOKEN=glpat-truncated",
            {"x-redposture-truncated": "true"},
            None,
        ),
        "/file",
        "project/demo/file",
    )
    assert body is not None
    assert body == b"API_TOKEN=glpat-abcdefghijklmnopqrst\n"
    collector.add("project/demo/file", body.decode(), charge=False)
    assert collector.result()["status"] == "partial"
    assert {finding["fingerprint"] for finding in collector.result()["findings"]} == {
        collector.result()["findings"][0]["fingerprint"]
    }


def test_collector_does_not_scan_cut_token_without_delimiter() -> None:
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=1000, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
    body = collector.read(
        lambda _path, _cap: (200, b"API_TOKEN=glpat-abcdefghijklmn", {"x-redposture-truncated": "true"}, None),
        "/file",
        "project/demo/file",
    )
    assert body is None
    assert collector.result()["status"] == "partial"
    assert collector.result()["findings"] == []


def test_zip_archive_inspects_file_path_without_extracting_to_disk() -> None:
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=10000, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
    output = BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr("vars/.env", "API_TOKEN=glpat-abcdefghijklmnopqrst")
    collector.scan_archive("project/demo/job/7/artifacts", output.getvalue(), "zip")
    assert "vars/.env" in collector.result()["findings"][0]["object_path"]


def test_archive_member_larger_than_one_portion_is_scanned_in_later_portions() -> None:
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=256, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("harbor", ctx, {"status": "open_no_auth"})
    output = BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr("large/.env", "API_TOKEN=glpat-abcdefghijklmnopqrst\n" * 100)
    collector.scan_archive("image/qa/layer", output.getvalue(), "zip")
    assert collector.result()["status"] == "complete"
    assert any(finding["type"] == "gitlab_token" for finding in collector.result()["findings"])
    assert collector.result()["bytes_read"] > 256


def test_streaming_tar_reaches_later_member_after_oversized_continuous_field() -> None:
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
    assert collector.result()["status"] == "complete"
    assert collector.result()["partial_reasons"] == []
    assert any(finding["type"] == "gitlab_token" for finding in collector.result()["findings"])


def test_streaming_tar_keeps_full_large_assignment_value() -> None:
    archive_bytes = BytesIO()
    token = "glpat-" + "Ab0" * 40_000
    content = ("API_TOKEN=" + token).encode()
    with tarfile.open(fileobj=archive_bytes, mode="w:gz") as archive:
        member = tarfile.TarInfo("app/.env")
        member.size = len(content)
        archive.addfile(member, BytesIO(content))
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=128, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("docker-registry", ctx, {"status": "open_no_auth"})
    collector.scan_archive("image/qa/layer", archive_bytes.getvalue(), "tar")
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert len(result["findings"]) == 1
    assert "".join(result["findings"][0]["value"].iter_text_chunks()) == token


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
        "/api/v4/projects?per_page=100&page=1&simple=true&order_by=id&sort=asc": [
            {"id": 7, "path_with_namespace": "team/app", "namespace": {"id": 4}}
        ],
        "/api/v4/projects/7/repository/branches?per_page=100&page=1": [{"name": "main", "commit": {"id": "c2"}}],
        "/api/v4/projects/7/repository/tree?recursive=true&ref=main&per_page=100&page=1": [
            {"type": "blob", "path": ".env"}
        ],
        "/api/v4/projects/7/repository/commits?all=true&per_page=100&page=1": [{"id": "c1", "parent_ids": []}],
        "/api/v4/projects/7/repository/commits/c1/diff?per_page=100&page=1": [
            {"new_path": "old.env", "old_path": "old.env", "new_file": True}
        ],
        "/api/v4/projects/7/variables?per_page=100&page=1": [
            {"key": "API_TOKEN", "value": "glpat-abcdefghijklmnopqrst"},
            {"key": "QA_PROJECT_PASSWORD", "value": "qa-project-owned-qa-012345abcdef"},
        ],
        "/api/v4/groups/4/variables?per_page=100&page=1": [
            {"key": "QA_GROUP_PASSWORD", "value": "qa-project-owned-qa-a9f720e3c4bd"}
        ],
        "/api/v4/groups/4": {"id": 4, "parent_id": None},
        "/api/v4/projects/7/jobs?per_page=100&page=1": [{"id": 9, "artifacts_file": {"filename": ""}}],
        "/api/v4/projects/7/wikis?with_content=1&per_page=100&page=1": [],
        "/api/v4/projects/7/snippets?per_page=100&page=1": [],
        "/api/v4/projects/7/packages?per_page=100&page=1": [],
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
    for value in ("qa-project-owned-qa-012345abcdef", "qa-project-owned-qa-a9f720e3c4bd"):
        assert sum(finding["value"] == value for finding in result["findings"]) == 1


@pytest.mark.parametrize("budget,expect_multiple", [(512, True), (10_000_000, False)])
def test_gitlab_raw_file_reads_ranges_past_first_portion(monkeypatch, budget: int, expect_multiple: bool) -> None:
    from redposture_core.modules.gitlab import actions
    from redposture_core.storage_discovery import discover_gitlab_sources

    payload = ("ordinary " * 110 + "\nAPI_TOKEN=glpat-abcdefghijklmnopqrst\n").encode()
    assert len(payload) > 512
    ranges: list[str] = []

    def fake(_host, _port, _method, path, _timeout, **kwargs):
        value: Any
        if path == "/api/v4/projects/team%2Fapp":
            value = {"id": 7, "path_with_namespace": "team/app"}
        elif path == "/api/v4/projects/7/repository/branches?per_page=100&page=1":
            value = [{"name": "main"}]
        elif path == "/api/v4/projects/7/repository/tree?recursive=true&ref=main&per_page=100&page=1":
            value = [{"type": "blob", "path": ".env"}]
        elif path == "/api/v4/projects/7/repository/files/.env/raw?ref=main&lfs=true":
            header = kwargs["headers"].get("Range")
            assert header is not None
            ranges.append(header)
            first, last = (int(part) for part in header.split("=")[1].split("-"))
            assert last - first + 1 <= 1024 * 1024
            start = int(header.split("=")[1].split("-")[0])
            end = min(start + kwargs["response_size_cap"], len(payload))
            return (
                206,
                payload[start:end],
                {
                    "content-range": f"bytes {start}-{end - 1}/{len(payload)}",
                    "etag": '"main-file-version"',
                },
                None,
            )
        elif path.endswith("per_page=100&page=1"):
            value = []
        else:
            raise AssertionError(path)
        return 200, json.dumps(value).encode(), {}, None

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=budget, discover_time=30, timeout=1),
        host="qa",
        port=80,
        credential=SimpleNamespace(token="tok"),
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    discover_gitlab_sources(
        ctx, {"token_valid": True, "token_projects": [], "project_filters": ["team/app"]}, collector
    )
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert (len(ranges) > 1) is expect_multiple
    assert sum(item["type"] == "gitlab_token" for item in result["findings"]) == 1


def test_gitlab_job_artifact_reads_verified_ranges_and_scans_zip(monkeypatch) -> None:
    import io
    import zipfile

    from redposture_core.modules.gitlab import actions
    from redposture_core.storage_discovery import discover_gitlab_sources

    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("build/output.txt", "ordinary " * 100 + "\nAPI_TOKEN=glpat-abcdefghijklmnopqrst\n")
    payload = stream.getvalue()
    ranges: list[int] = []

    def fake(_host, _port, _method, path, _timeout, **kwargs):
        value: Any
        if path == "/api/v4/projects/team%2Fapp":
            value = {"id": 7, "path_with_namespace": "team/app"}
        elif path == "/api/v4/projects/7/jobs?per_page=100&page=1":
            value = [{"id": 9, "artifacts_file": {"filename": "build.zip"}}]
        elif path == "/api/v4/projects/7/jobs/9/artifacts":
            header = kwargs["headers"].get("Range")
            assert header is not None
            start = int(header.split("=")[1].split("-")[0])
            ranges.append(start)
            end = min(start + kwargs["response_size_cap"], len(payload))
            return (
                206,
                payload[start:end],
                {
                    "content-range": f"bytes {start}-{end - 1}/{len(payload)}",
                    "etag": '"artifact-version"',
                },
                None,
            )
        elif path == "/api/v4/projects/7/jobs/9/trace":
            return 200, b"ordinary log", {}, None
        elif path.endswith("per_page=100&page=1"):
            value = []
        else:
            raise AssertionError(path)
        return 200, json.dumps(value).encode(), {}, None

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=512, discover_time=30, timeout=1),
        host="qa",
        port=80,
        credential=SimpleNamespace(token="tok"),
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    discover_gitlab_sources(
        ctx, {"token_valid": True, "token_projects": [], "project_filters": ["team/app"]}, collector
    )
    result = collector.result()
    assert len(ranges) > 1
    assert result["status"] == "complete", result["partial_reasons"]
    assert any("build/output.txt" in item["object_path"] for item in result["findings"])


def test_gitlab_large_raw_file_streams_when_range_is_ignored(monkeypatch) -> None:
    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.modules.gitlab import actions
    from redposture_core.storage_discovery import discover_gitlab_sources

    payload = ("ordinary " * 110 + "\nAPI_TOKEN=glpat-abcdefghijklmnopqrst\n").encode()

    def fake(_host, _port, _method, path, _timeout, **kwargs):
        value: Any
        if path == "/api/v4/projects/team%2Fapp":
            value = {"id": 7, "path_with_namespace": "team/app"}
        elif path == "/api/v4/projects/7/repository/branches?per_page=100&page=1":
            value = [{"name": "main"}]
        elif path == "/api/v4/projects/7/repository/tree?recursive=true&ref=main&per_page=100&page=1":
            value = [{"type": "blob", "path": ".env"}]
        elif path == "/api/v4/projects/7/repository/files/.env/raw?ref=main&lfs=true":
            assert kwargs["headers"]["Range"].startswith("bytes=0-")
            return 200, payload[:512], {"x-redposture-truncated": "true"}, None
        elif path.endswith("per_page=100&page=1"):
            value = []
        else:
            raise AssertionError(path)
        return 200, json.dumps(value).encode(), {}, None

    class Pool:
        def request_stream(self, _method, _url, *, on_chunk, chunk_size, **_kwargs):
            assert chunk_size <= 512
            for start in range(0, len(payload), chunk_size):
                on_chunk(payload[start : start + chunk_size])
            return HttpResponse(200, b"", {})

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=512, discover_time=30, timeout=1),
        host="qa",
        port=80,
        credential=SimpleNamespace(token="tok"),
        lifecycle_state=SimpleNamespace(http=Pool()),
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    discover_gitlab_sources(
        ctx, {"token_valid": True, "token_projects": [], "project_filters": ["team/app"]}, collector
    )
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert sum(item["type"] == "gitlab_token" for item in result["findings"]) == 1


def test_gitlab_stream_emits_complete_line_before_body_ends(monkeypatch) -> None:
    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.modules.gitlab import actions
    from redposture_core.storage_discovery import discover_gitlab_sources

    emitted: list[str] = []

    def fake(_host, _port, _method, path, _timeout, **kwargs):
        value: Any
        if path == "/api/v4/projects/team%2Fapp":
            value = {"id": 7, "path_with_namespace": "team/app"}
        elif path == "/api/v4/projects/7/repository/branches?per_page=100&page=1":
            value = [{"name": "main"}]
        elif path == "/api/v4/projects/7/repository/tree?recursive=true&ref=main&per_page=100&page=1":
            value = [{"type": "blob", "path": ".env"}]
        elif path == "/api/v4/projects/7/repository/files/.env/raw?ref=main&lfs=true":
            assert kwargs["headers"]["Range"]
            return 200, b"ordinary " * 64, {"x-redposture-truncated": "true"}, None
        elif path.endswith("per_page=100&page=1"):
            value = []
        else:
            raise AssertionError(path)
        return 200, json.dumps(value).encode(), {}, None

    class Pool:
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {})
            on_chunk(b"API_TOKEN=glpat-abcdefghijklmnopqrst\n")
            assert emitted, "first complete line must appear while response is still open"
            on_chunk(b"ordinary tail\n")
            return HttpResponse(200, b"", {})

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=512, discover_time=30, timeout=1),
        host="qa",
        port=80,
        credential=SimpleNamespace(token="tok"),
        lifecycle_state=SimpleNamespace(http=Pool()),
        live_emit=lambda rows: emitted.extend(rows),
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    discover_gitlab_sources(
        ctx, {"token_valid": True, "token_projects": [], "project_filters": ["team/app"]}, collector
    )
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert sum(item["type"] == "gitlab_token" for item in result["findings"]) == 1


def test_gitlab_stream_interruption_keeps_complete_line_only(monkeypatch) -> None:
    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.modules.gitlab import actions
    from redposture_core.storage_discovery import discover_gitlab_sources

    def fake(_host, _port, _method, path, _timeout, **kwargs):
        value: Any
        if path == "/api/v4/projects/team%2Fapp":
            value = {"id": 7, "path_with_namespace": "team/app"}
        elif path == "/api/v4/projects/7/repository/branches?per_page=100&page=1":
            value = [{"name": "main"}]
        elif path == "/api/v4/projects/7/repository/tree?recursive=true&ref=main&per_page=100&page=1":
            value = [{"type": "blob", "path": ".env"}]
        elif path == "/api/v4/projects/7/repository/files/.env/raw?ref=main&lfs=true":
            assert kwargs["headers"]["Range"]
            return 200, b"ordinary " * 64, {"x-redposture-truncated": "true"}, None
        elif path.endswith("per_page=100&page=1"):
            value = []
        else:
            raise AssertionError(path)
        return 200, json.dumps(value).encode(), {}, None

    class Pool:
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {})
            on_chunk(b"API_TOKEN=glpat-abcdefghijklmnopqrst\n")
            on_chunk(b"API_TOKEN=glpat-abcdef")
            return HttpResponse(200, b"", {}, error="connection lost", truncated=True)

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=512, discover_time=30, timeout=1),
        host="qa",
        port=80,
        credential=SimpleNamespace(token="tok"),
        lifecycle_state=SimpleNamespace(http=Pool()),
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    discover_gitlab_sources(
        ctx, {"token_valid": True, "token_projects": [], "project_filters": ["team/app"]}, collector
    )
    result = collector.result()
    assert result["status"] == "partial"
    assert "connection lost" in result["partial_reasons"][-1]
    assert sum(item["type"] == "gitlab_token" for item in result["findings"]) == 1


def test_streaming_discovery_denial_is_unavailable_without_confirmed_source() -> None:
    from redposture_core.clients.http_api import HttpResponse

    class Pool:
        def request_stream(self, _method, _url, **_kwargs):
            return HttpResponse(403, b"", {})

    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=128, discover_time=30))
    collector = DiscoveryCollector("jenkins", ctx, {"status": "auth_required"})
    assert collector.stream_http_content(Pool(), "http://qa/log", "job/app/log", headers={}, timeout=1) is False
    assert collector.result()["status"] == "unavailable"


def test_gitlab_discover_preserves_project_pagination_error(monkeypatch) -> None:
    from redposture_core.modules.gitlab import actions
    from redposture_core.storage_discovery import discover_gitlab_sources

    monkeypatch.setattr(
        actions,
        "_http_request",
        lambda *_args, **_kwargs: (503, b"", {}, None),
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
        "/api/v4/projects/7/wikis?with_content=1&per_page=100&page=1": [],
        "/api/v4/projects/7/snippets?per_page=100&page=1": [],
        "/api/v4/projects/7/packages?per_page=100&page=1": [],
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


def test_gitlab_discover_retries_oversized_project_page_without_skipping_later_project(monkeypatch) -> None:
    from urllib.parse import parse_qs, urlsplit

    from redposture_core.modules.gitlab import actions
    from redposture_core.storage_discovery import discover_gitlab_sources

    projects = [
        {"id": 7, "path_with_namespace": "team/first", "description": "a" * 80},
        {"id": 8, "path_with_namespace": "team/second", "description": "b" * 80},
    ]
    requested: list[tuple[int, int]] = []

    def fake(_host, _port, _method, path, _timeout, **kwargs):
        cap = kwargs["response_size_cap"]
        if path.startswith("/api/v4/projects?"):
            query = parse_qs(urlsplit(path).query)
            size, page = int(query["per_page"][0]), int(query["page"][0])
            requested.append((size, page))
            rows = projects[(page - 1) * size : page * size]
            body = json.dumps(rows).encode()
            headers = {"x-next-page": str(page + 1) if page * size < len(projects) else ""}
            if len(body) > cap:
                headers["x-redposture-truncated"] = "true"
            return 200, body[:cap], headers, None
        if path == "/api/v4/projects/8/variables?per_page=100&page=1":
            return 200, b'[{"key":"API_TOKEN","value":"glpat-abcdefghijklmnopqrst"}]', {}, None
        return 200, b"[]", {}, None

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30, timeout=1),
        host="qa",
        port=80,
        credential=SimpleNamespace(token="tok"),
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    monkeypatch.setattr(collector, "cap", lambda _maximum: 180)
    discover_gitlab_sources(ctx, {"token_valid": True, "token_projects": None, "project_filters": []}, collector)
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert (1, 2) in requested
    assert {item["value"] for item in result["findings"]} == {"glpat-abcdefghijklmnopqrst"}
    assert len({(item["type"], item["object_path"]) for item in result["findings"]}) == len(result["findings"])


def test_gitlab_discover_streams_single_large_project_and_keeps_group_scope(monkeypatch) -> None:
    from urllib.parse import parse_qs, urlsplit

    from redposture_core.modules.gitlab import actions
    from redposture_core.storage_discovery import discover_gitlab_sources

    project = {
        "id": 7,
        "path_with_namespace": "team/large",
        "namespace": {"id": 4, "kind": "group"},
        "description": "ordinary-" * 100_000,
    }
    streamed: list[str] = []

    def fake(_host, _port, _method, path, _timeout, **kwargs):
        if path.startswith("/api/v4/projects?"):
            query = parse_qs(urlsplit(path).query)
            rows = [project] if int(query["page"][0]) == 1 else []
            body = json.dumps(rows).encode()
            cap = kwargs["response_size_cap"]
            return 200, body[:cap], {"x-redposture-truncated": "true"} if len(body) > cap else {}, None
        if path == "/api/v4/groups/4/variables?per_page=100&page=1":
            return 200, b'[{"key":"API_TOKEN","value":"glpat-abcdefghijklmnopqrst"}]', {}, None
        if path == "/api/v4/groups/4":
            return 200, b"{}", {}, None
        return 200, b"[]", {}, None

    class Pool:
        def request_stream(self, _method, url, **kwargs):
            streamed.append(url)
            assert "per_page=1&page=1" in url
            kwargs["on_response"](200, {})
            body = json.dumps([project]).encode()
            for offset in range(0, len(body), 8191):
                kwargs["on_chunk"](body[offset : offset + 8191])
            return SimpleNamespace(error=None, truncated=False)

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30, timeout=1),
        host="qa",
        port=80,
        credential=SimpleNamespace(token="tok"),
        lifecycle_state=SimpleNamespace(http=Pool()),
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    monkeypatch.setattr(collector, "cap", lambda _maximum: 180)
    discover_gitlab_sources(ctx, {"token_valid": True, "token_projects": None, "project_filters": []}, collector)
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert len(streamed) == 1
    assert {item["value"] for item in result["findings"]} == {"glpat-abcdefghijklmnopqrst"}


def test_gitlab_discover_retries_oversized_variables_page_and_keeps_late_value(monkeypatch) -> None:
    from urllib.parse import parse_qs, urlsplit

    from redposture_core.modules.gitlab import actions
    from redposture_core.storage_discovery import discover_gitlab_sources

    variables = [
        {"key": "ORDINARY", "value": "harmless", "description": "a" * 70},
        {"key": "API_TOKEN", "value": "glpat-abcdefghijklmnopqrst", "description": "b" * 70},
    ]
    variable_pages: list[tuple[int, int]] = []

    def fake(_host, _port, _method, path, _timeout, **kwargs):
        if path.startswith("/api/v4/projects?"):
            return 200, b'[{"id":7,"path_with_namespace":"team/app"}]', {}, None
        if path.startswith("/api/v4/projects/7/variables?"):
            query = parse_qs(urlsplit(path).query)
            size, page = int(query["per_page"][0]), int(query["page"][0])
            variable_pages.append((size, page))
            body = json.dumps(variables[(page - 1) * size : page * size]).encode()
            cap = kwargs["response_size_cap"]
            return 200, body[:cap], {"x-redposture-truncated": "true"} if len(body) > cap else {}, None
        return 200, b"[]", {}, None

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30, timeout=1),
        host="qa",
        port=80,
        credential=SimpleNamespace(token="tok"),
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    monkeypatch.setattr(collector, "cap", lambda _maximum: 180)
    discover_gitlab_sources(ctx, {"token_valid": True, "token_projects": None, "project_filters": []}, collector)
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert (1, 2) in variable_pages
    assert "glpat-abcdefghijklmnopqrst" in {item["value"] for item in result["findings"]}


def test_gitlab_pages_follow_explicit_next_page_after_sparse_page() -> None:
    from urllib.parse import parse_qs, urlsplit

    from redposture_core.storage_discovery import _pages

    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30))
    collector = DiscoveryCollector("gitlab", ctx, {})
    requested: list[str] = []

    def get(path: str, _cap: int):
        requested.append(path)
        if parse_qs(urlsplit(path).query)["page"] == ["1"]:
            return 200, b'[{"id":1}]', {"x-next-page": "2"}, None
        return 200, b'[{"id":2}]', {"x-next-page": ""}, None

    assert list(_pages(collector, get, "/api/v4/projects/7/variables", "variables")) == [
        {"id": 1},
        {"id": 2},
    ]
    assert len(requested) == 2


def test_gitlab_discover_streams_one_large_variable_value_without_truncation(monkeypatch) -> None:
    from urllib.parse import parse_qs, urlsplit

    from redposture_core.modules.gitlab import actions
    from redposture_core.storage_discovery import discover_gitlab_sources

    value = "qa-gitlab-token-" + "A" * 1_200_000
    streamed: list[str] = []

    def fake(_host, _port, _method, path, _timeout, **kwargs):
        if path.startswith("/api/v4/projects?"):
            return 200, b'[{"id":7,"path_with_namespace":"team/app"}]', {}, None
        if path.startswith("/api/v4/projects/7/variables?"):
            query = parse_qs(urlsplit(path).query)
            body = json.dumps([{"key": "API_TOKEN", "value": value}] if int(query["page"][0]) == 1 else []).encode()
            cap = kwargs["response_size_cap"]
            return 200, body[:cap], {"x-redposture-truncated": "true"} if len(body) > cap else {}, None
        return 200, b"[]", {}, None

    class Pool:
        def request_stream(self, _method, url, **kwargs):
            streamed.append(url)
            assert "per_page=1&page=1" in url
            kwargs["on_response"](200, {})
            body = json.dumps([{"key": "API_TOKEN", "value": value}]).encode()
            for offset in range(0, len(body), 8191):
                kwargs["on_chunk"](body[offset : offset + 8191])
            return SimpleNamespace(error=None, truncated=False)

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30, timeout=1),
        host="qa",
        port=80,
        credential=SimpleNamespace(token="tok"),
        lifecycle_state=SimpleNamespace(http=Pool()),
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    monkeypatch.setattr(collector, "cap", lambda _maximum: 180)
    discover_gitlab_sources(ctx, {"token_valid": True, "token_projects": None, "project_filters": []}, collector)
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert len(streamed) == 1
    findings = [item for item in result["findings"] if item["value"] is not None]
    assert len(findings) == 1
    secret = findings[0]["value"]
    assert isinstance(secret, DiskBackedText)
    assert secret.byte_length == len(value)
    assert secret.digest == hashlib.sha256(value.encode()).hexdigest()


def test_gitlab_repeated_streamed_page_is_partial_without_duplicate_finding(monkeypatch) -> None:
    from redposture_core.modules.gitlab import actions
    from redposture_core.storage_discovery import discover_gitlab_sources

    value = "qa-token-" + "AbCd" * 25_000
    body = json.dumps([{"key": "API_TOKEN", "value": value}]).encode()

    def fake(_host, _port, _method, path, _timeout, **kwargs):
        if path.startswith("/api/v4/projects?"):
            return 200, b'[{"id":7,"path_with_namespace":"team/app"}]', {}, None
        if path.startswith("/api/v4/projects/7/variables?"):
            return 200, body[: kwargs["response_size_cap"]], {"x-redposture-truncated": "true"}, None
        return 200, b"[]", {}, None

    class Pool:
        def request_stream(self, _method, _url, **kwargs):
            kwargs["on_response"](200, {})
            for offset in range(0, len(body), 4096):
                kwargs["on_chunk"](body[offset : offset + 4096])
            return SimpleNamespace(error=None, truncated=False)

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30, timeout=1),
        host="qa",
        port=80,
        credential=SimpleNamespace(token="tok"),
        lifecycle_state=SimpleNamespace(http=Pool()),
    )
    collector = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    monkeypatch.setattr(collector, "cap", lambda _maximum: 180)
    discover_gitlab_sources(ctx, {"token_valid": True, "token_projects": None, "project_filters": []}, collector)
    report = collector.result()
    assert report["status"] == "partial"
    assert any("repeated_page" in reason for reason in report["partial_reasons"])
    assert (
        len([item for item in report["findings"] if item["value"].digest == hashlib.sha256(value.encode()).hexdigest()])
        == 1
    )


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


def test_registry_blob_continues_ranged_archive_beyond_one_portion() -> None:
    from redposture_core.storage_discovery import _scan_registry_blob

    archive_bytes = BytesIO()
    with ZipFile(archive_bytes, "w") as archive:
        archive.writestr("safe.txt", "ordinary " * 40)
        archive.writestr("app/.env", "API_TOKEN=glpat-abcdefghijklmnopqrst\n")
    payload = archive_bytes.getvalue()
    assert len(payload) > 64
    ranges: list[tuple[int, int]] = []

    def get(_path: str, _cap: int):
        raise AssertionError("blob must use the ranged reader")

    def get_range(_path: str, cap: int, start: int):
        assert cap <= 64
        end = min(start + cap, len(payload))
        ranges.append((start, end))
        return 206, payload[start:end], {"content-range": f"bytes {start}-{end - 1}/{len(payload)}"}, None

    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=64, discover_time=30), host="qa", port=5000)
    collector = DiscoveryCollector("docker-registry", ctx, {"status": "open_no_auth"})
    _scan_registry_blob(
        collector, get, "team/app", "sha256:layer", "image/team/app/layer", "application/zip", range_getter=get_range
    )
    result = collector.result()
    assert result["status"] == "complete"
    assert len(ranges) > 1
    assert result["bytes_read"] >= len(payload)
    baseline_ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=len(payload) + 1, discover_time=30), host="qa", port=5000
    )
    baseline = DiscoveryCollector("docker-registry", baseline_ctx, {"status": "open_no_auth"})
    baseline.scan_archive("image/team/app/layer", payload, "zip")
    assert [(item["type"], item["fingerprint"]) for item in result["findings"]] == [
        (item["type"], item["fingerprint"]) for item in baseline.result()["findings"]
    ]
    assert sum(item["type"] == "gitlab_token" for item in result["findings"]) == 1


def test_registry_blob_rejects_mismatched_content_range() -> None:
    from redposture_core.storage_discovery import _scan_registry_blob

    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=64, discover_time=30), host="qa", port=5000)
    collector = DiscoveryCollector("docker-registry", ctx, {"status": "open_no_auth"})
    _scan_registry_blob(
        collector,
        lambda _path, _cap: (200, b"", {}, None),
        "team/app",
        "sha256:layer",
        "image/team/app/layer",
        "application/zip",
        range_getter=lambda _path, _cap, _start: (206, b"partial", {"content-range": "bytes 9-15/20"}, None),
    )
    result = collector.result()
    assert result["status"] == "partial"
    assert not result["findings"]


def test_registry_blob_rejects_digest_mismatch_without_reporting_findings() -> None:
    from redposture_core.storage_discovery import _scan_registry_blob

    body = b"API_TOKEN=glpat-abcdefghijklmnopqrst\n"
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=64, discover_time=30), host="qa", port=5000)
    collector = DiscoveryCollector("docker-registry", ctx, {"status": "open_no_auth"})
    _scan_registry_blob(
        collector,
        lambda _path, _cap: (200, body, {}, None),
        "team/app",
        "sha256:" + "0" * 64,
        "image/team/app/config",
        "application/json",
        range_getter=lambda _path, _cap, _start: (200, body, {}, None),
    )
    result = collector.result()
    assert result["status"] == "partial"
    assert result["partial_reasons"] == ["image/team/app/config: digest_mismatch"]
    assert not result["findings"]


@pytest.mark.parametrize(
    ("etags", "complete", "reason"),
    [
        ((None, None), False, "range_identity_unverified"),
        (("same", "same"), True, None),
        (("before", "after"), False, "source_changed_during_ranges"),
    ],
)
def test_mutable_http_ranges_require_stable_identity(etags, complete, reason) -> None:
    import tempfile

    from redposture_core.storage_discovery import _download_http_ranges

    body = b"abcdefgh"
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=4, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("nexus", ctx, {"status": "open_no_auth"})

    def get(_path, cap, start):
        end = min(start + cap, len(body))
        headers = {"content-range": f"bytes {start}-{end - 1}/{len(body)}"}
        if etags[start // 4] is not None:
            headers["etag"] = etags[start // 4]
        return 206, body[start:end], headers, None

    with tempfile.SpooledTemporaryFile() as spool:
        assert _download_http_ranges(collector, get, "/asset", "asset", spool, require_validator=True) is complete
        if complete:
            spool.seek(0)
            assert spool.read() == body
    if reason:
        assert collector.partial_reasons == [f"asset: {reason}"]
    else:
        assert collector.partial_reasons == []


def test_registry_discover_routes_manifest_blob_through_ranges(monkeypatch) -> None:
    from redposture_core.modules.registry import actions
    from redposture_core.storage_discovery import discover_registry_sources

    archive_bytes = BytesIO()
    with ZipFile(archive_bytes, "w") as archive:
        archive.writestr("safe.txt", "ordinary " * 100)
        archive.writestr("app/.env", "API_TOKEN=glpat-abcdefghijklmnopqrst\n")
    payload = archive_bytes.getvalue()
    assert len(payload) > 512
    paths: list[tuple[str, str | None]] = []

    def fake(_host, _port, _method, path, _timeout, **kwargs):
        value: Any
        byte_range = kwargs["headers"].get("Range")
        paths.append((path, byte_range))
        if path.endswith("/blobs/sha256:layer"):
            assert byte_range is not None
            start = int(byte_range.split("=")[1].split("-")[0])
            end = min(start + kwargs["response_size_cap"], len(payload))
            return 206, payload[start:end], {"content-range": f"bytes {start}-{end - 1}/{len(payload)}"}, None
        if path.endswith("/blobs/sha256:cfg"):
            return 200, b'{"config":{"Env":[]}}', {}, None
        if path == "/v2/_catalog?n=100":
            value = {"repositories": ["team/app"]}
        elif path == "/v2/team/app/tags/list?n=100":
            value = {"tags": ["latest"]}
        elif path == "/v2/team/app/manifests/latest":
            value = {
                "config": {"digest": "sha256:cfg"},
                "layers": [{"digest": "sha256:layer", "mediaType": "application/zip"}],
            }
        else:
            raise AssertionError(path)
        return 200, json.dumps(value).encode(), {}, None

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=512, discover_time=30, timeout=1),
        host="qa",
        port=5000,
        credential=SimpleNamespace(username=None, password=None, token=None),
    )
    collector = DiscoveryCollector("docker-registry", ctx, {"status": "open_no_auth"})
    discover_registry_sources(ctx, {"status": "open_no_auth", "is_registry": True}, collector, "docker-registry")
    result = collector.result()
    assert result["partial_reasons"] == []
    assert result["status"] == "complete"
    assert sum(item["type"] == "gitlab_token" for item in result["findings"]) == 1
    assert len([item for item in paths if item[1] is not None]) > 1


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
                                "path": "/builds/2026.02/release-metadata.json",
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
    assert [item["value"] for item in findings] == ["glpat-abcdefghijklmnopqrst"]
    assert all("downloadUrl" not in finding["object_path"] for finding in findings)
    assert all("//builds/2026.02" not in finding["object_path"] for finding in findings)
    assert "/repository/raw-hosted/skip.env" not in paths
    assert not any(path.startswith("/v2/") for path in paths)


def test_nexus_asset_continues_verified_ranges(monkeypatch) -> None:
    import hashlib

    from redposture_core.modules.registry import actions
    from redposture_core.storage_discovery import discover_registry_sources

    archive_bytes = BytesIO()
    with ZipFile(archive_bytes, "w") as archive:
        archive.writestr("safe.txt", "ordinary " * 100)
        archive.writestr("app/.env", "API_TOKEN=glpat-abcdefghijklmnopqrst\n")
    payload = archive_bytes.getvalue()
    assert len(payload) > 512
    checksum = hashlib.sha256(payload).hexdigest()
    ranges: list[str] = []

    def fake(_host, _port, _method, path, _timeout, **kwargs):
        value: Any
        if path == "/service/rest/v1/repositories":
            value = [{"name": "raw-hosted", "format": "raw", "type": "hosted"}]
        elif path == "/service/rest/v1/components?repository=raw-hosted":
            value = {
                "items": [
                    {
                        "assets": [
                            {
                                "path": "release.zip",
                                "downloadUrl": "http://internal:8081/repository/raw-hosted/release.zip",
                                "checksum": {"sha256": checksum},
                            }
                        ]
                    }
                ],
                "continuationToken": None,
            }
        elif path == "/repository/raw-hosted/release.zip":
            header = kwargs["headers"].get("Range")
            assert header is not None
            ranges.append(header)
            start = int(header.split("=")[1].split("-")[0])
            end = min(start + kwargs["response_size_cap"], len(payload))
            return 206, payload[start:end], {"content-range": f"bytes {start}-{end - 1}/{len(payload)}"}, None
        else:
            raise AssertionError(path)
        return 200, json.dumps(value).encode(), {}, None

    monkeypatch.setattr(actions, "_http_request", fake)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=512, discover_time=30, timeout=1, repository="raw-hosted"),
        host="qa",
        port=8081,
        credential=SimpleNamespace(username=None, password=None, token=None),
    )
    collector = DiscoveryCollector("nexus", ctx, {"status": "open_no_auth"})
    discover_registry_sources(
        ctx, {"status": "open_no_auth", "is_nexus": True, "is_registry": True, "probe_status": 404}, collector, "nexus"
    )
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert len(ranges) > 1
    assert sum(item["type"] == "gitlab_token" for item in result["findings"]) == 1


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


@pytest.mark.parametrize("incomplete", [False, True])
def test_portainer_discover_streams_oversized_swarm_config_catalog(monkeypatch, incomplete: bool) -> None:
    from redposture_core import storage_discovery, web_panels
    from redposture_core.clients import http_session
    from redposture_core.clients.http_api import HttpResponse

    catalog_path = "/api/endpoints/2/docker/configs"
    catalog = json.dumps([{"Spec": {"Name": "ordinary-" * 100}, "ID": "cfg-late"}, {"ID": "cfg-late"}]).encode()
    if incomplete:
        catalog = catalog[:-1] + b","
    token = "glpat-abcdefghijklmnopqrst"
    detail = {"Spec": {"Data": base64.b64encode(f"API_TOKEN={token}".encode()).decode()}}
    calls: list[str] = []

    class Pool:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def close(self) -> None:
            pass

        def request_stream(self, _method: str, url: str, *, on_chunk, on_response, **_kwargs):
            assert url.endswith(catalog_path)
            on_response(200, {"content-type": "application/json"})
            for offset in range(0, len(catalog), 37):
                on_chunk(catalog[offset : offset + 37])
            return HttpResponse(200, b"", {"content-type": "application/json"})

    def fake_get(_pool, _base, path: str, **kwargs):
        calls.append(path)
        if path == catalog_path:
            cap = kwargs["response_size_cap"]
            return HttpResponse(200, catalog[:cap], {}, truncated=len(catalog) > cap)
        payload = (
            []
            if path in {"/api/stacks", "/api/endpoints/2/docker/secrets"}
            else detail
            if path == catalog_path + "/cfg-late"
            else None
        )
        assert payload is not None, path
        return HttpResponse(200, json.dumps(payload).encode(), {})

    monkeypatch.setattr(http_session, "HttpSessionPool", Pool)
    monkeypatch.setattr(web_panels, "_get", fake_get)
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30, timeout=1, secure=False), host="qa", port=9000)
    record = {"status": "valid_credentials", "ui": {"endpoint": "http://qa:9000", "session_token": "token"}}
    inventory = {"environments": {"records": [{"Id": 2, "Name": "local"}]}, "containers": {"records": []}}
    collector = DiscoveryCollector("portainer", ctx, record)
    monkeypatch.setattr(collector, "cap", lambda maximum=10 * 1024 * 1024: min(512, maximum))
    storage_discovery.discover_portainer_sources(ctx, record, inventory, collector)

    result = collector.result()
    assert result["status"] == ("partial" if incomplete else "complete"), result["partial_reasons"]
    assert bool(result["partial_reasons"]) is incomplete
    matching = [item for item in result["findings"] if item["value"] == token]
    assert len(matching) == 1, matching
    assert matching[0]["object_path"].endswith("/config/cfg-late/value"), matching
    assert catalog_path + "/cfg-late" in calls
    assert calls.count(catalog_path + "/cfg-late") == 1


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_portainer_discover_streams_oversized_swarm_config_detail(monkeypatch, encoding: str) -> None:
    from redposture_core import storage_discovery, web_panels
    from redposture_core.clients import http_session
    from redposture_core.clients.http_api import HttpResponse

    detail_path = "/api/endpoints/2/docker/configs/cfg-large"
    token = "glpat-abcdefghijklmnopqrst"
    raw_value = ("ordinary-data\n" * 10000 + f"API_TOKEN={token}\n").encode(encoding)
    detail = json.dumps({"ID": "cfg-large", "Spec": {"Data": base64.b64encode(raw_value).decode()}}).encode()
    streamed: list[str] = []

    class Pool:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def close(self) -> None:
            pass

        def request_stream(self, _method: str, url: str, *, on_chunk, on_response, **_kwargs):
            assert url.endswith(detail_path)
            streamed.append(url)
            on_response(200, {"content-type": "application/json"})
            for offset in range(0, len(detail), 37):
                on_chunk(detail[offset : offset + 37])
            return HttpResponse(200, b"", {"content-type": "application/json"})

    def fake_get(_pool, _base, path: str, **kwargs):
        if path == detail_path:
            cap = kwargs["response_size_cap"]
            return HttpResponse(200, detail[:cap], {}, truncated=len(detail) > cap)
        payload = [{"ID": "cfg-large"}] if path == "/api/endpoints/2/docker/configs" else []
        return HttpResponse(200, json.dumps(payload).encode(), {})

    monkeypatch.setattr(http_session, "HttpSessionPool", Pool)
    monkeypatch.setattr(web_panels, "_get", fake_get)
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30, timeout=1, secure=False), host="qa", port=9000)
    record = {"status": "valid_credentials", "ui": {"endpoint": "http://qa:9000", "session_token": "token"}}
    inventory = {"environments": {"records": [{"Id": 2, "Name": "local"}]}, "containers": {"records": []}}
    collector = DiscoveryCollector("portainer", ctx, record)
    monkeypatch.setattr(collector, "cap", lambda maximum=10 * 1024 * 1024: min(256, maximum))

    storage_discovery.discover_portainer_sources(ctx, record, inventory, collector)

    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert [item["value"] for item in result["findings"]] == [token]
    assert result["findings"][0]["object_path"].endswith("/config/cfg-large/value")
    assert streamed == ["http://qa:9000" + detail_path]


def test_portainer_discover_streams_oversized_swarm_secret_metadata(monkeypatch) -> None:
    from redposture_core import storage_discovery, web_panels
    from redposture_core.clients import http_session
    from redposture_core.clients.http_api import HttpResponse

    secret_path = "/api/endpoints/2/docker/secrets"
    token = "glpat-abcdefghijklmnopqrst"
    catalog = json.dumps(
        [{"ID": "secret-a", "Spec": {"Name": "ordinary-" * 100, "Labels": {"api_token": token}}}]
    ).encode()

    class Pool:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def close(self) -> None:
            pass

        def request_stream(self, _method: str, url: str, *, on_chunk, on_response, **_kwargs):
            assert url.endswith(secret_path)
            on_response(200, {"content-type": "application/json"})
            for offset in range(0, len(catalog), 37):
                on_chunk(catalog[offset : offset + 37])
            return HttpResponse(200, b"", {"content-type": "application/json"})

    def fake_get(_pool, _base, path: str, **kwargs):
        if path == secret_path:
            cap = kwargs["response_size_cap"]
            return HttpResponse(200, catalog[:cap], {}, truncated=len(catalog) > cap)
        assert path in {"/api/stacks", "/api/endpoints/2/docker/configs"}, path
        return HttpResponse(200, b"[]", {})

    monkeypatch.setattr(http_session, "HttpSessionPool", Pool)
    monkeypatch.setattr(web_panels, "_get", fake_get)
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30, timeout=1, secure=False), host="qa", port=9000)
    record = {"status": "valid_credentials", "ui": {"endpoint": "http://qa:9000", "session_token": "token"}}
    inventory = {"environments": {"records": [{"Id": 2, "Name": "local"}]}, "containers": {"records": []}}
    collector = DiscoveryCollector("portainer", ctx, record)
    monkeypatch.setattr(collector, "cap", lambda maximum=10 * 1024 * 1024: min(512, maximum))
    storage_discovery.discover_portainer_sources(ctx, record, inventory, collector)

    result = collector.result()
    assert any(item["value"] == token for item in result["findings"])
    assert result["status"] == "partial"
    assert any("secret_values_not_exposed_by_api" in reason for reason in result["partial_reasons"])
    assert not any("response_truncated" in reason for reason in result["partial_reasons"])


def test_portainer_config_value_keeps_generic_finding_without_specific_detector() -> None:
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=9000)
    collector = DiscoveryCollector("portainer", ctx, {"status": "valid_credentials"})
    collector.add(
        "portainer/environment/2/config/cfg/value",
        "API_TOKEN=lab-private-token-abcdefghij",
        prefer_specific=True,
    )
    findings = collector.result()["findings"]
    assert [(item["type"], item["value"]) for item in findings] == [("generic_secret", "lab-private-token-abcdefghij")]


@pytest.mark.parametrize("swarm_state,expected_status", [("inactive", "complete"), ("active", "partial")])
def test_portainer_discover_classifies_swarm_only_503_by_docker_state(
    monkeypatch: pytest.MonkeyPatch, swarm_state: str, expected_status: str
) -> None:
    from redposture_core import web_panels
    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.storage_discovery import discover_portainer_sources

    calls: list[str] = []

    def fake_get(_pool: object, _base: str, path: str, **_kwargs: object) -> HttpResponse:
        calls.append(path)
        if path == "/api/stacks":
            return HttpResponse(200, b"[]", {})
        if path == "/api/endpoints/2/docker/configs":
            return HttpResponse(503, b'{"message":"node is not part of a swarm"}', {})
        if path == "/api/endpoints/2/docker/info":
            return HttpResponse(200, json.dumps({"Swarm": {"LocalNodeState": swarm_state}}).encode(), {})
        if path == "/api/endpoints/2/docker/secrets":
            return HttpResponse(503, b'{"message":"node is not part of a swarm"}', {})
        raise AssertionError(f"unexpected request: {path}")

    monkeypatch.setattr(web_panels, "_get", fake_get)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30, timeout=1, endpoint="2", secure=False),
        host="qa",
        port=9000,
    )
    record = {"status": "valid_credentials", "ui": {"endpoint": "http://qa:9000", "session_token": "token"}}
    inventory = {"environments": {"records": [{"Id": 2, "Name": "local"}]}, "containers": {"records": []}}
    collector = DiscoveryCollector("portainer", ctx, record)
    discover_portainer_sources(ctx, record, inventory, collector)

    result = collector.result()
    assert result["status"] == expected_status
    assert "/api/endpoints/2/docker/info" in calls
    assert ("/api/endpoints/2/docker/secrets" in calls) is (swarm_state == "active")
    if swarm_state == "active":
        assert any("configs: HTTP 503" in reason for reason in result["partial_reasons"])
    else:
        assert result["partial_reasons"] == []


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


def test_portainer_discover_uses_remaining_target_deadline_for_http(monkeypatch) -> None:
    import time

    from redposture_core import web_panels
    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.storage_discovery import discover_portainer_sources

    timeouts: list[float] = []

    def fake_get(_pool, _base, _path, **kwargs):
        timeouts.append(kwargs["timeout"])
        return HttpResponse(200, b"[]", {})

    monkeypatch.setattr(web_panels, "_get", fake_get)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_max_bytes=100000, discover_time=30, timeout=1, endpoint=None, secure=False),
        host="qa",
        port=9000,
    )
    record = {"status": "valid_credentials", "ui": {"endpoint": "http://qa:9000"}}
    collector = DiscoveryCollector("portainer", ctx, record)
    collector.deadline = time.monotonic() + 0.005
    discover_portainer_sources(ctx, record, {"environments": {"records": []}}, collector)
    assert len(timeouts) == 1
    assert 0 < timeouts[0] <= 0.005


def test_authorized_empty_discovery_source_is_complete() -> None:
    from types import SimpleNamespace

    from redposture_core.storage_discovery import DiscoveryCollector

    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=10, discover_max_bytes=1024), host="h", port=1)
    collector = DiscoveryCollector("consul", ctx, {"status": "open_no_auth"})
    collector.mark_accessible_source()
    assert collector.result()["status"] == "complete"


def test_large_spooled_json_keeps_full_nested_value_without_size_partial() -> None:
    value = "qa-json-secret-" + "Ab0" * 400_000
    content = BytesIO(
        json.dumps({"neutral": "x" * 1_200_000, "nested": {"password": value}}, ensure_ascii=False).encode()
    )
    content.seek(0, 2)
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("nexus", ctx, {"status": "open_no_auth"})
    storage._scan_spooled_blob(collector, content, "asset/config.json", "application/json")
    report = collector.result()
    assert report["status"] == "complete", report["partial_reasons"]
    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert isinstance(finding["value"], DiskBackedText)
    assert "".join(finding["value"].iter_text_chunks()) == value
    assert finding["object_path"] == "$.asset/config.json.nested.password"


def test_large_archive_json_keeps_completed_fields_before_corruption() -> None:
    payload = (json.dumps({"password": "qa-first-secret", "note": "x" * 1_200_000})[:-1] + ', "bad":').encode()
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("docker-registry", ctx, {"status": "open_no_auth"})
    collector._scan_member_stream("image/layer", "config.json", BytesIO(payload))
    report = collector.result()
    assert report["status"] == "partial"
    assert any("invalid_json" in reason for reason in report["partial_reasons"])
    assert [item["value"] for item in report["findings"]] == ["qa-first-secret"]


def test_merge_spools_large_total_values_from_individually_small_collectors() -> None:
    reports = []
    for index in range(3):
        ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=80)
        collector = DiscoveryCollector("portainer", ctx, {"status": "open_no_auth"})
        collector.add(f"source-{index}", {"password": f"qa-{index}-" + "q" * 120000})
        reports.append(collector.result())
    merged = merge_discovery_results(*reports)
    assert isinstance(merged["findings"], SpoolingFindings)
    assert len(merged["findings"]) == 3
    assert merged["status"] == "complete"
