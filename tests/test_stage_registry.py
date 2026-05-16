from __future__ import annotations

import argparse
import io
import json
import urllib.error
from types import SimpleNamespace

import pytest

from redposture_core import stage_registry as registry
from redposture_core.console import Console


def test_human_bytes_and_path_helpers() -> None:
    assert registry._human_bytes(None) == "-"
    assert registry._human_bytes(10) == "10B"
    assert registry._human_bytes(1024) == "1.0KB"
    assert registry._normalize_path("v2") == "/v2"
    assert registry._normalize_path("") == "/"


def test_slug_quote_and_reference_helpers() -> None:
    assert registry._safe_slug("group/app name") == "group_app_name"
    assert registry._quote_repo("group/app") == "group/app"
    assert registry._quote_ref("sha256:abc") == "sha256:abc"


def test_parse_link_next_extracts_relative_next_path() -> None:
    header = '<https://registry.local/v2/_catalog?n=1000&last=a>; rel="next"'
    assert registry._parse_link_next(header) == "/v2/_catalog?n=1000&last=a"
    assert registry._parse_link_next(None) is None


def test_image_reference_helpers() -> None:
    assert registry._split_image_reference("repo/app:1.0") == ("repo/app", "1.0")
    assert registry._split_image_reference("repo/app@sha256:abc") == ("repo/app", "sha256:abc")
    assert registry._split_image_reference("repo/app") == ("repo/app", "latest")

    assert registry._display_image("repo/app", "latest") == "repo/app:latest"
    assert registry._display_image("repo/app", "sha256:abc") == "repo/app@sha256:abc"


def test_pick_latest_tag_prefers_latest() -> None:
    assert registry._pick_latest_tag(["1.0", "latest", "2.0"]) == "latest"
    assert registry._pick_latest_tag(["1.0", "2.0"]) == "2.0"
    assert registry._pick_latest_tag([]) is None


def test_parse_www_authenticate() -> None:
    scheme, params = registry._parse_www_authenticate(
        'Bearer realm="https://auth.local/token",service="registry",scope="registry:catalog:*"'
    )
    assert scheme == "bearer"
    assert params["realm"] == "https://auth.local/token"
    assert params["service"] == "registry"


def test_error_and_auth_helpers() -> None:
    assert registry._friendly_error_text("[Errno 61] Connection refused") == (
        "connection refused (service is not listening on target port)"
    )
    assert registry._friendly_error_text("[Errno 8] nodename nor servname provided") == "dns lookup failed"
    assert registry._friendly_error_from_exception(urllib.error.URLError(TimeoutError("timed out"))) == (
        "connection timeout"
    )
    assert registry._is_connection_timeout_fail_record({"status": "fail", "error": "connection timeout"}) is True
    assert registry._auth_headers(None, None, "tok") == {"Authorization": "Bearer tok"}
    assert registry._auth_headers("alice", "secret", None)["Authorization"].startswith("Basic ")


def test_fetch_registry_catalog_supports_pagination(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_http_request(
        host: str,
        port: int,
        method: str,
        path: str,
        timeout: float,
        *,
        headers: dict[str, str],
        body: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (host, port, method, timeout, headers, body)
        calls.append(path)
        if path == "/v2/_catalog?n=1000":
            return (
                200,
                json.dumps({"repositories": ["repo/b", "repo/a"]}).encode(),
                {"link": '<https://registry.local/v2/_catalog?n=1000&last=repo/b>; rel="next"'},
                None,
            )
        return (200, json.dumps({"repositories": ["repo/c"]}).encode(), {}, None)

    monkeypatch.setattr(registry, "_http_request", fake_http_request)

    repositories, error = registry._fetch_registry_catalog("registry.local", 5000, 1.0, headers={})
    assert error is None
    assert repositories == ["repo/a", "repo/b", "repo/c"]
    assert calls == ["/v2/_catalog?n=1000", "/v2/_catalog?n=1000&last=repo/b"]


def test_build_gitlab_repository_summaries_sorts_and_enriches() -> None:
    summaries = registry._build_gitlab_repository_summaries(
        ["repo/b", "repo/a", "repo/b"],
        {"repo/a": ["2.0", "latest"], "repo/b": ["1.0"]},
        {"repo/a": "2026-03-26T00:00:00Z"},
    )
    assert summaries == [
        {
            "repository": "repo/a",
            "tags": ["2.0", "latest"],
            "tags_count": 2,
            "latest_tag": "latest",
            "last_pushed": "2026-03-26T00:00:00Z",
        },
        {
            "repository": "repo/b",
            "tags": ["1.0"],
            "tags_count": 1,
            "latest_tag": "1.0",
            "last_pushed": None,
        },
    ]


def test_format_detect_record_service_labels() -> None:
    base = {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": "127.0.0.1",
        "port": 5000,
        "is_registry": True,
        "auth_required": False,
    }
    plain = registry._format_detect_record(base, "txt")
    assert "[*] Docker Registry Service" in plain

    gitlab = registry._format_detect_record({**base, "is_gitlab": True}, "txt")
    assert "GitLab Container Registry" in gitlab


def test_format_record_statuses() -> None:
    base = {"host": "127.0.0.1", "port": 5000, "image_count": 2}

    open_line = registry._format_record({**base, "status": "open_no_auth"}, "txt")
    assert "[+] anonymous access (images:2)" in open_line

    valid_token_line = registry._format_record({**base, "status": "valid_credentials", "token_provided": True}, "txt")
    assert "[+] token auth" in valid_token_line

    valid_creds_line = registry._format_record(
        {
            **base,
            "status": "valid_credentials",
            "token_provided": False,
            "provided_username": "admin",
            "provided_password": "admin",
        },
        "txt",
    )
    assert "[+] admin:admin" in valid_creds_line

    auth_required_line = registry._format_record(
        {
            **base,
            "status": "auth_required",
            "token_provided": False,
            "provided_credentials": True,
            "provided_username": "admin",
            "provided_password": "bad",
        },
        "txt",
    )
    assert "[-] admin:bad" in auth_required_line

    not_registry_line = registry._format_record(
        {"host": "127.0.0.1", "port": 5000, "status": "not_registry", "probe_status": 404},
        "txt",
    )
    assert "[-] not a Docker Registry v2 endpoint (status:404)" in not_registry_line

    unknown_line = registry._format_record(
        {"host": "127.0.0.1", "port": 5000, "status": "unknown_auth", "error": "weird"},
        "txt",
    )
    assert "[!] auth status unknown" in unknown_line

    fail_line = registry._format_record(
        {"host": "127.0.0.1", "port": 5000, "status": "fail", "error": "connection timeout"},
        "txt",
    )
    assert "[!] connection failed" in fail_line


def test_format_detail_records_vendor_inventory_and_targeted_views() -> None:
    inventory_record = {
        "host": "127.0.0.1",
        "port": 5000,
        "is_registry": True,
        "debug": True,
        "harbor": True,
        "is_harbor": True,
        "harbor_info": {"harbor_version": "2.12.0"},
        "harbor_projects": ["library"],
        "harbor_repositories": ["library/app"],
        "harbor_artifacts": ["library/app:1.0"],
        "gitlab": True,
        "is_gitlab": True,
        "gitlab_info": {"service": "container_registry", "realm": "https://gitlab.local/jwt/auth"},
        "gitlab_repository_details": [
            {"repository": "group/app", "tags_count": 2, "latest_tag": "latest", "last_pushed": "2026-03-26"}
        ],
        "nexus": True,
        "is_nexus": True,
        "nexus_info": {"version": "3.72.0"},
        "nexus_repository_details": [{"name": "docker-hosted", "type": "hosted", "online": True, "components": 4}],
        "assets": True,
        "nexus_assets": [{"download_url": "http://nexus/a", "checksums": {"sha256": "abc"}}],
    }
    lines = registry._format_detail_records(inventory_record, "txt")
    joined = "\n".join(lines)
    assert "Harbor detected version=2.12.0" in joined
    assert "GitLab Container Registry detected" in joined
    assert "group/app (tags:2) (latest:latest)" in joined
    assert "Nexus Repository detected version=3.72.0" in joined
    assert "downloadUrl=http://nexus/a checksum=sha256:abc" in joined

    targeted_record = {
        "host": "127.0.0.1",
        "port": 5000,
        "is_registry": True,
        "repository": "group/app",
        "tag": "latest",
        "show_tags": True,
        "selected_repository_tags": ["latest", "2.0"],
        "metadata": True,
        "metadata_result": {
            "env": ["A=1"],
            "labels": ["maintainer=ops"],
            "cmd": ["python", "app.py"],
            "suspicious": ["DB_PASSWORD=secret"],
        },
        "inspect": True,
        "inspections": [
            {
                "image": "group/app:latest",
                "layer_count": 2,
                "total_size": 1024,
                "env": ["A=1"],
                "exposed_ports": ["8080/tcp"],
                "labels": ["maintainer=ops"],
                "cmd": ["python", "app.py"],
                "history": ["RUN apk add curl"],
                "suspicious": ["DB_PASSWORD=secret"],
            }
        ],
        "download": True,
        "download_result": {"status": "ok", "path": "/tmp/app.tar", "size": 2048},
    }
    lines = registry._format_detail_records(targeted_record, "txt")
    joined = "\n".join(lines)
    assert "[*] Show Tags group/app" in joined
    assert "[*] Metadata group/app:latest" in joined
    assert "[*] ENV" in joined
    assert "[*] Inspect group/app:latest (layers:2) (size:1.0KB)" in joined
    assert "[+] Download complete path=/tmp/app.tar size=2.0KB" in joined


def test_format_detail_records_json_payloads() -> None:
    record = {
        "timestamp": "2026-03-26T00:00:00Z",
        "host": "127.0.0.1",
        "port": 5000,
        "is_registry": True,
        "show_images": True,
        "images": ["repo/app:1.0"],
        "gitlab": True,
        "is_gitlab": True,
        "gitlab_info": {"service": "container_registry"},
        "nexus": False,
        "harbor": False,
        "inspect": True,
        "image": "repo/app:1.0",
        "inspections": [{"image": "repo/app:1.0"}],
        "download": True,
        "download_result": {"status": "ok", "path": "/tmp/app.tar"},
    }
    payloads = [json.loads(item) for item in registry._format_detail_records(record, "json")]
    assert {item["type"] for item in payloads} == {"images", "harbor", "gitlab", "nexus", "inspect", "download"}


def test_audit_registry_host_open_access_collects_vendor_data_and_downloads(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        registry,
        "_http_request",
        lambda *_args, **_kwargs: (200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, None),
    )
    monkeypatch.setattr(
        registry,
        "_fetch_gitlab_info",
        lambda *_args, **_kwargs: ({"service": "container_registry", "realm": "https://gitlab.local/jwt/auth"}, None),
    )
    monkeypatch.setattr(registry, "_fetch_harbor_info", lambda *_args, **_kwargs: ({"harbor_version": "2.12.0"}, None))
    monkeypatch.setattr(registry, "_fetch_nexus_info", lambda *_args, **_kwargs: ({"version": "3.72.0"}, None))
    monkeypatch.setattr(
        registry,
        "_fetch_nexus_repository_records",
        lambda *_args, **_kwargs: ([{"name": "docker-hosted", "format": "docker", "type": "hosted"}], None),
    )
    monkeypatch.setattr(registry, "_fetch_nexus_components", lambda *_args, **_kwargs: ([{"name": "component"}], None))
    monkeypatch.setattr(
        registry,
        "_extract_nexus_assets",
        lambda _components: [{"download_url": "http://nexus.local/blob", "checksums": {"sha256": "abc"}}],
    )
    monkeypatch.setattr(registry, "_fetch_registry_catalog", lambda *_args, **_kwargs: (["repo/app"], None))
    monkeypatch.setattr(registry, "_fetch_repository_tags", lambda *_args, **_kwargs: (["1.0", "latest"], None))
    monkeypatch.setattr(registry, "_fetch_harbor_projects", lambda *_args, **_kwargs: (["library"], None))
    monkeypatch.setattr(
        registry,
        "_fetch_harbor_repositories",
        lambda *_args, **_kwargs: (["library/app"], None),
    )
    monkeypatch.setattr(
        registry,
        "_fetch_harbor_artifacts",
        lambda *_args, **_kwargs: (["library/app:latest"], None),
    )

    def fake_inspect_image(
        _host: str,
        _port: int,
        repo: str,
        ref: str,
        _timeout: float,
        *,
        headers: dict[str, str] | None = None,
    ):  # type: ignore[no-untyped-def]
        _ = headers
        return {
            "image": f"{repo}:{ref}",
            "repository": repo,
            "reference": ref,
            "created": "2026-03-26T00:00:00Z",
            "env": ["A=1"],
            "labels": ["maintainer=ops"],
            "cmd": ["python", "app.py"],
            "history": ["RUN apk add curl"],
            "suspicious": ["DB_PASSWORD=secret"],
            "layer_count": 2,
            "total_size": 1024,
        }

    monkeypatch.setattr(registry, "_inspect_image", fake_inspect_image)
    monkeypatch.setattr(
        registry,
        "_download_image",
        lambda *_args, **_kwargs: {"status": "ok", "path": "/tmp/app.tar", "size": 2048},
    )

    record = registry._audit_registry_host(
        "127.0.0.1",
        5000,
        1.0,
        0,
        username=None,
        password=None,
        token=None,
        docker=True,
        show_images=True,
        show_tags=True,
        repository="repo/app",
        tag="latest",
        metadata=True,
        harbor=True,
        gitlab=True,
        nexus=True,
        assets=True,
        inspect=True,
        image="repo/app:latest",
        download=True,
        download_dir="/tmp",
        console=Console(),
        debug=True,
    )

    assert record["status"] == "open_no_auth"
    assert record["image_count"] == 2
    assert record["gitlab_repository_details"][0]["repository"] == "repo/app"
    assert record["harbor_artifacts"] == ["library/app:latest"]
    assert record["nexus_assets"][0]["download_url"] == "http://nexus.local/blob"
    assert record["metadata_result"]["image"] == "repo/app:latest"
    assert record["inspections"][0]["repository"] == "repo/app"
    assert record["download_result"]["status"] == "ok"


def test_audit_registry_host_auth_required_without_access_builds_fallback_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        registry,
        "_http_request",
        lambda *_args, **_kwargs: (
            401,
            b'{"errors":[{"message":"unauthorized"}]}',
            {"www-authenticate": 'Bearer realm="https://auth.local/token",service="registry"'},
            None,
        ),
    )
    monkeypatch.setattr(registry, "_fetch_gitlab_info", lambda *_args, **_kwargs: (None, "not gitlab"))
    monkeypatch.setattr(registry, "_fetch_harbor_info", lambda *_args, **_kwargs: (None, "not harbor"))
    monkeypatch.setattr(registry, "_fetch_nexus_info", lambda *_args, **_kwargs: (None, "not nexus"))

    record = registry._audit_registry_host(
        "127.0.0.1",
        5000,
        1.0,
        0,
        username="admin",
        password="bad",
        token=None,
        docker=False,
        show_images=True,
        show_tags=True,
        repository="repo/app",
        tag="latest",
        metadata=True,
        harbor=False,
        gitlab=False,
        nexus=False,
        assets=False,
        inspect=True,
        image="repo/app:latest",
        download=True,
        download_dir="/tmp",
        console=Console(),
        debug=False,
    )

    assert record["status"] == "auth_required"
    assert record["images_error"] is None
    assert record["selected_repository_tags"] is None
    assert record["metadata_result"] is None
    assert record["inspection_error"] is None
    assert record["download_result"] is None


def test_audit_registry_host_marks_non_registry_and_retries_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "_fetch_gitlab_info", lambda *_args, **_kwargs: (None, "not gitlab"))
    monkeypatch.setattr(registry, "_fetch_harbor_info", lambda *_args, **_kwargs: (None, "not harbor"))
    monkeypatch.setattr(registry, "_fetch_nexus_info", lambda *_args, **_kwargs: (None, "not nexus"))
    monkeypatch.setattr(registry, "_http_request", lambda *_args, **_kwargs: (404, b"hello", {}, None))

    not_registry = registry._audit_registry_host(
        "127.0.0.1",
        5000,
        1.0,
        0,
        username=None,
        password=None,
        token=None,
        docker=False,
        show_images=False,
        show_tags=False,
        repository=None,
        tag=None,
        metadata=False,
        harbor=False,
        gitlab=False,
        nexus=False,
        assets=False,
        inspect=False,
        image=None,
        download=False,
        download_dir="/tmp",
        console=Console(),
        debug=False,
    )
    assert not_registry["status"] == "not_registry"
    assert not_registry["probe_status"] == 404

    monkeypatch.setattr(registry, "_http_request", lambda *_args, **_kwargs: (0, b"", {}, "connection refused"))
    monkeypatch.setattr(registry, "_retry_delay", lambda _attempt: 0.0)
    failed = registry._audit_registry_host(
        "127.0.0.1",
        5000,
        1.0,
        1,
        username=None,
        password=None,
        token=None,
        docker=False,
        show_images=False,
        show_tags=False,
        repository=None,
        tag=None,
        metadata=False,
        harbor=False,
        gitlab=False,
        nexus=False,
        assets=False,
        inspect=False,
        image=None,
        download=False,
        download_dir="/tmp",
        console=Console(),
        debug=False,
    )
    assert failed["status"] == "fail"
    assert "connection refused" in str(failed["error"])


def test_audit_registry_host_debug_stage_telemetry(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"count": 0}

    def fake_legacy(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        calls["count"] += 1
        show_images = bool(_kwargs.get("show_images"))
        base = {
            "timestamp": "2026-04-10T00:00:00Z",
            "host": "127.0.0.1",
            "port": 5000,
            "is_registry": True,
            "is_harbor": False,
            "is_gitlab": False,
            "is_nexus": False,
            "status": "open_no_auth",
            "auth_required": False,
            "provided_credentials": False,
            "provided_username": None,
            "provided_password": None,
            "token_provided": False,
            "debug": True,
            "show_images": show_images,
            "docker": False,
            "show_tags": False,
            "repository": None,
            "tag": None,
            "metadata": False,
            "harbor": False,
            "gitlab": False,
            "nexus": False,
            "assets": False,
            "inspect": False,
            "image": None,
            "download": False,
            "image_count": 1 if show_images else None,
            "images": ["repo/app:latest"] if show_images else None,
            "images_error": None,
            "harbor_info": None,
            "harbor_projects": None,
            "harbor_repositories": None,
            "harbor_artifacts": None,
            "harbor_error": None,
            "gitlab_info": None,
            "gitlab_error": None,
            "gitlab_repositories": None,
            "gitlab_repository_details": None,
            "selected_repository_tags": None,
            "metadata_result": None,
            "nexus_info": None,
            "nexus_repositories": None,
            "nexus_repository_details": None,
            "nexus_assets": None,
            "nexus_error": None,
            "inspections": None,
            "inspection_error": None,
            "download_result": None,
            "elapsed_ms": 2,
            "probe_status": 200,
            "error": None,
        }
        return base

    monkeypatch.setattr(registry, "_audit_registry_host_legacy", fake_legacy)

    record = registry._audit_registry_host(
        "127.0.0.1",
        5000,
        1.0,
        0,
        username=None,
        password=None,
        token=None,
        docker=False,
        show_images=True,
        show_tags=False,
        repository=None,
        tag=None,
        metadata=False,
        harbor=False,
        gitlab=False,
        nexus=False,
        assets=False,
        inspect=False,
        image=None,
        download=False,
        download_dir="/tmp",
        console=Console(),
        debug=True,
    )

    assert record["status"] == "open_no_auth"
    assert calls["count"] >= 2
    stage_names = [str(item.get("stage_name") or "") for item in record.get("stages") or [] if isinstance(item, dict)]
    assert "detect_protocol" in stage_names
    assert "auth_inference_credentials" in stage_names
    assert "access_capabilities" in stage_names
    assert "data" in stage_names
    assert any("stage_timing_summary" in str(item) for item in (record.get("debug_events") or []))


def test_audit_registry_targets_two_pass_gate_and_debug_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_call(*_args, run_deep_checks: bool, **_kwargs):  # type: ignore[no-untyped-def]
        host = str(_args[0])
        base = {
            "timestamp": "2026-04-10T00:00:00Z",
            "host": host,
            "port": 5000,
            "is_registry": True,
            "is_harbor": False,
            "is_gitlab": False,
            "is_nexus": False,
            "auth_required": False,
            "provided_credentials": False,
            "provided_username": None,
            "provided_password": None,
            "token_provided": False,
            "debug": False,
            "show_images": False,
            "docker": False,
            "show_tags": False,
            "repository": None,
            "tag": None,
            "metadata": False,
            "harbor": False,
            "gitlab": False,
            "nexus": False,
            "assets": False,
            "inspect": False,
            "image": None,
            "download": False,
            "image_count": None,
            "images": None,
            "images_error": None,
            "harbor_info": None,
            "harbor_projects": None,
            "harbor_repositories": None,
            "harbor_artifacts": None,
            "harbor_error": None,
            "gitlab_info": None,
            "gitlab_error": None,
            "gitlab_repositories": None,
            "gitlab_repository_details": None,
            "selected_repository_tags": None,
            "metadata_result": None,
            "nexus_info": None,
            "nexus_repositories": None,
            "nexus_repository_details": None,
            "nexus_assets": None,
            "nexus_error": None,
            "inspections": None,
            "inspection_error": None,
            "download_result": None,
            "elapsed_ms": 1,
            "probe_status": 200,
            "error": None,
            "stages": [],
            "stage_failed_at": None,
            "stage_durations_ms": {},
            "stage_attempts": {},
            "debug_events": [],
            "debug_events_streamed": False,
        }
        if not run_deep_checks:
            if host == "10.0.0.1":
                return {**base, "status": "open_no_auth"}
            return {**base, "status": "auth_required", "auth_required": True}
        return {**base, "status": "open_no_auth"}

    monkeypatch.setattr(registry, "_call_audit_registry_host_with_thread_debug", fake_call)

    emitted: list[str] = []
    debug_lines: list[str] = []
    totals = registry.audit_registry_targets(
        hosts=["10.0.0.1", "10.0.0.2"],
        port=5000,
        timeout=1.0,
        retries=0,
        workers=2,
        username=None,
        password=None,
        token=None,
        docker=False,
        show_images=False,
        show_tags=False,
        repository=None,
        tag=None,
        metadata=False,
        harbor=False,
        gitlab=False,
        nexus=False,
        assets=False,
        inspect=False,
        image=None,
        download=False,
        download_dir="/tmp",
        output_path=None,
        output_format="txt",
        emit_line=emitted.append,
        logger=None,
        console=Console(),
        debug=False,
        debug_emit=debug_lines.append,
    )

    assert totals == (2, 1, 0, 1, 0, 0)
    assert any("pass=1 detect start total=2" in line for line in debug_lines)
    assert any("pass=2 deep start total=1" in line for line in debug_lines)
    assert any("10.0.0.1:5000 stage2_gate=run reason=status=open_no_auth" in line for line in debug_lines)
    assert any("10.0.0.2:5000 stage2_gate=skip reason=status=auth_required" in line for line in debug_lines)


class _PlainConsole:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def render_tagged_payload_line(self, line: str, tag: str, *, payload_color: str = "white") -> bool:
        self.calls.append((line, tag, payload_color))
        return True


def test_fetch_manifest_payload_and_inspect_image_collects_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_http_request(
        _host: str,
        _port: int,
        _method: str,
        path: str,
        _timeout: float,
        *,
        headers: dict[str, str],
        body: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (headers, body)
        if path.endswith("/manifests/latest"):
            return (
                200,
                json.dumps(
                    {
                        "manifests": [
                            {"digest": "sha256:linux-amd64", "platform": {"os": "linux", "architecture": "amd64"}}
                        ]
                    }
                ).encode(),
                {},
                None,
            )
        if path.endswith("/manifests/sha256:linux-amd64"):
            return (
                200,
                json.dumps(
                    {
                        "config": {"digest": "sha256:cfg", "size": 100},
                        "layers": [
                            {"digest": "sha256:layer1", "mediaType": "application/test", "size": 10},
                            {"digest": "sha256:layer2", "mediaType": "application/test", "size": 20},
                        ],
                    }
                ).encode(),
                {"content-type": "application/vnd.oci.image.manifest.v1+json"},
                None,
            )
        if path.endswith("/blobs/sha256:cfg"):
            return (
                200,
                json.dumps(
                    {
                        "created": "2026-03-27T00:00:00Z",
                        "config": {
                            "Env": ["A=1", "DB_PASSWORD=secret"],
                            "Cmd": ["python", "app.py"],
                            "Labels": {"maintainer": "ops"},
                            "ExposedPorts": {"8080/tcp": {}},
                        },
                        "history": [{"created_by": "RUN apk add curl", "comment": "layer comment"}],
                    }
                ).encode(),
                {},
                None,
            )
        pytest.fail(f"unexpected path: {path}")

    monkeypatch.setattr(registry, "_http_request", fake_http_request)

    manifest_payload, manifest_error = registry._fetch_manifest_payload(
        "registry.local", 5000, "repo/app", "latest", 1.0, headers={}
    )
    assert manifest_error is None
    assert manifest_payload is not None
    assert manifest_payload["resolved_reference"] == "sha256:linux-amd64"

    metadata = registry._inspect_image("registry.local", 5000, "repo/app", "latest", 1.0, headers={})
    assert metadata["image"] == "repo/app:latest"
    assert metadata["repository"] == "repo/app"
    assert metadata["resolved_reference"] == "sha256:linux-amd64"
    assert metadata["config_digest"] == "sha256:cfg"
    assert metadata["layer_count"] == 2
    assert metadata["total_size"] == 130
    assert metadata["created"] == "2026-03-27T00:00:00Z"
    assert metadata["env"] == ["A=1", "DB_PASSWORD=secret"]
    assert metadata["cmd"] == ["python", "app.py"]
    assert metadata["labels"] == ["maintainer=ops"]
    assert metadata["exposed_ports"] == ["8080/tcp"]
    assert metadata["history"] == ["RUN apk add curl | comment=layer comment"]
    assert metadata["suspicious"] == ["DB_PASSWORD=secret"]


def test_vendor_helper_fetchers_cover_harbor_gitlab_and_nexus(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_http_request(
        _host: str,
        _port: int,
        _method: str,
        path: str,
        _timeout: float,
        *,
        headers: dict[str, str],
        body: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (headers, body)
        if path == "/api/v2.0/systeminfo":
            return 200, json.dumps({"harbor_version": "2.12.0"}).encode(), {}, None
        if path == "/api/v2.0/projects?page=1&page_size=200":
            return 200, json.dumps([{"name": "library"}, {"name": "infra"}, {"other": "skip"}]).encode(), {}, None
        if path == "/api/v2.0/projects/library/repositories?page=1&page_size=200":
            return 200, json.dumps([{"name": "library/app"}, {"name": "library/app"}]).encode(), {}, None
        if path == "/api/v2.0/projects/library/repositories/library%2Fapp/artifacts?page=1&page_size=20&with_tag=true":
            return (
                200,
                json.dumps(
                    [{"digest": "sha256:aaa", "tags": [{"name": "1.0"}, {"name": "latest"}]}, {"digest": "sha256:bbb"}]
                ).encode(),
                {},
                None,
            )
        if path == "/jwt/auth?service=container_registry&scope=registry:catalog:*":
            return 200, json.dumps({"token": "jwt-token", "scope": "registry:catalog:*"}).encode(), {}, None
        if path == "/service/rest/v1/status":
            return 200, b"", {}, None
        if path == "/service/rest/v1/repositories":
            return (
                200,
                json.dumps(
                    [
                        {"name": "docker-hosted", "format": "docker", "type": "hosted", "url": "http://nexus/repo"},
                        {"name": "docker-group", "format": "docker", "type": "group", "online": True},
                    ]
                ).encode(),
                {},
                None,
            )
        if path == "/service/rest/v1/components?repository=docker-hosted":
            return (
                200,
                json.dumps(
                    {
                        "items": [
                            {
                                "name": "app",
                                "version": "1.0",
                                "assets": [
                                    {
                                        "path": "app/manifests/1.0",
                                        "downloadUrl": "http://nexus/download",
                                        "checksum": {"sha256": "abc"},
                                    }
                                ],
                            }
                        ],
                        "continuationToken": "next",
                    }
                ).encode(),
                {},
                None,
            )
        if path == "/service/rest/v1/components?repository=docker-hosted&continuationToken=next":
            return 200, json.dumps({"items": [], "continuationToken": None}).encode(), {}, None
        pytest.fail(f"unexpected path: {path}")

    def fake_http_request_url(
        url: str,
        _method: str,
        _timeout: float,
        *,
        headers: dict[str, str],
        body: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (headers, body)
        assert "jwt/auth" in url
        return 200, json.dumps({"access_token": "tok", "expires_in": 60}).encode(), {}, None

    monkeypatch.setattr(registry, "_http_request", fake_http_request)
    monkeypatch.setattr(registry, "_http_request_url", fake_http_request_url)

    harbor_info, harbor_error = registry._fetch_harbor_info("registry.local", 5000, 1.0, headers={})
    assert harbor_error is None
    assert harbor_info == {"harbor_version": "2.12.0"}

    harbor_projects, harbor_projects_error = registry._fetch_harbor_projects("registry.local", 5000, 1.0, headers={})
    assert harbor_projects_error is None
    assert harbor_projects == ["infra", "library"]

    harbor_repos, harbor_repos_error = registry._fetch_harbor_repositories(
        "registry.local", 5000, "library", 1.0, headers={}
    )
    assert harbor_repos_error is None
    assert harbor_repos == ["library/app"]

    harbor_artifacts, harbor_artifacts_error = registry._fetch_harbor_artifacts(
        "registry.local", 5000, "library", "library/app", 1.0, headers={}
    )
    assert harbor_artifacts_error is None
    assert harbor_artifacts == ["library/app:1.0@sha256:aaa", "library/app:latest@sha256:aaa", "library/app@sha256:bbb"]

    fallback_info, fallback_error = registry._fetch_gitlab_info("registry.local", 5000, "", 1.0, headers={}, deep=True)
    assert fallback_error is None
    assert fallback_info["detected_by"] == "jwt_auth_probe"
    assert fallback_info["token_received"] is True

    header_info, header_error = registry._fetch_gitlab_info(
        "registry.local",
        5000,
        'Bearer realm="https://gitlab.local/jwt/auth",service="container_registry"',
        1.0,
        headers={},
        deep=True,
    )
    assert header_error is None
    assert header_info["detected_by"] == "www_authenticate"
    assert header_info["token_probe_status"] == "ok"
    assert header_info["token_received"] is True

    nexus_info, nexus_info_error = registry._fetch_nexus_info("registry.local", 5000, 1.0, headers={})
    assert nexus_info_error is None
    assert nexus_info == {}

    nexus_repos, nexus_repos_error = registry._fetch_nexus_repositories("registry.local", 5000, 1.0, headers={})
    assert nexus_repos_error is None
    assert "docker-hosted (format=docker, type=hosted, url=http://nexus/repo)" in nexus_repos

    nexus_records, nexus_records_error = registry._fetch_nexus_repository_records(
        "registry.local", 5000, 1.0, headers={}
    )
    assert nexus_records_error is None
    assert nexus_records[0]["name"] == "docker-group"
    assert nexus_records[1]["name"] == "docker-hosted"

    components, components_error = registry._fetch_nexus_components(
        "registry.local", 5000, "docker-hosted", 1.0, headers={}
    )
    assert components_error is None
    assets = registry._extract_nexus_assets(components or [])
    assert assets == [
        {
            "component_name": "app",
            "component_version": "1.0",
            "path": "app/manifests/1.0",
            "download_url": "http://nexus/download",
            "checksums": {"sha256": "abc"},
        }
    ]


def test_plain_registry_renderers_and_target_dispatcher(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    console = _PlainConsole()
    assert registry._render_plain_registry_line(console, "REGISTRY\t127.0.0.1\t5000\trepo/app:latest", suspicious=True)
    assert console.calls == [("REGISTRY\t127.0.0.1\t5000\trepo/app:latest", "REGISTRY", "orange")]
    assert registry._looks_like_registry_image_ref("REGISTRY\t127.0.0.1\t5000\trepo/app:latest") is True
    assert registry._looks_like_registry_image_ref("REGISTRY\t127.0.0.1\t5000\trepo/app@sha256:abc") is True
    assert registry._looks_like_registry_data_row("REGISTRY\t127.0.0.1\t5000\tdownloadUrl=http://nexus/a") is True
    assert registry._looks_like_registry_data_row("REGISTRY\t127.0.0.1\t5000\tgitlab/project-api") is True

    def fake_audit_registry_host(*args, **kwargs):  # type: ignore[no-untyped-def]
        _ = (args, kwargs)
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": "127.0.0.1",
            "port": 5000,
            "is_registry": True,
            "status": "open_no_auth",
            "show_images": True,
            "images": ["repo/app:latest"],
            "image_count": 1,
            "show_tags": False,
            "metadata": False,
            "inspect": False,
            "download": False,
            "error": None,
        }

    monkeypatch.setattr(registry, "_audit_registry_host", fake_audit_registry_host)
    output_path = tmp_path / "registry.json"
    emitted: list[str] = []

    totals = registry.audit_registry_targets(
        hosts=["127.0.0.1"],
        port=5000,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        token=None,
        docker=True,
        show_images=True,
        show_tags=False,
        repository=None,
        tag=None,
        metadata=False,
        harbor=False,
        gitlab=False,
        nexus=False,
        assets=False,
        inspect=False,
        image=None,
        download=False,
        download_dir=str(tmp_path),
        output_path=str(output_path),
        output_format="json",
        emit_line=emitted.append,
        logger=None,
        console=Console(),
        debug=False,
    )

    assert totals == (1, 1, 0, 0, 0, 0)
    output_lines = output_path.read_text(encoding="utf-8").splitlines()
    assert len(output_lines) >= 2
    assert any(json.loads(line).get("detected") is True for line in output_lines)
    assert any("repo/app:latest" in line for line in output_lines + emitted)


class _RegistryConsoleCapture:
    instances: list[_RegistryConsoleCapture] = []

    def __init__(self, debug: bool = False) -> None:
        self.debug = debug
        self.messages: list[tuple[str, str]] = []
        type(self).instances.append(self)

    def error(self, message: str) -> None:
        self.messages.append(("error", message))

    def warn(self, message: str) -> None:
        self.messages.append(("warn", message))

    def info(self, message: str) -> None:
        self.messages.append(("info", message))

    def plain(self, message: str, color: str | None = None) -> None:
        _ = color
        self.messages.append(("plain", message))

    def render_tagged_payload_line(self, line: str, tag: str, payload_color: str | None = None) -> bool:
        _ = (line, tag, payload_color)
        return False


def _registry_args(**overrides: object) -> argparse.Namespace:
    data: dict[str, object] = {
        "debug": False,
        "timeout": 1.0,
        "retries": 0,
        "username": None,
        "password": None,
        "token": None,
        "show_tags": False,
        "repository": None,
        "tag": None,
        "metadata": False,
        "assets": False,
        "nexus": False,
        "download": False,
        "image": None,
        "ports": None,
        "port": 5000,
        "docker": False,
        "images": False,
        "harbor": False,
        "gitlab": False,
        "inspect": False,
        "targets": "127.0.0.1",
        "hosts": None,
        "hosts_file": None,
        "output": None,
        "output_format": "txt",
        "workers": 1,
        "download_dir": ".",
    }
    data.update(overrides)
    return argparse.Namespace(**data)


def test_http_request_and_download_error_paths(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    http_error = urllib.error.HTTPError(
        "http://registry.local/v2/",
        401,
        "Unauthorized",
        {"WWW-Authenticate": "Bearer realm=token"},
        io.BytesIO(b'{"errors":[{"code":"UNAUTHORIZED"}]}'),
    )

    def raise_http_error(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise http_error

    monkeypatch.setattr(registry.urllib.request, "urlopen", raise_http_error)
    status, body, headers, error = registry._http_request("registry.local", 5000, "GET", "/v2/", 1.0, headers={})
    assert status == 401 and error is None
    assert b"UNAUTHORIZED" in body
    assert headers.get("www-authenticate", "").startswith("Bearer")

    def raise_url_error(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise urllib.error.URLError(TimeoutError("timed out"))

    monkeypatch.setattr(registry.urllib.request, "urlopen", raise_url_error)
    status, body, headers, error = registry._http_request("registry.local", 5000, "GET", "/v2/", 1.0, headers={})
    assert status == 0 and body == b"" and headers == {}
    assert error == "connection timeout"

    out_file = tmp_path / "blob.bin"
    status, size, error = registry._http_download("registry.local", 5000, "/v2/blob", 1.0, str(out_file), headers={})
    assert status == 0 and size == 0
    assert error == "connection timeout"


def test_registry_catalog_and_tags_error_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_http_request(
        _host: str,
        _port: int,
        _method: str,
        path: str,
        _timeout: float,
        *,
        headers: dict[str, str],
        body: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (headers, body)
        if path == "/v2/_catalog?n=1000":
            return 401, b"", {}, None
        if path.startswith("/v2/repo/tags/list"):
            return 404, b"", {}, None
        return 500, b"oops", {}, None

    monkeypatch.setattr(registry, "_http_request", fake_http_request)
    repos, repos_error = registry._fetch_registry_catalog("registry.local", 5000, 1.0, headers={})
    assert repos is None
    assert repos_error == "authentication required"

    tags, tags_error = registry._fetch_repository_tags("registry.local", 5000, "repo", 1.0, headers={})
    assert tags == []
    assert tags_error is None

    tags2, tags_error2 = registry._fetch_repository_tags("registry.local", 5000, "repo2", 1.0, headers={})
    assert tags2 is None
    assert "returned status 500" in str(tags_error2)


@pytest.mark.parametrize(
    ("overrides", "expected_error"),
    [
        ({"timeout": 0}, "--timeout must be > 0"),
        ({"retries": -1}, "--retries must be >= 0"),
        ({"username": "a"}, "--username and --password must be set together"),
        ({"username": "a", "password": "b", "token": "tok"}, "use either --token or --username/--password, not both"),
        ({"show_tags": True}, "--show-tags requires --repository"),
        ({"tag": "latest"}, "--tag requires --repository"),
        ({"metadata": True, "repository": "repo"}, "--metadata requires --repository and --tag"),
        ({"assets": True}, "--assets requires --nexus"),
        ({"download": True}, "--download requires --image"),
    ],
)
def test_run_registry_stage_validation_errors(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object], expected_error: str
) -> None:
    _RegistryConsoleCapture.instances.clear()
    monkeypatch.setattr(registry, "Console", _RegistryConsoleCapture)
    rc = registry.run_registry_stage(_registry_args(**overrides), logger=object())  # type: ignore[arg-type]
    assert rc == 2
    errors = [msg for level, msg in _RegistryConsoleCapture.instances[-1].messages if level == "error"]
    assert any(expected_error in msg for msg in errors)


def test_run_registry_stage_https_target_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _RegistryConsoleCapture.instances.clear()
    monkeypatch.setattr(registry, "Console", _RegistryConsoleCapture)
    rc = registry.run_registry_stage(_registry_args(targets="https://registry.local:5000/v2/_catalog"), logger=object())  # type: ignore[arg-type]
    assert rc == 2
    errors = [msg for level, msg in _RegistryConsoleCapture.instances[-1].messages if level == "error"]
    assert any("accepts only http:// URL targets" in msg for msg in errors)


def test_run_registry_stage_debug_and_unreachable_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    _RegistryConsoleCapture.instances.clear()
    monkeypatch.setattr(registry, "Console", _RegistryConsoleCapture)

    monkeypatch.setattr(registry, "collect_scan_ports", lambda *_a, **_k: [15000, 15010])
    monkeypatch.setattr(
        registry,
        "collect_scan_target_specs",
        lambda *_a, **_k: [SimpleNamespace(host="127.0.0.1", scheme="", explicit_port=None)],
    )
    monkeypatch.setattr(
        registry,
        "build_scan_execution_groups",
        lambda *_a, **_k: [
            SimpleNamespace(hosts=["127.0.0.1"], port=15000),
            SimpleNamespace(hosts=["127.0.0.1"], port=15010),
        ],
    )
    captured_kwargs: list[dict[str, object]] = []

    def fake_audit_registry_targets(**kwargs):  # type: ignore[no-untyped-def]
        captured_kwargs.append(kwargs)
        # total=1, open=0, valid=0, auth=0, not_registry=0, fail=1
        return 1, 0, 0, 0, 0, 1

    monkeypatch.setattr(registry, "audit_registry_targets", fake_audit_registry_targets)
    rc = registry.run_registry_stage(_registry_args(debug=True, docker=True, images=True), logger=object())  # type: ignore[arg-type]
    assert rc == 0
    assert len(captured_kwargs) == 2
    assert captured_kwargs[0]["port"] == 15000
    assert captured_kwargs[1]["port"] == 15010
    messages = _RegistryConsoleCapture.instances[-1].messages
    assert any(level == "info" and "registry audit started" in msg for level, msg in messages)
    assert any(level == "warn" and "all registry targets are unreachable" in msg for level, msg in messages)


def test_should_download_large_non_tty_and_prompt_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    class _WarnConsole:
        def __init__(self) -> None:
            self.warns: list[str] = []

        def warn(self, message: str) -> None:
            self.warns.append(message)

    console = _WarnConsole()
    monkeypatch.setattr(registry.sys.stdin, "isatty", lambda: False)
    assert registry._should_download_large(1024 * 1024 * 512, "repo/app:latest", console) is False
    assert any("download skipped" in message for message in console.warns)

    monkeypatch.setattr(registry.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")
    assert registry._should_download_large(1024 * 1024 * 512, "repo/app:latest", console) is True

    monkeypatch.setattr("builtins.input", lambda _prompt: "n")
    assert registry._should_download_large(1024 * 1024 * 512, "repo/app:latest", console) is False

    def _raise_eof(_prompt: str) -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", _raise_eof)
    assert registry._should_download_large(1024 * 1024 * 512, "repo/app:latest", console) is False


def test_download_image_success_and_failure_paths(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    console = Console()
    missing_repo = registry._download_image(
        "registry.local",
        5000,
        1.0,
        headers={},
        inspect_data={"image": "repo/app:latest", "repository": ""},
        download_dir=str(tmp_path),
        console=console,
    )
    assert missing_repo["status"] == "fail"

    monkeypatch.setattr(registry, "_should_download_large", lambda *_a, **_k: False)
    skipped = registry._download_image(
        "registry.local",
        5000,
        1.0,
        headers={},
        inspect_data={"image": "repo/app:latest", "repository": "repo/app", "total_size": 999},
        download_dir=str(tmp_path),
        console=console,
    )
    assert skipped["status"] == "skipped"

    monkeypatch.setattr(registry, "_should_download_large", lambda *_a, **_k: True)
    calls: list[str] = []

    def fake_http_download(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        out_path: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, int, str | None]:
        _ = headers
        calls.append(path)
        with open(out_path, "wb") as fh:
            fh.write(b"x")
        return 200, 1, None

    monkeypatch.setattr(registry, "_http_download", fake_http_download)
    success = registry._download_image(
        "registry.local",
        5000,
        1.0,
        headers={},
        inspect_data={
            "image": "repo/app:latest",
            "repository": "repo/app",
            "total_size": 3,
            "manifest_raw": '{"schemaVersion":2}',
            "config_blob": {"arch": "amd64"},
            "config_digest": "sha256:cfg",
            "layers": [{"digest": "sha256:layer1"}, {"digest": "sha256:layer2"}],
        },
        download_dir=str(tmp_path),
        console=console,
    )
    assert success["status"] == "ok"
    assert success["size"] == 3
    assert any("/blobs/sha256:cfg" in item for item in calls)
    assert any("/blobs/sha256:layer1" in item for item in calls)

    def fail_http_download(
        _host: str,
        _port: int,
        path: str,
        _timeout: float,
        _out_path: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, int, str | None]:
        _ = headers
        if path.endswith("sha256:cfg"):
            return 200, 1, None
        if path.endswith("sha256:layer1"):
            return 500, 0, None
        return 0, 0, "broken pipe"

    monkeypatch.setattr(registry, "_http_download", fail_http_download)
    failed = registry._download_image(
        "registry.local",
        5000,
        1.0,
        headers={},
        inspect_data={
            "image": "repo/app:latest",
            "repository": "repo/app",
            "total_size": 3,
            "config_digest": "sha256:cfg",
            "layers": [{"digest": "sha256:layer1"}],
        },
        download_dir=str(tmp_path),
        console=console,
    )
    assert failed["status"] == "fail"
    assert "returned status 500" in str(failed["error"])


def test_fetch_gitlab_info_error_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "_http_request", lambda *_a, **_k: (404, b"", {}, None))
    info, error = registry._fetch_gitlab_info("registry.local", 5000, "", 1.0, headers={}, deep=False)
    assert info is None
    assert error == "not gitlab"

    monkeypatch.setattr(registry, "_http_request", lambda *_a, **_k: (200, b"not-json", {}, None))
    fallback_info, fallback_error = registry._fetch_gitlab_info(
        "registry.local",
        5000,
        "",
        1.0,
        headers={},
        deep=True,
    )
    assert fallback_error is None
    assert fallback_info is not None
    assert fallback_info["token_probe_status"] == "failed"

    deep_info, deep_error = registry._fetch_gitlab_info(
        "registry.local",
        5000,
        'Bearer realm="ftp://gitlab.local/jwt/auth",service="container_registry"',
        1.0,
        headers={},
        deep=True,
    )
    assert deep_error is None
    assert deep_info is not None
    assert deep_info["token_probe_status"] == "skipped"

    monkeypatch.setattr(registry, "_http_request_url", lambda *_a, **_k: (500, b"", {}, None))
    deep_info2, deep_error2 = registry._fetch_gitlab_info(
        "registry.local",
        5000,
        'Bearer realm="https://gitlab.local/jwt/auth",service="container_registry"',
        1.0,
        headers={},
        deep=True,
    )
    assert deep_error2 is None
    assert deep_info2 is not None
    assert deep_info2["token_probe_status"] == "failed"


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (401, b"", "authentication required"),
        (404, b"", "not nexus"),
        (500, b"", "/service/rest/v1/status returned status 500"),
        (200, b"not-json", "nexus status payload is invalid JSON"),
        (200, b"[]", "nexus status payload is invalid"),
    ],
)
def test_fetch_nexus_info_error_paths(monkeypatch: pytest.MonkeyPatch, status: int, body: bytes, expected: str) -> None:
    monkeypatch.setattr(registry, "_http_request", lambda *_a, **_k: (status, body, {}, None))
    info, error = registry._fetch_nexus_info("registry.local", 5000, 1.0, headers={})
    assert info is None
    assert error == expected


def test_fetch_nexus_repositories_error_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "_http_request", lambda *_a, **_k: (200, b"{}", {}, None))
    repos, error = registry._fetch_nexus_repositories("registry.local", 5000, 1.0, headers={})
    assert repos is None
    assert error == "nexus repositories payload is invalid"

    monkeypatch.setattr(
        registry,
        "_http_request",
        lambda *_a, **_k: (
            200,
            b'[{"name":"docker-hosted","format":"docker","type":"hosted"},{"name":"docker-hosted"}]',
            {},
            None,
        ),
    )
    repos2, error2 = registry._fetch_nexus_repositories("registry.local", 5000, 1.0, headers={})
    assert error2 is None
    assert repos2 is not None
    assert any(item.startswith("docker-hosted") for item in repos2)


def test_render_colored_registry_line_paths() -> None:
    class _PaintConsole:
        def __init__(self) -> None:
            self.lines: list[str] = []

        def _paint(self, text: str, color: str, _stream) -> str:  # type: ignore[no-untyped-def]
            return f"<{color}>{text}</{color}>"

        def plain(self, message: str, color: str | None = None) -> None:
            _ = color
            self.lines.append(message)

    console = _PaintConsole()
    assert (
        registry._render_colored_registry_line(
            console,
            "REGISTRY 127.0.0.1 5000 [*] Docker Registry Service (auth required:False) (images:2)",
        )
        is True
    )
    assert console.lines
    assert "cyan" in console.lines[0]
    assert "red" in console.lines[0]
    assert registry._render_colored_registry_line(console, "OTHER\tline") is False


@pytest.mark.parametrize(
    ("status", "body", "headers", "creds", "expected_state"),
    [
        (
            403,
            b'{"errors":[{"message":"authentication required"}]}',
            {"docker-distribution-api-version": "registry/2.0"},
            {"username": None, "password": None},
            "auth_required",
        ),
        (
            200,
            b"{}",
            {"docker-distribution-api-version": "registry/2.0"},
            {"username": "admin", "password": "admin"},
            "valid_credentials",
        ),
        (
            403,
            b'{"errors":[{"message":"forbidden"}]}',
            {"docker-distribution-api-version": "registry/2.0"},
            {"username": None, "password": None},
            "unknown_auth",
        ),
    ],
)
def test_audit_registry_host_legacy_state_matrix(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    body: bytes,
    headers: dict[str, str],
    creds: dict[str, str | None],
    expected_state: str,
) -> None:
    monkeypatch.setattr(registry, "_http_request", lambda *_a, **_k: (status, body, headers, None))
    monkeypatch.setattr(registry, "_fetch_gitlab_info", lambda *_a, **_k: (None, "not gitlab"))
    monkeypatch.setattr(registry, "_fetch_harbor_info", lambda *_a, **_k: (None, "not harbor"))
    monkeypatch.setattr(registry, "_fetch_nexus_info", lambda *_a, **_k: (None, "not nexus"))

    record = registry._audit_registry_host_legacy(
        "127.0.0.1",
        5000,
        1.0,
        0,
        username=creds["username"],
        password=creds["password"],
        token=None,
        docker=False,
        show_images=True,
        show_tags=True,
        repository="repo/app",
        tag="latest",
        metadata=True,
        harbor=False,
        gitlab=False,
        nexus=False,
        assets=False,
        inspect=False,
        image=None,
        download=False,
        download_dir=".",
        console=Console(),
        debug=False,
    )

    assert record["status"] == expected_state
    assert record["is_registry"] is True
    if expected_state != "valid_credentials":
        assert record["images_error"] in {None, "authentication required"}


def test_audit_registry_host_legacy_inspect_and_download_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        registry,
        "_http_request",
        lambda *_a, **_k: (200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, None),
    )
    monkeypatch.setattr(registry, "_fetch_gitlab_info", lambda *_a, **_k: (None, "not gitlab"))
    monkeypatch.setattr(registry, "_fetch_harbor_info", lambda *_a, **_k: (None, "not harbor"))
    monkeypatch.setattr(registry, "_fetch_nexus_info", lambda *_a, **_k: (None, "not nexus"))
    monkeypatch.setattr(registry, "_fetch_registry_catalog", lambda *_a, **_k: ([], None))

    record = registry._audit_registry_host_legacy(
        "127.0.0.1",
        5000,
        1.0,
        0,
        username=None,
        password=None,
        token=None,
        docker=False,
        show_images=False,
        show_tags=False,
        repository=None,
        tag=None,
        metadata=False,
        harbor=False,
        gitlab=False,
        nexus=False,
        assets=False,
        inspect=True,
        image=":bad",
        download=True,
        download_dir=".",
        console=Console(),
        debug=False,
    )
    assert record["status"] == "open_no_auth"
    assert "invalid --image value" in str(record["inspection_error"])
    assert isinstance(record["download_result"], dict)
    assert record["download_result"]["status"] == "fail"


def test_format_detail_records_presence_unknown_and_download_variants() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 5000,
        "is_registry": True,
        "debug": True,
        "show_images": True,
        "images": [],
        "images_error": "catalog unavailable",
        "harbor": True,
        "is_harbor": None,
        "harbor_info": None,
        "harbor_error": "probe failed",
        "gitlab": True,
        "is_gitlab": False,
        "gitlab_error": "",
        "nexus": True,
        "is_nexus": None,
        "nexus_info": None,
        "nexus_error": "nexus probe failed",
        "show_tags": True,
        "repository": "repo/app",
        "selected_repository_tags": [],
        "metadata": True,
        "tag": "latest",
        "metadata_result": {"error": "denied"},
        "inspect": True,
        "inspections": [{"image": "repo/app:latest", "error": "boom"}],
        "inspection_error": "inspect failed",
        "download": True,
        "download_result": {"status": "skipped", "size": 10, "error": "non-interactive"},
        "assets": False,
    }
    lines = registry._format_detail_records(record, "txt")
    text = "\n".join(lines)
    assert "[*] Show Images" in text
    assert "catalog unavailable" in text
    assert "Harbor presence unknown: probe failed" in text
    assert "GitLab Container Registry not detected" in text
    assert "Nexus presence unknown: nexus probe failed" in text
    assert "Metadata repo/app:latest err=denied" in text
    assert "Inspect repo/app:latest err=boom" in text
    assert "Download skipped" in text


def test_audit_registry_host_staged_retry_and_detect_only(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[bool, bool, bool]] = []
    responses = iter(
        [
            {"status": "open_no_auth", "is_registry": True, "error": None},
            {"status": "fail", "is_registry": True, "error": "deep failed"},
            {"status": "open_no_auth", "is_registry": True, "error": None},
            {"status": "open_no_auth", "is_registry": True, "error": None},
        ]
    )

    def fake_legacy(*_args, show_images: bool, show_tags: bool, inspect: bool, **_kwargs):  # type: ignore[no-untyped-def]
        calls.append((show_images, show_tags, inspect))
        try:
            item = dict(next(responses))
        except StopIteration:
            item = {"status": "open_no_auth", "is_registry": True, "error": None}
        item.update(
            {
                "timestamp": "2026-04-10T00:00:00Z",
                "host": "127.0.0.1",
                "port": 5000,
                "is_harbor": False,
                "is_gitlab": False,
                "is_nexus": False,
                "auth_required": False,
                "provided_credentials": False,
                "provided_username": None,
                "provided_password": None,
                "token_provided": False,
                "debug": True,
                "show_images": show_images,
                "docker": False,
                "show_tags": show_tags,
                "repository": None,
                "tag": None,
                "metadata": False,
                "harbor": False,
                "gitlab": False,
                "nexus": False,
                "assets": False,
                "inspect": inspect,
                "image": None,
                "download": False,
                "image_count": 0,
                "images": [],
                "images_error": None,
                "harbor_info": None,
                "harbor_projects": None,
                "harbor_repositories": None,
                "harbor_artifacts": None,
                "harbor_error": None,
                "gitlab_info": None,
                "gitlab_error": None,
                "gitlab_repositories": None,
                "gitlab_repository_details": None,
                "selected_repository_tags": None,
                "metadata_result": None,
                "nexus_info": None,
                "nexus_repositories": None,
                "nexus_repository_details": None,
                "nexus_assets": None,
                "nexus_error": None,
                "inspections": None,
                "inspection_error": None,
                "download_result": None,
                "elapsed_ms": 1,
                "probe_status": 200,
            }
        )
        return item

    monkeypatch.setattr(registry, "_audit_registry_host_legacy", fake_legacy)
    monkeypatch.setattr(registry, "_retry_delay", lambda _i: 0.0)

    record = registry._audit_registry_host(
        "127.0.0.1",
        5000,
        1.0,
        1,
        username=None,
        password=None,
        token=None,
        docker=False,
        show_images=True,
        show_tags=True,
        repository=None,
        tag=None,
        metadata=False,
        harbor=False,
        gitlab=False,
        nexus=False,
        assets=False,
        inspect=True,
        image=None,
        download=False,
        download_dir=".",
        console=Console(),
        debug=True,
        run_deep_checks=True,
    )
    assert record["status"] == "open_no_auth"
    assert record["attempts"] == 2
    assert any("retry_decision stage=data" in event for event in record["debug_events"])

    detect_only = registry._audit_registry_host(
        "127.0.0.1",
        5000,
        1.0,
        0,
        username=None,
        password=None,
        token=None,
        docker=False,
        show_images=False,
        show_tags=False,
        repository=None,
        tag=None,
        metadata=False,
        harbor=False,
        gitlab=False,
        nexus=False,
        assets=False,
        inspect=False,
        image=None,
        download=False,
        download_dir=".",
        console=Console(),
        debug=True,
        run_deep_checks=False,
    )
    assert detect_only["status"] == "open_no_auth"
    assert any("detect-only result=open_no_auth" in event for event in detect_only["debug_events"])


@pytest.mark.parametrize(
    ("status", "body", "expected_error"),
    [
        (401, b"", "authentication required"),
        (404, b"", "not harbor"),
        (500, b"", "/api/v2.0/systeminfo returned status 500"),
        (200, b"not-json", "harbor systeminfo payload is invalid JSON"),
        (200, b"[]", "harbor systeminfo payload is invalid"),
    ],
)
def test_fetch_harbor_info_error_paths(
    monkeypatch: pytest.MonkeyPatch, status: int, body: bytes, expected_error: str
) -> None:
    monkeypatch.setattr(registry, "_http_request", lambda *_a, **_k: (status, body, {}, None))
    info, error = registry._fetch_harbor_info("registry.local", 5000, 1.0, headers={})
    assert info is None
    assert error == expected_error


@pytest.mark.parametrize(
    ("helper_name", "path_fragment"),
    [
        ("_fetch_harbor_projects", "/api/v2.0/projects"),
        ("_fetch_harbor_repositories", "/api/v2.0/projects/library/repositories"),
        ("_fetch_harbor_artifacts", "/api/v2.0/projects/library/repositories/library%2Fapp/artifacts"),
    ],
)
def test_fetch_harbor_collection_helpers_error_paths(
    monkeypatch: pytest.MonkeyPatch, helper_name: str, path_fragment: str
) -> None:
    def fake_http_request(
        _host: str,
        _port: int,
        _method: str,
        path: str,
        _timeout: float,
        *,
        headers: dict[str, str],
        body: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (headers, body)
        assert path_fragment in path
        return 200, b"{}", {}, None

    monkeypatch.setattr(registry, "_http_request", fake_http_request)
    helper = getattr(registry, helper_name)
    if helper_name == "_fetch_harbor_projects":
        result, error = helper("registry.local", 5000, 1.0, headers={})
    elif helper_name == "_fetch_harbor_repositories":
        result, error = helper("registry.local", 5000, "library", 1.0, headers={})
    else:
        result, error = helper("registry.local", 5000, "library", "library/app", 1.0, headers={})
    assert result is None
    assert "payload is invalid" in str(error)


def test_http_request_url_and_render_colored_registry_line_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Resp:
        status = 200
        headers = {"X-Test": "ok"}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:  # type: ignore[no-untyped-def]
            _ = (exc_type, exc, tb)
            return False

        def read(self) -> bytes:
            return b'{"token":"ok"}'

    monkeypatch.setattr(registry.urllib.request, "urlopen", lambda *_a, **_k: _Resp())
    status, body, headers, error = registry._http_request_url("https://auth.local/token", "GET", 1.0, headers={})
    assert status == 200 and error is None
    assert b'"token"' in body and headers["x-test"] == "ok"

    http_error = urllib.error.HTTPError(
        "https://auth.local/token",
        401,
        "Unauthorized",
        {"WWW-Authenticate": 'Bearer realm="x"'},
        io.BytesIO(b'{"errors":[{"message":"unauthorized"}]}'),
    )
    monkeypatch.setattr(registry.urllib.request, "urlopen", lambda *_a, **_k: (_ for _ in ()).throw(http_error))
    status2, body2, headers2, error2 = registry._http_request_url("https://auth.local/token", "GET", 1.0, headers={})
    assert status2 == 401 and error2 is None
    assert b"unauthorized" in body2
    assert "www-authenticate" in headers2

    monkeypatch.setattr(
        registry.urllib.request,
        "urlopen",
        lambda *_a, **_k: (_ for _ in ()).throw(urllib.error.URLError(TimeoutError("timed out"))),
    )
    status3, body3, headers3, error3 = registry._http_request_url("https://auth.local/token", "GET", 1.0, headers={})
    assert status3 == 0 and body3 == b"" and headers3 == {}
    assert error3 == "connection timeout"

    class _ColorConsole:
        def __init__(self) -> None:
            self.lines: list[str] = []

        def _paint(self, text: str, color: str, _stream) -> str:  # type: ignore[no-untyped-def]
            return f"<{color}>{text}</{color}>"

        def plain(self, line: str, color: str | None = None) -> None:
            _ = color
            self.lines.append(line)

    color_console = _ColorConsole()
    rendered = registry._render_colored_registry_line(
        color_console,
        "REGISTRY\t127.0.0.1\t5000\t [*] Docker Registry Service (auth required:True) (images:4)",
    )
    assert rendered is True
    assert color_console.lines and "bright_green" in color_console.lines[0]
    assert registry._render_colored_registry_line(color_console, "OTHER\t127\t5000\t[*] skip") is False


def test_manifest_blob_and_metadata_error_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest_none, manifest_err = registry._fetch_manifest_payload(
        "registry.local",
        5000,
        "repo/app",
        "latest",
        1.0,
        headers={},
        depth=5,
    )
    assert manifest_none is None
    assert manifest_err == "manifest recursion depth exceeded"

    monkeypatch.setattr(registry, "_http_request", lambda *_a, **_k: (200, b"not-json", {}, None))
    manifest_none2, manifest_err2 = registry._fetch_manifest_payload(
        "registry.local",
        5000,
        "repo/app",
        "latest",
        1.0,
        headers={},
    )
    assert manifest_none2 is None
    assert manifest_err2 == "manifest is not valid JSON"

    blob_none, blob_err = registry._fetch_blob_json("registry.local", 5000, "repo/app", "sha256:cfg", 1.0, headers={})
    assert blob_none is None
    assert blob_err == "blob JSON payload is invalid"

    invalid_meta = registry._extract_image_metadata("repo/app", "latest", {"manifest": []})
    assert invalid_meta["error"] == "manifest payload is invalid"
    assert invalid_meta["image"] == "repo/app:latest"


def test_run_registry_stage_debug_file_output_logs_mode(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    _RegistryConsoleCapture.instances.clear()
    monkeypatch.setattr(registry, "Console", _RegistryConsoleCapture)
    monkeypatch.setattr(registry, "collect_scan_ports", lambda *_a, **_k: [5000])
    monkeypatch.setattr(
        registry,
        "collect_scan_target_specs",
        lambda *_a, **_k: [SimpleNamespace(host="127.0.0.1", scheme="", explicit_port=None)],
    )
    monkeypatch.setattr(
        registry,
        "build_scan_execution_groups",
        lambda *_a, **_k: [SimpleNamespace(hosts=["127.0.0.1"], port=5000, scheme_hint=None)],
    )
    monkeypatch.setattr(registry, "audit_registry_targets", lambda **_k: (1, 1, 0, 0, 0, 0))

    out_file = tmp_path / "registry-out.jsonl"
    rc = registry.run_registry_stage(
        _registry_args(
            debug=True,
            output_format="json",
            output=str(out_file),
            token="tok",
            images=True,
            docker=True,
            repository="repo/app",
            show_tags=True,
            tag="latest",
            metadata=True,
            harbor=True,
            gitlab=True,
            nexus=True,
            assets=True,
            inspect=True,
            image="repo/app:latest",
            download=True,
        ),
        logger=object(),  # type: ignore[arg-type]
    )
    assert rc == 0
    infos = [msg for level, msg in _RegistryConsoleCapture.instances[-1].messages if level == "info"]
    assert any("registry audit started" in msg and "format=json" in msg and "output=" in msg for msg in infos)


def test_format_detail_records_branch_matrix_errors_and_download_variants() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 5000,
        "is_registry": True,
        "debug": True,
        "show_images": True,
        "images": [],
        "images_error": "authentication required",
        "harbor": True,
        "is_harbor": None,
        "harbor_error": "probe failed",
        "gitlab": True,
        "is_gitlab": True,
        "gitlab_info": {"token_probe_status": "failed", "token_probe_error": "realm returned status 500"},
        "gitlab_repositories": [],
        "gitlab_repository_details": [],
        "show_tags": True,
        "repository": "repo/app",
        "selected_repository_tags": [],
        "metadata": True,
        "tag": "latest",
        "metadata_result": {"error": "manifest unavailable"},
        "nexus": True,
        "is_nexus": True,
        "nexus_info": {},
        "nexus_repository_details": [],
        "assets": True,
        "nexus_assets": [],
        "nexus_error": "permission denied",
        "inspect": True,
        "image": "repo/app:latest",
        "inspection_error": "inspect failed",
        "inspections": [
            {"image": "repo/app:latest", "error": "manifest denied"},
            {
                "image": "repo/app:2.0",
                "layer_count": 0,
                "total_size": 0,
                "env": [],
                "exposed_ports": [],
                "labels": [],
                "cmd": [],
                "history": [],
                "suspicious": ["TOKEN=secret"],
            },
        ],
        "download": True,
        "download_result": {"status": "skipped", "size": 1024, "error": "download not confirmed"},
    }
    lines = registry._format_detail_records(record, "txt")
    joined = "\n".join(lines)
    assert "[*] Show Images" in joined
    assert "authentication required" in joined
    assert "[!] Harbor presence unknown: probe failed" in joined
    assert "GitLab Container Registry detected" in joined
    assert "GitLab token probe status=failed" in joined
    assert "realm returned status 500" in joined
    assert "[*] Show Tags repo/app" in joined
    assert "repo/app: authentication required" in joined
    assert "Metadata repo/app:latest err=manifest unavailable" in joined
    assert "Nexus Repository detected" in joined
    assert "[*] Nexus Assets" in joined and "<no assets>" in joined
    assert "permission denied" in joined
    assert "inspect failed" in joined
    assert "Inspect repo/app:latest err=manifest denied" in joined
    assert "[*] Inspect repo/app:2.0 (layers:0) (size:0B)" in joined
    assert "[!] Possible Secret Indicators" in joined
    assert "Download skipped size=1.0KB reason=download not confirmed" in joined

    record["download_result"] = {"status": "fail", "error": "layer download failed"}
    lines2 = registry._format_detail_records(record, "txt")
    assert any("Download failed err=layer download failed" in line for line in lines2)


def test_run_registry_stage_multi_port_uses_single_global_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    _RegistryConsoleCapture.instances.clear()
    monkeypatch.setattr(registry, "Console", _RegistryConsoleCapture)
    monkeypatch.setattr(registry, "collect_scan_ports", lambda *_a, **_k: [5000, 5001])
    monkeypatch.setattr(
        registry,
        "collect_scan_target_specs",
        lambda *_a, **_k: [SimpleNamespace(host="127.0.0.1", scheme="", explicit_port=None)],
    )
    monkeypatch.setattr(
        registry,
        "build_scan_execution_groups",
        lambda *_a, **_k: [
            SimpleNamespace(hosts=["127.0.0.1"], port=5000, scheme_hint=None),
            SimpleNamespace(hosts=["127.0.0.1"], port=5001, scheme_hint=None),
        ],
    )

    class _FakeProgress:
        instances: list[_FakeProgress] = []

        def __init__(self, _label: str, total: int, *, enabled: bool = True, leave: bool = True) -> None:
            _ = (enabled, leave)
            self.total = total
            self.advances: list[int] = []
            self.closed = False
            type(self).instances.append(self)

        def advance(self, step: int = 1) -> None:
            self.advances.append(int(step))

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(
        registry,
        "start_command_progress",
        lambda _args, label, total, **kwargs: _FakeProgress(label, total, **kwargs),
    )
    captured: list[dict[str, object]] = []

    def fake_audit(**kwargs):  # type: ignore[no-untyped-def]
        captured.append(kwargs)
        return (len(kwargs["hosts"]), 1, 0, 0, 0, 0)

    monkeypatch.setattr(registry, "audit_registry_targets", fake_audit)

    rc = registry.run_registry_stage(_registry_args(), logger=object())  # type: ignore[arg-type]
    assert rc == 0
    assert len(captured) == 2
    assert all(call["show_progress"] is False for call in captured)
    assert len(_FakeProgress.instances) == 1
    progress = _FakeProgress.instances[0]
    assert progress.total == 2
    assert progress.advances == [1, 1]
    assert progress.closed is True
