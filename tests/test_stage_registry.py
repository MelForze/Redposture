from __future__ import annotations

import json
import urllib.error

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
    assert record["images_error"] == "authentication required"
    assert record["selected_repository_tags"] is None
    assert record["metadata_result"]["error"] == "cannot fetch metadata without registry access"
    assert record["inspection_error"] == "cannot inspect images without registry access"
    assert record["download_result"]["error"] == "registry access denied"


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
