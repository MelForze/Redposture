"""Registry bearer, manifest, identity and download paths without remote I/O."""

from __future__ import annotations

import base64
import importlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.registry import actions


@pytest.mark.parametrize("product", ["docker_registry", "harbor", "nexus"])
def test_product_action_facades_use_the_same_verified_registry_implementation(product: str) -> None:
    facade = importlib.import_module(f"redposture_core.modules.{product}.actions")
    assert facade.collect_registry_data is actions.collect_registry_data


@pytest.mark.known_defect_audit
def test_gitlab_blob_download_exchanges_registry_bearer_challenge(tmp_path: Path) -> None:
    """Known defect: manifest reads exchange Bearer tokens, blob downloads do not."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            if self.path.startswith("/token"):
                body = b'{"token":"scoped-qa-token"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path.startswith("/v2/demo/blobs/"):
                if self.headers.get("Authorization") == "Bearer scoped-qa-token":
                    body = b"registry-blob"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(401)
                self.send_header(
                    "WWW-Authenticate",
                    f'Bearer realm="http://127.0.0.1:{self.server.server_port}/token",service="registry",scope="repository:demo:pull"',
                )
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        output = tmp_path / "blob"
        status, size, error = actions._http_download(
            "127.0.0.1",
            server.server_port,
            "/v2/demo/blobs/sha256:abc",
            1,
            str(output),
            headers={"Authorization": "Basic ZGVtbzpwYXNz"},
        )
        assert (status, size, error) == (200, len(b"registry-blob"), None)
        assert output.read_bytes() == b"registry-blob"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


def test_bearer_token_exchange_forwards_basic_only_and_caches_by_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[tuple[str, dict[str, str]]] = []

    class Client:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def get(self, url: str, *, headers: dict[str, str], **_kwargs: object) -> HttpResponse:
            requests.append((url, headers))
            return HttpResponse(200, b'{"token":"scoped-token"}', {})

    monkeypatch.setattr(actions, "HttpApiClient", Client)
    actions._BEARER_TOKEN_CACHE.clear()
    challenge = 'Bearer realm="http://registry.local/token",service="registry",scope="repository:app:pull"'
    try:
        assert actions._fetch_registry_bearer_token(challenge, 1, request_headers={"authorization": "Basic abc"}) == (
            "scoped-token",
            None,
        )
        assert actions._fetch_registry_bearer_token(challenge, 1, request_headers={"authorization": "Basic abc"}) == (
            "scoped-token",
            None,
        )
        assert len(requests) == 1
        assert requests[0][1]["Authorization"] == "Basic abc"
        assert "scope=repository%3Aapp%3Apull" in requests[0][0]
        assert actions._fetch_registry_bearer_token(challenge, 1, request_headers={}) == ("scoped-token", None)
        assert len(requests) == 2
        assert "Authorization" not in requests[1][1]
    finally:
        actions._BEARER_TOKEN_CACHE.clear()


@pytest.mark.parametrize(
    ("challenge", "response", "reason"),
    [
        ('Basic realm="registry"', None, "unsupported"),
        ('Bearer service="registry"', None, "missing realm"),
        ('Bearer realm="file:///tmp/token"', None, "invalid"),
        ('Bearer realm="http://registry.local/token"', HttpResponse(503, b"", {}), "status 503"),
        ('Bearer realm="http://registry.local/token"', HttpResponse(200, b"not-json", {}), "invalid JSON"),
        ('Bearer realm="http://registry.local/token"', HttpResponse(200, b"{}", {}), "did not return"),
        ('Bearer realm="http://registry.local/token"', HttpResponse(0, b"", {}, error="reset"), "reset"),
    ],
)
def test_bearer_token_exchange_reports_specific_failure(
    monkeypatch: pytest.MonkeyPatch, challenge: str, response: HttpResponse | None, reason: str
) -> None:
    class Client:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def get(self, *_args: object, **_kwargs: object) -> HttpResponse:
            assert response is not None
            return response

    monkeypatch.setattr(actions, "HttpApiClient", Client)
    _token, error = actions._fetch_registry_bearer_token(challenge, 1, request_headers={})
    assert error is not None and reason in error


def test_gitlab_registry_basic_requires_a_jwt_with_user_subject(monkeypatch: pytest.MonkeyPatch) -> None:
    challenge = {"www-authenticate": 'Bearer realm="http://gitlab.local/jwt/auth",service="container_registry"'}
    probe = (401, b"", challenge, None)
    token_payload = base64.urlsafe_b64encode(json.dumps({"sub": "alice"}).encode()).decode().rstrip("=")
    token = f"header.{token_payload}.signature"
    calls: list[str] = []

    def request(url: str, _method: str, _timeout: float, **_kwargs: object):
        calls.append(url)
        return 200, json.dumps({"token": token}).encode(), {}, None

    monkeypatch.setattr(actions, "_http_request_url", request)
    assert actions._verify_registry_credential(
        "gitlab", "gitlab.local", 5050, 1, "alice", "password", None, anonymous_probe=probe
    ) == (True, None)
    assert len(calls) == 1 and "service=container_registry" in calls[0]
    monkeypatch.setattr(actions, "_http_request_url", lambda *_args, **_kwargs: (200, b'{"token":"opaque"}', {}, None))
    decision, reason = actions._verify_registry_credential(
        "gitlab", "gitlab.local", 5050, 1, "alice", "password", None, anonymous_probe=probe
    )
    assert decision is None and "does not identify" in str(reason)


def test_manifest_index_selects_linux_amd64_then_reads_suspicious_config(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    index = {
        "manifests": [
            {"digest": "sha256:arm", "platform": {"os": "linux", "architecture": "arm64"}},
            {"digest": "sha256:amd", "platform": {"os": "linux", "architecture": "amd64"}},
        ]
    }
    manifest = {"config": {"digest": "sha256:cfg", "size": 5}, "layers": [{"digest": "sha256:layer", "size": 7}]}
    config = {
        "config": {"Env": ["PASSWORD=secret123"], "Cmd": ["run"], "Labels": {"owner": "qa"}},
        "history": [{"created_by": "echo hello"}],
        "created": "2026-01-01",
    }

    def request(_host: str, _port: int, _method: str, path: str, _timeout: float, **_kwargs: object):
        calls.append(path)
        payload = index if path.endswith("/latest") else config if path.endswith("/sha256:cfg") else manifest
        return 200, json.dumps(payload).encode(), {"content-type": "application/json"}, None

    monkeypatch.setattr(actions, "_http_request", request)
    inspected = actions._inspect_image("registry.local", 5000, "app", "latest", 1, headers={})
    assert inspected["resolved_reference"] == "sha256:amd"
    assert inspected["total_size"] == 12
    assert inspected["env"] == ["PASSWORD=secret123"]
    assert inspected["suspicious"] == ["PASSWORD=secret123"]
    assert not any("sha256:arm" in path for path in calls)


@pytest.mark.parametrize("stage", ["config", "layer", "success"])
def test_download_tracks_partial_bytes_and_writes_only_under_output_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stage: str
) -> None:
    paths: list[str] = []

    def download(_host: str, _port: int, path: str, _timeout: float, output: str, **_kwargs: object):
        paths.append(path)
        if stage == "config" and "cfg" in path:
            return 503, 0, "upstream error"
        if stage == "layer" and "layer" in path:
            return 503, 0, "upstream error"
        Path(output).write_bytes(b"content")
        return 200, 7, None

    monkeypatch.setattr(actions, "_http_download", download)
    inspected = {
        "image": "app:latest",
        "repository": "app",
        "total_size": 12,
        "manifest_raw": "{}",
        "config_blob": {"config": {}},
        "config_digest": "sha256:cfg",
        "layers": [{"digest": "sha256:layer", "size": 7}],
    }
    console = SimpleNamespace(warn=lambda _message: None)
    result = actions._download_image(
        "127.0.0.1", 5000, 1, headers={}, inspect_data=inspected, download_dir=str(tmp_path), console=console
    )
    assert result["status"] == ("ok" if stage == "success" else "fail")
    assert result.get("size") == (14 if stage == "success" else 7 if stage == "layer" else 0)
    assert len(paths) == (1 if stage == "config" else 2)
    assert all(path.startswith("/v2/app/blobs/") for path in paths)
    assert all(path.is_relative_to(tmp_path) for path in tmp_path.rglob("*"))


@pytest.mark.parametrize("fault", ["transport", "auth", "missing", "invalid", "malformed"])
def test_manifest_failures_never_create_image_metadata(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    def request(*_args: object, **_kwargs: object):
        return {
            "transport": (0, b"", {}, "reset"),
            "auth": (401, b"", {}, None),
            "missing": (404, b"", {}, None),
            "invalid": (200, b"not-json", {}, None),
            "malformed": (200, b"[]", {}, None),
        }[fault]

    monkeypatch.setattr(actions, "_http_request", request)
    inspected = actions._inspect_image("registry.local", 5000, "app", "latest", 1, headers={})
    assert inspected["error"]
    assert "layers" not in inspected


@pytest.mark.parametrize("fault", ["transport", "auth", "server", "invalid"])
def test_catalog_and_tag_pagination_preserve_partial_results_after_error(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    calls = 0

    def request(*_args: object, **_kwargs: object):
        nonlocal calls
        calls += 1
        if calls == 1:
            return 200, b'{"repositories":["app"],"tags":["v1"]}', {"link": '</v2/_catalog?page=2>; rel="next"'}, None
        return {
            "transport": (0, b"", {}, "connection reset"),
            "auth": (401, b"", {}, None),
            "server": (503, b"", {}, None),
            "invalid": (200, b"not-json", {}, None),
        }[fault]

    monkeypatch.setattr(actions, "_http_request", request)
    repositories, catalog_error = actions._fetch_registry_catalog("127.0.0.1", 5000, 1, headers={})
    assert repositories == ["app"] and catalog_error and catalog_error.startswith("partial:")
    calls = 0
    tags, tags_error = actions._fetch_repository_tags("127.0.0.1", 5000, "app", 1, headers={})
    assert tags == ["v1"] and tags_error and tags_error.startswith("partial:")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b'{"data":{"appName":"Sonatype Nexus","version":"2.15.1"}}', "2.15.1"),
        (b"<status><data><appName>Sonatype Nexus</appName><version>2.15.1</version></data></status>", "2.15.1"),
        (b'{"data":{"appName":"Foreign","version":"2.15.1"}}', None),
        (b"<status><data></data></status>", None),
        (b"broken-xml", None),
    ],
)
def test_nexus_legacy_status_requires_vendor_and_full_version(raw: bytes, expected: str | None) -> None:
    info = actions._nexus_2_status_info(raw)
    assert (info or {}).get("version") == expected


def test_stage_two_merge_keeps_detection_diagnostics_and_deep_results() -> None:
    merged = actions._merge_stage2_record(
        {
            "host": "127.0.0.1",
            "status": "auth_required",
            "debug_events": ["detect", "", 3],
            "debug_events_streamed": False,
        },
        {
            "status": "valid_credentials",
            "images": ["app:v1"],
            "debug_events": [None, "deep"],
            "debug_events_streamed": True,
        },
    )
    assert merged["host"] == "127.0.0.1"
    assert merged["status"] == "valid_credentials"
    assert merged["images"] == ["app:v1"]
    assert merged["debug_events"] == ["detect", "deep"]
    assert merged["debug_events_streamed"] is True


@pytest.mark.parametrize("code", ["NAME_UNKNOWN", "MANIFEST_UNKNOWN", "UNAUTHORIZED", "OTHER"])
def test_oci_error_payload_only_confirms_registry_specific_codes(code: str) -> None:
    body = json.dumps({"errors": [{"code": code}, "bad", None]}).encode()
    assert actions._registry_probe_has_fingerprint(404, body, {}) is (code in {"NAME_UNKNOWN", "MANIFEST_UNKNOWN"})
