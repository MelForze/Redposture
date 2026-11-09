"""GitLab discovery continues one large response when Range is ignored."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from types import SimpleNamespace

import pytest

from redposture_core.clients.http_api import http_target_context
from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.discovery_values import DiskBackedText
from redposture_core.storage_discovery import DiscoveryCollector, discover_gitlab_sources, discover_portainer_sources


@pytest.mark.parametrize("prefix", ["", "/gitlab"])
@pytest.mark.parametrize("range_failure", [None, "timed out", "[SSL: WRONG_VERSION_NUMBER] wrong version number"])
def test_gitlab_large_raw_file_is_read_from_one_streaming_response(
    prefix: str, range_failure: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from redposture_core.modules.gitlab import actions

    payload = ("ordinary " * 110 + "\nAPI_TOKEN=glpat-abcdefghijklmnopqrst\n").encode()
    raw_requests: list[str | None] = []
    original_request = actions._http_request

    def request_with_range_timeout(*args, **kwargs):
        if range_failure and "/repository/files/.env/raw" in str(args[3]) and kwargs.get("headers", {}).get("Range"):
            raw_requests.append(kwargs["headers"]["Range"])
            return 0, b"", {}, range_failure
        return original_request(*args, **kwargs)

    monkeypatch.setattr(actions, "_http_request", request_with_range_timeout)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            assert self.path.startswith(prefix + "/api/v4/")
            path = self.path[len(prefix) :]
            if path == "/api/v4/projects/team%2Fapp":
                body = json.dumps({"id": 7, "path_with_namespace": "team/app"}).encode()
            elif path == "/api/v4/projects/7/repository/branches?per_page=100&page=1":
                body = b'[{"name":"main"}]'
            elif path == "/api/v4/projects/7/repository/tree?recursive=true&ref=main&per_page=100&page=1":
                body = b'[{"type":"blob","path":".env"}]'
            elif path == "/api/v4/projects/7/repository/files/.env/raw?ref=main&lfs=true":
                raw_requests.append(self.headers.get("Range"))
                body = payload
            elif path.endswith("per_page=100&page=1"):
                body = b"[]"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with closing(HttpSessionPool(timeout=1)) as pool:
            ctx = SimpleNamespace(
                args=SimpleNamespace(discover_max_bytes=512, discover_time=30, timeout=1),
                host="127.0.0.1",
                port=server.server_address[1],
                credential=SimpleNamespace(token=None),
                lifecycle_state=SimpleNamespace(http=pool),
            )
            collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
            target = SimpleNamespace(scheme="http", path=prefix)
            with http_target_context(target, api_prefixes=("/api/v4",)):
                discover_gitlab_sources(
                    ctx, {"token_valid": False, "public_projects": [], "project_filters": ["team/app"]}, collector
                )
            result = collector.result()
            assert result["status"] == "complete", result["partial_reasons"]
            assert [(item["type"], item["value"]) for item in result["findings"]] == [
                ("gitlab_token", "glpat-abcdefghijklmnopqrst")
            ]
            assert len(raw_requests) == 2 and raw_requests[0] and raw_requests[1] is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_nexus_asset_uses_single_disk_backed_http_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core.modules.registry import actions
    from redposture_core.storage_discovery import discover_registry_sources

    token = "glpat-abcdefghijklmnopqrst"
    payload = b"ordinary-data\n" * 100_000 + f"API_TOKEN={token}\n".encode()
    checksum = hashlib.sha256(payload).hexdigest()
    asset_requests: list[str | None] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            assert self.path == "/repository/raw-hosted/qa-large.env"
            asset_requests.append(self.headers.get("Range"))
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            for offset in range(0, len(payload), 8192):
                self.wfile.write(payload[offset : offset + 8192])

        def log_message(self, *_args: object) -> None:
            pass

    def fake(_host, _port, _method, path, _timeout, **_kwargs):
        body: object
        if path == "/service/rest/v1/repositories":
            body = [{"name": "raw-hosted", "format": "raw", "type": "hosted"}]
        elif path == "/service/rest/v1/components?repository=raw-hosted":
            body = {
                "items": [
                    {
                        "assets": [
                            {
                                "path": "/qa-large.env",
                                "downloadUrl": "http://internal:8081/repository/raw-hosted/qa-large.env",
                                "checksum": {"sha256": checksum},
                            }
                        ]
                    }
                ],
                "continuationToken": None,
            }
        else:
            raise AssertionError(f"buffered asset request: {path}")
        return 200, json.dumps(body).encode(), {}, None

    monkeypatch.setattr(actions, "_http_request", fake)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with closing(HttpSessionPool(timeout=2)) as pool:
            ctx = SimpleNamespace(
                args=SimpleNamespace(discover_time=30, timeout=2, repository="raw-hosted", asset="qa-large.env"),
                host="127.0.0.1",
                port=server.server_address[1],
                credential=SimpleNamespace(username=None, password=None, token=None),
                lifecycle_state=SimpleNamespace(
                    http=pool, scheme="http", host="127.0.0.1", port=server.server_address[1], base_path=""
                ),
            )
            collector = DiscoveryCollector("nexus", ctx, {"status": "open_no_auth"})
            discover_registry_sources(
                ctx, {"status": "open_no_auth", "is_nexus": True, "probe_status": 404}, collector, "nexus"
            )
            result = collector.result()
            assert result["status"] == "complete", result["partial_reasons"]
            assert [item["value"] for item in result["findings"]] == [token]
            assert asset_requests == [None]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


@pytest.mark.parametrize("failure", ["digest", "truncated"])
def test_nexus_asset_stream_failure_keeps_only_prior_completed_findings(failure: str) -> None:
    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.storage_discovery import _download_http_blob_stream

    source = "nexus/repository/raw-hosted/asset/qa.env"
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=8081)
    collector = DiscoveryCollector("nexus", ctx, {"status": "open_no_auth"})
    collector.add("prior/file", {"api_token": "glpat-abcdefghijklmnopqrst"})

    class Pool:
        def request_stream(self, _method: str, _url: str, *, on_response, on_chunk, **_kwargs):
            on_response(200, {"content-length": "80"})
            on_chunk(b"API_TOKEN=glpat-zyxwvutsrqponmlkjihg\n")
            return HttpResponse(200, b"", {}, error="unexpected EOF" if failure == "truncated" else None)

    with BytesIO() as spool:
        assert not _download_http_blob_stream(
            collector,
            Pool(),
            "http://qa/repository/raw-hosted/qa.env",
            source,
            spool,
            headers={},
            timeout=1,
            expected_digest="sha256:" + "0" * 64,
        )
    result = collector.result()
    assert result["status"] == "partial"
    assert any(
        ("digest_mismatch" if failure == "digest" else "unexpected EOF") in reason
        for reason in result["partial_reasons"]
    )
    assert {item["value"] for item in result["findings"]} == {"glpat-abcdefghijklmnopqrst"}


def test_portainer_stack_file_streams_past_one_portion() -> None:
    stack_content = ("ordinary stack line\n" * 100) + "API_TOKEN=glpat-abcdefghijklmnopqrst\n" + "tail\n"
    stack_body = json.dumps({"StackFileContent": stack_content}).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/portainer/api/stacks":
                body = b'[{"Id":11,"Name":"app"}]'
            elif self.path == "/portainer/api/stacks/11/file":
                body = stack_body
            elif self.path in {
                "/portainer/api/endpoints/2/docker/configs",
                "/portainer/api/endpoints/2/docker/secrets",
            }:
                body = b"[]"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        ctx = SimpleNamespace(
            args=SimpleNamespace(discover_max_bytes=512, discover_time=30, timeout=1, secure=False),
            host="127.0.0.1",
            port=server.server_address[1],
        )
        record = {
            "status": "valid_credentials",
            "ui": {"endpoint": f"http://127.0.0.1:{server.server_address[1]}/portainer", "session_token": "qa"},
        }
        inventory = {
            "environments": {"records": [{"Id": 2, "Name": "local"}]},
            "containers": {"records": []},
            "images": {"records": []},
        }
        collector = DiscoveryCollector("portainer", ctx, record)
        discover_portainer_sources(ctx, record, inventory, collector)
        result = collector.result()
        assert result["status"] == "complete", result["partial_reasons"]
        assert sum(item["type"] == "gitlab_token" for item in result["findings"]) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_portainer_large_container_inspect_streams_selected_fields() -> None:
    inspect = {
        "Config": {
            "Env": ["ordinary text " * 100, "API_TOKEN=glpat-abcdefghijklmnopqrst"],
            "password": 123456,
            "Tty": True,
        },
        "GraphDriver": {"Data": {"Ignored": "API_TOKEN=glpat-zyxwvutsrqponmlkjihg"}},
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/api/stacks":
                body = b"[]"
            elif self.path == "/api/endpoints/2/docker/containers/qa-container/json":
                body = json.dumps(inspect).encode()
            elif self.path in {"/api/endpoints/2/docker/configs", "/api/endpoints/2/docker/secrets"}:
                body = b"[]"
            elif self.path.startswith("/api/endpoints/2/docker/containers/qa-container/logs?"):
                body = b""
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        ctx = SimpleNamespace(
            args=SimpleNamespace(discover_max_bytes=512, discover_time=30, timeout=1, secure=False),
            host="127.0.0.1",
            port=server.server_address[1],
        )
        record = {"status": "valid_credentials", "ui": {"endpoint": f"http://127.0.0.1:{ctx.port}"}}
        inventory = {
            "environments": {"records": [{"Id": 2, "Name": "local"}]},
            "containers": {"records": [{"environment": 2, "Id": "qa-container"}]},
            "images": {"records": []},
        }
        collector = DiscoveryCollector("portainer", ctx, record)
        discover_portainer_sources(ctx, record, inventory, collector)
        result = collector.result()
        assert result["status"] == "complete", result["partial_reasons"]
        tokens = [item for item in result["findings"] if item["type"] == "gitlab_token"]
        assert len(tokens) == 1
        assert "Config" in tokens[0]["object_path"]
        assert any("password" in item["object_path"] for item in result["findings"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_portainer_swarm_catalog_streams_through_real_http_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    token = "glpat-abcdefghijklmnopqrst"
    catalog = json.dumps([{"Spec": {"Name": "ordinary-" * 100}, "ID": "cfg-late"}]).encode()
    detail = json.dumps({"Spec": {"Data": base64.b64encode(f"API_TOKEN={token}".encode()).decode()}}).encode()
    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            if self.path == "/portainer/api/endpoints/2/docker/configs":
                body = catalog
            elif self.path == "/portainer/api/endpoints/2/docker/configs/cfg-late":
                body = detail
            elif self.path in {"/portainer/api/stacks", "/portainer/api/endpoints/2/docker/secrets"}:
                body = b"[]"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        ctx = SimpleNamespace(
            args=SimpleNamespace(discover_time=30, timeout=1, secure=False),
            host="127.0.0.1",
            port=server.server_address[1],
        )
        record = {
            "status": "valid_credentials",
            "ui": {"endpoint": f"http://127.0.0.1:{ctx.port}/portainer", "session_token": "qa"},
        }
        inventory = {
            "environments": {"records": [{"Id": 2, "Name": "local"}]},
            "containers": {"records": []},
            "images": {"records": []},
        }
        collector = DiscoveryCollector("portainer", ctx, record)
        monkeypatch.setattr(collector, "cap", lambda maximum=10 * 1024 * 1024: min(512, maximum))
        discover_portainer_sources(ctx, record, inventory, collector)

        result = collector.result()
        assert result["status"] == "complete", result["partial_reasons"]
        assert any(item["value"] == token for item in result["findings"])
        assert requests.count("/portainer/api/endpoints/2/docker/configs") == 2
        assert "/portainer/api/endpoints/2/docker/configs/cfg-late" in requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


@pytest.mark.parametrize("broken_tail", [False, True])
@pytest.mark.parametrize("large_file", [False, True])
def test_portainer_large_stack_catalog_keeps_completed_rows_and_reads_files(monkeypatch, broken_tail, large_file):
    token = "glpat-abcdefghijklmnopqrstuv"
    rows = [{"Id": index, "Name": f"qa-{index}", "Note": "ordinary " * 100} for index in (1, 2, 3)]
    catalog = json.dumps(rows[:2])[:-1].encode() + b',{"Id":' if broken_tail else json.dumps(rows).encode()
    file_requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/portainer/api/stacks":
                body = catalog
            elif self.path.startswith("/portainer/api/stacks/") and self.path.endswith("/file"):
                stack_id = int(self.path.split("/")[-2])
                file_requests.append(stack_id)
                content = f"API_TOKEN={token}\n" if stack_id == 2 else "# ordinary\n"
                if large_file:
                    content = "# ordinary\n" * 200 + content
                body = json.dumps({"StackFileContent": content}).encode()
            else:
                body = b"[]"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        ctx = SimpleNamespace(
            args=SimpleNamespace(discover_time=30, timeout=1, secure=False),
            host="127.0.0.1",
            port=server.server_address[1],
        )
        record = {
            "status": "valid_credentials",
            "ui": {"endpoint": f"http://127.0.0.1:{ctx.port}/portainer", "session_token": "qa"},
        }
        inventory = {
            "environments": {"records": [{"Id": 2, "Name": "local"}]},
            "containers": {"records": []},
            "images": {"records": []},
        }
        collector = DiscoveryCollector("portainer", ctx, record)
        monkeypatch.setattr(collector, "cap", lambda maximum=10 * 1024 * 1024: min(512, maximum))
        discover_portainer_sources(ctx, record, inventory, collector)
        result = collector.result()
        assert result["status"] == ("partial" if broken_tail else "complete"), result["partial_reasons"]
        expected_ids = [1, 2] if broken_tail else [1, 2, 3]
        assert file_requests == [stack_id for stack_id in expected_ids for _ in range(2 if large_file else 1)]
        assert sum(item["value"] == token for item in result["findings"]) == 1
        if broken_tail:
            assert any("invalid_stream" in reason for reason in result["partial_reasons"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_streamed_json_field_does_not_scan_error_message_as_stack_content() -> None:
    from redposture_core.clients.http_api import HttpResponse

    class Pool:
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            try:
                on_chunk(b'{"error":"API_TOKEN=glpat-abcdefghijklmnopqrst"}')
            except Exception:
                return HttpResponse(200, b"", {}, error="invalid JSON field")
            return HttpResponse(200, b"", {})

    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=128, discover_time=30), host="qa", port=9000)
    collector = DiscoveryCollector("portainer", ctx, {"status": "open_no_auth"})
    assert not collector.stream_json_text_field(
        Pool(), "http://qa/api/stacks/11/file", "portainer/stack/11/file", "StackFileContent", headers={}, timeout=1
    )
    result = collector.result()
    assert result["status"] == "partial"
    assert result["findings"] == []


def test_streamed_json_scalars_do_not_scan_denied_response_body() -> None:
    from redposture_core.clients.http_api import HttpResponse

    class Pool:
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            try:
                on_response(403, {"Content-Type": "application/json"})
            except Exception:
                return HttpResponse(403, b"", {}, error="denied")
            on_chunk(b'{"Config":{"Env":["API_TOKEN=glpat-abcdefghijklmnopqrst"]}}')
            return HttpResponse(403, b"", {}, error="denied")

    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=512, discover_time=30), host="qa", port=9000)
    collector = DiscoveryCollector("portainer", ctx, {"status": "open_no_auth"})
    assert not collector.stream_json_scalars(
        Pool(), "http://qa/api/containers/1/json", "portainer/container/1", headers={}, timeout=1, root_kind="object"
    )
    result = collector.result()
    assert result["status"] == "unavailable"
    assert result["findings"] == []


def test_streamed_json_scalars_require_the_selected_value_subtree() -> None:
    from redposture_core.clients.http_api import HttpResponse

    class Pool:
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            on_chunk(b'{"errors":["API_TOKEN=glpat-abcdefghijklmnopqrst"]}')
            return HttpResponse(200, b"", {})

    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=9000)
    collector = DiscoveryCollector("vault", ctx, {"status": "open_no_auth"})
    assert not collector.stream_json_scalars(
        Pool(),
        "http://qa/v1/secret/large",
        "vault/secret/large",
        headers={},
        timeout=1,
        root_kind="object",
        exclude=lambda path: path[:1] != ("data",),
        required_prefix=("data",),
    )
    result = collector.result()
    assert result["status"] == "partial"
    assert result["findings"] == []


def test_streamed_stack_interruption_keeps_completed_line_only() -> None:
    from redposture_core.clients.http_api import HttpResponse

    class Pool:
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            on_chunk(b'{"StackFileContent":"API_TOKEN=glpat-abcdefghijklmnopqrst\\nAPI_TOKEN=glpat-incomplete')
            return HttpResponse(200, b"", {}, error="unexpected EOF", truncated=True)

    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=128, discover_time=30), host="qa", port=9000)
    collector = DiscoveryCollector("portainer", ctx, {"status": "open_no_auth"})
    assert not collector.stream_json_text_field(
        Pool(), "http://qa/api/stacks/11/file", "portainer/stack/11/file", "StackFileContent", headers={}, timeout=1
    )
    result = collector.result()
    assert result["status"] == "partial"
    assert result["findings"]
    assert len({item["fingerprint"] for item in result["findings"]}) == 1


@pytest.mark.parametrize("padding", ["ordinary text ", "обычный текст "])
def test_streamed_stack_one_long_delimited_line_crosses_internal_portions(padding: str) -> None:
    from redposture_core.clients.http_api import HttpResponse

    content = (padding * 100) + " API_TOKEN=glpat-abcdefghijklmnopqrst " + (padding * 100)
    payload = json.dumps({"StackFileContent": content}).encode()

    class Pool:
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            for position in range(0, len(payload), 67):
                on_chunk(payload[position : position + 67])
            return HttpResponse(200, b"", {})

    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=512, discover_time=30), host="qa", port=9000)
    collector = DiscoveryCollector("portainer", ctx, {"status": "open_no_auth"})
    assert collector.stream_json_text_field(
        Pool(), "http://qa/api/stacks/11/file", "portainer/stack/11/file", "StackFileContent", headers={}, timeout=1
    )
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert sum(item["type"] == "gitlab_token" for item in result["findings"]) == 1


def test_streamed_stack_indivisible_assignment_keeps_complete_value() -> None:
    from redposture_core.clients.http_api import HttpResponse

    payload = json.dumps({"StackFileContent": "API_TOKEN=" + "a" * 2048}).encode()

    class Pool:
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            for position in range(0, len(payload), 67):
                on_chunk(payload[position : position + 67])
            return HttpResponse(200, b"", {})

    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=512, discover_time=30), host="qa", port=9000)
    collector = DiscoveryCollector("portainer", ctx, {"status": "open_no_auth"})
    assert collector.stream_json_text_field(
        Pool(), "http://qa/api/stacks/11/file", "portainer/stack/11/file", "StackFileContent", headers={}, timeout=1
    )
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert len(result["findings"]) == 1
    assert "".join(result["findings"][0]["value"].iter_text_chunks()) == "a" * 2048


def test_streamed_json_scalars_retains_full_large_secret_field() -> None:
    from redposture_core.clients.http_api import HttpResponse

    token = "glpat-" + "Ab0" * 400_000
    payload = json.dumps({"data": {"api_token": token}}).encode()

    class Pool:
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            for position in range(0, len(payload), 67):
                on_chunk(payload[position : position + 67])
            return HttpResponse(200, b"", {})

    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=9000)
    collector = DiscoveryCollector("vault", ctx, {"status": "open_no_auth"})
    assert collector.stream_json_scalars(
        Pool(),
        "http://qa/v1/secret/large",
        "vault/secret/large",
        headers={},
        timeout=1,
        root_kind="object",
        required_prefix=("data",),
    )
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert len(result["findings"]) == 1
    value = result["findings"][0]["value"]
    assert isinstance(value, DiskBackedText)
    assert "".join(value.iter_text_chunks()) == token


def test_streamed_nomad_job_uses_same_place_as_buffered_job() -> None:
    from redposture_core.clients.http_api import HttpResponse

    source = "job_specs.default.qa-000"
    spec = {"ID": "qa-000", "TaskGroups": [{"Tasks": [{"Env": {"password": "qa-nomad-secret-Ab0"}}]}]}
    payload = json.dumps(spec).encode()

    class Pool:
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            for position in range(0, len(payload), 7):
                on_chunk(payload[position : position + 7])
            return HttpResponse(200, b"", {})

    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=4646)
    buffered = DiscoveryCollector("nomad", ctx, {"status": "open_no_auth"})
    assert buffered.add(source, spec)
    expected = [item["object_path"] for item in buffered.result()["findings"]]
    assert expected == ["$.job_specs.default.qa-000.TaskGroups[0].Tasks[0].Env.password"]

    streamed = DiscoveryCollector("nomad", ctx, {"status": "open_no_auth"})
    assert streamed.stream_json_scalars(
        Pool(), "http://qa/v1/job/qa-000", source, headers={}, timeout=1, root_kind="object", path_style="dot"
    )
    assert [item["object_path"] for item in streamed.result()["findings"]] == expected


@pytest.mark.parametrize("prefix", ["", "ordinary status "])
def test_streamed_json_scalars_keeps_complete_long_assignment_in_neutral_field(prefix: str) -> None:
    from redposture_core.clients.http_api import HttpResponse

    token = "glpat-" + "Ab0" * 400_000
    payload = json.dumps({"apps": {"app": [{"id": "app-1", "message": prefix + "API_TOKEN=" + token}]}}).encode()

    class Pool:
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            for position in range(0, len(payload), 32_768):
                on_chunk(payload[position : position + 32_768])
            return HttpResponse(200, b"", {})

    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=8088)
    collector = DiscoveryCollector("yarn", ctx, {"status": "open_no_auth"})
    assert collector.stream_json_scalars(
        Pool(), "http://qa/ws/v1/cluster/apps", "yarn/apps", headers={}, timeout=1, root_kind="object"
    )
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    values = [item["value"] for item in result["findings"]]
    assert len(values) == 1 and isinstance(values[0], DiskBackedText)
    assert "".join(values[0].iter_text_chunks()) == token


@pytest.mark.parametrize("interrupted", [False, True])
def test_streamed_json_scalars_neutral_long_assignment_never_confirms_prefix_or_placeholder(
    interrupted: bool,
) -> None:
    from redposture_core.clients.http_api import HttpResponse

    value = "glpat-" + "Ab0" * 400_000 if interrupted else "x" * 1_100_000
    payload = json.dumps({"message": "API_TOKEN=" + value}).encode()
    if interrupted:
        payload = payload[:-2]

    class Pool:
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            for position in range(0, len(payload), 32_768):
                on_chunk(payload[position : position + 32_768])
            return (
                HttpResponse(200, b"", {}, error="unexpected EOF", truncated=True)
                if interrupted
                else HttpResponse(200, b"", {})
            )

    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=8088)
    collector = DiscoveryCollector("yarn", ctx, {"status": "open_no_auth"})
    complete = collector.stream_json_scalars(
        Pool(), "http://qa/ws/v1/cluster/apps", "yarn/apps", headers={}, timeout=1, root_kind="object"
    )
    assert complete is not interrupted
    result = collector.result()
    assert result["status"] == ("partial" if interrupted else "complete")
    assert result["findings"] == []


def test_streamed_json_scalars_long_placeholder_is_not_a_finding() -> None:
    from redposture_core.clients.http_api import HttpResponse

    payload = json.dumps({"data": {"api_token": "x" * 1_100_000}}).encode()

    class Pool:
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            for position in range(0, len(payload), 32_768):
                on_chunk(payload[position : position + 32_768])
            return HttpResponse(200, b"", {})

    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=9000)
    collector = DiscoveryCollector("vault", ctx, {"status": "open_no_auth"})
    assert collector.stream_json_scalars(
        Pool(), "http://qa/v1/secret/large", "vault/secret/large", headers={}, timeout=1, root_kind="object"
    )
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert result["findings"] == []


def test_streamed_json_scalars_interrupted_long_secret_does_not_confirm_prefix() -> None:
    from redposture_core.clients.http_api import HttpResponse

    payload = b'{"data":{"api_token":"' + b"glpat-" + b"Ab0" * 400_000

    class Pool:
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            for position in range(0, len(payload), 32_768):
                on_chunk(payload[position : position + 32_768])
            return HttpResponse(200, b"", {}, error="unexpected EOF", truncated=True)

    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=9000)
    collector = DiscoveryCollector("vault", ctx, {"status": "open_no_auth"})
    assert not collector.stream_json_scalars(
        Pool(), "http://qa/v1/secret/large", "vault/secret/large", headers={}, timeout=1, root_kind="object"
    )
    result = collector.result()
    assert result["status"] == "partial"
    assert result["findings"] == []


def test_streamed_json_secret_field_recursively_reads_large_embedded_json() -> None:
    from redposture_core.clients.http_api import HttpResponse

    payload = json.dumps(
        {"data": {"api_token": json.dumps({"note": "x" * 1_200_000, "password": "qa-inner-password"})}}
    ).encode()

    class Pool:
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            for offset in range(0, len(payload), 32768):
                on_chunk(payload[offset : offset + 32768])
            return HttpResponse(200, b"", {})

    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=8200)
    collector = DiscoveryCollector("vault", ctx, {"status": "open_no_auth"})
    assert collector.stream_json_scalars(
        Pool(), "http://qa/source", "vault/source", headers={}, timeout=1, root_kind="object"
    )
    report = collector.result()
    assert report["status"] == "complete", report["partial_reasons"]
    assert [item["value"] for item in report["findings"]] == ["qa-inner-password"]
