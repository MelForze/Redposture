"""A MinIO browser redirect must not turn the Console into the S3 verifier."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.minio import actions
from redposture_core.modules.minio.stage import build_minio_plan, build_minio_spec
from redposture_core.stage_runtime import AuditCommandRunner


class _Server(ThreadingHTTPServer):
    def __init__(self, handler: type[BaseHTTPRequestHandler]) -> None:
        super().__init__(("127.0.0.1", 0), handler)
        self.calls: list[tuple[str, str]] = []
        self.console_url = ""
        self.redirect_signed_root = False


class _BaseHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args: Any) -> None:
        return

    def reply(self, status: int, body: bytes = b"", *, location: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(body)


class _ApiHandler(_BaseHandler):
    def do_GET(self) -> None:
        server = cast(_Server, self.server)
        authorization = self.headers.get("Authorization", "")
        server.calls.append((self.path, authorization))
        path = self.path.partition("?")[0]
        if path == "/minio/health/live":
            self.reply(200)
        elif path == "/" and (not authorization or server.redirect_signed_root):
            self.reply(307, location=server.console_url)
        elif path == "/" and "Credential=minioadmin/" in authorization:
            self.reply(200, b"<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>")
        elif path == "/" and authorization:
            self.reply(403, b"<Error><Code>InvalidAccessKeyId</Code></Error>")
        elif path.startswith("/minio/admin/") and "Credential=minioadmin/" in authorization:
            self.reply(200, b'{"mode":"online","servers":[]}')
        elif path.startswith("/minio/admin/") and authorization:
            self.reply(403, b'{"Code":"InvalidAccessKeyId","Message":"unknown access key"}')
        elif path.startswith("/minio/admin/"):
            self.reply(403, b'{"Code":"AccessDenied","Message":"Access Denied"}')
        else:
            self.reply(404)


class _ConsoleHandler(_BaseHandler):
    def do_GET(self) -> None:
        server = cast(_Server, self.server)
        server.calls.append((self.path, self.headers.get("Authorization", "")))
        if self.path == "/":
            authorization = self.headers.get("Authorization", "")
            if authorization:
                self.reply(
                    400,
                    b"<Error><Code>InvalidArgument</Code>"
                    b"<Message>S3 API Requests must be made to API port.</Message></Error>",
                )
            else:
                self.reply(200, b"<html><title>MinIO Console</title><body>Login</body></html>")
        else:
            self.reply(404)


@pytest.mark.parametrize("target_kind", ["api", "console"])
def test_defcreds_reaches_s3_api_after_console_redirect(monkeypatch: pytest.MonkeyPatch, target_kind: str) -> None:
    api = _Server(_ApiHandler)
    console = _Server(_ConsoleHandler)
    api.console_url = f"http://127.0.0.1:{console.server_port}/"
    monkeypatch.setattr(actions, "_CONSOLE_API_CANDIDATE_PORTS", (api.server_port,))
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (api, console)]
    for thread in threads:
        thread.start()
    try:
        port = api.server_port if target_kind == "api" else console.server_port
        args = parse_args(["minio", "-t", f"http://127.0.0.1:{port}", "--defcreds", "--timeout", "1", "--retries", "0"])
        lines: list[str] = []
        runner = AuditCommandRunner(args=args, spec=build_minio_spec(args), emit_line=lines.append)
        runner.run_plan(build_minio_plan(args))
        output = "\n".join(lines)
        assert "S3 API:unverified" not in output
        assert "credential verification unavailable" not in output
        assert "auth required:False" not in output
        assert "minioadmin:minioadmin" in output
        assert f"S3 API:http://127.0.0.1:{api.server_port}" in output
        assert any("Credential=minioadmin/" in auth for _path, auth in api.calls)
        assert all(not auth for _path, auth in console.calls)
    finally:
        for server in (api, console):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=3)


def test_defcreds_handles_real_console_wrong_port_and_admin_json(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _Server(_ApiHandler)
    console = _Server(_ConsoleHandler)
    api.console_url = f"http://127.0.0.1:{console.server_port}/"
    api.redirect_signed_root = True
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (api, console)]
    for thread in threads:
        thread.start()
    try:
        args = parse_args(
            ["minio", "-t", f"http://127.0.0.1:{api.server_port}", "--defcreds", "--timeout", "1", "--retries", "0"]
        )
        lines: list[str] = []
        runner = AuditCommandRunner(args=args, spec=build_minio_spec(args), emit_line=lines.append)
        runner.run_plan(build_minio_plan(args))
        output = "\n".join(lines)
        assert "minioadmin:minioadmin" in output
        assert "credential verification unavailable" not in output
        assert "access:secret" in output
        assert "[-] access:secret" in output
        assert any(path.startswith("/minio/admin/") and auth for path, auth in api.calls)
    finally:
        for server in (api, console):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=3)
