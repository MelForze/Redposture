"""Wire-level authentication matrix for anonymous, basic, token and SSO modes."""

from __future__ import annotations

import base64
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.grafana.stage import build_grafana_plan, build_grafana_spec
from redposture_core.stage_runtime import AuditCommandRunner


class _GrafanaAuthServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, mode: str) -> None:
        super().__init__(("127.0.0.1", 0), _GrafanaAuthHandler)
        self.mode = mode
        self.authorizations: list[str] = []


class _GrafanaAuthHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def qa(self) -> _GrafanaAuthServer:
        return cast(_GrafanaAuthServer, self.server)

    def _reply(self, status: int, payload: object, *, content_type: str = "application/json") -> None:
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        value = self.headers.get("Authorization", "")
        if value:
            self.qa.authorizations.append(value)
        expected_basic = "Basic " + base64.b64encode(b"qa-user:qa-pass").decode("ascii")
        return (self.qa.mode == "basic" and value == expected_basic) or (
            self.qa.mode == "token" and value == "Bearer qa-token"
        )

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path == "/api/health":
            self._reply(200, {"database": "ok", "version": "11.0.0", "commit": "qa"})
            return
        if self.path == "/login":
            if self.qa.mode == "sso":
                self._reply(
                    200,
                    b'<html><form id="kc-form-login" action="/realms/qa/login-actions/authenticate"></form></html>',
                    content_type="text/html",
                )
            else:
                self._reply(200, b"<html><title>Grafana</title><form>login</form></html>", content_type="text/html")
            return
        if self.path == "/api/user":
            if self._authorized():
                self._reply(200, {"id": 1, "login": "qa-user", "isGrafanaAdmin": False})
            else:
                self._reply(401, {"message": "Unauthorized"})
            return
        if self.path == "/api/datasources":
            if self.qa.mode == "anonymous" or self._authorized():
                self._reply(200, [])
            else:
                self._reply(401, {"message": "Unauthorized"})
            return
        self._reply(404, {})

    def log_message(self, *_args: object) -> None:
        return


@contextmanager
def _serve(mode: str) -> Iterator[_GrafanaAuthServer]:
    server = _GrafanaAuthServer(mode)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


def _run(server: _GrafanaAuthServer, *extra: str) -> dict[str, Any]:
    args = parse_args(
        [
            "grafana",
            "-t",
            f"http://127.0.0.1:{server.server_port}",
            "--timeout",
            "1",
            "--retries",
            "0",
            "--format",
            "json",
            *extra,
        ]
    )
    lines: list[str] = []
    AuditCommandRunner(args=args, spec=build_grafana_spec(args), emit_line=lines.append).run_plan(
        build_grafana_plan(args)
    )
    records = [json.loads(line) for line in lines if json.loads(line).get("type") != "summary"]
    assert len(records) == 1
    return records[0]


@pytest.mark.parametrize(
    ("mode", "extra", "expected_status", "expected_method"),
    [
        ("anonymous", (), "open_no_auth", None),
        ("basic", ("-u", "qa-user", "-p", "qa-pass"), "valid_credentials", None),
        ("token", ("--apitoken", "qa-token"), "valid_credentials", None),
        ("sso", ("--defcreds",), "auth_required", "sso"),
    ],
)
def test_real_grafana_authentication_modes(
    mode: str,
    extra: tuple[str, ...],
    expected_status: str,
    expected_method: str | None,
) -> None:
    with _serve(mode) as server:
        record = _run(server, *extra)

    assert record["status"] == expected_status
    assert record.get("auth_method") == expected_method
    if mode == "anonymous":
        assert record["auth_required"] is False
    elif mode == "basic":
        assert record["provided_credentials_ok"] is True
        assert any(value.startswith("Basic ") for value in server.authorizations)
    elif mode == "token":
        assert record["provided_credentials_ok"] is True
        assert "Bearer qa-token" in server.authorizations
    else:
        assert record["auth_required"] is True
        assert record["sso_provider"] == "keycloak"
        assert record["attempted_credentials_count"] == 0
