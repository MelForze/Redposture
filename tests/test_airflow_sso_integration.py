from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.airflow.stage import build_airflow_plan, build_airflow_spec
from redposture_core.stage_runtime import AuditCommandRunner


class _Server(ThreadingHTTPServer):
    def __init__(self, handler: type[BaseHTTPRequestHandler]) -> None:
        super().__init__(("127.0.0.1", 0), handler)
        self.calls: list[str] = []
        self.idp_url = ""


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


class _AirflowHandler(_BaseHandler):
    def do_GET(self) -> None:
        server = cast(_Server, self.server)
        server.calls.append(self.path)
        if self.path == "/api/v2/version":
            self.reply(404)
        elif self.path == "/api/v1/version":
            self.reply(200, b'{"version":"2.11.1","git_version":"qa"}')
        elif self.path == "/api/v1/dags":
            self.reply(302, location=server.idp_url)
        else:
            self.reply(404)


class _KeycloakHandler(_BaseHandler):
    def do_GET(self) -> None:
        cast(_Server, self.server).calls.append(self.path)
        self.reply(
            200,
            b'<html><body><form id="kc-form-login" action="/realms/qa/login-actions/authenticate">Login</form></body></html>',
        )


@pytest.mark.parametrize("output_format", ["txt", "json"])
def test_airflow_keycloak_redirect_is_reported_as_sso_and_skips_defcreds(output_format: str) -> None:
    airflow = _Server(_AirflowHandler)
    keycloak = _Server(_KeycloakHandler)
    airflow.idp_url = (
        f"http://127.0.0.1:{keycloak.server_port}/realms/qa/protocol/openid-connect/auth"
        "?client_id=airflow&redirect_uri=http%3A%2F%2Fairflow.invalid%2Foauth-authorized"
        "&response_type=code&scope=openid"
    )
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (airflow, keycloak)]
    for thread in threads:
        thread.start()
    try:
        args = parse_args(
            [
                "airflow",
                "-t",
                f"http://127.0.0.1:{airflow.server_port}",
                "--defcreds",
                "--timeout",
                "1",
                "--retries",
                "0",
                "-f",
                output_format,
            ]
        )
        lines: list[str] = []
        AuditCommandRunner(args=args, spec=build_airflow_spec(args), emit_line=lines.append).run_plan(
            build_airflow_plan(args)
        )
        assert airflow.calls.count("/api/v1/dags") == 1
        assert all("/api/v1/pools" not in call and "/api/v1/eventLogs" not in call for call in airflow.calls)
        if output_format == "txt":
            output = "\n".join(lines)
            assert "Airflow (auth required:sso) (provider:keycloak) (version:2.11.1)" in output
            assert "airflow:airflow" not in output
        else:
            payloads = [json.loads(line) for line in lines]
            result = next(payload for payload in payloads if payload.get("service") == "airflow")
            assert result["auth_required"] is True
            assert result["auth_method"] == "sso"
            assert result["sso_provider"] == "keycloak"
            assert result["credential_verification_status"] == "unavailable"
    finally:
        for server in (airflow, keycloak):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=3)
