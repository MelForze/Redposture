"""An external login redirect must not become the origin of Grafana API calls."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.modules.grafana import actions, stage
from redposture_core.stage_runtime import AuditCommandRunner


@pytest.mark.parametrize("route", ["runtime", "legacy"])
@pytest.mark.parametrize("output_format", ["txt", "json"])
def test_external_oidc_redirect_does_not_get_followed_or_receive_api_probes(tmp_path, route, output_format):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            requests.append((self.path, self.headers.get("Authorization")))
            headers = {}
            if self.path == "/api/health":
                status, body = 200, json.dumps({"database": "ok", "version": "13.3.0", "commit": "abcdef"}).encode()
            elif self.path == "/login":
                status, body = 302, b""
                headers["Location"] = (
                    f"http://localhost:{self.server.server_port}/realms/ops/protocol/openid-connect/auth?client_id=grafana&response_type=code&redirect_uri=http://qa/login/generic_oauth"
                )
            else:
                status, body = 200, b"<title>Enter infrastructure</title>"
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    previous = vars(actions._THREAD_LOCAL_HTTP).copy()
    path = tmp_path / ("sso." + output_format)
    state = None
    try:
        if route == "runtime":
            args = parse_args(
                [
                    "grafana",
                    "-t",
                    f"http://127.0.0.1:{server.server_port}",
                    "--defcreds",
                    "--no-color",
                    "-r",
                    "0",
                    "--timeout",
                    "1",
                    "-f",
                    output_format,
                    "-o",
                    str(path),
                ]
            )
            result = AuditCommandRunner(
                args=args, spec=stage.build_grafana_spec(args), emit_line=lambda line: None
            ).run_plan(stage.build_grafana_plan(args))
            record = result.records[0]
            text = path.read_text()
            assert "\x1b" not in text
            if output_format == "json":
                assert json.loads(text)["auth_required"] is True
            else:
                assert "(auth required:sso)" in text
        else:
            state = actions.GrafanaLifecycleState(
                http=HttpSessionPool(timeout=1), host="127.0.0.1", port=server.server_port, scheme="http"
            )
            actions._activate_grafana_transport(state)
            record = actions._audit_grafana_host("127.0.0.1", server.server_port, 1, 0, None, None, True, [])
        assert record["is_grafana"] is True
        assert record["auth_required"] is True and record["sso_provider"] == "keycloak"
        assert record["auth_attempts"] == []
        assert [path for path, _ in requests] == ["/api/health", "/login"]
        assert all(auth is None for _, auth in requests)
    finally:
        if state is not None:
            state.close()
        vars(actions._THREAD_LOCAL_HTTP).clear()
        vars(actions._THREAD_LOCAL_HTTP).update(previous)
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()
