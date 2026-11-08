"""Real HTTP framing, mount prefixes and saved output for legacy API 404."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.clients.http_api import HttpResponse
from redposture_core.console import Console
from redposture_core.modules.grafana import stage
from redposture_core.stage_runtime import AuditCommandRunner
from tests.application_markup import application_page
from tests.test_grafana_auth_ping import Peer
from tests.test_grafana_extended_auth import PAYLOADS
from tests.test_grafana_extended_auth import Peer as ExtendedPeer


@pytest.mark.parametrize("redirect_mount", [False, True])
@pytest.mark.parametrize("mode", ["basic", "cookie", "unavailable"])
@pytest.mark.parametrize("fallback_path", [None, *PAYLOADS])
@pytest.mark.parametrize("output_format", ["txt", "json"])
def test_prefixed_live_http_verifier_and_saved_output(tmp_path, mode, output_format, redirect_mount, fallback_path):
    peer = (
        Peer(mode)
        if fallback_path is None
        else ExtendedPeer(fallback_path, mode if mode != "unavailable" else "unavailable")
    )
    observed = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def handle_request(self):
            path = urlsplit(self.path).path
            observed.append((self.command, path))
            if redirect_mount and path == "/login":
                self.send_response(302)
                self.send_header("Location", "/grafana/login")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            assert path.startswith("/grafana/") or (redirect_mount and path == "/api/health")
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else None
            local_path = path.removeprefix("/grafana")
            if local_path == "/api/health":
                result = peer.reply(200, {"database": "ok", "version": "13.0.1", "commit": "abcdef"})
            elif local_path == "/login" and self.command == "GET":
                result = HttpResponse(200, application_page("grafana").encode(), {"Content-Type": "text/html"})
            elif fallback_path is not None and mode == "unavailable":
                result = peer.reply(404, {})
            else:
                result = peer.request(self.command, "http://local" + local_path, headers=dict(self.headers), body=body)
            self.send_response(result.status)
            for key, value in result.headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(result.body)))
            self.end_headers()
            self.wfile.write(result.body)

        do_GET = handle_request
        do_POST = handle_request

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    path = tmp_path / ("result." + output_format)
    args = parse_args(
        [
            "grafana",
            "-t",
            f"http://127.0.0.1:{server.server_port}" + ("/" if redirect_mount else "/grafana/"),
            "-u",
            "alice",
            "-p",
            "correct",
            "-r",
            "0",
            "--timeout",
            "1",
            "--no-color",
            "-f",
            output_format,
            "-o",
            str(path),
        ]
    )
    lines = []
    try:
        result = AuditCommandRunner(
            args=args, spec=stage.build_grafana_spec(args), console=Console(no_color=True), emit_line=lines.append
        ).run_plan(stage.build_grafana_plan(args))
        assert result.record_count == result.detected_count == 1
        record = result.records[0]
        assert record["is_grafana"] is True
        if mode == "unavailable":
            assert record["auth_required"] is None and record["provided_credentials_ok"] is None
        else:
            assert record["auth_required"] is True and record["provided_credentials_ok"] is True
        text = path.read_text()
        assert "\x1b" not in text
        assert observed and all(
            path.startswith("/grafana/") or (redirect_mount and path in {"/api/health", "/login"})
            for _, path in observed
        )
        assert ("GET", "/grafana/api/login/ping") in observed
        if fallback_path is not None:
            assert ("GET", "/grafana" + fallback_path) in observed
        if output_format == "json":
            saved = json.loads(text)
            assert saved["auth_required"] is record["auth_required"]
            assert saved["provided_credentials_ok"] is record["provided_credentials_ok"]
            assert saved["auth_attempts"][0]["ok"] is record["provided_credentials_ok"]
        elif mode == "unavailable":
            assert "[*] alice:correct (unverified:" in text and "[-] alice:correct" not in text
        else:
            assert "[+] alice:correct" in text and "auth required:True" in text
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()
