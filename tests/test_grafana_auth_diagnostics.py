"""Unavailable APIs are concise in normal output and complete in debug."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.grafana import actions, stage
from redposture_core.stage_runtime import AuditCommandRunner
from tests.application_markup import application_page


@pytest.mark.parametrize("error", ["backend timeout", "HTTP 404", "HTTP 429", "x" * 500 + "END"])
def test_unverified_summary_is_short_and_unknown_warning_is_debug_only(error):
    record = {
        "host": "qa",
        "port": 80,
        "is_grafana": True,
        "status": "unknown_auth",
        "error": error,
        "auth_attempts": [{"username": "alice", "password": "secret", "ok": None, "error": error}],
    }
    assert actions._format_record(record, "txt") == ""
    lines = actions._format_auth_attempt_detail_records(record, "txt")
    assert len(lines) == 1
    assert lines[0].endswith("[*] alice:secret (unverified: api's unavailable)")
    assert error not in lines[0]


@pytest.mark.parametrize("debug", [False, True])
@pytest.mark.parametrize("output_format", ["txt", "json"])
def test_rate_limited_api_keeps_unknown_and_full_debug_without_ansi(tmp_path, debug, output_format):
    body = "<html><title>429 Too Many Requests</title>" + "rate limit " * 60 + "\x1b[31mTAIL_PROOF</html>"
    calls = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def do_GET(self):
            calls.append(("GET", self.path))
            headers = {}
            if self.path == "/api/health":
                status, payload = 200, json.dumps({"database": "ok", "version": "13.3.0"})
            elif self.path == "/login":
                status, payload = 200, application_page("grafana")
            elif self.path == "/api/login/ping":
                status, payload = 429, body
                headers = {"Retry-After": "42"}
            else:
                status, payload = 404, '{"message":"Not found"}'
            encoded = payload.encode()
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_POST(self):
            pytest.fail("429 must stop login fallback")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    path = tmp_path / f"result.{output_format}"
    argv = [
        "grafana",
        "-t",
        f"http://127.0.0.1:{server.server_port}",
        "-u",
        "alice",
        "-p",
        "secret",
        "--timeout",
        "1",
        "-r",
        "0",
        "--no-color",
        "-f",
        output_format,
        "-o",
        str(path),
    ]
    if debug:
        argv.append("--debug")
    args = parse_args(argv)
    debug_lines = []
    args.debug_emit = debug_lines.append
    try:
        result = AuditCommandRunner(
            args=args, spec=stage.build_grafana_spec(args), emit_line=lambda _line: None
        ).run_plan(stage.build_grafana_plan(args))
        record = result.records[0]
        assert record["is_grafana"] is True
        assert record["auth_required"] is None and record["provided_credentials_ok"] is None
        assert record["auth_http_status"] == 429
        text = path.read_text()
        assert "auth status unknown" not in text
        if output_format == "txt":
            assert "[*] alice:secret (unverified: api's unavailable)" in text
            assert "TAIL_PROOF" not in text
        else:
            assert json.loads(text)["auth_required"] is None
        assert "\x1b" not in text
        trace = [line for line in debug_lines if line.startswith("grafana_http ")]
        assert bool(trace) is debug
        if debug:
            responses = [json.loads(line.removeprefix("grafana_http ")) for line in trace]
            rate = [item for item in responses if item["status"] == 429]
            assert rate and rate[-1]["body"] == body
            assert rate[-1]["headers"]["Retry-After"] == "42"
            assert rate[-1]["truncated"] is False
            assert any("TAIL_PROOF" in line for line in debug_lines)
            assert all("\x1b" not in line for line in debug_lines)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()
