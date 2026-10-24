"""Exercise real Spark HTTP lifecycle, URL prefix/TLS and output files."""

from __future__ import annotations

import json
import ssl
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from redposture_core.cli import main


@contextmanager
def spark_server(
    surface: str, material: dict[str, Path] | None = None, *, mtls=False, probe_status=400
) -> Iterator[tuple[str, list[tuple[str, str, Any]]]]:
    calls: list[tuple[str, str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def send(self, status, value):
            body = value.encode() if isinstance(value, str) else json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "text/html" if isinstance(value, str) else "application/json")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            calls.append(("GET", self.path, None))
            if not self.path.startswith("/proxy/"):
                return self.send(404, {})
            path = urlsplit(self.path).path.removeprefix("/proxy")
            if surface == "master" and path == "/json/":
                return self.send(
                    200,
                    {
                        "url": "spark://master:7077",
                        "cores": 2,
                        "workers": [
                            {
                                "id": "worker-qa",
                                "host": "private-worker",
                                "port": 7078,
                                "cores": 2,
                                "coresused": 0,
                                "memory": 1024,
                                "memoryused": 0,
                                "state": "ALIVE",
                            }
                        ],
                        "activeapps": [
                            {
                                "id": "app-qa",
                                "name": "password=qa-spark-secret",
                                "user": "alice",
                                "state": "RUNNING",
                                "cores": 1,
                            }
                        ],
                    },
                )
            if surface == "master" and path == "/":
                return self.send(
                    200, '<title>Spark Master at spark://master:7077</title><span class="version">3.5.1</span>'
                )
            if surface == "rest" and path == "/v1/submissions/status/redposture-probe":
                return self.send(
                    200,
                    {
                        "action": "SubmissionStatusResponse",
                        "serverSparkVersion": "3.5.1",
                        "submissionId": "redposture-probe",
                        "success": False,
                    },
                )
            if surface == "foreign":
                return self.send(200, {"version": "3.5.1"})
            return self.send(404, {})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            calls.append(("POST", self.path, body))
            assert body == {"action": "CreateSubmissionRequest"}
            if self.path == "/proxy/v1/submissions/create" and surface == "rest":
                return self.send(
                    probe_status,
                    {
                        "action": "ErrorResponse",
                        "serverSparkVersion": "3.5.1",
                        "message": "Malformed request: Validation of message CreateSubmissionRequest failed! 'clientSparkVersion' is missing in message CreateSubmissionRequest.",
                    },
                )
            return self.send(404, {})

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if material:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(material["server_cert"]), str(material["server_key"]))
        if mtls:
            tls.verify_mode = ssl.CERT_REQUIRED
            tls.load_verify_locations(cafile=str(material["ca_cert"]))
        httpd.socket = tls.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"{'https' if material else 'http'}://localhost:{httpd.server_port}/proxy", calls
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


@pytest.mark.parametrize("surface", ["master", "rest"])
@pytest.mark.parametrize("tls", [False, True])
def test_real_http_spark_runner_prefix_tls_and_clean_saved_output(
    surface, tls, mtls_material, tmp_path, capsys, monkeypatch
):
    monkeypatch.setenv("FORCE_COLOR", "1")
    with spark_server(surface, mtls_material if tls else None) as (url, calls):
        common = ["spark", "-t", url, "--no-color", "--timeout", "1", "--show-workers", "--show-apps"]
        if tls:
            common += ["--tls-ca", str(mtls_material["ca_cert"])]
        output = tmp_path / "spark.json"
        assert main([*common, "--discover", "-f", "json", "-o", str(output)]) == 0
        result = json.loads(output.read_text())
        assert result["is_spark"] is True
        assert result["surface"] == ("master_ui" if surface == "master" else "submission_rest")
        assert result["submit_access"] == "unverified"
        if surface == "master":
            assert len(result["workers"]) == len(result["apps"]) == 1
            assert result["content_discovery"]["findings"]
            assert "spark_metadata" not in result
        text = tmp_path / "spark.txt"
        assert main([*common, "-o", str(text)]) == 0
        assert "Apache Spark" in text.read_text()
        assert "Enumeration" in text.read_text()
        assert "\x1b" not in output.read_text() + text.read_text() + capsys.readouterr().out
        assert all(method == "GET" and path.startswith("/proxy/") for method, path, _ in calls)


@pytest.mark.parametrize("probe_status,reachable,access", [(400, True, "unverified"), (403, False, "denied")])
def test_explicit_probe_real_http_keeps_create_payload_non_executable(probe_status, reachable, access, capsys):
    with spark_server("rest", probe_status=probe_status) as (url, calls):
        assert main(["spark", "-t", url, "--probe-submit", "--no-color", "--timeout", "1", "-f", "json"]) == 0
        result = json.loads(capsys.readouterr().out)
        assert result["submit_parser_reachable"] is reachable
        assert result["submit_access"] == access
        assert result["submit_probe"]["execution"] is False
        assert [(path, payload) for method, path, payload in calls if method == "POST"] == [
            ("/proxy/v1/submissions/create", {"action": "CreateSubmissionRequest"})
        ]


def test_real_mtls_spark_runner_uses_client_identity(mtls_material, capsys):
    with spark_server("rest", mtls_material, mtls=True) as (url, calls):
        assert (
            main(
                [
                    "spark",
                    "-t",
                    url,
                    "--tls-ca",
                    str(mtls_material["ca_cert"]),
                    "--tls-cert",
                    str(mtls_material["client_cert"]),
                    "--tls-key",
                    str(mtls_material["client_key"]),
                    "--no-color",
                    "--timeout",
                    "1",
                    "-f",
                    "json",
                ]
            )
            == 0
        )
        assert json.loads(capsys.readouterr().out)["is_spark"] is True
        assert all(method == "GET" for method, _path, _payload in calls)


def test_foreign_http200_never_appears_as_spark(capsys):
    with spark_server("foreign") as (url, _calls):
        assert main(["spark", "-t", url, "--no-color", "--timeout", "1", "-f", "json"]) == 0
        assert json.loads(capsys.readouterr().out)["is_spark"] is False
