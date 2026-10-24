"""Exercise YARN through the real scoped HTTP transport and CLI runner."""

from __future__ import annotations

import json
import select
import socket
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
from redposture_core.cli_args import parse_args
from redposture_core.modules.yarn.stage import build_yarn_plan

INFO = {
    "clusterInfo": {
        "state": "STARTED",
        "haState": "ACTIVE",
        "resourceManagerVersion": "3.3.6",
        "hadoopVersion": "3.3.6",
    }
}
APP = {
    "id": "application_1234_0001",
    "name": "audit",
    "state": "RUNNING",
    "diagnostics": "password=qa-database-password",
}


@contextmanager
def server(
    material: dict[str, Path] | None = None, *, mutual: bool = False, protected: bool = False
) -> Iterator[tuple[str, list[tuple[str, str]]]]:
    calls: list[tuple[str, str]] = []
    connect = socket.create_connection

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: Any) -> None:
            pass

        def do_GET(self) -> None:
            self.respond()

        def do_POST(self) -> None:
            self.respond()

        def do_CONNECT(self) -> None:
            calls.append((self.command, self.path))
            with connect(("127.0.0.1", self.server.server_address[1]), timeout=2) as upstream:
                self.send_response(200)
                self.end_headers()
                peers = {self.connection: upstream, upstream: self.connection}
                while True:
                    readable, _, _ = select.select(list(peers), [], [], 2)
                    if not readable:
                        return
                    for source in readable:
                        payload = source.recv(65536)
                        if not payload:
                            return
                        peers[source].sendall(payload)

        def respond(self) -> None:
            calls.append((self.command, self.path))
            path = urlsplit(self.path).path
            if not path.startswith("/proxy/"):
                self.send(404, {})
                return
            path = path[len("/proxy") :]
            if path == "/ws/v1/cluster/info":
                self.send(200, INFO)
            elif protected:
                self.send(
                    403, {"RemoteException": {"exception": "AuthorizationException", "message": "Permission denied"}}
                )
            elif path == "/ws/v1/cluster/apps/new-application" and self.command == "POST":
                self.send(
                    200,
                    {
                        "application-id": "application_1234_0002",
                        "maximum-resource-capability": {"memory": 8192, "vCores": 8},
                    },
                )
            elif self.command != "GET":
                self.send(405, {})
            elif path == "/ws/v1/cluster/apps":
                self.send(200, {"apps": {"app": [APP]}})
            elif path == "/ws/v1/cluster/apps/application_1234_0001":
                self.send(200, {"app": APP})
            elif path == "/ws/v1/cluster/nodes":
                self.send(200, {"nodes": None})
            elif path == "/ws/v1/cluster/metrics":
                self.send(200, {"clusterMetrics": {"totalMB": 8192, "allocatedMB": 1024, "totalNodes": 0}})
            else:
                self.send(404, {})

        def send(self, status: int, value: Any) -> None:
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.daemon_threads = True
    if material:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(material["server_cert"]), str(material["server_key"]))
        if mutual:
            tls.load_verify_locations(str(material["ca_cert"]))
            tls.verify_mode = ssl.CERT_REQUIRED
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


@pytest.mark.parametrize("protocol", ["http", "tls", "mtls"])
@pytest.mark.parametrize("suffix", ["", "/ws/v1/cluster/info"])
def test_runner_prefix_tls_discovery_inventory_and_plain_outputs(
    protocol: str, suffix: str, mtls_material: dict[str, Path], tmp_path: Path, capsys: Any
) -> None:
    with server(mtls_material if protocol != "http" else None, mutual=protocol == "mtls") as (url, calls):
        common = ["yarn", "-t", url + suffix, "--timeout", "1", "-r", "0", "--no-color"]
        if protocol != "http":
            common += ["--tls-ca", str(mtls_material["ca_cert"])]
        if protocol == "mtls":
            common += ["--tls-cert", str(mtls_material["client_cert"]), "--tls-key", str(mtls_material["client_key"])]
        json_file = tmp_path / "yarn.json"
        inventory = ["--show-apps", "--show-nodes", "--show-metrics"]
        assert main([*common, *inventory, "--discover", "--enum-cve", "-f", "json", "-o", str(json_file)]) == 0
        saved = json_file.read_text()
        record = json.loads(saved)
        assert record["is_yarn"] is True
        assert record["version"] == "3.3.6"
        assert record["apps"] == [APP]
        assert record["nodes"] == []
        assert record["metrics"]["totalNodes"] == 0
        assert record["content_discovery"]["findings"]
        assert record["submit_access"] == "unverified"
        assert record["rce_potential"] is False
        assert "provided_credentials_ok" not in record
        assert "\x1b" not in saved
        assert "\x1b" not in capsys.readouterr().out
        txt_file = tmp_path / "yarn.txt"
        assert main([*common, *inventory, "-o", str(txt_file)]) == 0
        saved_txt = txt_file.read_text()
        assert "Applications Enumeration" in saved_txt
        assert "Nodes Enumeration" in saved_txt
        assert "\x1b" not in saved_txt
        assert "\x1b" not in capsys.readouterr().out
        assert all(method == "GET" and path.startswith("/proxy/ws/v1/cluster/") for method, path in calls)


@pytest.mark.parametrize("protected,expected", [(False, "allowed"), (True, "denied")])
def test_cli_probe_sends_only_application_id_allocation(protected: bool, expected: str, capsys: Any) -> None:
    with server(protected=protected) as (url, calls):
        assert main(["yarn", "-t", url, "--probe-submit", "-f", "json", "--no-color", "-r", "0"]) == 0
        record = json.loads(capsys.readouterr().out)
        assert record["allocation_access"] == expected
        assert record["submit_access"] == "unverified"
        assert record["submit_probe"]["submitted"] is False
        assert record["submit_probe"]["executed"] is False
        assert record["rce_potential"] is (not protected)
        assert [(method, path) for method, path in calls if method != "GET"] == [
            ("POST", "/proxy/ws/v1/cluster/apps/new-application")
        ]


def test_cli_honors_outbound_http_proxy(capsys: Any) -> None:
    with server() as (url, calls):
        proxy = url.rsplit("/proxy", 1)[0]
        port = urlsplit(proxy).port
        assert (
            main(
                [
                    "yarn",
                    "-t",
                    f"http://service.test:{port}/proxy",
                    "--proxy",
                    proxy,
                    "-f",
                    "json",
                    "--no-color",
                    "-r",
                    "0",
                ]
            )
            == 0
        )
        record = json.loads(capsys.readouterr().out)
        assert record["is_yarn"] is True
        assert ("CONNECT", f"service.test:{port}") in calls
        assert all(path.startswith("/proxy/ws/v1/cluster/") for method, path in calls if method == "GET")


def test_cli_default_port_and_no_password_or_execution_contract(capsys: Any) -> None:
    args = parse_args(["yarn", "-t", "127.0.0.1"])
    plan = build_yarn_plan(args)
    assert plan.ports == (8088,)
    assert not plan.credential_runs
    for flag in ("--defcreds", "--token", "--user", "--pass"):
        with pytest.raises(SystemExit) as error:
            parse_args(["yarn", "-t", "127.0.0.1", flag, "candidate"])
        assert error.value.code == 2
    execute_args = parse_args(["yarn", "-t", "127.0.0.1", "--execute", "candidate"])
    assert execute_args.execute == "candidate"
    capsys.readouterr()
