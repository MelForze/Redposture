"""Portainer full command lifecycle against controlled HTTP(S) services."""

from __future__ import annotations

import json
import select
import socket
import ssl
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from redposture_core.cli import main


@contextmanager
def portainer_server(
    material=None, *, anonymous=False, blocked=False, mismatch=False, accepted_pair=("admin", "secret")
):
    calls = []
    connect = socket.create_connection

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def send(self, status, value):
            body = value.encode() if isinstance(value, str) else json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def do_CONNECT(self):
            calls.append(("CONNECT", self.path, {}))
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

        def do_GET(self):
            calls.append(("GET", self.path, dict(self.headers)))
            path = urlsplit(self.path).path.removeprefix("/tenant")
            if not urlsplit(self.path).path.startswith("/tenant/"):
                return self.send(404, {})
            if path == "/api/system/status":
                return self.send(200, {"Version": "2.45.2", "InstanceID": "qa"})
            if path == "/":
                return self.send(200, "<title>Portainer</title>")
            auth = (
                self.headers.get("Authorization") == "Bearer issued"
                or self.headers.get("Authorization") == "Bearer eyJ.test.jwt"
                or self.headers.get("X-API-Key") == "ptr_qa"
            )
            if path == "/api/users/me":
                return (
                    self.send(200, {"Id": 1, "Username": "other" if mismatch else accepted_pair[0], "Role": 1})
                    if auth
                    else self.send(401, {"message": "unauthorized"})
                )
            if path == "/api/endpoints":
                return (
                    self.send(200, [{"Id": 1, "Name": "local", "Type": 1}])
                    if auth or anonymous
                    else self.send(401, {"message": "unauthorized"})
                )
            if not (auth or anonymous):
                return self.send(401, {"message": "unauthorized"})
            if path == "/api/endpoints/1/docker/containers/json":
                return self.send(
                    200,
                    [
                        {
                            "Id": "abc",
                            "Names": ["/app"],
                            "Image": "qa",
                            "State": "running",
                            "Labels": {"password": "portainer-qa-very-secret"},
                        }
                    ],
                )
            if path == "/api/endpoints/1/docker/images/json":
                return self.send(200, [])
            if path == "/api/endpoints/1/docker/networks":
                return self.send(200, [])
            if path == "/api/endpoints/1/docker/volumes":
                return self.send(200, {"Volumes": []})
            if path == "/api/endpoints/1/docker/info":
                return self.send(200, {"ServerVersion": "27.5.1", "Containers": 1, "Images": 0, "OSType": "linux"})
            if path == "/api/endpoints/1/docker/system/df":
                return self.send(200, {"LayersSize": 0, "Containers": [], "Images": [], "Volumes": []})
            return self.send(404, {})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            calls.append(("POST", self.path, body))
            if self.path != "/tenant/api/auth":
                return self.send(404, {})
            if blocked:
                return self.send(429, {"message": "too many requests"})
            if body == {"Username": accepted_pair[0], "Password": accepted_pair[1]}:
                return self.send(200, {"jwt": "issued"})
            return self.send(422, {"message": "Invalid credentials"})

        def do_PUT(self):
            raise AssertionError("mutation forbidden")

        def do_DELETE(self):
            raise AssertionError("mutation forbidden")

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if material:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(material["server_cert"]), str(material["server_key"]))
        httpd.socket = tls.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"{'https' if material else 'http'}://localhost:{httpd.server_port}/tenant", calls
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3)


@pytest.mark.parametrize("tls", [False, True])
@pytest.mark.parametrize("auth", ["pair", "key", "jwt"])
def test_real_portainer_auth_inventory_prefix_tls_and_clean_files(tls, auth, mtls_material, tmp_path, capsys):
    with portainer_server(mtls_material if tls else None) as (url, calls):
        credentials = {
            "pair": ["-u", "admin", "-p", "secret"],
            "key": ["--token", "ptr_qa"],
            "jwt": ["--token", "eyJ.test.jwt"],
        }[auth]
        common = [
            "portainer",
            "-t",
            url,
            "--timeout",
            "1",
            "--no-color",
            *credentials,
            "--show-endpoints",
            "--endpoint",
            "local",
            "--show-containers",
            "--show-images",
            "--show-networks",
            "--show-volumes",
            "--show-system",
        ]
        output = tmp_path / "result.json"
        assert main([*common, "--discover", "-f", "json", "-o", str(output)]) == 0
        record = json.loads(output.read_text())
        assert record["is_portainer"] is True
        assert record.get("is_docker") is not True
        assert record["provided_credentials_ok"] is True
        assert record["ui"]["inventory"]["containers"]["count"] == 1
        assert record["ui"]["inventory"]["images"]["count"] == 0
        assert record["content_discovery"]["findings"]
        assert "portainer_metadata" not in record
        assert "issued" not in output.read_text()
        assert "ptr_qa" not in output.read_text()
        assert "eyJ.test.jwt" not in output.read_text()
        txt = tmp_path / "result.txt"
        assert main([*common, "-o", str(txt)]) == 0
        assert "Portainer" in txt.read_text()
        assert "Containers Enumeration (count:1)" in txt.read_text()
        assert "\x1b" not in output.read_text() + txt.read_text() + capsys.readouterr().out
        assert all(method == "GET" or path == "/tenant/api/auth" for method, path, body in calls)
        if auth != "pair":
            assert all(method == "GET" for method, path, body in calls)


def test_full_command_defcreds_stops_after_first_429(capsys):
    from redposture_core.web_panels import default_pairs

    with portainer_server(blocked=True) as (url, calls):
        assert main(["portainer", "-t", url, "--defcreds", "--no-color", "--timeout", "1", "-f", "json"]) == 0
        record = json.loads(capsys.readouterr().out)
        assert record["status"] == "rate_limited"
        assert len([call for call in calls if call[0] == "POST"]) == 1
        assert record["credential_attempts_skipped"] == len(default_pairs("portainer")) - 1


@pytest.mark.parametrize(
    "accepted_pair", [("portainer", "portainer123"), ("root", "root"), ("administrator", "administrator")]
)
def test_full_defcreds_sweep_finds_non_admin_identity_once(accepted_pair, capsys, tmp_path):
    from redposture_core.web_panels import default_pairs

    target = tmp_path / "portainer.json"
    with portainer_server(accepted_pair=accepted_pair) as (url, calls):
        assert (
            main(
                ["portainer", "-t", url, "--defcreds", "--no-color", "--timeout", "1", "-f", "json", "-o", str(target)]
            )
            == 0
        )
        record = json.loads(target.read_text())
        attempted = [(body["Username"], body["Password"]) for method, path, body in calls if method == "POST"]
        assert attempted == list(default_pairs("portainer"))
        assert attempted.count(accepted_pair) == 1
        assert record["provided_credentials_ok"] is True
        assert record["provided_username"] == accepted_pair[0]
        verified = [
            item
            for item in record["attempted_credentials"]
            if item["status"] == "valid_credentials" and item["credential_state"] == "valid"
        ]
        assert [(item["username"], item["password"]) for item in verified] == [accepted_pair]
        assert "issued" not in target.read_text()
        assert "\x1b" not in target.read_text() + capsys.readouterr().out


def test_full_command_mismatched_identity_cannot_authenticate(capsys):
    with portainer_server(mismatch=True) as (url, calls):
        assert (
            main(
                [
                    "portainer",
                    "-t",
                    url,
                    "-u",
                    "admin",
                    "-p",
                    "secret",
                    "--show-containers",
                    "--no-color",
                    "--timeout",
                    "1",
                    "-f",
                    "json",
                ]
            )
            == 0
        )
        record = json.loads(capsys.readouterr().out)
        assert record["provided_credentials_ok"] is None
        assert record["credential_state"] == "unverified"
        assert not any("/docker/" in path for method, path, body in calls)


def test_anonymous_inventory_is_exposure_without_credentials(capsys):
    with portainer_server(anonymous=True) as (url, calls):
        assert main(["portainer", "-t", url, "--show-endpoints", "--no-color", "--timeout", "1", "-f", "json"]) == 0
        record = json.loads(capsys.readouterr().out)
        assert record["status"] == "open_no_auth"
        assert record["auth_required"] is False
        assert record["ui"]["inventory"]["environments"]["count"] == 1
        assert record.get("provided_credentials_ok") is not True
        assert all(method == "GET" for method, path, body in calls)


def test_real_http_proxy_carries_portainer_prefix_and_key(capsys):
    with portainer_server() as (url, calls):
        proxy = url.removesuffix("/tenant")
        assert (
            main(
                [
                    "portainer",
                    "-t",
                    "http://portainer.invalid:9000/tenant",
                    "--proxy",
                    proxy,
                    "--token",
                    "ptr_qa",
                    "--show-endpoints",
                    "--no-color",
                    "--timeout",
                    "1",
                    "-f",
                    "json",
                ]
            )
            == 0
        )
        record = json.loads(capsys.readouterr().out)
        assert record.get("provided_credentials_ok") is True, (record, calls)
        assert record["ui"]["inventory"]["environments"]["count"] == 1
        assert any(path == "/tenant/api/users/me" and body.get("X-API-Key") == "ptr_qa" for method, path, body in calls)


@pytest.mark.parametrize("kind", ["pair", "token"])
def test_real_spray_preserves_portainer_verifier_for_pairs_and_tokens(kind, tmp_path, capsys):
    with portainer_server() as (url, calls):
        source = tmp_path / "credentials.txt"
        source.write_text("admin:secret\n" if kind == "pair" else "ptr_qa\n")
        option = "--pairs" if kind == "pair" else "--tokens"
        assert (
            main(
                [
                    "spray",
                    "-t",
                    url,
                    "--modules",
                    "portainer",
                    option,
                    str(source),
                    "--checkpoint",
                    str(tmp_path / "spray.sqlite"),
                    "--origin-rate",
                    "1000",
                    "--account-interval",
                    "0.001",
                    "--no-color",
                    "--timeout",
                    "1",
                    "-f",
                    "json",
                ]
            )
            == 0
        )
        records = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
        attempts = [record for record in records if record.get("credential_type") == kind]
        assert len(attempts) == 1
        assert attempts[0]["status"] == "valid"
        assert attempts[0]["module"] == "portainer"
        assert attempts[0]["surface"] == "ui"
        assert any(path == "/tenant/api/users/me" for method, path, body in calls)
