"""Exercise the actual HTTP client, target-prefix/TLS binding and output runner."""

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

TOKEN = "11111111-1111-4111-8111-111111111111"
INVALID = "00000000-0000-4000-8000-000000000001"
SECRET = "qa-database-password"


@contextmanager
def server(
    module: str, protected: bool, material: dict[str, Path] | None
) -> Iterator[tuple[str, list[tuple[str, str]]]]:
    calls: list[tuple[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: Any) -> None:
            pass

        def do_GET(self) -> None:
            self.respond()

        def do_LIST(self) -> None:
            self.respond()

        def respond(self) -> None:
            calls.append((self.command, self.path))
            path = urlsplit(self.path).path
            if not path.startswith("/proxy/"):
                self.send(404, {})
                return
            path = path[len("/proxy") :]
            supplied = self.headers.get(
                {"vault": "X-Vault-Token", "nomad": "X-Nomad-Token", "jupyter": "Authorization"}[module], ""
            )
            valid = supplied == ("token " + TOKEN if module == "jupyter" else TOKEN)
            allowed = valid or not protected
            if module == "vault":
                if path == "/v1/sys/health":
                    self.send(
                        200,
                        {
                            "initialized": True,
                            "sealed": False,
                            "standby": False,
                            "version": "1.17.5",
                            "enterprise": False,
                        },
                    )
                elif path == "/v1/auth/token/lookup-self":
                    self.send(200, {"data": {"id": TOKEN, "policies": ["reader"], "ttl": 300}}) if valid else self.send(
                        403, {"errors": ["invalid token"]}
                    )
                elif not allowed:
                    self.send(403, {"errors": ["permission denied"]})
                elif path == "/v1/sys/mounts":
                    self.send(200, {"data": {"secret/": {"type": "kv", "options": {"version": "2"}}}})
                elif path == "/v1/sys/auth":
                    self.send(200, {"data": {"token/": {"type": "token"}}})
                elif path == "/v1/secret/metadata/":
                    self.send(200, {"data": {"keys": ["config"]}})
                elif path == "/v1/secret/data/config":
                    self.send(200, {"data": {"data": {"password": SECRET}}})
                else:
                    self.send(404, {})
            elif module == "nomad":
                if path == "/v1/status/leader":
                    self.send(200, "127.0.0.1:4647")
                elif path == "/ui/":
                    self.send(200, '<title>Nomad</title><meta name="nomad-ui/config/environment">')
                elif path == "/v1/acl/token/self":
                    if valid and protected:
                        self.send(
                            200, {"SecretID": TOKEN, "AccessorID": "accessor", "Type": "client", "Policies": ["read"]}
                        )
                    elif not protected:
                        self.send(200, {"ACLsEnabled": False})
                    else:
                        self.send(403, "ACL token not found")
                elif not allowed:
                    self.send(403, "Permission denied")
                elif path == "/v1/agent/self":
                    self.send(
                        200, {"config": {"Version": {"Version": "1.10.1"}, "ACL": {"Enabled": protected}}, "stats": {}}
                    )
                elif path == "/v1/jobs":
                    self.send(200, [{"ID": "reporting", "Namespace": "default"}])
                elif path == "/v1/job/reporting":
                    self.send(200, {"ID": "reporting", "TaskGroups": [{"Tasks": [{"Env": {"PASSWORD": SECRET}}]}]})
                elif path == "/v1/nodes":
                    self.send(200, [])
                elif path == "/v1/agent/members":
                    self.send(200, {"Members": []})
                else:
                    self.send(404, {})
            else:
                if path == "/api":
                    self.send(200, {"version": "2.17.0"})
                elif path == "/login":
                    self.send(200, '<title>Jupyter Server</title><form id="login_form">')
                elif not allowed:
                    self.send(403, {"message": "Forbidden", "reason": None})
                elif path == "/api/status":
                    self.send(
                        200, {"connections": 0, "kernels": 0, "started": "2026-10-20", "last_activity": "2026-10-20"}
                    )
                elif path == "/api/me":
                    self.send(200, {"identity": {"username": "reader"}})
                elif path in {"/api/kernels", "/api/sessions"}:
                    self.send(200, [])
                elif path == "/api/contents":
                    self.send(
                        200,
                        {
                            "name": "",
                            "path": "",
                            "type": "directory",
                            "content": [{"name": "demo.ipynb", "path": "demo.ipynb", "type": "notebook"}],
                        },
                    )
                elif path == "/api/contents/demo.ipynb":
                    self.send(
                        200,
                        {
                            "name": "demo.ipynb",
                            "path": "demo.ipynb",
                            "type": "notebook",
                            "content": {"cells": [{"source": "password = '" + SECRET + "'"}]},
                        },
                    )
                else:
                    self.send(404, {})

        def send(self, status: int, data: Any) -> None:
            body = data.encode() if isinstance(data, str) and data.startswith("<") else json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html" if body.startswith(b"<") else "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.daemon_threads = True
    if material:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(material["server_cert"]), str(material["server_key"]))
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


@pytest.mark.parametrize("module", ["vault", "nomad", "jupyter"])
@pytest.mark.parametrize("protected", [True, False])
@pytest.mark.parametrize("tls", [True, False])
def test_real_http_runner_prefix_tls_token_inventory_and_discovery(
    module: str, protected: bool, tls: bool, mtls_material: dict[str, Path], tmp_path: Path, capsys: Any
) -> None:
    with server(module, protected, mtls_material if tls else None) as (url, calls):
        flags = {
            "vault": ["--show-mounts", "--show-auth"],
            "nomad": ["--show-jobs", "--show-nodes", "--show-members"],
            "jupyter": ["--show-contents", "--show-sessions", "--show-kernels"],
        }[module]
        common = [module, "-t", url, "--no-color", "--timeout", "1"]
        if tls:
            common += ["--tls-ca", str(mtls_material["ca_cert"])]
        output = tmp_path / "result.json"
        assert (
            main([*common, "--token", TOKEN, *flags, "--discover", "--enum-cve", "-f", "json", "-o", str(output)]) == 0
        )
        result = json.loads(output.read_text())
        assert result[f"is_{module}"] is True
        assert (
            result["provided_credentials_ok"] is True
            if protected or module == "vault"
            else result.get("provided_credentials_ok") is not True
        )
        assert result["content_discovery"]["findings"]
        assert "\x1b" not in output.read_text()
        txt = tmp_path / "result.txt"
        assert main([*common, "--token", TOKEN, *flags, "-o", str(txt)]) == 0
        assert "\x1b" not in txt.read_text()
        assert "Enumeration" in txt.read_text() or "Secret Engines" in txt.read_text()
        capsys.readouterr()
        assert main([*common, "--token", INVALID, "-f", "json"]) == 0
        invalid = json.loads(capsys.readouterr().out)
        assert invalid.get("provided_credentials_ok") is not True
        assert all(method in {"GET", "LIST"} and path.startswith("/proxy/") for method, path in calls)
