"""CLI-to-wire execution contracts; emulation, separate from vendor labs."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _frame(value):
    data = json.dumps(value).encode()
    return b"\x81" + (bytes([len(data)]) if len(data) < 126 else b"\x7e" + len(data).to_bytes(2, "big")) + data


@pytest.mark.parametrize("mode", ["nomad-job", "nomad-allocation", "nomad-probe", "jupyter-kernel", "jupyter-terminal"])
@pytest.mark.parametrize("tls", [False, True])
def test_execute_http_contract(mode, tls, tmp_path, mtls_material):
    _run(mode, tls, False, tmp_path, mtls_material)


@pytest.mark.parametrize("mode", ["nomad-job", "jupyter-kernel"])
def test_execute_http_denial_does_not_claim_success_or_create_resource(mode, tmp_path, mtls_material):
    _run(mode, False, True, tmp_path, mtls_material)


def _run(mode, tls, deny, tmp_path, material):
    module, action = mode.split("-", 1)
    state = {"job": None, "created": [], "deleted": [], "commands": [], "posts": []}
    allocation = "11111111-2222-3333-4444-555555555555"

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def reply(self, status, value, raw=False):
            body = value if raw else json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/plain" if raw else "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urlsplit(self.path)
            path = parsed.path.removeprefix("/proxy")
            token = self.headers.get("Authorization") == "token qa-token"
            if path.endswith("/channels") or path.endswith("/websocket/owned") or path.endswith("/exec"):
                key = self.headers["Sec-WebSocket-Key"]
                accept = base64.b64encode(
                    hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
                ).decode()
                self.send_response(101)
                self.send_header("Upgrade", "websocket")
                self.send_header("Connection", "Upgrade")
                self.send_header("Sec-WebSocket-Accept", accept)
                self.end_headers()
                self.connection.settimeout(3)

                def read_request():
                    a, b = self.rfile.read(2)
                    length = b & 127
                    if length in {126, 127}:
                        length = int.from_bytes(self.rfile.read(2 if length == 126 else 8), "big")
                    mask = self.rfile.read(4)
                    data = self.rfile.read(length)
                    return json.loads(bytes(c ^ mask[i % 4] for i, c in enumerate(data)))

                request = read_request()
                if module == "nomad":
                    packets = [
                        {"stdout": {"data": base64.b64encode(b"emulated-output\n").decode()}},
                        {"exited": True, "result": {"exit_code": 7}},
                    ]
                elif action == "kernel":
                    code = request["content"]["code"]
                    assert "printf qa" in code
                    state["commands"].append(code)
                    marker = re.search(r"REDPOSTURE_RESULT_[a-f0-9]+", code).group()
                    parent = {"msg_id": request["header"]["msg_id"]}
                    packets = [
                        {
                            "parent_header": parent,
                            "msg_type": "stream",
                            "content": {
                                "text": marker
                                + json.dumps({"exit_code": 7, "stdout": "emulated-output\n", "stderr": ""})
                            },
                        },
                        {"parent_header": parent, "msg_type": "execute_reply", "content": {"status": "ok"}},
                        {"parent_header": parent, "msg_type": "status", "content": {"execution_state": "idle"}},
                    ]
                else:
                    assert request[0] == "stdin"
                    nonce = re.search(r"\\036([a-f0-9]+)READY", request[1]).group(1)
                    self.wfile.write(_frame(["stdout", "\x1e" + nonce + "READY\x1f"]))
                    self.wfile.flush()
                    while "START" not in request[1]:
                        request = read_request()
                    state["commands"].append(request[1])
                    packets = [["stdout", "\x1e" + nonce + "START\x1femulated-output\r\n\x1e" + nonce + "END:7\x1f"]]
                self.wfile.write(b"".join(_frame(p) for p in packets))
                self.wfile.flush()
                self.close_connection = True
                return
            if module == "nomad":
                routes = {
                    "/v1/agent/self": {
                        "config": {"Version": {"Version": "1.10.1"}, "ACL": {"Enabled": False}},
                        "stats": {},
                    },
                    "/v1/status/leader": "127.0.0.1:4647",
                    "/v1/jobs": [],
                    "/v1/acl/token/self": {"SecretID": "qa-token", "AccessorID": "qa", "Type": "management"},
                    f"/v1/allocation/{allocation}": {"TaskStates": {"app": {"State": "running"}}},
                    "/v1/allocation/owned": {
                        "TaskStates": {"command": {"Events": [{"Type": "Terminated", "ExitCode": 7}]}}
                    },
                }
                if path.endswith("/allocations"):
                    return self.reply(200, [{"ID": "owned", "JobID": state["job"], "ClientStatus": "complete"}])
                if path.startswith("/v1/client/fs/logs/"):
                    return self.reply(200, b"emulated-output\n", raw=True)
                return self.reply(200, routes[path]) if path in routes else self.reply(404, {})
            if path == "/api":
                return self.reply(200, {"version": "2.17.0"})
            if path == "/login":
                return self.reply(200, "<title>Jupyter</title><form id='login_form'>")
            if path == "/api/status":
                return (
                    self.reply(200, {"connections": 0, "kernels": 0, "started": "now", "last_activity": "now"})
                    if token
                    else self.reply(403, {"message": "Forbidden"})
                )
            if path == "/api/terminals":
                return self.reply(200, [{"name": "existing"}]) if token else self.reply(403, {})
            return self.reply(404, {})

        def do_POST(self):
            path = urlsplit(self.path).path.removeprefix("/proxy")
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            state["posts"].append(path)
            if deny:
                return self.reply(403, {"message": "Forbidden"})
            if module == "nomad":
                state["job"] = body["Job"]["ID"]
                assert body["Job"]["Stop"] is (action == "probe")
                state["created"].append(state["job"])
                return self.reply(200, {"EvalID": "eval", "JobModifyIndex": 5})
            state["created"].append("owned")
            return self.reply(201, {"id": "owned"}) if path == "/api/kernels" else self.reply(200, {"name": "owned"})

        def do_DELETE(self):
            path = urlsplit(self.path).path.removeprefix("/proxy")
            state["deleted"].append(path.rsplit("/", 1)[-1])
            return self.reply(200, {})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(material["server_cert"], material["server_key"])
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"{'https://localhost' if tls else 'http://127.0.0.1'}:{server.server_port}/proxy"
        output = tmp_path / "result.json"
        args = [
            sys.executable,
            str(ROOT / "redposture.py"),
            module,
            "-t",
            target,
            "--token",
            "qa-token",
            "--format",
            "json",
            "-o",
            str(output),
        ]
        if tls:
            args += ["--tls-ca", str(material["ca_cert"])]
        if action == "probe":
            args += ["--probe-submit"]
        else:
            args += ["--execute", "printf qa", "--execute-timeout", "2", "--execute-max-bytes", "1048576"]
            if module == "jupyter":
                args += ["--execute-via", action, "--kernel", "python3", "--show-terminals"]
            elif action == "allocation":
                args += ["--allocation", allocation, "--task", "app"]
        completed = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=10)
        records = [json.loads(line) for line in output.read_text().splitlines()]
        record = next(r for r in records if r.get("is_" + module))
        if deny:
            assert not record["execution"]["executed"]
            assert not state["created"] and len(state["posts"]) == 1
            assert completed.returncode != 0
        elif action == "probe":
            assert record["submit_probe"]["access"] == "allowed"
            assert not record["submit_probe"]["executed"]
        else:
            assert record["execution"]["executed"] and record["execution"]["exit_code"] == 7, (record, completed.stderr)
            assert record["execution"]["stdout"] == "emulated-output\n"
        assert sorted(state["created"]) == sorted(state["deleted"])
        assert "\x1b" not in output.read_text()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
