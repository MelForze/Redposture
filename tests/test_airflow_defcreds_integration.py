"""Wire-level QA for the complete Airflow default-credential lifecycle."""

from __future__ import annotations

import base64
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import urlsplit

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.airflow.stage import build_airflow_plan, build_airflow_spec
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandResult, AuditCommandRunner

Credential = tuple[str, str]


class _AirflowQaServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        generation: str,
        *,
        valid: set[Credential] | None = None,
        transient: set[Credential] | None = None,
        anonymous: bool = False,
    ) -> None:
        super().__init__(("127.0.0.1", 0), _AirflowQaHandler)
        self.generation = generation
        self.valid = set(valid or ())
        self.transient = set(transient or ())
        self.anonymous = anonymous
        self.calls: list[tuple[str, str, str | None]] = []
        self.basic_dag_requests: list[Credential] = []
        self.token_attempts: list[Credential] = []
        self.issued_tokens: dict[str, Credential] = {}


class _AirflowQaHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args: Any) -> None:
        return

    @property
    def qa(self) -> _AirflowQaServer:
        return cast(_AirflowQaServer, self.server)

    def _reply(self, status: int, payload: object | None = None) -> None:
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _basic_credential(self) -> Credential | None:
        value = self.headers.get("Authorization", "")
        if not value.startswith("Basic "):
            return None
        try:
            decoded = base64.b64decode(value[6:], validate=True).decode("utf-8")
            username, password = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            return None
        return username, password

    def _bearer_credential(self) -> Credential | None:
        value = self.headers.get("Authorization", "")
        if not value.startswith("Bearer "):
            return None
        return self.qa.issued_tokens.get(value[7:])

    def _problem(self, status: int) -> None:
        title = "Unauthorized" if status == 401 else "Forbidden"
        self._reply(status, {"status": status, "title": title, "detail": "Access denied"})

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        path = urlsplit(self.path).path
        authorization = self.headers.get("Authorization")
        self.qa.calls.append(("GET", path, authorization))

        if path == "/api/v2/version":
            if self.qa.generation == "v2":
                self._reply(200, {"version": "3.0.2", "git_version": "qa"})
            else:
                self._reply(404)
            return
        if path == "/api/v1/version":
            if self.qa.generation == "v1":
                self._reply(200, {"version": "2.11.1", "git_version": "qa"})
            else:
                self._reply(404)
            return

        prefix = f"/api/{self.qa.generation}"
        if path not in {f"{prefix}/dags", f"{prefix}/variables", f"{prefix}/connections"}:
            self._reply(404)
            return
        if self.qa.anonymous:
            key = "dags" if path.endswith("/dags") else "variables" if path.endswith("/variables") else "connections"
            self._reply(200, {key: [], "total_entries": 0})
            return

        credential = self._basic_credential() if self.qa.generation == "v1" else self._bearer_credential()
        if path.endswith("/dags") and self.qa.generation == "v1" and credential is not None:
            self.qa.basic_dag_requests.append(credential)
            if credential in self.qa.transient:
                self._reply(503, {"detail": "temporary backend failure"})
                return
        if credential not in self.qa.valid:
            self._problem(401 if path.endswith("/dags") else 403)
            return
        key = "dags" if path.endswith("/dags") else "variables" if path.endswith("/variables") else "connections"
        self._reply(200, {key: [], "total_entries": 0})

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        path = urlsplit(self.path).path
        self.qa.calls.append(("POST", path, self.headers.get("Authorization")))
        if path != "/auth/token" or self.qa.generation != "v2":
            self._reply(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            credential = str(payload["username"]), str(payload["password"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self._reply(400, {"detail": "invalid request"})
            return
        self.qa.token_attempts.append(credential)
        if credential in self.qa.transient:
            self._reply(503, {"detail": "temporary backend failure"})
            return
        if credential not in self.qa.valid:
            self._reply(401, {"detail": "invalid credentials"})
            return
        token = f"qa-token-{len(self.qa.issued_tokens) + 1}"
        self.qa.issued_tokens[token] = credential
        self._reply(200, {"access_token": token, "token_type": "bearer"})


@contextmanager
def _serve(
    generation: str,
    *,
    valid: set[Credential] | None = None,
    transient: set[Credential] | None = None,
    anonymous: bool = False,
) -> Iterator[_AirflowQaServer]:
    server = _AirflowQaServer(generation, valid=valid, transient=transient, anonymous=anonymous)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _run(
    server: _AirflowQaServer,
    *,
    output_format: str = "txt",
    extra_args: tuple[str, ...] = (),
) -> tuple[AuditCommandResult, list[str], AuditCommandPlan]:
    args = parse_args(
        [
            "airflow",
            "-t",
            f"http://127.0.0.1:{server.server_port}",
            "--defcreds",
            "--timeout",
            "1",
            "--retries",
            "0",
            "--workers",
            "1",
            "-f",
            output_format,
            *extra_args,
        ]
    )
    plan = build_airflow_plan(args)
    lines: list[str] = []
    result = AuditCommandRunner(args=args, spec=build_airflow_spec(args), emit_line=lines.append).run_plan(plan)
    return result, lines, plan


def _plan_pairs(plan: AuditCommandPlan) -> list[Credential]:
    return [(str(run.username), str(run.password)) for run in plan.credential_runs]


def test_airflow2_defcreds_checks_every_pair_and_continues_after_success_and_transient_failure() -> None:
    valid = {("admin", "admin"), ("airflow", "airflow")}
    with _serve("v1", valid=valid, transient={("service", "service")}) as server:
        result, lines, plan = _run(server)

    expected = _plan_pairs(plan)
    assert len(expected) == 18
    assert server.basic_dag_requests[: len(expected)] == expected
    assert set(server.basic_dag_requests[: len(expected)]) == set(expected)
    credential_lines = [line for line in lines if "\t [+] " in line or "\t [-] " in line]
    assert len(credential_lines) == len(expected)
    assert any("[+] admin:admin (Dags:0) (Keys:0) (Connections:0)" in line for line in credential_lines)
    assert any("[+] airflow:airflow" in line for line in credential_lines)
    assert any("[-] service:service" in line for line in credential_lines)
    assert result.detected_count == 1 and result.operational_failure_count == 0


def test_airflow2_defcreds_all_rejected_reports_every_pair_once() -> None:
    with _serve("v1") as server:
        result, lines, plan = _run(server)

    expected = _plan_pairs(plan)
    assert server.basic_dag_requests == expected
    rejected = [line for line in lines if "\t [-] " in line]
    assert len(rejected) == len(expected)
    assert not any("\t [+] " in line for line in lines)
    assert result.records[0]["provided_credentials_ok"] is False
    assert len(result.records[0]["attempted_credentials"]) == len(expected)


def test_airflow3_defcreds_deduplicates_provided_pair_uses_bearer_and_redacts_json() -> None:
    valid = {("airflow", "airflow")}
    with _serve("v2", valid=valid, transient={("dev", "dev")}) as server:
        _result, lines, plan = _run(
            server,
            output_format="json",
            extra_args=("-u", "airflow", "-p", "airflow"),
        )

    expected = _plan_pairs(plan)
    assert len(expected) == 18
    assert expected[0] == ("airflow", "airflow")
    assert expected.count(("airflow", "airflow")) == 1
    assert server.token_attempts == expected
    assert any(auth and auth.startswith("Bearer qa-token-") for _method, _path, auth in server.calls)
    payload = next(json.loads(line) for line in lines if line.startswith("{") and '"service": "airflow"' in line)
    assert payload["credential_state"] == "valid"
    assert payload["authenticated_dags_count"] == 0
    assert payload["authenticated_keys_count"] == 0
    assert payload["authenticated_connections_count"] == 0
    assert "role" not in payload
    assert payload["default_credentials"] is False
    assert "credential_password" not in payload
    assert "attempted_credentials" not in payload
    assert "qa-token-" not in json.dumps(payload)


@pytest.mark.parametrize("generation", ["v1", "v2"])
def test_anonymous_airflow_skips_unverifiable_defcreds(generation: str) -> None:
    with _serve(generation, anonymous=True) as server:
        result, lines, _plan = _run(server)

    assert server.basic_dag_requests == []
    assert server.token_attempts == []
    assert result.records[0]["status"] == "open_no_auth"
    assert result.records[0]["credential_verification_status"] == "unavailable"
    assert sum("Airflow (auth required:False)" in line for line in lines) == 1
    assert not any("\t [+] " in line or "\t [-] " in line for line in lines)
