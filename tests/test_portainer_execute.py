"""Portainer Docker exec: selected environment/container, evidence, and no replay."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from types import SimpleNamespace as NS
from typing import Any

from redposture_core.audit_models import AuditRecord
from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.portainer import execution


def _response(status: int, payload: Any, *, raw: bool = False) -> HttpResponse:
    body = payload if raw else json.dumps(payload).encode()
    return HttpResponse(status, body, {"Content-Type": "application/json"})


def _frame(stream: int, value: bytes) -> bytes:
    return bytes([stream, 0, 0, 0]) + len(value).to_bytes(4, "big") + value


class Pool:
    def __init__(self, *, env: dict[str, str] | None = None) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.command: list[str] = []
        self.exit_code: int | None = None
        self.env = env

    def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
        self.calls.append((method, url, kwargs))
        if method == "GET" and url.endswith("/api/endpoints?start=0&limit=100"):
            return _response(200, [{"Id": 2, "Name": "qa-engine"}])
        if method == "GET" and url.endswith("/exec/exec-1/json"):
            return _response(200, {"Running": False, "ExitCode": self.exit_code})
        raise AssertionError(f"unexpected request: {method} {url}")

    def request_once(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
        self.calls.append((method, url, kwargs))
        if method == "POST" and url.endswith("/containers/qa-container/exec"):
            payload = json.loads(kwargs["body"])
            assert payload["AttachStdout"] is True
            assert payload["AttachStderr"] is True
            assert payload["Tty"] is False
            self.command = payload["Cmd"]
            assert self.command[:2] == ["/bin/sh", "-c"]
            return _response(201, {"Id": "exec-1"})
        if method == "POST" and url.endswith("/exec/exec-1/start"):
            assert json.loads(kwargs["body"]) == {"Detach": False, "Tty": False}
            completed = subprocess.run(self.command, capture_output=True, timeout=5, env=self.env)
            self.exit_code = completed.returncode
            return _response(200, _frame(1, completed.stdout) + _frame(2, completed.stderr), raw=True)
        raise AssertionError(f"unexpected one-shot request: {method} {url}")

    def close(self) -> None:
        return None


def _context(
    pool: Pool, command: str | None = "printf out; printf err >&2; exit 7", *, record_session: bool = True
) -> Any:
    args = NS(
        execute=command,
        execute_timeout=2.0,
        execute_max_bytes=1024,
        endpoint="qa-engine",
        container="qa-container",
    )
    record = AuditRecord.from_mapping(
        {
            "host": "qa",
            "port": 9443,
            "status": "valid_credentials",
            "detection_status": "confirmed",
            "is_portainer": True,
            "surface": "ui",
            "ui_product": "portainer",
            "ui": {"endpoint": "http://qa:9443/prefix", **({"session_api_key": "ptr_qa"} if record_session else {})},
        },
        module="portainer",
        service="portainer",
    )
    state = NS(execution=None, sessions={("admin", "secret", None): {"session_api_key": "ptr_qa"}})
    credential = NS(username="admin", password="secret", token=None)
    return NS(args=args, lifecycle_state=state, host="qa", port=9443, credential=credential), record, state


def test_portainer_exec_uses_selected_environment_and_returns_streams(monkeypatch) -> None:
    pool = Pool()
    monkeypatch.setattr(execution, "HttpSessionPool", lambda **_: pool)
    ctx, record, _ = _context(pool)
    result = execution.collect(ctx, record.to_dict(), ctx.lifecycle_state)
    assert result["execution"] == {
        "command": "printf out; printf err >&2; exit 7",
        "mode": "portainer_docker_exec",
        "surface": "ui",
        "executed": True,
        "exit_code": 7,
        "stdout": "out",
        "stderr": "err",
        "status": "complete",
        "error": None,
        "cleanup": "not_needed",
        "truncated": False,
    }
    assert result["execute_verified"] is True
    assert len([call for call in pool.calls if call[0] == "POST"]) == 2
    assert all(call[2]["headers"]["X-API-Key"] == "ptr_qa" for call in pool.calls)


def test_portainer_exec_caches_ambiguous_result_and_never_replays(monkeypatch) -> None:
    pool = Pool()
    monkeypatch.setattr(execution, "HttpSessionPool", lambda **_: pool)
    ctx, record, state = _context(pool)
    first = execution.collect(ctx, record.to_dict(), state)
    second = execution.collect(ctx, record.to_dict(), state)
    assert second["execution"] == first["execution"]
    assert len([call for call in pool.calls if call[0] == "POST"]) == 2


def test_portainer_exec_uses_state_session_when_record_redacts_it(monkeypatch) -> None:
    pool = Pool()
    monkeypatch.setattr(execution, "HttpSessionPool", lambda **_: pool)
    ctx, record, state = _context(pool, record_session=False)
    result = execution.collect(ctx, record.to_dict(), state)
    assert result["execute_verified"] is True


def test_portainer_exec_requires_explicit_selector_without_network(monkeypatch) -> None:
    pool = Pool()
    monkeypatch.setattr(execution, "HttpSessionPool", lambda **_: pool)
    ctx, record, state = _context(pool)
    ctx.args.endpoint = None
    result = execution.collect(ctx, record.to_dict(), state)
    assert result["execution"]["executed"] is False
    assert "--endpoint" in result["execution"]["error"]
    assert not pool.calls


def test_portainer_exec_timeout_has_remote_proof_and_does_not_stop_container(monkeypatch, tmp_path) -> None:
    pool = Pool()
    monkeypatch.setattr(execution, "HttpSessionPool", lambda **_: pool)
    marker = tmp_path / "late"
    ctx, record, state = _context(pool, f"(sleep 0.4; printf LATE > {shlex.quote(str(marker))}) & wait")
    ctx.args.execute_timeout = 0.1
    result = execution.collect(ctx, record.to_dict(), state)
    assert result["execute_verified"] is True
    assert result["execution"]["status"] == "timeout"
    assert result["execution"]["cleanup"] == "complete"
    start = next(call for call in pool.calls if call[1].endswith("/exec/exec-1/start"))
    assert start[2]["timeout"] > ctx.args.execute_timeout
    assert all(not call[1].endswith(("/stop", "/kill")) for call in pool.calls)
    time.sleep(0.5)
    assert not marker.exists()


def test_portainer_exec_unsupported_runtime_does_not_send_command(monkeypatch, tmp_path) -> None:
    pool = Pool(env={**os.environ, "PATH": str(tmp_path)})
    monkeypatch.setattr(execution, "HttpSessionPool", lambda **_: pool)
    marker = tmp_path / "sent"
    ctx, record, state = _context(pool, f"printf SENT > {shlex.quote(str(marker))}")
    result = execution.collect(ctx, record.to_dict(), state)
    assert result["execute_verified"] is False
    assert result["execution"]["status"] == "unsupported"
    assert "Python" in result["execution"]["error"]
    assert not marker.exists()


def test_portainer_completed_exec_without_correlated_command_proof_is_unverified(monkeypatch) -> None:
    class NoProofPool(Pool):
        def request_once(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
            if url.endswith("/exec/exec-1/start"):
                self.calls.append((method, url, kwargs))
                self.exit_code = 0
                return _response(200, _frame(1, b"unrelated output"), raw=True)
            return super().request_once(method, url, **kwargs)

    pool = NoProofPool()
    monkeypatch.setattr(execution, "HttpSessionPool", lambda **_: pool)
    ctx, record, state = _context(pool)
    result = execution.collect(ctx, record.to_dict(), state)
    assert result["execute_verified"] is False
    assert result["execution"]["exit_code"] is None
    assert result["execution"]["cleanup"] == "unknown"


def test_portainer_command_streams_and_saved_json_have_no_ansi(monkeypatch) -> None:
    pool = Pool()
    monkeypatch.setattr(execution, "HttpSessionPool", lambda **_: pool)
    ctx, record, state = _context(pool, "printf '\\033[31mout\\033[0m'; printf '\\033[32merr\\033[0m' >&2")
    result = execution.collect(ctx, record.to_dict(), state)
    assert result["execution"]["stdout"] == "out"
    assert result["execution"]["stderr"] == "err"
    assert "\\u001b" not in json.dumps(result)
