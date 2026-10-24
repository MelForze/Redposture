"""Jenkins Script Console execution: identity proof, CSRF session, and bounded output."""

from __future__ import annotations

import base64
import json
import re
import shlex
from pathlib import Path
from types import SimpleNamespace as NS
from typing import Any
from urllib.parse import parse_qs, unquote

from redposture_core.audit_models import AuditRecord
from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.jenkins import execution
from tests.groovy_execute_support import run_groovy


def _response(status: int, body: bytes | str, headers: dict[str, str] | None = None) -> HttpResponse:
    return HttpResponse(status, body.encode() if isinstance(body, str) else body, headers or {})


class Pool:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
        self.calls.append((method, url, kwargs))
        assert method == "GET" and url.endswith("/crumbIssuer/api/json")
        return _response(
            200, '{"crumb":"crumb-qa","crumbRequestField":"Jenkins-Crumb"}', {"Set-Cookie": "JSESSIONID=qa; Path=/"}
        )

    def request_once(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
        self.calls.append((method, url, kwargs))
        assert method == "POST" and url.endswith("/scriptText")
        form = kwargs["body"].decode()
        script = unquote(parse_qs(form)["script"][0])
        nonce = re.search(r"RP_EXEC_[0-9a-f]+:", script).group(0)
        proof = {
            "exit_code": 7,
            "stdout_b64": base64.b64encode(b"out").decode(),
            "stderr_b64": base64.b64encode(b"err").decode(),
            "timed_out": False,
            "truncated": False,
        }
        encoded = base64.b64encode(json.dumps(proof).encode()).decode()
        return _response(200, "Script output\n" + nonce + encoded + "\n")

    def close(self) -> None:
        return None


def _context(pool: Pool, *, source: str = "provided") -> tuple[Any, dict[str, Any], Any]:
    args = NS(execute="printf out; printf err >&2; exit 7", execute_timeout=2.0, execute_max_bytes=1024)
    record = AuditRecord.from_mapping(
        {
            "host": "qa",
            "port": 8080,
            "status": "valid_credentials",
            "detection_status": "confirmed",
            "is_jenkins": True,
            "api_endpoint": "http://qa:8080/prefix",
            "provided_credentials_ok": True,
        },
        module="jenkins",
        service="jenkins",
    ).to_dict()
    credential = NS(username="admin", password="secret", source=source)
    state = NS(http=pool, execution=None)
    return NS(args=args, credential=credential, lifecycle_state=state), record, state


def test_jenkins_script_console_returns_proven_output_and_uses_crumb() -> None:
    pool = Pool()
    ctx, record, state = _context(pool)
    result = execution.collect(ctx, record, state)
    assert result["execution"]["executed"] is True
    assert result["execution"]["exit_code"] == 7
    assert result["execution"]["stdout"] == "out"
    assert result["execution"]["stderr"] == "err"
    assert pool.calls[0][2]["headers"]["Authorization"].startswith("Basic ")
    assert pool.calls[1][2]["headers"]["Jenkins-Crumb"] == "crumb-qa"
    assert pool.calls[1][2]["headers"]["Cookie"] == "JSESSIONID=qa"


def test_jenkins_execution_is_one_shot_when_data_hook_repeats() -> None:
    pool = Pool()
    ctx, record, state = _context(pool, source="api_token")
    first = execution.collect(ctx, record, state)
    second = execution.collect(ctx, record, state)
    assert first["execution"] == second["execution"]
    assert len([call for call in pool.calls if call[0] == "POST"]) == 1
    assert len([call for call in pool.calls if call[0] == "GET"]) == 0


def test_jenkins_execution_requires_verified_identity_without_network() -> None:
    pool = Pool()
    ctx, record, state = _context(pool)
    record["provided_credentials_ok"] = None
    result = execution.collect(ctx, record, state)
    assert result["execution"]["executed"] is False
    assert not pool.calls


def test_jenkins_generated_script_drains_large_output_without_pipe_deadlock() -> None:
    script = execution._script("head -c 262144 /dev/zero; head -c 262144 /dev/zero >&2; exit 7", "RP_LARGE:", 1500, 64)
    proof = execution._decode_proof(run_groovy(script), "RP_LARGE:")
    stdout = base64.b64decode(proof["stdout_b64"])
    stderr = base64.b64decode(proof["stderr_b64"])
    assert proof["exit_code"] == 7 and proof["timed_out"] is False
    assert proof["truncated"] is True and len(stdout) + len(stderr) == 64


def test_jenkins_generated_timeout_preserves_partial_output_and_kills_descendants(tmp_path: Path) -> None:
    late = tmp_path / "jenkins-late"
    command = "printf before; (sleep 0.8; printf leaked > " + shlex.quote(str(late)) + ") & wait"
    script = execution._script(command, "RP_TIMEOUT:", 200, 64)
    output = run_groovy(
        script, after='Thread.sleep(1100); println("RP_LEFTOVER:" + new File(' + json.dumps(str(late)) + ").exists())"
    )
    proof_text = output.split("RP_LEFTOVER:", 1)[0]
    proof = execution._decode_proof(proof_text, "RP_TIMEOUT:")
    assert proof["timed_out"] is True and type(proof["exit_code"]) is int
    assert base64.b64decode(proof["stdout_b64"]) == b"before"
    assert "RP_LEFTOVER:false" in output
