"""Nexus Script API protocol and ambiguous-write cleanup regressions."""

from __future__ import annotations

import json
import re
from types import SimpleNamespace as NS
from typing import Any

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.nexus import execution
from tests.groovy_execute_support import run_groovy


def _response(status: int | None, value: Any = None, **kwargs: Any) -> HttpResponse:
    return HttpResponse(status, json.dumps(value).encode(), {"Content-Type": "application/json"}, **kwargs)


class ScriptPool:
    def __init__(self, *, create: str = "ok", exists: int = 200, run: str = "ok", cleanup: int = 204) -> None:
        self.create, self.exists, self.run, self.cleanup = create, exists, run, cleanup
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.name = self.marker = ""

    def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
        self.calls.append((method, url, kwargs))
        if method == "POST" and url.endswith("/script"):
            data = json.loads(kwargs["body"])
            self.name = data["name"]
            self.marker = re.search(r"RP_NEXUS_[0-9a-f]+:", data["content"])[0]
            if self.create == "lost":
                return _response(None, error="response lost after create")
            if self.create == "raised":
                raise OSError("response lost after create")
            if self.create == "denied":
                return _response(403)
            return _response(204)
        if method == "POST" and url.endswith("/" + self.name + "/run"):
            if kwargs["headers"].get("Content-Type") != "application/json":
                return _response(415)
            proof: dict[str, Any] = {
                "exit_code": 7,
                "stdout": "out\n",
                "stderr": "err\n",
                "timed_out": False,
                "truncated": False,
            }
            if self.run == "bad_exit":
                proof["exit_code"] = True
            if self.run == "bad_stdout":
                proof["stdout"] = ["out"]
            if self.run == "missing_stderr":
                proof.pop("stderr")
            if self.run == "ansi":
                proof["stdout"] = "\x1b[31mout\x1b[0m"
            result = self.marker + json.dumps(proof)
            if self.run == "raw":
                return HttpResponse(200, result.encode(), {"Content-Type": "application/json"})
            if self.run == "wrong_marker":
                result = "RP_NEXUS_wrong:" + json.dumps(proof)
            if self.run == "trailing":
                result += " trailing response"
            if self.run == "prefix":
                result = "unrelated output " + result
            return _response(
                200,
                {
                    "name": "another-script" if self.run == "wrong_name" else self.name,
                    "result": None if self.run == "null" else result,
                },
            )
        assert url.endswith("/" + self.name), (method, url)
        if method == "GET":
            return _response(self.exists, {"name": self.name, "type": "groovy", "content": ""})
        assert method == "DELETE"
        return _response(self.cleanup)


def _collect(pool: ScriptPool) -> tuple[dict[str, Any], Any, dict[str, Any], Any]:
    ctx = NS(
        args=NS(execute="printf out; printf err >&2; exit 7", execute_timeout=1.0, execute_max_bytes=64),
        credential=NS(username="admin", password="qa", token=None),
    )
    state = NS(http=pool, scheme="http", base_path="/prefix", host="nexus.test", port=8081, execution=None)
    record = {
        "is_nexus": True,
        "status": "valid_credentials",
        "provided_credentials_ok": True,
        "detection_status": "confirmed",
    }
    return execution.collect(ctx, record, state), ctx, record, state


def test_nexus_run_uses_json_media_type_and_actual_named_result_envelope() -> None:
    pool = ScriptPool()
    result, *_ = _collect(pool)
    output = result["execution"]
    assert output["executed"] is True and output["exit_code"] == 7
    assert output["stdout"] == "out\n" and output["stderr"] == "err\n"
    assert output["cleanup"] == "complete"
    assert [method for method, _, _ in pool.calls] == ["POST", "POST", "DELETE"]
    assert all(call[2]["retries"] == 0 and call[2]["replay_safe"] is False for call in pool.calls)


@pytest.mark.parametrize(
    "mode",
    ["raw", "null", "wrong_name", "wrong_marker", "trailing", "prefix", "bad_exit", "bad_stdout", "missing_stderr"],
)
def test_nexus_rejects_unverified_or_malformed_run_envelopes(mode: str) -> None:
    pool = ScriptPool(run=mode)
    result, ctx, record, state = _collect(pool)
    assert result["execution"]["executed"] is False and result["operational_failure"] is True
    assert result["execution"]["cleanup"] == "complete"
    count = len(pool.calls)
    again = execution.collect(ctx, record, state)
    assert len(pool.calls) == count
    assert again["operational_failure"] is True


@pytest.mark.parametrize("create", ["lost", "raised"])
def test_nexus_lost_create_response_checks_and_deletes_only_its_name_without_replay(create: str) -> None:
    pool = ScriptPool(create=create)
    result, ctx, record, state = _collect(pool)
    assert result["execution"]["executed"] is False
    assert result["execution"]["cleanup"] == "complete"
    assert [method for method, _, _ in pool.calls] == ["POST", "GET", "DELETE"]
    assert pool.calls[1][1] == pool.calls[2][1] == pool.calls[0][1] + "/" + pool.name
    again = execution.collect(ctx, record, state)
    assert again["execution"] == result["execution"] and again["operational_failure"] is True
    assert len(pool.calls) == 3


def test_nexus_missing_ambiguous_script_is_complete_cleanup_without_delete() -> None:
    pool = ScriptPool(create="lost", exists=404)
    result, *_ = _collect(pool)
    assert result["execution"]["cleanup"] == "complete"
    assert [method for method, _, _ in pool.calls] == ["POST", "GET"]


def test_nexus_unknown_existence_still_attempts_own_name_cleanup() -> None:
    pool = ScriptPool(create="lost", exists=503, cleanup=403)
    result, *_ = _collect(pool)
    assert result["execution"]["cleanup"] == "failed"
    assert result["execution"]["cleanup_error"]
    assert [method for method, _, _ in pool.calls] == ["POST", "GET", "DELETE"]


def test_nexus_denied_creation_does_not_delete_any_script() -> None:
    pool = ScriptPool(create="denied")
    result, *_ = _collect(pool)
    assert result["execution"]["executed"] is False
    assert result["execution"]["cleanup"] == "not_needed"
    assert [method for method, _, _ in pool.calls] == ["POST"]


def test_nexus_envelope_output_is_sanitized_before_saved_json() -> None:
    result, *_ = _collect(ScriptPool(run="ansi"))
    assert result["execution"]["stdout"] == "out"
    assert "\x1b" not in json.dumps(result)


def test_nexus_generated_script_returns_completion_value_instead_of_null() -> None:
    source = execution._script("printf out; printf err >&2; exit 7", "RP_NEXUS_TEST:", 1.0, 64)
    encoded = __import__("base64").b64encode(source.encode()).decode()
    wrapper = (
        'def result = new GroovyShell().evaluate(new String(java.util.Base64.decoder.decode("'
        + encoded
        + '"), "UTF-8")); println("RP_RETURN:" + groovy.json.JsonOutput.toJson(result))'
    )
    output = run_groovy(wrapper)
    returned = json.loads(output.split("RP_RETURN:", 1)[1])
    assert isinstance(returned, str) and returned.startswith("RP_NEXUS_TEST:")
    proof = json.loads(returned.removeprefix("RP_NEXUS_TEST:"))
    assert proof["exit_code"] == 7 and proof["stdout"] == "out" and proof["stderr"] == "err"


def test_nexus_generated_script_drains_large_output_with_bounded_capture() -> None:
    script = execution._script(
        "head -c 262144 /dev/zero; head -c 262144 /dev/zero >&2; exit 7", "RP_NEXUS_TEST:", 1.5, 64
    )
    output = run_groovy(script)
    proof = json.loads(output.split("RP_NEXUS_TEST:", 1)[1])
    assert proof["exit_code"] == 7 and proof["timed_out"] is False and proof["truncated"] is True
    assert len(proof["stdout"].encode()) + len(proof["stderr"].encode()) == 64
