"""Explicit Provectus UI execution: routing, evidence, limits, and no replay."""

from __future__ import annotations

import base64
import json
import re
import shlex
from pathlib import Path
from types import SimpleNamespace as NS
from typing import Any

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.kafka import actions, execution, policy, render, stage
from redposture_core.stage_runtime import render_record_with_module
from tests.groovy_execute_support import run_groovy


def args(*flags: str) -> Any:
    return parse_args(["kafka", "-t", "http://127.0.0.1:8080/prefix", *flags])


def response(value: Any, *, status: int = 200, **kw: Any) -> HttpResponse:
    return HttpResponse(status, json.dumps(value).encode(), {"Content-Type": "application/json"}, **kw)


class Pool:
    def __init__(self, mode: str = "ok") -> None:
        self.mode = mode
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request_once(self, method: str, url: str, **kw: Any) -> HttpResponse:
        self.calls.append((method, url, kw))
        assert method == "PUT" and url == "http://qa/prefix/api/smartfilters/testexecutions"
        script = json.loads(kw["body"])["filterCode"]
        match = re.search(r"RP_EXEC_[0-9a-f]+:", script)
        assert match, "request must carry its own completion nonce"
        proof = {
            "exit_code": 7 if self.mode == "nonzero" else 0,
            "stdout_b64": base64.b64encode(b"hello\n").decode(),
            "stderr_b64": base64.b64encode(b"warning\n").decode(),
            "timed_out": self.mode == "timeout_proof",
            "truncated": self.mode == "limited",
        }
        if self.mode == "bad_type":
            proof["exit_code"] = True
        if self.mode == "bad_b64":
            proof["stdout_b64"] = "%%%"
        if self.mode == "oversized":
            proof["stdout_b64"] = base64.b64encode(b"x" * 100).decode()
        if self.mode == "ansi":
            proof["stdout_b64"] = base64.b64encode(b"\x1b[31mhello\x1b[0m").decode()
        nonce = "RP_EXEC_wrong:" if self.mode == "wrong_nonce" else match[0]
        encoded = base64.b64encode(json.dumps(proof).encode()).decode()
        if self.mode.startswith("http_"):
            return response({"error": "denied"}, status=int(self.mode.removeprefix("http_")))
        if self.mode == "lost":
            return HttpResponse(None, b"", {}, error="timed out")
        if self.mode == "redirect":
            return HttpResponse(307, b"", {"Location": "/other"})
        if self.mode == "html":
            return HttpResponse(200, b"<html>login</html>", {"Content-Type": "text/html"})
        if self.mode == "bare_success":
            return response({"result": True})
        return response({"error": "Execution error : java.lang.RuntimeException: " + nonce + encoded})

    def request(self, method: str, url: str, **kw: Any) -> HttpResponse:
        self.calls.append((method, url, kw))
        assert method == "GET", "inventory must remain read-only"
        return response([{"name": "qa", "status": "online"}])


def apply(
    mode: str = "ok",
    *,
    vendor: str | None = "provectus",
    status: str = "open_no_auth",
    command: str | None = "printf hello",
    max_bytes: int = 1024,
    pool: Pool | None = None,
    state: Any = None,
    broker: bool = False,
) -> tuple[dict[str, Any], Any, Pool]:
    options = args(*(["--execute", command, "--execute-max-bytes", str(max_bytes)] if command is not None else []))
    pool = pool or Pool(mode)
    state = state or actions.KafkaLifecycleState(
        ui_base="http://qa/prefix", ui_http=pool, ui_vendor=vendor, ui_cookie="SESSION=qa"
    )
    prior = AuditRecord.from_mapping(
        {
            "host": "127.0.0.1",
            "port": 8080,
            "is_kafka": True,
            "is_kafka_ui": not broker,
            "kafka_interface": "broker" if broker else "ui",
            "ui_vendor": vendor,
            "status": status,
            "detection_status": "confirmed",
        },
        module="kafka",
        service="kafka",
    )
    ctx = NS(
        args=options,
        lifecycle_state=state,
        host="127.0.0.1",
        port=8080,
        credential=NS(username=None, password=None, source="anonymous"),
    )
    data = stage.build_kafka_spec(options).data
    assert data is not None
    return data(ctx, prior).to_dict(), state, pool


def test_execute_flags_use_shared_bounds_before_any_network() -> None:
    options = args("--execute", "id", "--execute-timeout", "2", "--execute-max-bytes", "128")
    assert policy.validate_args(options, NS(error=pytest.fail)) is None
    assert options.execute == "id" and options.execute_timeout == 2 and options.execute_max_bytes == 128


def test_generated_groovy_keeps_time_unit_constant_after_deadline_substitution() -> None:
    script = execution._script("printf hello", "RP_EXEC_TEST:", 5000, 4096)
    assert "java.util.concurrent.TimeUnit.MILLISECONDS" in script
    assert "java.util.concurrent.TimeUnit.5000" not in script


def _generated_proof(script: str, nonce: str, *, after: str = "") -> tuple[dict[str, Any], str]:
    output = run_groovy(script, after=after)
    match = re.search(re.escape(nonce) + r"([A-Za-z0-9+/]+={0,2})", output)
    assert match, output
    return json.loads(base64.b64decode(match[1], validate=True)), output


def test_kafka_generated_timeout_preserves_proof_after_closed_streams(tmp_path: Path) -> None:
    late = tmp_path / "kafka-late"
    command = "printf before; (sleep 0.8; printf leaked > " + shlex.quote(str(late)) + ") & wait"
    script = execution._script(command, "RP_TIMEOUT:", 200, 64)
    proof, output = _generated_proof(
        script,
        "RP_TIMEOUT:",
        after='Thread.sleep(1100); println("RP_LEFTOVER:" + new File(' + json.dumps(str(late)) + ").exists())",
    )
    assert proof["timed_out"] is True and type(proof["exit_code"]) is int
    assert base64.b64decode(proof["stdout_b64"]) == b"before"
    assert "RP_LEFTOVER:false" in output


def test_kafka_generated_script_drains_large_output_with_bounded_capture() -> None:
    script = execution._script("head -c 262144 /dev/zero; head -c 262144 /dev/zero >&2; exit 7", "RP_LARGE:", 1500, 64)
    proof, _ = _generated_proof(script, "RP_LARGE:")
    assert proof["exit_code"] == 7 and proof["timed_out"] is False and proof["truncated"] is True
    assert len(base64.b64decode(proof["stdout_b64"])) + len(base64.b64decode(proof["stderr_b64"])) == 64


@pytest.mark.parametrize(
    "flags",
    [
        ["--execute", " "],
        ["--execute", "a\0b"],
        ["--execute", "x" * 65537],
        ["--execute", "id", "--execute-timeout", "nan"],
        ["--execute", "id", "--execute-timeout", "0"],
        ["--execute", "id", "--execute-max-bytes", "0"],
        ["--execute", "id", "--topic", "qa", "--write-message", "x"],
        ["--execute", "id", "--probe-write"],
    ],
)
def test_invalid_execution_is_rejected_before_network(flags: list[str]) -> None:
    errors: list[str] = []
    assert policy.validate_args(args(*flags), NS(error=errors.append)) == 2
    assert errors


def test_execute_rejects_an_explicit_empty_write_message() -> None:
    errors: list[str] = []
    assert (
        policy.validate_args(
            args("--execute", "id", "--topic", "qa", "--write-message", ""),
            NS(error=errors.append),
        )
        == 2
    )
    assert errors


@pytest.mark.parametrize("mode,code", [("ok", 0), ("nonzero", 7)])
def test_ui_command_needs_correlated_result_and_keeps_channels(mode: str, code: int) -> None:
    result, _, pool = apply(mode)
    execution = result["execution"]
    assert execution["executed"] is True and execution["exit_code"] == code
    assert execution["stdout"] == "hello\n" and execution["stderr"] == "warning\n"
    assert execution["surface"] == "ui" and result.get("backend_credentials_ok") is not True
    assert len(pool.calls) == 1
    method, url, kw = pool.calls[0]
    assert method == "PUT" and url.endswith("/prefix/api/smartfilters/testexecutions")
    assert kw["headers"]["Cookie"] == "SESSION=qa"
    assert base64.b64encode(b"printf hello").decode() in json.loads(kw["body"])["filterCode"]


@pytest.mark.parametrize(
    "mode",
    [
        "lost",
        "redirect",
        "html",
        "bare_success",
        "wrong_nonce",
        "bad_type",
        "bad_b64",
        "http_401",
        "http_403",
        "http_429",
        "http_500",
    ],
)
def test_unverified_result_never_replays_or_claims_execution(mode: str) -> None:
    result, state, pool = apply(mode)
    assert result["execution"]["executed"] is False and result["operational_failure"] is True
    assert result["execution"]["error"]
    again, _, _ = apply(mode, state=state, pool=pool)
    assert again["execution"] == result["execution"]
    assert len(pool.calls) == 1


@pytest.mark.parametrize("vendor,broker", [("kafbat", False), (None, False), ("akhq", False), (None, True)])
def test_unsupported_product_never_gets_active_request(vendor: str | None, broker: bool) -> None:
    result, _, pool = apply(vendor=vendor, broker=broker)
    assert result["execution"]["status"] == "unsupported"
    assert result["execution"]["executed"] is False
    assert not pool.calls


def test_auth_failure_and_no_execute_never_send_active_request() -> None:
    result, _, pool = apply(status="auth_required")
    assert not pool.calls and result["execution"]["executed"] is False
    result, _, pool = apply(command=None)
    assert "execution" not in result
    assert pool.calls and all(method == "GET" for method, _, _ in pool.calls)


def test_repeated_data_hook_executes_only_once_per_target() -> None:
    result, state, pool = apply()
    again, _, _ = apply(state=state, pool=pool)
    assert result["execution"] == again["execution"]
    assert len(pool.calls) == 1


@pytest.mark.parametrize("mode", ["limited", "oversized", "timeout_proof"])
def test_output_and_timeout_are_not_reported_complete(mode: str) -> None:
    result, _, _ = apply(mode, max_bytes=8)
    output = result["execution"]
    assert output["status"] in {"partial", "timeout"}
    assert len((output["stdout"] + output["stderr"]).encode()) <= 8
    if mode == "timeout_proof":
        assert output["executed"] is False and result["operational_failure"] is True


def test_execution_output_is_sanitized_and_rendered_in_txt_only() -> None:
    result, _, _ = apply("ansi")
    assert result["execution"]["stdout"] == "hello"
    text = "\n".join(
        render_record_with_module(render, AuditRecord.from_mapping(result, module="kafka", service="kafka"), "txt")
    )
    assert "Execute Command" in text and "\t hello" in text and "(UI)" in text
    assert "\x1b" not in text and "\x1b" not in json.dumps(result)
    assert not render._format_execution_records(result, "json")


def test_execution_color_uses_airflow_heading_access_and_unknown_palette() -> None:
    class Colors:
        line = ""

        def _paint(self, value: str, color: str, _stream: object) -> str:
            return f"<{color}>{value}</{color}>"

        def plain(self, value: str) -> None:
            self.line = value

    console = Colors()
    for line, color, token in [
        ("[*] Execute Command (UI)", "white", "Execute Command"),
        ("[*] Discover Complete (status:partial) (UI)", "orange", "status:partial"),
    ]:
        assert render._render_colored_kafka_line(console, "KAFKA\t127.0.0.1\t8080\t " + line)
        assert f"<{color}>{token}" in console.line
