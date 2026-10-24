"""Execution contracts for Nexus, Spark Standalone and Hadoop YARN."""

from __future__ import annotations

import base64
import json
import re
from types import SimpleNamespace as NS
from typing import Any

from redposture_core.cli_args import parse_args
from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.nexus import execution as nexus_execution
from redposture_core.modules.spark import execution as spark_execution
from redposture_core.modules.yarn import execution as yarn_execution


def _response(status: int, body: str | dict[str, Any] = "") -> HttpResponse:
    raw = body.encode() if isinstance(body, str) else json.dumps(body).encode()
    return HttpResponse(status, raw, {"Content-Type": "application/json"})


def test_new_modules_accept_shared_execute_flags() -> None:
    for module in ("nexus", "spark", "yarn"):
        args = parse_args([module, "-t", "127.0.0.1", "--execute", "id", "--execute-timeout", "2"])
        assert args.execute == "id"
        assert args.execute_timeout == 2


def test_nexus_script_api_proves_result_and_deletes_temporary_script() -> None:
    class Pool:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, dict[str, Any]]] = []
            self.marker = ""

        def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
            self.calls.append((method, url, kwargs))
            if method == "POST" and url.endswith("/service/rest/v1/script"):
                body = json.loads(kwargs["body"])
                self.name = body["name"]
                self.marker = re.search(r"RP_NEXUS_[A-Za-z0-9]+:", body["content"]).group(0)
                return _response(204)
            if method == "POST" and url.endswith("/run"):
                return _response(
                    200,
                    {
                        "name": self.name,
                        "result": self.marker
                        + json.dumps(
                            {"exit_code": 7, "stdout": "out", "stderr": "err", "timed_out": False, "truncated": False}
                        ),
                    },
                )
            if method == "DELETE":
                return _response(204)
            raise AssertionError((method, url))

    pool = Pool()
    ctx = NS(
        args=NS(execute="printf out; printf err >&2; exit 7", execute_timeout=2.0, execute_max_bytes=4096),
        credential=NS(username="admin", password="secret", token=None),
        host="nexus.test",
        port=8081,
    )
    state = NS(http=pool, scheme="http", base_path="", host="nexus.test", port=8081, execution=None)
    record = {
        "is_nexus": True,
        "status": "valid_credentials",
        "provided_credentials_ok": True,
    }
    result = nexus_execution.collect(ctx, record, state)
    assert result["execute_verified"] is True
    assert result["execution"]["exit_code"] == 7
    assert result["execution"]["stdout"] == "out"
    assert result["execution"]["stderr"] == "err"
    assert result["execution"]["cleanup"] == "complete"
    assert [method for method, _url, _kwargs in pool.calls] == ["POST", "POST", "DELETE"]


def test_nexus_execution_does_not_send_without_verified_access() -> None:
    class Pool:
        def __init__(self) -> None:
            self.calls = 0

        def request(self, _method: str, _url: str, **_kwargs: Any) -> HttpResponse:
            self.calls += 1
            raise AssertionError("unverified Nexus must not receive a script request")

    pool = Pool()
    ctx = NS(args=NS(execute="id", execute_timeout=1.0, execute_max_bytes=1024), credential=NS())
    state = NS(http=pool, scheme="http", base_path="", host="nexus.test", port=8081, execution=None)
    result = nexus_execution.collect(ctx, {"is_nexus": True, "status": "auth_required"}, state)
    assert result["execute_verified"] is False
    assert result["execution"]["error"] == "Nexus access is not verified; command was not sent"
    assert pool.calls == 0


def test_spark_artifact_contains_command_and_proof_marker() -> None:
    artifact = spark_execution.build_artifact("id", "RP_SPARK_TEST:")
    text = artifact.decode("utf-8")
    assert "RP_SPARK_TEST:" in text
    assert "subprocess" in text
    assert "id" in text
    compile(text, "redposture-spark-artifact.py", "exec")


def test_spark_execution_submits_artifact_and_waits_for_terminal_driver() -> None:
    class Pool:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, dict[str, Any]]] = []

        def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
            self.calls.append((method, url, kwargs))
            if method == "POST" and url.endswith("/v1/submissions/create"):
                return _response(200, {"submissionId": "driver-1"})
            if method == "GET" and url.endswith("/v1/submissions/status/driver-1"):
                return _response(200, {"driverState": "FINISHED"})
            raise AssertionError((method, url))

    pool = Pool()
    state = NS(http=pool)
    ctx = NS(
        args=NS(execute="id", execute_timeout=1.0, execute_max_bytes=4096),
        host="spark.test",
        port=6066,
        lifecycle_state=state,
    )
    record = {
        "is_spark": True,
        "surface": "submission_rest",
        "status": "open_no_auth",
        "api_endpoint": "http://spark.test:6066",
        "version": "3.5.1",
    }
    result = spark_execution.collect(ctx, record, state)
    assert result["execute_verified"] is False
    assert result["execution"]["exit_code"] is None
    assert result["execution"]["cleanup"] == "complete"
    body = json.loads(pool.calls[0][2]["body"])
    assert body["action"] == "CreateSubmissionRequest"
    assert body["appResource"].startswith("file:")


def test_spark_execution_kills_running_submission_on_timeout() -> None:
    class Pool:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, dict[str, Any]]] = []

        def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
            self.calls.append((method, url, kwargs))
            if method == "POST" and url.endswith("/v1/submissions/create"):
                return _response(200, {"submissionId": "driver-2"})
            if method == "GET" and url.endswith("/v1/submissions/status/driver-2"):
                return _response(200, {"driverState": "RUNNING"})
            if method == "POST" and url.endswith("/v1/submissions/kill/driver-2"):
                return _response(200, {"success": True})
            raise AssertionError((method, url))

    pool = Pool()
    state = NS(http=pool)
    ctx = NS(
        args=NS(execute="id", execute_timeout=0.1, execute_max_bytes=4096),
        host="spark.test",
        port=6066,
        lifecycle_state=state,
    )
    record = {
        "is_spark": True,
        "surface": "submission_rest",
        "status": "open_no_auth",
        "api_endpoint": "http://spark.test:6066",
    }
    result = spark_execution.collect(ctx, record, state)
    assert result["execute_verified"] is False
    assert result["execution"]["status"] == "timeout"
    assert result["execution"]["cleanup"] == "failed"
    assert any(method == "POST" and url.endswith("/v1/submissions/kill/driver-2") for method, url, _ in pool.calls)


def test_yarn_execution_submits_temporary_application_and_reports_success() -> None:
    class Pool:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, dict[str, Any]]] = []

        def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
            self.calls.append((method, url, kwargs))
            if method == "POST" and url.endswith("/ws/v1/cluster/apps/new-application"):
                return _response(200, {"application-id": "application_1234_0001"})
            if method == "POST" and url.endswith("/ws/v1/cluster/apps"):
                return _response(202, {})
            if method == "GET" and url.endswith("/ws/v1/cluster/apps/application_1234_0001"):
                return _response(200, {"app": {"state": "FINISHED", "finalStatus": "SUCCEEDED"}})
            raise AssertionError((method, url))

    pool = Pool()
    state = NS(http=pool)
    ctx = NS(
        args=NS(execute="id", execute_timeout=1.0, execute_max_bytes=4096),
        host="yarn.test",
        port=8088,
        lifecycle_state=state,
    )
    record = {
        "is_yarn": True,
        "status": "open_no_auth",
        "api_endpoint": "http://yarn.test:8088",
    }
    result = yarn_execution.collect(ctx, record, state)
    assert result["execute_verified"] is False
    assert result["execution"]["exit_code"] is None
    assert result["execution"]["cleanup"] == "complete"
    body = json.loads(pool.calls[1][2]["body"])
    assert body["application-id"] == "application_1234_0001"
    assert "/bin/sh" in body["am-container-spec"]["commands"]["command"]


def test_yarn_submission_wraps_command_and_cleanup_is_explicit() -> None:
    body = yarn_execution.submission_body("application_1234_0001", "id", "RP_YARN_TEST:")
    command = body["am-container-spec"]["commands"]["command"]
    assert "/bin/sh" in command
    encoded = command.split("echo ", 1)[1].split(" | base64", 1)[0]
    decoded = base64.b64decode(encoded).decode()
    assert "id" in decoded and "RP_YARN_TEST:" in decoded
    assert body["application-id"] == "application_1234_0001"
    assert yarn_execution.is_terminal_state({"state": "FINISHED"})
    assert not yarn_execution.is_terminal_state({"state": "RUNNING"})
