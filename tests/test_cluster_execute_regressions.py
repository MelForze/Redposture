"""Execution is proven by a command marker, never by a cluster lifecycle state."""

from __future__ import annotations

import base64
import json
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace as NS
from typing import Any
from urllib.parse import unquote, urlparse

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.spark import execution as spark
from redposture_core.modules.yarn import execution as yarn


def _response(status: int | None, value: Any = None, *, error: str | None = None) -> HttpResponse:
    body = value.encode() if isinstance(value, str) else json.dumps(value).encode()
    return HttpResponse(status, body, {"Content-Type": "application/json"}, error=error)


def test_cluster_worker_and_node_url_overrides_parse() -> None:
    assert (
        parse_args(["spark", "-t", "127.0.0.1", "--execute-worker-url", "http://127.0.0.1:19681"]).execute_worker_url
        == "http://127.0.0.1:19681"
    )
    assert (
        parse_args(["yarn", "-t", "127.0.0.1", "--execute-node-url", "http://127.0.0.1:19842"]).execute_node_url
        == "http://127.0.0.1:19842"
    )


class ClusterPool:
    def __init__(
        self,
        product: str,
        *,
        state: str = "FINISHED",
        exit_code: int = 7,
        status_http: int = 200,
        kill_ack: bool = True,
        lost_submit: bool = False,
        logs_present: bool = True,
    ) -> None:
        self.product, self.state, self.exit_code = product, state, exit_code
        self.status_http, self.kill_ack, self.lost_submit = status_http, kill_ack, lost_submit
        self.logs_present = logs_present
        self.killed = False
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.marker = ""

    def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
        self.calls.append((method, url, kwargs))
        if self.product == "spark":
            if url.endswith("/create"):
                body = json.loads(kwargs["body"])
                path = Path(unquote(urlparse(body["appResource"]).path))
                self.marker = re.search(r"RP_SPARK_[0-9a-f]+:", path.read_text())[0]
                return _response(200, {"success": True, "submissionId": "driver-1"})
            if "/status/" in url:
                return _response(self.status_http, {"driverState": self.state, "workerHostPort": "worker:4151"})
            if "/kill/" in url:
                return _response(200, {"success": self.kill_ack})
            if "/log?" in url:
                if not self.logs_present:
                    return _response(404, "")
                proof = {
                    "exit_code": self.exit_code,
                    "stdout": "out\n",
                    "stderr": "err\n",
                    "timed_out": False,
                    "truncated": False,
                }
                return _response(200, self.marker + json.dumps(proof))
        else:
            if url.endswith("/new-application"):
                return _response(200, {"application-id": "application_1234_0001"})
            if url.endswith("/apps") and method == "POST":
                body = json.loads(kwargs["body"])
                encoded = re.search(r"echo ([A-Za-z0-9+/=]+)", body["am-container-spec"]["commands"]["command"])[1]
                self.marker = re.search(r"RP_YARN_[0-9a-f]+:", base64.b64decode(encoded).decode())[0]
                if self.lost_submit:
                    return _response(None, {}, error="response lost after submit")
                return _response(202, {})
            if url.endswith("/state") and method == "PUT":
                self.killed = self.kill_ack
                return _response(200, {"state": "KILLED" if self.kill_ack else "RUNNING"})
            if "/apps/application_" in url:
                current = "KILLED" if self.killed else self.state
                final = "SUCCEEDED" if current == "FINISHED" else "FAILED"
                return _response(
                    self.status_http,
                    {
                        "app": {
                            "state": current,
                            "finalStatus": final,
                            "amHostHttpAddress": "node:8042",
                            "amContainerLogs": "http://node:8042/node/containerlogs/container_1234_0001_01_000001/test",
                        }
                    },
                )
            if "/containerlogs/" in url:
                if not self.logs_present:
                    return _response(404, "")
                if "prelaunch.out?" in url:
                    content = (
                        "Launching container\n"
                        + self.marker
                        + "BEGIN\nout\n\n"
                        + self.marker
                        + str(self.exit_code)
                        + "\n"
                    )
                    return _response(
                        200, f"LogLength:{len(content)}\nLogContents:\n" + content + "End of LogType:prelaunch.out.\n"
                    )
                if "prelaunch.err?" in url:
                    return _response(200, "LogLength:4\nLogContents:\nerr\nEnd of LogType:prelaunch.err.\n")
                return _response(404, "")
        raise AssertionError((method, url))


def _run(product: str, pool: ClusterPool, *, timeout: float = 0.3) -> dict[str, Any]:
    state = NS(http=pool, execution=None)
    ctx = NS(
        args=NS(
            execute="printf out; printf err >&2; exit 7",
            execute_timeout=timeout,
            execute_max_bytes=8192,
            execute_worker_url="http://worker:8081",
            execute_node_url="http://node:8042",
        ),
        lifecycle_state=state,
    )
    record = {
        f"is_{product}": True,
        "status": "open_no_auth",
        "api_endpoint": "http://cluster:6066" if product == "spark" else "http://cluster:8088",
    }
    if product == "spark":
        record["surface"] = "submission_rest"
    return {"spark": spark, "yarn": yarn}[product].collect(ctx, record, state)


def test_spark_submission_uses_two_pythonrunner_arguments_and_actual_command_proof() -> None:
    pool = ClusterPool("spark", exit_code=7)
    result = _run("spark", pool)
    body = json.loads(pool.calls[0][2]["body"])
    assert body["mainClass"] == "org.apache.spark.deploy.PythonRunner"
    assert len(body["appArgs"]) >= 2
    assert body["sparkProperties"].get("spark.master") != "spark://redposture"
    assert result["execute_verified"] is True
    assert result["execution"]["exit_code"] == 7
    assert result["execution"]["stdout"] == "out\n"
    assert result["execution"]["stderr"] == "err\n"
    assert any("/log?" in url for _, url, _ in pool.calls)


@pytest.mark.parametrize("product", ["spark", "yarn"])
def test_cluster_terminal_failed_before_command_does_not_fabricate_exit(product: str) -> None:
    pool = ClusterPool(product, state="FAILED", logs_present=False)
    result = _run(product, pool)
    assert result["execute_verified"] is False
    assert result["execution"]["executed"] is False
    assert result["execution"]["exit_code"] is None


@pytest.mark.parametrize("product", ["spark", "yarn"])
def test_cluster_poll_denial_does_not_count_as_completion(product: str) -> None:
    result = _run(product, ClusterPool(product, status_http=403))
    assert result["execute_verified"] is False
    assert result["execution"]["exit_code"] is None


def test_spark_generated_artifact_bounds_large_command_output(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.py"
    artifact.write_bytes(spark.build_artifact("yes X | head -c 2097152", "RP_TEST:", 2, max_bytes=64))
    result = subprocess.run([sys.executable, str(artifact)], capture_output=True, timeout=5)
    proof = json.loads(result.stdout.decode().split("RP_TEST:", 1)[1])
    assert len(proof["stdout"].encode()) <= 64
    assert proof["truncated"] is True
    assert len(result.stdout) < 512


def test_yarn_failed_application_can_still_prove_real_nonzero_shell_exit() -> None:
    result = _run("yarn", ClusterPool("yarn", state="FAILED", exit_code=7))
    assert result["execute_verified"] is True
    assert result["execution"]["exit_code"] == 7
    assert result["execution"]["stdout"] == "out\n"
    assert result["execution"]["stderr"] == "err\n"


def test_yarn_reads_command_proof_while_container_is_running_then_stops_it() -> None:
    pool = ClusterPool("yarn", state="RUNNING", exit_code=0)
    result = _run("yarn", pool)
    assert result["execute_verified"] is True
    assert result["execution"]["exit_code"] == 0
    assert result["execution"]["cleanup"] == "complete"
    assert any(method == "PUT" and url.endswith("/state") for method, url, _ in pool.calls)
    body = json.loads(
        next(kwargs["body"] for method, url, kwargs in pool.calls if method == "POST" and url.endswith("/apps"))
    )
    encoded = re.search(r"echo ([A-Za-z0-9+/=]+)", body["am-container-spec"]["commands"]["command"])[1]
    assert "BEGIN" in base64.b64decode(encoded).decode()


def test_yarn_lost_submit_response_checks_and_cleans_known_application() -> None:
    pool = ClusterPool("yarn", state="RUNNING", lost_submit=True)
    result = _run("yarn", pool, timeout=0.1)
    assert result["execute_verified"] is False
    assert any(method == "PUT" and url.endswith("/state") for method, url, _ in pool.calls)
    assert sum(method == "POST" and url.endswith("/apps") for method, url, _ in pool.calls) == 1


@pytest.mark.parametrize("product", ["spark", "yarn"])
def test_cluster_rejected_kill_remains_failed_cleanup(product: str) -> None:
    result = _run(product, ClusterPool(product, state="RUNNING", kill_ack=False), timeout=0.1)
    assert result["execution"]["cleanup"] == "failed"
