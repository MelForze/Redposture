"""Explicit Spark Standalone submission execution with a temporary artifact."""

from __future__ import annotations

import json
import re
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from ..execution_api import api, finish
from ..token_api import json_value


def _output(command: str) -> dict[str, Any]:
    return {
        "command": command,
        "mode": "spark_submission_artifact",
        "surface": "backend",
        "executed": False,
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "status": "unverified",
        "error": None,
        "cleanup": "not_needed",
        "truncated": False,
    }


def build_artifact(command: str, marker: str, timeout: float = 30.0, max_bytes: int = 1048576) -> bytes:
    """Build a self-contained Python application used by Spark's submit REST API."""

    payload = json.dumps(command, ensure_ascii=True)
    marker_value = json.dumps(marker, ensure_ascii=True)
    timeout_value = repr(max(0.1, float(timeout)))
    limit_value = repr(max(1, int(max_bytes)))
    return (
        "import json, os, signal, subprocess, sys, threading\n"
        f"command = {payload}\nmarker = {marker_value}\n"
        f"timeout = {timeout_value}\nlimit = {limit_value}\n"
        "proc = subprocess.Popen(['/bin/sh', '-c', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)\n"
        "parts = {'stdout': bytearray(), 'stderr': bytearray()}\n"
        "lock = threading.Lock()\ntruncated = [False]\n"
        "def drain(name, stream):\n"
        "    while True:\n"
        "        chunk = stream.read(8192)\n"
        "        if not chunk: break\n"
        "        with lock:\n"
        "            kept = len(parts['stdout']) + len(parts['stderr'])\n"
        "            take = max(0, min(len(chunk), limit - kept))\n"
        "            parts[name].extend(chunk[:take])\n"
        "            if take != len(chunk): truncated[0] = True\n"
        "threads = [threading.Thread(target=drain, args=(name, stream), daemon=True) for name, stream in (('stdout', proc.stdout), ('stderr', proc.stderr))]\n"
        "for thread in threads: thread.start()\n"
        "timed_out = False\n"
        "try: proc.wait(timeout=timeout)\n"
        "except subprocess.TimeoutExpired:\n"
        "    timed_out = True\n"
        "    try: os.killpg(proc.pid, signal.SIGKILL)\n"
        "    except ProcessLookupError: pass\n"
        "    proc.wait()\n"
        "for thread in threads: thread.join(timeout=2)\n"
        "proof = {'exit_code': 124 if timed_out else proc.returncode, 'stdout': bytes(parts['stdout']).decode('utf-8', 'replace'), 'stderr': bytes(parts['stderr']).decode('utf-8', 'replace'), 'timed_out': timed_out, 'truncated': truncated[0]}\n"
        "print(marker + json.dumps(proof, ensure_ascii=True), flush=True)\n"
        "sys.exit(proof['exit_code'])\n"
    ).encode()


def _terminal_state(value: Any) -> bool:
    state = value.get("driverState") if isinstance(value, dict) else None
    return state in {"FINISHED", "ERROR", "KILLED", "FAILED"}


def _confirm_stopped(ctx: Any, record: dict[str, Any], submission_id: str, deadline: float) -> bool:
    while time.monotonic() < deadline:
        check = api(ctx, record, "spark", "GET", "/v1/submissions/status/" + submission_id)
        if check.status == 200 and not check.error and _terminal_state(json_value(check)):
            return True
        time.sleep(0.1)
    return False


def _proof_from_log(value: str, marker: str) -> dict[str, Any] | None:
    position = value.rfind(marker)
    if position < 0:
        return None
    line = value[position + len(marker) :].splitlines()[0]
    try:
        proof = json.loads(line)
    except (ValueError, TypeError):
        return None
    if (
        not isinstance(proof, dict)
        or not isinstance(proof.get("exit_code"), int)
        or isinstance(proof["exit_code"], bool)
    ):
        return None
    if not all(isinstance(proof.get(name), str) for name in ("stdout", "stderr")):
        return None
    if not all(isinstance(proof.get(name), bool) for name in ("timed_out", "truncated")):
        return None
    return proof


def _worker_url(ctx: Any, record: dict[str, Any], status: dict[str, Any]) -> str | None:
    explicit = getattr(ctx.args, "execute_worker_url", None)
    if isinstance(explicit, str) and explicit:
        return explicit.rstrip("/")
    worker = status.get("workerHostPort")
    if not isinstance(worker, str) or not worker:
        return None
    host = worker.rsplit(":", 1)[0]
    if not host or not re.fullmatch(r"[A-Za-z0-9._-]+", host):
        return None
    scheme = urlsplit(str(record.get("api_endpoint") or "http://")).scheme or "http"
    return f"{scheme}://{host}:8081"


def _read_worker_proof(
    ctx: Any, record: dict[str, Any], status: dict[str, Any], submission_id: str, marker: str, limit: int
) -> dict[str, Any] | None:
    base = _worker_url(ctx, record, status)
    if base is None:
        return None
    cap = min(128 * 1024 * 1024, limit * 4 + 65536)
    url = base + "/log?driverId=" + quote(submission_id, safe="") + "&logType=stdout&byteLength=" + str(cap - 4096)
    response = ctx.lifecycle_state.http.request(
        "GET",
        url,
        headers={"Accept": "text/plain"},
        timeout=min(5.0, float(ctx.args.execute_timeout)),
        response_size_cap=cap,
        retries=0,
        replay_safe=False,
        allow_cross_origin_redirects=False,
    )
    if response.status != 200 or response.error or response.truncated:
        return None
    return _proof_from_log(response.text, marker)


def collect(ctx: Any, record: dict[str, Any], state: Any) -> dict[str, Any]:
    payload = dict(record)
    command = getattr(ctx.args, "execute", None)
    if command is None:
        return payload
    limit = int(getattr(ctx.args, "execute_max_bytes", 1048576))
    output = _output(command)
    payload["execution"] = output
    payload["execute_verified"] = False
    if record.get("is_spark") is not True:
        output["error"] = "--execute supports confirmed Spark only"
    elif record.get("surface") != "submission_rest":
        output["error"] = "Spark command execution requires the confirmed submission REST surface"
    elif record.get("status") not in {"open_no_auth", "valid_credentials"}:
        output["error"] = "Spark submission REST access is not verified; command was not sent"
    else:
        cached = getattr(state, "execution", None)
        if cached is not None:
            payload.update(execution=cached, execute_verified=cached.get("executed") is True)
            if not payload["execute_verified"]:
                payload["operational_failure"] = True
            return payload
        state.execution = output
        artifact_path: Path | None = None
        submission_id: str | None = None
        running = False
        marker = "RP_SPARK_" + secrets.token_hex(12) + ":"
        timeout = float(getattr(ctx.args, "execute_timeout", 30.0))
        try:
            with tempfile.NamedTemporaryFile(prefix="redposture-spark-", suffix=".py", delete=False) as handle:
                artifact_path = Path(handle.name)
                handle.write(build_artifact(command, marker, timeout, limit))
            request = {
                "action": "CreateSubmissionRequest",
                "appResource": artifact_path.as_uri(),
                "sparkProperties": {
                    "spark.app.name": "RedPosture one-shot execution",
                    "spark.driver.memory": "512m",
                    "spark.driver.cores": "1",
                },
                "clientSparkVersion": str(record.get("version") or "unknown"),
                "mainClass": "org.apache.spark.deploy.PythonRunner",
                "appArgs": [artifact_path.as_uri(), ""],
                "environmentVariables": {},
            }
            response = api(ctx, record, "spark", "POST", "/v1/submissions/create", request, timeout=timeout)
            created = json_value(response)
            submission_id = str(created.get("submissionId") or "") if isinstance(created, dict) else ""
            if (
                response.status not in {200, 201}
                or response.error
                or (isinstance(created, dict) and created.get("success") is False)
                or not submission_id
            ):
                raise ValueError(response.error or f"Spark submission HTTP {response.status}")
            running = True
            # The remote artifact enforces the command deadline. Scheduling the driver
            # and publishing its log needs a separate, bounded allowance.
            deadline = time.monotonic() + timeout + min(15.0, max(5.0, timeout / 2))
            latest: dict[str, Any] | None = None
            while time.monotonic() < deadline:
                status_response = api(ctx, record, "spark", "GET", "/v1/submissions/status/" + submission_id)
                latest = json_value(status_response)
                if status_response.status != 200 or status_response.error or status_response.truncated:
                    output["error"] = status_response.error or f"Spark status HTTP {status_response.status}"
                    latest = None
                    break
                if _terminal_state(latest):
                    break
                time.sleep(0.1)
            if not _terminal_state(latest):
                if output["error"] is None:
                    output.update(status="timeout", error="Spark submission did not reach a terminal driver state")
            else:
                latest_model = latest if isinstance(latest, dict) else {}
                driver_state = str(latest_model.get("driverState"))
                proof = _read_worker_proof(ctx, record, latest_model, submission_id, marker, limit)
                if proof is None:
                    output["error"] = f"Spark driver state: {driver_state}; command proof unavailable from worker log"
                else:
                    output.update(
                        executed=True,
                        exit_code=proof["exit_code"],
                        stdout=proof["stdout"],
                        stderr=proof["stderr"],
                        truncated=proof["truncated"],
                        status="timeout" if proof["timed_out"] else "partial" if proof["truncated"] else "complete",
                        error="remote command timed out" if proof["timed_out"] else None,
                        proof="worker_log_marker",
                    )
                running = False
        except (OSError, RuntimeError, ValueError, TypeError, json.JSONDecodeError) as exc:
            output["error"] = str(exc)
        finally:
            if submission_id and running:
                try:
                    killed = api(
                        ctx,
                        record,
                        "spark",
                        "POST",
                        "/v1/submissions/kill/" + submission_id,
                        timeout=min(5.0, timeout),
                    )
                    kill_model = json_value(killed)
                    acknowledged = (
                        killed.status in {200, 202}
                        and not killed.error
                        and isinstance(kill_model, dict)
                        and kill_model.get("success") is True
                    )
                    output["cleanup"] = "failed"
                    if _confirm_stopped(ctx, record, submission_id, time.monotonic() + 3.0):
                        output["cleanup"] = "complete"
                    if output["cleanup"] == "failed":
                        output["cleanup_error"] = killed.error or (
                            "Spark termination was not confirmed" if acknowledged else "Spark kill was rejected"
                        )
                except (OSError, RuntimeError, ValueError, TypeError) as exc:
                    output["cleanup"] = "failed"
                    output["cleanup_error"] = str(exc)
            if artifact_path is not None:
                try:
                    artifact_path.unlink(missing_ok=True)
                    if output["cleanup"] != "failed":
                        output["cleanup"] = "complete"
                except OSError as exc:
                    output["cleanup"] = "failed"
                    output["cleanup_error"] = str(exc)
    finish(output, max_bytes=limit)
    payload["execute_verified"] = output["executed"] is True
    if not payload["execute_verified"]:
        payload["operational_failure"] = True
    return payload


__all__ = ["build_artifact", "collect"]
