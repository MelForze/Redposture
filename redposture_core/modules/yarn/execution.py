"""Explicit Hadoop YARN application execution with bounded cleanup."""

from __future__ import annotations

import base64
import re
import shlex
import time
from typing import Any
from urllib.parse import quote, urlsplit

from ..execution_api import api, finish
from ..token_api import json_value


def submission_body(application_id: str, command: str, marker: str, timeout: float = 30.0) -> dict[str, Any]:
    wrapper = (
        f"printf '%s\\n' {shlex.quote(marker + 'BEGIN')}\n"
        f"timeout --signal=TERM --kill-after=1s {max(1, int(timeout))}s /bin/sh -lc {shlex.quote(command)}\n"
        "rc=$?\n"
        f"printf '\\n%s%s\\n' {shlex.quote(marker)} \"$rc\"\n"
    )
    encoded = base64.b64encode(wrapper.encode()).decode()
    return {
        "application-id": application_id,
        "application-name": "RedPosture one-shot execution",
        "application-type": "REDPOSTURE",
        "queue": "default",
        "resource": {"memory": 128, "vCores": 1},
        "am-container-spec": {
            "commands": {"command": "echo " + encoded + " | base64 -d | /bin/sh"},
            "environment": {"variables": {}},
        },
        "application-tags": "redposture-execute",
    }


def is_terminal_state(payload: Any) -> bool:
    model = payload.get("app") if isinstance(payload, dict) and isinstance(payload.get("app"), dict) else payload
    return isinstance(model, dict) and str(model.get("state") or "").upper() in {
        "FINISHED",
        "FAILED",
        "KILLED",
    }


def _output(command: str) -> dict[str, Any]:
    return {
        "command": command,
        "mode": "yarn_temporary_application",
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


def _state_model(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    model = payload.get("app")
    return model if isinstance(model, dict) else payload


def _node_log_base(ctx: Any, model: dict[str, Any]) -> tuple[str, str] | None:
    log_link = model.get("amContainerLogs")
    if not isinstance(log_link, str):
        return None
    parsed = urlsplit(log_link)
    parts = parsed.path.split("/")
    try:
        container_id = parts[parts.index("containerlogs") + 1]
    except (ValueError, IndexError):
        return None
    if not container_id.startswith("container_"):
        return None
    explicit = getattr(ctx.args, "execute_node_url", None)
    base = explicit.rstrip("/") if isinstance(explicit, str) and explicit else f"{parsed.scheme}://{parsed.netloc}"
    return base, container_id


def _read_node_log(ctx: Any, base: str, container_id: str, name: str, limit: int) -> tuple[str, bool] | None:
    size = min(128 * 1024 * 1024, limit + 4096)
    url = base + "/ws/v1/node/containerlogs/" + quote(container_id, safe="") + "/" + name + "?size=-" + str(size)
    response = ctx.lifecycle_state.http.request(
        "GET",
        url,
        headers={"Accept": "text/plain"},
        timeout=min(5.0, float(ctx.args.execute_timeout)),
        response_size_cap=size + 4096,
        retries=0,
        replay_safe=False,
        allow_cross_origin_redirects=False,
    )
    if response.status != 200 or response.error or response.truncated:
        return None
    raw = response.body
    start = raw.find(b"LogContents:\n")
    if start >= 0:
        end = raw.rfind(b"End of LogType:")
        if end < start:
            return None
        content = raw[start + len(b"LogContents:\n") : end]
        length = re.search(rb"(?m)^LogLength:(\d+)$", raw[:start])
        total = int(length.group(1)) if length else len(content)
        return content.decode("utf-8", errors="replace"), total > len(content)
    return response.text, len(response.body) >= size


def _read_command_proof(ctx: Any, model: dict[str, Any], marker: str, limit: int) -> dict[str, Any] | None:
    node = _node_log_base(ctx, model)
    if node is None:
        return None
    stdout_result = _read_node_log(ctx, *node, "prelaunch.out", limit)
    if stdout_result is None:
        stdout_result = _read_node_log(ctx, *node, "stdout", limit)
    if stdout_result is None:
        return None
    stdout, truncated = stdout_result
    begin_at = stdout.rfind(marker + "BEGIN\n")
    if begin_at >= 0:
        stdout = stdout[begin_at + len(marker) + len("BEGIN\n") :]
    marker_at = stdout.rfind("\n" + marker)
    if marker_at < 0 and stdout.startswith(marker):
        marker_at = -1
    if marker_at < -1:
        return None
    if marker_at == -1 and not stdout.startswith(marker):
        return None
    tail = stdout[marker_at + 1 + len(marker) :].strip()
    if not tail or not (tail.isdecimal() or tail.startswith("-") and tail[1:].isdecimal()):
        return None
    stderr_result = _read_node_log(ctx, *node, "prelaunch.err", limit)
    if stderr_result is None:
        stderr_result = _read_node_log(ctx, *node, "stderr", limit)
    stderr = stderr_result[0] if stderr_result is not None else ""
    return {
        "exit_code": int(tail),
        "stdout": stdout[:marker_at],
        "stderr": stderr,
        "truncated": truncated or (stderr_result[1] if stderr_result else False),
    }


def _confirm_stopped(ctx: Any, record: dict[str, Any], app_id: str, deadline: float) -> bool:
    while time.monotonic() < deadline:
        check = api(ctx, record, "yarn", "GET", "/ws/v1/cluster/apps/" + app_id)
        if check.status == 200 and not check.error and is_terminal_state(json_value(check)):
            return True
        time.sleep(0.1)
    return False


def collect(ctx: Any, record: dict[str, Any], state: Any) -> dict[str, Any]:
    payload = dict(record)
    command = getattr(ctx.args, "execute", None)
    if command is None:
        return payload
    limit = int(getattr(ctx.args, "execute_max_bytes", 1048576))
    output = _output(command)
    payload["execution"] = output
    payload["execute_verified"] = False
    if record.get("is_yarn") is not True:
        output["error"] = "--execute supports confirmed YARN only"
    elif record.get("status") not in {"open_no_auth", "valid_credentials"}:
        output["error"] = "YARN access is not verified; command was not sent"
    else:
        cached = getattr(state, "execution", None)
        if cached is not None:
            payload.update(execution=cached, execute_verified=cached.get("executed") is True)
            if not payload["execute_verified"]:
                payload["operational_failure"] = True
            return payload
        state.execution = output
        app_id: str | None = None
        running = False
        timeout = float(getattr(ctx.args, "execute_timeout", 30.0))
        import secrets

        marker = "RP_YARN_" + secrets.token_hex(12) + ":"
        try:
            allocation = api(ctx, record, "yarn", "POST", "/ws/v1/cluster/apps/new-application")
            allocation_model = json_value(allocation)
            app_id = str(allocation_model.get("application-id") or "") if isinstance(allocation_model, dict) else ""
            if allocation.status not in {200, 201} or not app_id:
                raise ValueError(allocation.error or f"YARN application allocation HTTP {allocation.status}")
            running = True  # The allocated ID is known even if the submit response is lost.
            submitted = api(
                ctx,
                record,
                "yarn",
                "POST",
                "/ws/v1/cluster/apps",
                submission_body(app_id, command, marker, timeout),
                timeout=timeout,
            )
            if submitted.status not in {200, 201, 202} or submitted.error:
                raise ValueError(submitted.error or f"YARN application submission HTTP {submitted.status}")
            deadline = time.monotonic() + timeout + min(15.0, max(5.0, timeout / 2)) + 5.0
            latest: dict[str, Any] | None = None
            proof: dict[str, Any] | None = None
            while time.monotonic() < deadline:
                status_response = api(ctx, record, "yarn", "GET", "/ws/v1/cluster/apps/" + app_id)
                latest = json_value(status_response)
                if status_response.status != 200 or status_response.error or status_response.truncated:
                    output["error"] = status_response.error or f"YARN status HTTP {status_response.status}"
                    latest = None
                    break
                current = _state_model(latest)
                if current is not None:
                    proof = _read_command_proof(ctx, current, marker, limit)
                    if proof is not None:
                        break
                if is_terminal_state(latest):
                    break
                time.sleep(0.2)
            model = _state_model(latest)
            if proof is not None:
                output.update(
                    executed=True,
                    exit_code=proof["exit_code"],
                    stdout=proof["stdout"],
                    stderr=proof["stderr"],
                    truncated=proof["truncated"],
                    status="timeout" if proof["exit_code"] == 124 else "partial" if proof["truncated"] else "complete",
                    error="remote deadline reached or command returned 124" if proof["exit_code"] == 124 else None,
                    proof="node_log_marker",
                    application_id=app_id,
                )
                running = not is_terminal_state(latest)
                if not running:
                    output["cleanup"] = "complete"
            elif not is_terminal_state(latest):
                if output["error"] is None:
                    output.update(status="timeout", error="YARN application did not reach a terminal state")
            else:
                model = model or {}
                state_name = str(model.get("state") or "UNKNOWN")
                output.update(
                    error=f"YARN application state: {state_name}; command proof unavailable from node log",
                    application_id=app_id,
                )
                running = False
                output["cleanup"] = "complete"
        except (OSError, RuntimeError, ValueError, TypeError) as exc:
            output["error"] = str(exc)
        finally:
            if app_id and running:
                try:
                    killed = api(
                        ctx,
                        record,
                        "yarn",
                        "PUT",
                        "/ws/v1/cluster/apps/" + app_id + "/state",
                        {"state": "KILLED"},
                        timeout=min(5.0, timeout),
                    )
                    kill_model = json_value(killed)
                    acknowledged = (
                        killed.status in {200, 202}
                        and not killed.error
                        and isinstance(kill_model, dict)
                        and kill_model.get("state") == "KILLED"
                    )
                    output["cleanup"] = "failed"
                    # The application may reach a terminal state between log proof
                    # and the kill request; that is already a complete cleanup.
                    if _confirm_stopped(ctx, record, app_id, time.monotonic() + min(2.0, timeout)):
                        output["cleanup"] = "complete"
                    if output["cleanup"] == "failed":
                        output["cleanup_error"] = killed.error or (
                            "YARN termination was not confirmed" if acknowledged else "YARN kill was rejected"
                        )
                except (OSError, RuntimeError, ValueError, TypeError) as exc:
                    output["cleanup"] = "failed"
                    output["cleanup_error"] = str(exc)
            elif app_id:
                output["cleanup"] = "complete"
    finish(output, max_bytes=limit)
    payload["execute_verified"] = output["executed"] is True
    if not payload["execute_verified"]:
        payload["operational_failure"] = True
    return payload


__all__ = ["collect", "is_terminal_state", "submission_body"]
