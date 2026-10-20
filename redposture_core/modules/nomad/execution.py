"""Explicit Nomad batch/selected-allocation execution with bounded cleanup."""

from __future__ import annotations

import base64
import json
import re
import secrets
import time
from typing import Any
from urllib.parse import urlencode

from ..execution_api import api, open_ws, result
from ..token_api import json_value, path_value


def _query(ctx: Any) -> str:
    return "?" + urlencode({"namespace": ctx.args.namespace})


def _job(ctx: Any, name: str, *, stopped: bool = False) -> dict[str, Any]:
    # Keep the allocation alive until both log streams contain the completion
    # marker. Otherwise a client's immediate GC can erase output before we read
    # it. The hold is bounded even if this client disappears before cleanup.
    marker = "REDPOSTURE_EXIT_" + name
    command = (
        "true"
        if stopped
        else (
            "( "
            + ctx.args.execute
            + "\n ); _rp_rc=$?; "
            + f"printf '\\036{marker}:%s\\037' \"$_rp_rc\"; "
            + f"printf '\\036{marker}:%s\\037' \"$_rp_rc\" >&2; "
            + f'sleep {ctx.args.execute_timeout + 5:g}; exit "$_rp_rc"'
        )
    )
    return {
        "ID": name,
        "Name": name,
        "Namespace": ctx.args.namespace,
        "Type": "batch",
        "Stop": stopped,
        "Datacenters": ["*"],
        "TaskGroups": [
            {
                "Name": "command",
                "Count": 1,
                "RestartPolicy": {"Attempts": 0, "Mode": "fail"},
                "ReschedulePolicy": {"Attempts": 0, "Unlimited": False},
                "Tasks": [
                    {
                        "Name": "command",
                        "Driver": "raw_exec",
                        "Config": {"command": "/bin/sh", "args": ["-c", command]},
                        "Resources": {"CPU": 100, "MemoryMB": 32},
                        "KillTimeout": 1000000000,
                    }
                ],
            }
        ],
    }


def _cleanup(ctx: Any, prior: dict[str, Any], name: str, output: dict[str, Any]) -> None:
    try:
        response = api(
            ctx, prior, "nomad", "DELETE", "/v1/job/" + path_value(name) + _query(ctx) + "&purge=true", timeout=5
        )
        output["cleanup"] = "complete" if response.status in {200, 404} and not response.error else "failed"
        if output["cleanup"] == "failed":
            output["cleanup_error"] = f"job cleanup HTTP {response.status}"
    except Exception as exc:
        output["cleanup"] = "failed"
        output["cleanup_error"] = str(exc)


def probe_submit(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    name = "redposture-submit-" + secrets.token_hex(10)
    output: dict[str, Any] = {"job": name, "access": "unverified", "cleanup": "not_needed", "executed": False}
    attempted = False
    try:
        attempted = True
        response = api(ctx, prior, "nomad", "POST", "/v1/jobs" + _query(ctx), {"Job": _job(ctx, name, stopped=True)})
        if response.status in {400, 401, 403, 404, 429}:
            attempted = False
        model = json_value(response)
        if response.status == 200 and isinstance(model, dict) and type(model.get("JobModifyIndex")) is int:
            output["access"] = "allowed"
        elif response.status in {401, 403}:
            output["access"] = "denied"
        else:
            output["error"] = f"stopped job registration unconfirmed: HTTP {response.status}"
        return output
    except Exception as exc:
        output["error"] = str(exc)
        return output
    finally:
        if attempted:
            _cleanup(ctx, prior, name, output)


def _allocation(ctx: Any, prior: dict[str, Any], output: dict[str, Any]) -> dict[str, Any]:
    allocation = ctx.args.allocation
    response = api(ctx, prior, "nomad", "GET", "/v1/allocation/" + path_value(allocation) + _query(ctx))
    model = json_value(response)
    tasks = model.get("TaskStates") if isinstance(model, dict) else None
    if response.status != 200 or not isinstance(tasks, dict):
        raise ValueError(f"allocation unavailable: HTTP {response.status}")
    running = [name for name, state in tasks.items() if isinstance(state, dict) and state.get("State") == "running"]
    task = ctx.args.task
    if task is None:
        if len(running) != 1:
            raise ValueError("specify --task: allocation must have exactly one running task for automatic selection")
        task = running[0]
    if task not in running:
        raise ValueError("selected --task is not running in the allocation")
    output.update(allocation=allocation, task=task)
    query = urlencode(
        {
            "command": json.dumps(["/bin/sh", "-c", ctx.args.execute]),
            "task": task,
            "tty": "false",
            "namespace": ctx.args.namespace,
        }
    )
    with open_ws(ctx, prior, "nomad", "/v1/client/allocation/" + path_value(allocation) + "/exec?" + query) as ws:
        ws.send_json({"stdin": {"close": True}})
        while True:
            message = ws.recv_json()
            if not isinstance(message, dict):
                raise ValueError("invalid allocation exec message")
            for channel in ("stdout", "stderr"):
                stream = message.get(channel)
                if isinstance(stream, dict) and isinstance(stream.get("data"), str):
                    raw = base64.b64decode(stream["data"], validate=True)
                    output[channel] += raw.decode("utf-8", errors="replace")
            if message.get("exited") is True:
                terminal = message.get("result")
                code = terminal.get("exit_code") if isinstance(terminal, dict) else None
                if type(code) is not int:
                    raise ValueError("allocation exit frame has no exit code")
                output.update(executed=True, exit_code=code, status="complete")
                return output


def execute(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    output = result(ctx, "allocation" if ctx.args.allocation else "temporary_job")
    if ctx.args.allocation:
        try:
            return _allocation(ctx, prior, output)
        except Exception as exc:
            output["error"] = str(exc)
            return output
    name = "redposture-execute-" + secrets.token_hex(10)
    output["job"] = name
    attempted = False
    deadline = time.monotonic() + ctx.args.execute_timeout
    try:
        attempted = True
        response = api(ctx, prior, "nomad", "POST", "/v1/jobs" + _query(ctx), {"Job": _job(ctx, name)})
        if response.status in {400, 401, 403, 404, 429}:
            attempted = False
        registered = json_value(response)
        if response.status != 200 or not isinstance(registered, dict) or not isinstance(registered.get("EvalID"), str):
            raise ValueError(f"job registration unconfirmed: HTTP {response.status}")
        while time.monotonic() < deadline:
            response = api(
                ctx,
                prior,
                "nomad",
                "GET",
                "/v1/job/" + path_value(name) + "/allocations" + _query(ctx),
                timeout=max(0.1, min(3, deadline - time.monotonic())),
            )
            allocations = json_value(response)
            if response.status != 200 or not isinstance(allocations, list):
                raise ValueError(f"allocation listing unavailable: HTTP {response.status}")
            # Batch retries are disabled; observe only the allocation for our job.
            owned = [
                a
                for a in allocations
                if isinstance(a, dict) and a.get("JobID") == name and isinstance(a.get("ID"), str)
            ]
            if not owned:
                evaluation = api(
                    ctx,
                    prior,
                    "nomad",
                    "GET",
                    "/v1/evaluation/" + path_value(registered["EvalID"]) + _query(ctx),
                    timeout=max(0.1, min(3, deadline - time.monotonic())),
                )
                details = json_value(evaluation)
                failed = details.get("FailedTGAllocs") if isinstance(details, dict) else None
                if evaluation.status == 200 and isinstance(failed, dict) and failed:
                    raise ValueError("job placement blocked: " + json.dumps(failed, ensure_ascii=False)[:2000])
            if owned:
                allocation = owned[-1]
                output["allocation"] = allocation["ID"]
                detail = api(
                    ctx,
                    prior,
                    "nomad",
                    "GET",
                    "/v1/allocation/" + path_value(allocation["ID"]) + _query(ctx),
                    timeout=max(0.1, min(3, deadline - time.monotonic())),
                )
                model = json_value(detail)
                states = model.get("TaskStates", {}) if isinstance(model, dict) else {}
                task = states.get("command", {}) if isinstance(states, dict) else {}
                events = task.get("Events", []) if isinstance(task, dict) else []
                exited = next(
                    (
                        e
                        for e in reversed(events)
                        if isinstance(e, dict) and e.get("Type") == "Terminated" and type(e.get("ExitCode")) is int
                    ),
                    None,
                )
                marker = "\x1eREDPOSTURE_EXIT_" + name + ":"
                exit_codes = []
                for channel in ("stdout", "stderr"):
                    query = urlencode(
                        {
                            "namespace": ctx.args.namespace,
                            "task": "command",
                            "type": channel,
                            "plain": "true",
                            "follow": "false",
                            "origin": "end",
                            "offset": 4096,
                        }
                    )
                    tail = api(
                        ctx,
                        prior,
                        "nomad",
                        "GET",
                        "/v1/client/fs/logs/" + path_value(allocation["ID"]) + "?" + query,
                        max_bytes=4096,
                    )
                    match = (
                        re.search(re.escape(marker) + r"(-?\d+)\x1f", tail.text)
                        if tail.status == 200 and not tail.error
                        else None
                    )
                    if match:
                        exit_codes.append(int(match.group(1)))
                marker_complete = len(exit_codes) == 2 and exit_codes[0] == exit_codes[1]
                if marker_complete or exited is not None:
                    if marker_complete:
                        code = exit_codes[0]
                    else:
                        assert exited is not None
                        code = exited["ExitCode"]
                    output.update(executed=True, exit_code=code, status="complete")
                    for channel in ("stdout", "stderr"):
                        query = urlencode(
                            {
                                "namespace": ctx.args.namespace,
                                "task": "command",
                                "type": channel,
                                "plain": "true",
                                "follow": "false",
                                "origin": "start",
                                "offset": 0,
                            }
                        )
                        log = api(
                            ctx,
                            prior,
                            "nomad",
                            "GET",
                            "/v1/client/fs/logs/" + path_value(allocation["ID"]) + "?" + query,
                        )
                        if log.status != 200 or log.error:
                            output.update(status="partial", error=f"{channel} log unavailable: HTTP {log.status}")
                        else:
                            output[channel] = log.text.split(marker, 1)[0]
                            if log.truncated:
                                output.update(status="partial", error="execution output byte limit")
                    return output
                if allocation.get("ClientStatus") in {"failed", "lost"}:
                    raise ValueError(
                        "allocation failed before a confirmed command exit: "
                        + json.dumps(states, ensure_ascii=False)[:2000]
                    )
            time.sleep(min(0.2, max(0, deadline - time.monotonic())))
        raise TimeoutError("execution deadline reached; job may be pending or still running")
    except Exception as exc:
        output["error"] = str(exc)
        return output
    finally:
        if attempted:
            _cleanup(ctx, prior, name, output)
