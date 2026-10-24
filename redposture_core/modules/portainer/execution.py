"""One-shot Docker exec through a confirmed Portainer environment."""

from __future__ import annotations

import base64
import binascii
import json
import secrets
import shlex
from contextlib import closing
from typing import Any
from urllib.parse import quote

from ...clients.docker_engine import decode_docker_stream_bytes
from ...clients.http_session import HttpSessionPool
from ..execution_api import finish

_REMOTE_WRAPPER = r"""
import json
import sys

marker = sys.argv[4]

def emit(value):
    sys.stdout.write(marker + json.dumps(value, separators=(",", ":")) + "\n")
    sys.stdout.flush()

try:
    import base64
    import os
    import selectors
    import signal
    import subprocess
    import time
except ImportError:
    emit({"unsupported": True, "error": "Remote Python 3 lacks process/capture support; command was not sent"})
    sys.exit(125)

if sys.version_info < (3, 6) or not hasattr(os, "killpg") or not hasattr(os, "set_blocking"):
    emit({"unsupported": True, "error": "Remote Python 3 cannot isolate command processes; command was not sent"})
    sys.exit(125)

command, timeout, limit = sys.argv[1], float(sys.argv[2]), int(sys.argv[3])
try:
    process = subprocess.Popen(command, shell=True, executable="/bin/sh", start_new_session=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
except OSError as error:
    emit({"unsupported": True, "error": "Remote shell unavailable; command was not sent: " + str(error)})
    sys.exit(125)

selector = selectors.DefaultSelector()
buffers = {"stdout": bytearray(), "stderr": bytearray()}
totals = {"stdout": 0, "stderr": 0}
timed_out = False
truncated = False
cleanup_complete = True
deadline = time.monotonic() + timeout

def kill_group():
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass

try:
    for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    while selector.get_map() or process.poll() is None:
        now = time.monotonic()
        if now >= deadline and not timed_out:
            timed_out = True
            kill_group()
        if timed_out and now >= deadline + 2:
            # A process that detached itself can keep an inherited pipe open.
            # Never let that prevent the bounded wrapper from returning proof.
            truncated = True
            cleanup_complete = False
            break
        for key, _ in selector.select(0.05):
            chunk = os.read(key.fileobj.fileno(), 65536)
            if not chunk:
                selector.unregister(key.fileobj)
                key.fileobj.close()
                continue
            name = key.data
            totals[name] += len(chunk)
            remaining = max(0, limit - len(buffers[name]))
            buffers[name].extend(chunk[:remaining])
finally:
    # Also remove children left in our group after a shell backgrounds work and
    # exits normally. The surrounding selected container is never signalled.
    kill_group()
    selector.close()
    for stream in (process.stdout, process.stderr):
        if not stream.closed:
            stream.close()
    process.wait()

exit_code = process.returncode
if exit_code < 0:
    exit_code = 128 - exit_code
emit({"exit_code": exit_code,
      "stdout_b64": base64.b64encode(buffers["stdout"]).decode("ascii"),
      "stderr_b64": base64.b64encode(buffers["stderr"]).decode("ascii"),
      "timed_out": timed_out,
      "cleanup_complete": cleanup_complete,
      "truncated": truncated or any(totals[name] > len(buffers[name]) for name in buffers)})
"""


def _wrapper(command: str, marker: str, timeout: float, max_bytes: int) -> str:
    # An HTTP timeout cannot terminate Docker exec. Require a remote runtime
    # that can supervise an isolated process group even if the client is lost.
    unsupported = marker + json.dumps(
        {"unsupported": True, "error": "Remote Python 3 unavailable; command was not sent"}, separators=(",", ":")
    )
    return (
        "if ! command -v python3 >/dev/null 2>&1; then "
        f"printf '%s\\n' {shlex.quote(unsupported)}; exit 125; fi\n"
        "exec python3 -c "
        + shlex.quote(_REMOTE_WRAPPER)
        + " "
        + " ".join(shlex.quote(value) for value in (command, str(timeout), str(max_bytes), marker))
    )


def _proof(raw: bytes, marker: str) -> dict[str, Any]:
    if not raw.startswith(marker.encode()):
        raise ValueError("Portainer Docker exec returned no correlated command completion evidence")
    try:
        value = json.loads(raw[len(marker) :])
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Portainer Docker exec returned invalid command completion evidence") from exc
    if not isinstance(value, dict):
        raise ValueError("Portainer Docker exec returned invalid command completion evidence")
    if value.get("unsupported") is True and isinstance(value.get("error"), str):
        return value
    if (
        type(value.get("exit_code")) is not int
        or type(value.get("timed_out")) is not bool
        or type(value.get("truncated")) is not bool
        or type(value.get("cleanup_complete")) is not bool
        or not isinstance(value.get("stdout_b64"), str)
        or not isinstance(value.get("stderr_b64"), str)
    ):
        raise ValueError("Portainer Docker exec returned invalid command completion evidence")
    try:
        for stream in ("stdout", "stderr"):
            value[stream] = base64.b64decode(value.pop(stream + "_b64"), validate=True).decode(
                "utf-8", errors="replace"
            )
    except (binascii.Error, ValueError, UnicodeError) as exc:
        raise ValueError("Portainer Docker exec returned invalid captured output") from exc
    return value


def _output(command: str) -> dict[str, Any]:
    return {
        "command": command,
        "mode": "portainer_docker_exec",
        "surface": "ui",
        "executed": False,
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "status": "unverified",
        "error": None,
        "cleanup": "not_needed",
        "truncated": False,
    }


def _headers(ui: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    if ui.get("session_cookie"):
        result["Cookie"] = str(ui["session_cookie"])
    if ui.get("session_api_key"):
        result["X-API-Key"] = str(ui["session_api_key"])
    if ui.get("session_token"):
        result["Authorization"] = "Bearer " + str(ui["session_token"])
    if ui.get("session_authorization"):
        result["Authorization"] = str(ui["session_authorization"])
    return result


def _json(response: Any) -> Any:
    if response.error or response.truncated or response.status not in {200, 201}:
        return None
    try:
        return response.json()
    except (TypeError, ValueError, UnicodeError):
        return None


def _fail(payload: dict[str, Any], output: dict[str, Any], message: str) -> dict[str, Any]:
    output["error"] = message
    finish(output, max_bytes=payload["_execute_max_bytes"])
    payload.update(execution=output, execute_verified=False, operational_failure=True)
    payload.pop("_execute_max_bytes", None)
    return payload


def collect(ctx: Any, record: dict[str, Any], state: Any) -> dict[str, Any]:
    payload = dict(record)
    command = getattr(ctx.args, "execute", None)
    if command is None:
        return payload
    limit = int(getattr(ctx.args, "execute_max_bytes", 1048576))
    payload["_execute_max_bytes"] = limit
    output = _output(command)
    if record.get("is_portainer") is not True or record.get("ui_product") != "portainer":
        return _fail(payload, output, "--execute supports confirmed Portainer UI only")
    if record.get("detection_status") != "confirmed" or record.get("status") not in {
        "open_no_auth",
        "valid_credentials",
    }:
        return _fail(payload, output, "Portainer access is not verified; command was not sent")
    endpoint = str(getattr(ctx.args, "endpoint", "") or "").strip()
    container = str(getattr(ctx.args, "container", "") or "").strip()
    if not endpoint:
        return _fail(payload, output, "--execute requires an explicit --endpoint")
    if not container:
        return _fail(payload, output, "--execute requires an explicit --container")
    cached = getattr(state, "execution", None)
    if cached is not None:
        payload.update(execution=cached, execute_verified=cached.get("executed") is True)
        if cached.get("executed") is not True:
            payload["operational_failure"] = True
        payload.pop("_execute_max_bytes", None)
        return payload
    state.execution = output
    ui = dict(record.get("ui") or {})
    credential = getattr(ctx, "credential", None)
    session_key = (
        getattr(credential, "username", None),
        getattr(credential, "password", None),
        getattr(credential, "token", None),
    )
    stored_session = getattr(state, "sessions", {}).get(session_key, {})
    if isinstance(stored_session, dict):
        ui.update(stored_session)
    base = str(ui.get("endpoint") or "").rstrip("/")
    headers = {"Accept": "application/json", **_headers(ui)}
    if not base or not any(key in headers for key in ("Authorization", "X-API-Key", "Cookie")):
        return _fail(payload, output, "Portainer session unavailable; command was not sent")
    timeout = float(getattr(ctx.args, "execute_timeout", 30.0))
    cap = ((limit + 2) // 3) * 8 + 65536
    marker = "RP_PORTAINER_" + secrets.token_hex(12) + ":"
    timed_out = False
    try:
        with closing(
            HttpSessionPool(
                timeout=min(timeout, 30.0),
                insecure=not bool(getattr(ctx.args, "secure", False)),
                proxy=getattr(ctx.args, "_proxy_config", None),
                retries=0,
            )
        ) as pool:
            endpoints = pool.request(
                "GET",
                base + "/api/endpoints?start=0&limit=100",
                headers=headers,
                timeout=timeout,
                response_size_cap=8 * 1024 * 1024,
                retries=0,
            )
            listed = _json(endpoints)
            if not isinstance(listed, list):
                return _fail(payload, output, "Portainer environment list unavailable")
            selected = next(
                (
                    item
                    for item in listed
                    if isinstance(item, dict)
                    and (str(item.get("Id")) == endpoint or str(item.get("Name", "")).casefold() == endpoint.casefold())
                ),
                None,
            )
            if not isinstance(selected, dict) or type(selected.get("Id")) is not int:
                return _fail(payload, output, f"Portainer environment not found: {endpoint}")
            docker_base = f"{base}/api/endpoints/{selected['Id']}/docker"
            create = pool.request_once(
                "POST",
                docker_base + "/containers/" + quote(container, safe="") + "/exec",
                headers={**headers, "Content-Type": "application/json"},
                body=json.dumps(
                    {
                        "AttachStdout": True,
                        "AttachStderr": True,
                        "Tty": False,
                        "Cmd": ["/bin/sh", "-c", _wrapper(command, marker, timeout, limit)],
                    }
                ).encode(),
                timeout=timeout,
                response_size_cap=128 * 1024,
            )
            created = _json(create)
            if not isinstance(created, dict) or not isinstance(created.get("Id"), str) or not created["Id"]:
                return _fail(payload, output, "Portainer Docker exec create returned no exec ID")
            exec_id = quote(created["Id"], safe="")
            output["cleanup"] = "unknown"
            started = pool.request_once(
                "POST",
                docker_base + "/exec/" + exec_id + "/start",
                headers={**headers, "Content-Type": "application/json"},
                body=b'{"Detach":false,"Tty":false}',
                timeout=timeout + 5.0,
                response_size_cap=cap,
            )
            if started.error or started.truncated or started.status != 200:
                output["cleanup"] = "unknown"
                message = started.error or (
                    "Portainer Docker exec response was truncated"
                    if started.truncated
                    else f"Portainer Docker exec start failed: HTTP {started.status}"
                )
                return _fail(
                    payload,
                    output,
                    message + "; command outcome unknown; the remote execution deadline remains active",
                )
            streams = decode_docker_stream_bytes(started.body or b"")
            proof = _proof(streams["stdout"], marker)
            if proof.get("unsupported") is True:
                output.update(status="unsupported", cleanup="not_needed")
                return _fail(payload, output, proof["error"])
            inspect = pool.request(
                "GET",
                docker_base + "/exec/" + exec_id + "/json",
                headers=headers,
                timeout=timeout,
                response_size_cap=128 * 1024,
                retries=0,
            )
            details = _json(inspect)
            if (
                not isinstance(details, dict)
                or type(details.get("ExitCode")) is not int
                or details.get("Running") is not False
            ):
                return _fail(payload, output, "Portainer Docker exec returned no completed exit evidence")
            timed_out = proof["timed_out"]
            output.update(
                executed=True,
                exit_code=proof["exit_code"],
                stdout=proof["stdout"],
                stderr=proof["stderr"],
                truncated=proof["truncated"],
                cleanup="not_needed" if proof["cleanup_complete"] else "failed",
                status="timeout" if timed_out else "partial" if proof["truncated"] else "complete",
            )
            if timed_out:
                output.update(
                    cleanup="complete" if proof["cleanup_complete"] else "failed",
                    error="Remote command exceeded its execution deadline",
                )
            if not proof["cleanup_complete"]:
                output["cleanup_error"] = "A detached process retained command pipes after process-group termination"
    except (OSError, RuntimeError, TypeError, ValueError, KeyError) as exc:
        output["error"] = str(exc)
    finish(output, max_bytes=limit)
    if timed_out:
        output["status"] = "timeout"
    payload.update(execution=output, execute_verified=output["executed"] is True)
    if output["executed"] is not True:
        payload["operational_failure"] = True
    payload.pop("_execute_max_bytes", None)
    return payload


__all__ = ["collect"]
