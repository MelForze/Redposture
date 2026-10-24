"""One-shot Jenkins Script Console execution with proof and bounded output."""

from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
from typing import Any
from urllib.parse import urlencode

from ..execution_api import finish
from ..groovy_execution import process_script


def _script(command: str, nonce: str, milliseconds: int, limit: int) -> str:
    return (
        process_script(command, milliseconds, limit, login_shell=True)
        + r"""
def proof = [exit_code: exitCode, stdout_b64: java.util.Base64.encoder.encodeToString(stdout), stderr_b64: java.util.Base64.encoder.encodeToString(stderr), timed_out: timed, truncated: clipped]
println("{{NONCE}}" + java.util.Base64.encoder.encodeToString(groovy.json.JsonOutput.toJson(proof).getBytes("UTF-8")))
""".replace("{{NONCE}}", nonce)
    )


def _output(command: str) -> dict[str, Any]:
    return {
        "command": command,
        "mode": "jenkins_script_console",
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


def _basic(ctx: Any) -> str | None:
    credential = getattr(ctx, "credential", None)
    username = getattr(credential, "username", None)
    password = getattr(credential, "password", None)
    if not username or password is None:
        return None
    value = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    return "Basic " + value


def _decode_proof(text: str, nonce: str) -> dict[str, Any]:
    match = re.search(re.escape(nonce) + r"([A-Za-z0-9+/]+={0,2})\s*$", text)
    if not match:
        raise ValueError("Jenkins Script Console returned no correlated command completion evidence")
    proof = json.loads(base64.b64decode(match[1], validate=True))
    if not isinstance(proof, dict) or type(proof.get("exit_code")) is not int:
        raise ValueError("invalid Jenkins command completion evidence")
    if type(proof.get("timed_out")) is not bool or type(proof.get("truncated")) is not bool:
        raise ValueError("invalid Jenkins command completion evidence")
    return proof


def collect(ctx: Any, record: dict[str, Any], state: Any) -> dict[str, Any]:
    payload = dict(record)
    command = getattr(ctx.args, "execute", None)
    if command is None:
        return payload
    limit = int(getattr(ctx.args, "execute_max_bytes", 1048576))
    output = _output(command)
    if record.get("is_jenkins") is not True:
        output["error"] = "--execute supports confirmed Jenkins only"
    elif record.get("detection_status") != "confirmed" or record.get("provided_credentials_ok") is not True:
        output["error"] = "Jenkins identity is not verified; command was not sent"
    elif not str(record.get("api_endpoint") or "").strip():
        output["error"] = "Jenkins API endpoint is unavailable"
    else:
        cached = getattr(state, "execution", None)
        if cached is not None:
            payload.update(execution=cached, execute_verified=cached.get("executed") is True)
            if cached.get("executed") is not True:
                payload["operational_failure"] = True
            return payload
        state.execution = output
        pool = getattr(state, "http", None)
        basic = _basic(ctx)
        if pool is None or not hasattr(pool, "request") or not hasattr(pool, "request_once") or basic is None:
            output["error"] = "Jenkins authenticated HTTP session unavailable; command was not sent"
        else:
            nonce = "RP_EXEC_" + secrets.token_hex(16) + ":"
            try:
                headers = {"Accept": "application/json", "Authorization": basic}
                credential = getattr(ctx, "credential", None)
                source = str(getattr(credential, "source", "") or "")
                if source != "api_token":
                    crumb = pool.request(
                        "GET",
                        str(record["api_endpoint"]).rstrip("/") + "/crumbIssuer/api/json",
                        headers=headers,
                        timeout=ctx.args.execute_timeout,
                        response_size_cap=64 * 1024,
                        retries=0,
                    )
                    crumb_data = crumb.json() if crumb.status == 200 and not crumb.error else None
                    if (
                        not isinstance(crumb_data, dict)
                        or not isinstance(crumb_data.get("crumb"), str)
                        or not isinstance(crumb_data.get("crumbRequestField"), str)
                    ):
                        raise ValueError("Jenkins CSRF crumb unavailable")
                    headers[crumb_data["crumbRequestField"]] = crumb_data["crumb"]
                    cookie = next(
                        (
                            str(value).split(";", 1)[0]
                            for key, value in crumb.headers.items()
                            if key.lower() == "set-cookie"
                        ),
                        "",
                    )
                    if cookie:
                        headers["Cookie"] = cookie
                script = _script(command, nonce, max(1, int(ctx.args.execute_timeout * 1000)), limit)
                response = pool.request_once(
                    "POST",
                    str(record["api_endpoint"]).rstrip("/") + "/scriptText",
                    headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
                    body=urlencode({"script": script}).encode(),
                    timeout=ctx.args.execute_timeout + 2,
                    response_size_cap=limit * 2 + 65536,
                )
                if response.error or response.status != 200 or response.truncated:
                    raise ValueError(response.error or f"Jenkins Script Console HTTP {response.status}")
                proof = _decode_proof(response.text, nonce)
                for channel in ("stdout", "stderr"):
                    output[channel] = base64.b64decode(proof[channel + "_b64"], validate=True).decode(
                        "utf-8", errors="replace"
                    )
                timed = proof["timed_out"]
                output.update(
                    executed=not timed,
                    exit_code=proof["exit_code"],
                    status="timeout" if timed else "partial" if proof["truncated"] else "complete",
                    truncated=proof["truncated"],
                    error="command exceeded execution deadline" if timed else None,
                )
            except (OSError, RuntimeError, ValueError, KeyError, TypeError, binascii.Error) as exc:
                output["error"] = str(exc)
    finish(output, max_bytes=limit)
    payload.update(execution=output, execute_verified=output["executed"] is True)
    if output["executed"] is not True:
        payload["operational_failure"] = True
    return payload


__all__ = ["collect"]
