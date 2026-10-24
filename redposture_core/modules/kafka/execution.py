"""Explicit, one-shot execution in confirmed Provectus UI, never on a broker."""

from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
from typing import Any

from ..execution_api import finish
from ..groovy_execution import process_script


def _script(command: str, nonce: str, milliseconds: int, limit: int) -> str:
    return (
        process_script(command, milliseconds, limit, windows=True)
        + r"""
def proof = [exit_code: exitCode, stdout_b64: java.util.Base64.encoder.encodeToString(stdout), stderr_b64: java.util.Base64.encoder.encodeToString(stderr), timed_out: timed, truncated: clipped]
throw new RuntimeException("{{NONCE}}" + java.util.Base64.encoder.encodeToString(groovy.json.JsonOutput.toJson(proof).getBytes("UTF-8")))
""".replace("{{NONCE}}", nonce)
    )


def collect(ctx: Any, record: dict[str, Any], state: Any) -> dict[str, Any]:
    payload = dict(record)
    command = getattr(ctx.args, "execute", None)
    if command is None:
        return payload
    output: dict[str, Any] = {
        "command": command,
        "mode": "provectus_groovy",
        "surface": "ui",
        "executed": False,
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "status": "unverified",
        "error": None,
        "cleanup": "not_needed",
    }
    vendor = record.get("ui_vendor")
    if not record.get("is_kafka_ui") or vendor != "provectus" or record.get("kafka_interface") != "ui":
        output.update(
            status="unsupported",
            error="--execute supports confirmed Provectus Kafka UI only; broker/Kafbat/other HTTP surfaces are unsupported",
        )
    elif record.get("detection_status") != "confirmed" or record.get("status") not in {
        "open_no_auth",
        "valid_credentials",
        "weak_default_creds",
    }:
        output["error"] = "Kafka UI access is not verified; command was not sent"
    elif not state.ui_base or state.ui_http is None:
        output["error"] = "Kafka UI session unavailable; command was not sent"
    else:
        cached = getattr(state, "ui_execution", None)
        if cached is not None:
            output = cached
        else:
            # Cache before sending, including ambiguous failures: no replay on a
            # repeated data hook after a lost response or an inventory failure.
            state.ui_execution = output
            limit = ctx.args.execute_max_bytes
            nonce = "RP_EXEC_" + secrets.token_hex(16) + ":"
            code = _script(command, nonce, max(1, int(ctx.args.execute_timeout * 1000)), limit)
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            if state.ui_cookie:
                headers["Cookie"] = state.ui_cookie
            csrf = getattr(state, "ui_csrf", "")
            if csrf:
                headers["X-CSRF-TOKEN"] = csrf
            try:
                response = state.ui_http.request_once(
                    "PUT",
                    state.ui_base + "/api/smartfilters/testexecutions",
                    headers=headers,
                    body=json.dumps(
                        {
                            "filterCode": code,
                            "value": "{}",
                            "key": "",
                            "headers": {},
                            "partition": 0,
                            "offset": 0,
                            "timestampMs": 0,
                        }
                    ).encode(),
                    timeout=ctx.args.execute_timeout + 3,
                    response_size_cap=limit * 2 + 65536,
                )
                if response.error or response.truncated or response.status != 200:
                    raise ValueError(response.error or f"HTTP {response.status}; execution result unavailable")
                data = response.json()
                error = data.get("error") if isinstance(data, dict) else None
                match = (
                    re.search(re.escape(nonce) + r"([A-Za-z0-9+/]+={0,2})$", error.strip())
                    if isinstance(error, str)
                    else None
                )
                if not match:
                    raise ValueError("Kafka UI returned no correlated command completion evidence")
                proof = json.loads(base64.b64decode(match[1], validate=True))
                if (
                    not isinstance(proof, dict)
                    or type(proof.get("exit_code")) is not int
                    or type(proof.get("timed_out")) is not bool
                    or type(proof.get("truncated")) is not bool
                ):
                    raise ValueError("invalid Kafka UI command completion evidence")
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
    payload.update(execution=output, execute_verified=output["executed"])
    if not output["executed"]:
        payload["operational_failure"] = True
    if output["status"] == "partial":
        payload["partial"] = True
    return payload
