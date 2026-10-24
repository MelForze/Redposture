"""One-shot execution through the Nexus Repository Script API.

Nexus does not expose a shell endpoint as part of the registry API.  The
supported administrative surface is the temporary Groovy script API.  This
helper only uses it after the Nexus product and the supplied identity have
both been confirmed, and always attempts to delete the script afterwards.
"""

from __future__ import annotations

import json
import re
import secrets
from typing import Any

from ..execution_api import finish
from ..groovy_execution import process_script
from ..registry.actions import _auth_headers

_MARKER_PREFIX = "RP_NEXUS_"


def _output(command: str) -> dict[str, Any]:
    return {
        "command": command,
        "mode": "nexus_groovy_script",
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


def _base_url(state: Any) -> str:
    scheme = str(getattr(state, "scheme", "") or "") or ("https" if int(state.port) == 443 else "http")
    host = str(state.host or "")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    base_path = str(getattr(state, "base_path", "") or "").rstrip("/")
    return f"{scheme}://{host}:{int(state.port)}{base_path}"


def _script_path(state: Any) -> str:
    base = _base_url(state)
    if str(getattr(state, "base_path", "") or "").rstrip("/").endswith("/service/rest"):
        return base + "/v1/script"
    return base + "/service/rest/v1/script"


def _script(command: str, marker: str, timeout: float, limit: int) -> str:
    # Nexus serializes the evaluated return value into result; println alone
    # writes to the server log and leaves result null.
    return (
        process_script(command, max(1, int(timeout * 1000)), limit, login_shell=True)
        + r"""
def proof = [exit_code: exitCode, stdout: new String(stdout, "UTF-8"), stderr: new String(stderr, "UTF-8"), timed_out: timed, truncated: clipped]
return "{{MARKER}}" + groovy.json.JsonOutput.toJson(proof)
""".replace("{{MARKER}}", marker)
    )


def _parse_proof(text: str, marker: str, script_name: str) -> dict[str, Any]:
    envelope = json.loads(text)
    if (
        not isinstance(envelope, dict)
        or envelope.get("name") != script_name
        or not isinstance(envelope.get("result"), str)
    ):
        raise ValueError("invalid Nexus Script API result envelope")
    match = re.fullmatch(re.escape(marker) + r"(\{.*\})\s*", envelope["result"], re.S)
    if match is None:
        raise ValueError("Nexus Script API returned no correlated command completion evidence")
    value = json.loads(match.group(1))
    if not isinstance(value, dict) or type(value.get("exit_code")) is not int:
        raise ValueError("invalid Nexus command completion evidence")
    if type(value.get("timed_out")) is not bool or type(value.get("truncated")) is not bool:
        raise ValueError("invalid Nexus command completion evidence")
    if not isinstance(value.get("stdout"), str) or not isinstance(value.get("stderr"), str):
        raise ValueError("invalid Nexus command completion evidence")
    return value


def _cleanup_script(
    pool: Any, endpoint: str, script_name: str, headers: dict[str, str], timeout: float, *, ambiguous: bool
) -> tuple[str, str | None]:
    url = endpoint + "/" + script_name
    request_options = {
        "headers": headers,
        "timeout": min(5.0, timeout),
        "response_size_cap": 65536,
        "retries": 0,
        "replay_safe": False,
        "allow_cross_origin_redirects": False,
    }
    if ambiguous:
        try:
            existing = pool.request("GET", url, **request_options)
            if existing.status == 404 and not existing.error:
                return "complete", None
        except (OSError, RuntimeError, ValueError, TypeError):
            # A failed existence check does not resolve the lost create. The
            # unique name is already known, so still attempt its deletion.
            pass
    try:
        deleted = pool.request("DELETE", url, **request_options)
        if deleted.status in {200, 204, 404} and not deleted.error:
            return "complete", None
        return "failed", deleted.error or f"Nexus script cleanup HTTP {deleted.status}"
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        return "failed", str(exc)


def collect(ctx: Any, record: dict[str, Any], state: Any) -> dict[str, Any]:
    payload = dict(record)
    command = getattr(ctx.args, "execute", None)
    if command is None:
        return payload
    limit = int(getattr(ctx.args, "execute_max_bytes", 1048576))
    output = _output(command)
    payload["execution"] = output
    payload["execute_verified"] = False
    if record.get("is_nexus") is not True:
        output["error"] = "--execute supports confirmed Nexus only"
    elif record.get("detection_status") in {"not_service", "transport_failure", "unknown"}:
        output["error"] = "Nexus identity is not confirmed; command was not sent"
    elif record.get("status") not in {"open_no_auth", "valid_credentials"}:
        output["error"] = "Nexus access is not verified; command was not sent"
    elif record.get("status") == "valid_credentials" and record.get("provided_credentials_ok") is not True:
        output["error"] = "Nexus credentials are not verified; command was not sent"
    else:
        cached = getattr(state, "execution", None)
        if cached is not None:
            payload.update(execution=cached, execute_verified=cached.get("executed") is True)
            if cached.get("executed") is not True:
                payload["operational_failure"] = True
            return payload
        state.execution = output
        script_name = "redposture-exec-" + secrets.token_hex(10)
        marker = _MARKER_PREFIX + secrets.token_hex(12) + ":"
        timeout = float(getattr(ctx.args, "execute_timeout", 30.0))
        headers = _auth_headers(
            getattr(getattr(ctx, "credential", None), "username", None),
            getattr(getattr(ctx, "credential", None), "password", None),
            getattr(getattr(ctx, "credential", None), "token", None),
        )
        endpoint = _script_path(state)
        created = False
        create_ambiguous = False
        try:
            pool = state.http
            body = {
                "name": script_name,
                "type": "groovy",
                "content": _script(command, marker, timeout, limit),
            }
            # Set before sending: a lost response cannot establish whether
            # Nexus applied the create, and must not leave our script behind.
            create_ambiguous = True
            created_response = pool.request(
                "POST",
                endpoint,
                headers={**headers, "Accept": "application/json", "Content-Type": "application/json"},
                body=json.dumps(body).encode(),
                timeout=timeout,
                response_size_cap=max(65536, limit * 2),
                retries=0,
                replay_safe=False,
                allow_cross_origin_redirects=False,
            )
            if (
                not created_response.error
                and created_response.status is not None
                and 400 <= created_response.status < 500
            ):
                create_ambiguous = False
            if created_response.error or created_response.status not in {200, 201, 204}:
                raise ValueError(created_response.error or f"Nexus script creation HTTP {created_response.status}")
            created = True
            run_response = pool.request(
                "POST",
                endpoint + "/" + script_name + "/run",
                headers={**headers, "Accept": "application/json", "Content-Type": "application/json"},
                body=b"{}",
                timeout=timeout + 2,
                # Command text is JSON inside the JSON result envelope: control
                # bytes may expand to six escapes, then be escaped once more.
                response_size_cap=max(65536, limit * 12 + 65536),
                retries=0,
                replay_safe=False,
                allow_cross_origin_redirects=False,
            )
            if run_response.error or run_response.status not in {200, 201} or run_response.truncated:
                raise ValueError(run_response.error or f"Nexus script run HTTP {run_response.status}")
            proof = _parse_proof(run_response.text, marker, script_name)
            timed_out = proof["timed_out"]
            output.update(
                executed=not timed_out,
                exit_code=proof["exit_code"],
                stdout=proof["stdout"],
                stderr=proof["stderr"],
                truncated=proof["truncated"],
                status="timeout" if timed_out else "partial" if proof["truncated"] else "complete",
                error="command exceeded execution deadline" if timed_out else None,
            )
        except (OSError, RuntimeError, ValueError, TypeError, json.JSONDecodeError) as exc:
            output["error"] = str(exc)
        finally:
            if created or create_ambiguous:
                cleanup, cleanup_error = _cleanup_script(
                    state.http, endpoint, script_name, headers, timeout, ambiguous=not created
                )
                output["cleanup"] = cleanup
                if cleanup_error:
                    output["cleanup_error"] = cleanup_error
    finish(output, max_bytes=limit)
    payload["execute_verified"] = output["executed"] is True
    if not payload["execute_verified"]:
        payload["operational_failure"] = True
    return payload


__all__ = ["collect"]
