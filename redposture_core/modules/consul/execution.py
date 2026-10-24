"""One-shot Consul script-check execution with bounded output and cleanup."""

from __future__ import annotations

import re
import secrets
import shlex
import time
import urllib.parse
from typing import Any

from ..execution_api import finish
from . import actions

_END_MARKER = "RP_EXEC_END_"


def _output(command: str) -> dict[str, Any]:
    return {
        "command": command,
        "mode": "consul_script_check",
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


def _wrapper(command: str, marker: str, *, max_bytes: int = 1048576, guard_dir: str | None = None) -> str:
    """Claim the command once on the agent and replay only its bounded result.

    The guard must outlive the check: an invocation already scheduled by the
    agent must not execute again after the client has deregistered the check.
    Only the bounded result and exit status remain; FIFO/capture work is removed.
    """
    guard = guard_dir or "/tmp/redposture-exec-" + marker
    return (
        "umask 077\n"
        f"rp_guard={shlex.quote(guard)}\n"
        'if ! mkdir "$rp_guard" 2>/dev/null; then\n'
        '  if [ -r "$rp_guard/result" ] && [ -r "$rp_guard/status" ]; then\n'
        '    cat "$rp_guard/result"\n'
        '    read -r rp_rc < "$rp_guard/status"\n'
        '    exit "$rp_rc"\n'
        "  fi\n"
        "  exit 125\n"
        "fi\n"
        "for rp_tool in mktemp mkfifo head cat wc mv rm; do\n"
        '  command -v "$rp_tool" >/dev/null 2>&1 || exit 125\n'
        "done\n"
        "head -c 1 </dev/null >/dev/null 2>&1 || exit 125\n"
        'rp_work=$(mktemp -d "$rp_guard/work.XXXXXX") || exit 125\n'
        "trap 'rm -rf \"$rp_work\"' 0\n"
        'mkfifo "$rp_work/stream" || exit 125\n'
        # Drain after the bounded prefix so commands never block or receive
        # SIGPIPE merely because the requested capture limit has been reached.
        f'(head -c {max_bytes + 1} > "$rp_work/data"; cat >/dev/null) < "$rp_work/stream" &\n'
        "rp_reader=$!\n"
        f'/bin/sh -c {shlex.quote(command)} > "$rp_work/stream" 2>&1\n'
        "rp_rc=$?\n"
        'wait "$rp_reader" || exit 125\n'
        'rp_size=$(wc -c < "$rp_work/data")\n'
        "rp_truncated=0\n"
        f'[ "$rp_size" -le {max_bytes} ] || rp_truncated=1\n'
        f'head -c {max_bytes} "$rp_work/data" > "$rp_guard/result.tmp" || exit 125\n'
        f'printf \'\\n{marker}:%s:%s\\n\' "$rp_rc" "$rp_truncated" >> "$rp_guard/result.tmp"\n'
        'printf \'%s\\n\' "$rp_rc" > "$rp_guard/status"\n'
        'mv "$rp_guard/result.tmp" "$rp_guard/result" || exit 125\n'
        'cat "$rp_guard/result"\n'
        'exit "$rp_rc"'
    )


def _proof(output: str, marker: str) -> tuple[str, int]:
    command_output, exit_code, _truncated = _proof_details(output, marker)
    return command_output, exit_code


def _proof_details(output: str, marker: str) -> tuple[str, int, bool]:
    # Include exactly the LF introduced by the wrapper in the match. Trailing
    # command newlines, including CRLF, belong to the command and are retained.
    match = re.search(r"\n" + re.escape(marker) + r":(-?\d+)(?::([01]))?\n?\Z", output)
    if match is None:
        raise ValueError("Consul script check returned no correlated command completion evidence")
    try:
        exit_code = int(match.group(1))
    except ValueError as exc:  # pragma: no cover - regex already restricts digits
        raise ValueError("invalid Consul command completion evidence") from exc
    return output[: match.start()], exit_code, match.group(2) == "1"


def _server_output(output: str) -> tuple[str, bool]:
    # Consul retains the tail of truncated script output and prepends this
    # product envelope. Its header is transport metadata, never user stdout.
    match = re.match(r"\ACaptured (\d+) of (\d+) bytes\r?\n\.\.\.\r?\n", output)
    if match is not None and int(match.group(2)) > int(match.group(1)):
        return output[match.end() :], True
    return output, False


def _cleanup(
    state: Any,
    check_id: str,
    timeout: float,
    headers: dict[str, str] | None,
) -> tuple[bool, str | None]:
    try:
        status, error = actions._consul_put_no_body(
            str(state.host),
            int(state.port),
            f"/v1/agent/check/deregister/{urllib.parse.quote(check_id, safe='')}",
            timeout,
            scheme=str(state.scheme),
            insecure=bool(state.insecure),
            headers=headers,
        )
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        return False, str(exc)
    if error is None and status in {200, 204}:
        return True, None
    return False, error or f"status={status}"


def collect(ctx: Any, record: dict[str, Any], state: Any) -> dict[str, Any]:
    payload = dict(record)
    command = getattr(ctx.args, "execute", None)
    if command is None:
        return payload
    limit = int(getattr(ctx.args, "execute_max_bytes", 1048576))
    output = _output(command)
    payload["execution"] = output
    payload["execute_verified"] = False
    if record.get("is_consul") is not True:
        output["error"] = "--execute supports confirmed Consul only"
        finish(output, max_bytes=limit)
        return payload
    access_status = record.get("status")
    access_verified = access_status in {"open_no_auth", "valid_credentials"} or (
        access_status == "ok" and (record.get("auth_required") is False or record.get("auth_valid") is True)
    )
    if not access_verified:
        output["error"] = "Consul access is not verified; command was not sent"
        finish(output, max_bytes=limit)
        return payload
    if record.get("rce") is not True:
        output["error"] = "Consul script checks are not enabled; command was not sent"
        finish(output, max_bytes=limit)
        return payload
    cached = getattr(state, "execution", None)
    if cached is not None:
        payload["execution"] = cached
        payload["execute_verified"] = cached.get("executed") is True
        return payload

    # Cache before the first write so a retry cannot register a second check.
    state.execution = output
    timeout = float(getattr(ctx.args, "execute_timeout", 30.0))
    headers = dict(getattr(state, "auth_headers", None) or {}) or None
    check_id = "redposture-exec-" + secrets.token_hex(10)
    marker = _END_MARKER + secrets.token_hex(12)
    guard_dir = "/tmp/" + check_id
    payload_body = {
        "ID": check_id,
        "Name": "RedPosture one-shot execution",
        "Notes": "Temporary check; deregistered after completion",
        "Args": ["/bin/sh", "-c", _wrapper(command, marker, max_bytes=limit, guard_dir=guard_dir)],
        "Interval": "1s",
        "Timeout": f"{max(1, int(timeout))}s",
        "OutputMaxSize": limit + len(marker) + 128,
    }
    registered = False
    try:
        with actions._ConsulLifecycleReplay(state):
            status, _response, error = actions._consul_put_json(
                str(state.host),
                int(state.port),
                "/v1/agent/check/register",
                timeout,
                payload_body,
                scheme=str(state.scheme),
                insecure=bool(state.insecure),
                headers=headers,
            )
            if error is not None or status not in {200, 204}:
                raise ValueError(error or f"Consul check registration failed: HTTP {status}")
            registered = True
            deadline = time.monotonic() + max(4.0, timeout * 2.0 + 1.0)
            while time.monotonic() < deadline:
                _status, checks, error = actions._consul_get_checks(
                    str(state.host),
                    int(state.port),
                    timeout,
                    scheme=str(state.scheme),
                    insecure=bool(state.insecure),
                    headers=headers,
                )
                if error or _status != 200:
                    raise ValueError(error or f"Consul check polling failed: HTTP {_status}")
                entry = checks.get(check_id) if isinstance(checks, dict) else None
                if isinstance(entry, dict) and isinstance(entry.get("Output"), str):
                    raw_output, server_truncated = _server_output(entry["Output"])
                    try:
                        command_output, exit_code, capture_truncated = _proof_details(raw_output, marker)
                    except ValueError:
                        command_output = raw_output if server_truncated else ""
                        exit_code = None
                        capture_truncated = False
                    if server_truncated or capture_truncated:
                        output.update(stdout=command_output, status="partial", truncated=True)
                    if exit_code is not None:
                        output.update(
                            executed=True,
                            exit_code=exit_code,
                            stdout=command_output,
                            status="partial" if output["truncated"] else "complete",
                        )
                        break
                    if server_truncated:
                        break
                time.sleep(0.2)
            if output["executed"] is not True:
                output["error"] = "Consul script check returned no correlated command completion evidence"
    except (OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
        output["error"] = str(exc)
    finally:
        if registered:
            with actions._ConsulLifecycleReplay(state):
                cleaned, cleanup_error = _cleanup(state, check_id, timeout, headers)
            output["cleanup"] = "complete" if cleaned else "failed"
            output["retained_guard"] = guard_dir
            if not cleaned:
                output["cleanup_error"] = cleanup_error or "deregister failed"
    finish(output, max_bytes=limit)
    payload["execute_verified"] = output["executed"] is True
    if not payload["execute_verified"]:
        payload["operational_failure"] = True
    return payload


__all__ = ["collect"]
