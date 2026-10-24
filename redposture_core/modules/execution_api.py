"""Explicit execution helpers: bounded requests, no action replay, truthful results."""

from __future__ import annotations

import json
import math
import re
from typing import Any

from ..clients.websocket import WebSocket


def add_flags(group: Any) -> None:
    group.add_argument(
        "--execute", metavar="command", help="Execute a shell command on the confirmed service and return its output."
    )
    group.add_argument(
        "--execute-timeout",
        type=float,
        default=30.0,
        metavar="seconds",
        help="Execution deadline (default: 30 seconds).",
    )
    group.add_argument(
        "--execute-max-bytes",
        type=int,
        default=1048576,
        metavar="bytes",
        help="Maximum captured execution data (default: 1048576).",
    )


def validate(args: Any, console: Any) -> int | None:
    command = getattr(args, "execute", None)
    try:
        command_bytes = command.encode() if command is not None else b""
    except UnicodeEncodeError:
        command_bytes = b"x" * 65537
    if command is not None and (not command.strip() or "\x00" in command or len(command_bytes) > 65536):
        console.error("--execute must be nonempty, without NUL, at most 65536 bytes")
        return 2
    timeout = getattr(args, "execute_timeout", 30)
    if not math.isfinite(timeout) or not 0 < timeout <= 3600:
        console.error("--execute-timeout must be > 0 and <= 3600")
        return 2
    if not 0 < getattr(args, "execute_max_bytes", 1048576) <= 64 * 1024 * 1024:
        console.error("--execute-max-bytes must be > 0 and <= 67108864")
        return 2
    return None


def headers(ctx: Any, prior: dict[str, Any], module: str) -> dict[str, str]:
    token = getattr(getattr(ctx, "credential", None), "token", None) if prior.get("token_valid") else None
    auth_headers = (
        {
            ("Authorization" if module == "jupyter" else "X-Nomad-Token"): (
                "token " + token if module == "jupyter" else token
            )
        }
        if token
        else {}
    )
    return {**prior.get("_execution_headers", {}), **auth_headers}


def api(
    ctx: Any,
    prior: dict[str, Any],
    module: str,
    method: str,
    path: str,
    body: Any = None,
    *,
    timeout: float | None = None,
    max_bytes: int | None = None,
) -> Any:
    return ctx.lifecycle_state.http.request(
        method,
        prior["api_endpoint"].rstrip("/") + path,
        headers={"Accept": "application/json", "Content-Type": "application/json", **headers(ctx, prior, module)},
        body=json.dumps(body).encode() if body is not None else None,
        timeout=timeout or min(5.0, getattr(ctx.args, "execute_timeout", 30)),
        response_size_cap=max_bytes
        if max_bytes is not None
        else max(65536, getattr(ctx.args, "execute_max_bytes", 1048576)),
        retries=0,
        replay_safe=False,
        allow_cross_origin_redirects=False,
    )


def open_ws(ctx: Any, prior: dict[str, Any], module: str, path: str) -> WebSocket:
    return WebSocket(
        ctx.lifecycle_state.http,
        prior["api_endpoint"].rstrip("/") + path,
        headers=headers(ctx, prior, module),
        timeout=ctx.args.execute_timeout + 2,
        max_bytes=min(64 * 1024 * 1024, ctx.args.execute_max_bytes * 8 + 65536),
    )


def result(ctx: Any, mode: str) -> dict[str, Any]:
    return {
        "command": ctx.args.execute,
        "mode": mode,
        "executed": False,
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "status": "unverified",
        "error": None,
        "cleanup": "not_needed",
    }


def finish(output: dict[str, Any], *, max_bytes: int = 1048576) -> dict[str, Any]:
    for name in ("stdout", "stderr", "error", "cleanup_error"):
        if isinstance(output.get(name), str):
            output[name] = re.sub(
                r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\|$)|[PX^_][^\x1b]*(?:\x1b\\|$)|[ -/]*[0-~])",
                "",
                output[name],
            ).replace("\x1b", "")
    remaining = max_bytes
    for name in ("stdout", "stderr"):
        raw = str(output.get(name) or "").encode("utf-8", errors="replace")
        if len(raw) > remaining:
            output[name] = raw[:remaining].decode("utf-8", errors="ignore")
            output.update(status="partial", truncated=True)
        remaining -= len(str(output.get(name) or "").encode())
    return output


def render(module: str, record: dict[str, Any]) -> list[str]:
    output = record.get("execution")
    if not isinstance(output, dict):
        return []
    prefix = f"{module.upper()}\t{record.get('host') or '?'}\t{record.get('port') or 0}\t"
    verified = output.get("executed") is True
    rows = [f"{prefix} [*] Execute Command", f"{prefix} command={output.get('command') or ''}"]
    has_output = False
    for channel in ("stdout", "stderr"):
        for line in str(output.get(channel) or "").splitlines():
            rows.append(f"{prefix} {line}")
            has_output = True
    if not verified:
        rows.append(f"{prefix} <error:{output.get('error') or 'execution not verified'}>")
    elif isinstance(output.get("exit_code"), int) and output["exit_code"] != 0:
        rows.append(f"{prefix} <error:command exited with status {output['exit_code']}>")
    elif not has_output:
        rows.append(f"{prefix} <no output>")
    if output.get("status") == "partial":
        rows.append(f"{prefix} <error:output incomplete>")
    if output.get("cleanup") == "failed":
        rows.append(f"{prefix} <error:cleanup failed: {output.get('cleanup_error') or 'unknown error'}>")
    return rows
