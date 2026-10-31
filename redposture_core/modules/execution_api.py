"""Explicit execution helpers: bounded requests, no action replay, truthful results."""

from __future__ import annotations

import json
import math
import re
from typing import Any

from ..clients.websocket import WebSocket
from ..console import Console
from ..shell_capture import MAX_CAPTURE_BYTES, CommandResult, ShellView, read_shell_command


def add_flags(group: Any, *, include_os_shell: bool = False, os_shell_help: str | None = None) -> None:
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
    if include_os_shell:
        group.add_argument(
            "--os-shell",
            action="store_true",
            help=os_shell_help or "Start an interactive shell using the confirmed service execution surface.",
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


def validate_os_shell(
    args: Any,
    console: Any,
    *,
    forbidden: tuple[str, ...] = (),
    unsupported_reason: str | None = None,
) -> int | None:
    if not bool(getattr(args, "os_shell", False)):
        return None
    if unsupported_reason:
        console.error(f"--os-shell is unsupported: {unsupported_reason}")
        return 2
    if getattr(args, "execute", None) is not None:
        console.error("--os-shell cannot be combined with --execute")
        return 2
    if getattr(args, "output", None):
        console.error("--os-shell cannot be used with -o/--output")
        return 2
    if str(getattr(args, "output_format", "txt") or "txt").lower() != "txt":
        console.error("--os-shell requires --format txt")
        return 2
    if bool(getattr(args, "defcreds", False)):
        console.error("--os-shell cannot be combined with --defcreds")
        return 2
    for name in forbidden:
        value = getattr(args, name, None)
        if bool(value):
            console.error(f"--os-shell cannot be combined with --{name.replace('_', '-')}")
            return 2
    return None


def validate_os_shell_plan(plan: Any, console: Any) -> int | None:
    try:
        plan.require_single_target_spec()
    except (AttributeError, ValueError) as exc:
        console.error(f"--os-shell requires exactly one target: {exc}")
        return 2
    return None


def run_os_shell(
    ctx: Any,
    record: Any,
    state: Any,
    *,
    module: str,
    surface: str,
    execute_once: Any,
    cache_fields: tuple[str, ...] = ("execution", "ui_execution"),
    preflight: Any = None,
) -> None:
    """Run repeated one-shot commands against an already authenticated target."""
    console = Console(
        debug=bool(getattr(ctx.args, "debug", False)),
        no_color=bool(getattr(ctx.args, "no_color", False)),
    )
    command_record = record.to_dict() if callable(getattr(record, "to_dict", None)) else record
    if callable(preflight):
        refusal = preflight(command_record)
        if refusal:
            console.error(str(refusal))
            return
    shell = ShellView()
    try:
        shell.capture_bytes = min(
            MAX_CAPTURE_BYTES,
            max(1, int(getattr(ctx.args, "execute_max_bytes", shell.capture_bytes))),
        )
    except (TypeError, ValueError):
        pass
    original_command = getattr(ctx.args, "execute", None)
    original_max_bytes = getattr(ctx.args, "execute_max_bytes", None)
    while True:
        try:
            command = read_shell_command(f"{module}-os> ")
        except (EOFError, KeyboardInterrupt):
            console.plain("")
            break
        if not command.strip():
            continue
        if command.strip().lower() in {"exit", "quit"}:
            break
        handled, should_exit = shell.handle(command, console)
        if should_exit:
            break
        if handled:
            continue
        try:
            encoded = command.encode("utf-8")
        except UnicodeEncodeError:
            shell.show(CommandResult(error="command is not valid UTF-8"), console)
            continue
        if "\x00" in command or len(encoded) > 65536:
            shell.show(CommandResult(error="command must not contain NUL and must be at most 65536 bytes"), console)
            continue
        shell.remember(command)
        try:
            ctx.args.execute = command
            ctx.args.execute_max_bytes = shell.capture_bytes
            for field in cache_fields:
                if hasattr(state, field):
                    setattr(state, field, None)
            result_payload = execute_once(ctx, command_record, state)
        except KeyboardInterrupt:
            shell.show(
                CommandResult(error="interrupted locally; command outcome is unknown", outcome_unknown=True), console
            )
            continue
        except Exception as exc:
            shell.show(CommandResult(error=f"command result unavailable: {exc}", outcome_unknown=True), console)
            continue
        finally:
            ctx.args.execute = original_command
            if original_max_bytes is not None:
                ctx.args.execute_max_bytes = original_max_bytes
        payload = result_payload.to_dict() if callable(getattr(result_payload, "to_dict", None)) else result_payload
        output = payload.get("execution") if isinstance(payload, dict) else None
        if not isinstance(output, dict):
            shell.show(CommandResult(error="execution adapter returned no command result"), console)
            continue
        stdout = str(output.get("stdout") or "").encode("utf-8", errors="replace")
        stderr = str(output.get("stderr") or "").encode("utf-8", errors="replace")
        executed = output.get("executed") is True
        exit_code = output.get("exit_code")
        truncated = output.get("truncated") is True
        stdout_total = output.get("stdout_total")
        stderr_total = output.get("stderr_total")
        result = CommandResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code if type(exit_code) is int else None,
            duration_ms=output.get("duration_ms") if type(output.get("duration_ms")) is int else None,
            stdout_total=stdout_total if type(stdout_total) is int else len(stdout),
            stderr_total=stderr_total if type(stderr_total) is int else len(stderr),
            capture_truncated=truncated,
            error=None if executed else str(output.get("error") or "command was not verified"),
            outcome_unknown=bool(output.get("outcome_unknown")) or (not executed and output.get("status") == "timeout"),
        )
        shell.show(result, console)
        cleanup = str(output.get("cleanup") or "")
        if cleanup in {"failed", "unknown"}:
            detail = str(output.get("cleanup_error") or "cleanup status is unknown")
            label = "failed" if cleanup == "failed" else "unknown"
            console.plain(f"[-] cleanup {label}: {detail}", color="true_red")
    ctx.args.execute = original_command
    if original_max_bytes is not None:
        ctx.args.execute_max_bytes = original_max_bytes


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
