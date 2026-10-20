"""Run one requested shell command in an owned kernel or terminal, then remove it."""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from textwrap import indent
from typing import Any

from ..execution_api import api, open_ws, result
from ..token_api import json_value, path_value


def _cleanup(ctx: Any, prior: dict[str, Any], path: str, output: dict[str, Any]) -> None:
    try:
        response = api(ctx, prior, "jupyter", "DELETE", path, timeout=5)
        output["cleanup"] = "complete" if response.status in {200, 204, 404} and not response.error else "failed"
        if output["cleanup"] == "failed":
            output["cleanup_error"] = f"resource cleanup HTTP {response.status}"
    except Exception as exc:
        output.update(cleanup="failed", cleanup_error=str(exc))


def _create(ctx: Any, prior: dict[str, Any], path: str, body: Any, output: dict[str, Any]) -> Any:
    # A lost/invalid creation reply can leave a server-side resource whose ID
    # we never received. Do not replay the POST or claim cleanup was unnecessary.
    output.update(cleanup="failed", cleanup_error="creation unconfirmed; resource ID unknown")
    response = api(ctx, prior, "jupyter", "POST", path, body)
    if response.status in {400, 401, 403, 404, 405, 409, 429, 501} and not response.error:
        output["cleanup"] = "not_needed"
        output.pop("cleanup_error", None)
    return response


def _kernel(ctx: Any, prior: dict[str, Any], output: dict[str, Any]) -> dict[str, Any]:
    response = _create(ctx, prior, "/api/kernels", {"name": ctx.args.kernel}, output)
    model = json_value(response)
    if response.status in {403, 404, 501}:
        output.update(error=f"kernel creation HTTP {response.status}", setup_denied=True)
        return output
    if response.status != 201 or not isinstance(model, dict) or not isinstance(model.get("id"), str) or not model["id"]:
        output["error"] = f"kernel creation unconfirmed: HTTP {response.status}"
        return output
    kid = model["id"]
    output.pop("cleanup_error", None)
    output["kernel"] = kid
    marker = "REDPOSTURE_RESULT_" + secrets.token_hex(16)
    mid = secrets.token_hex(16)
    cap = ctx.args.execute_max_bytes
    # Execute on the remote Python kernel. A process group bounds shell children
    # on timeout; only the returned marker/exit result proves completion.
    code = (
        "import subprocess, json, os, signal, selectors, time\n"
        f"_rp_p = subprocess.Popen({ctx.args.execute!r}, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)\n"
        "_rp_sel = selectors.DefaultSelector()\n"
        "_rp_sel.register(_rp_p.stdout, selectors.EVENT_READ, 0)\n"
        "_rp_sel.register(_rp_p.stderr, selectors.EVENT_READ, 1)\n"
        f"_rp_deadline = time.monotonic() + {ctx.args.execute_timeout!r}\n"
        "_rp_buffers = [bytearray(), bytearray()]\n_rp_truncated = _rp_timeout = False\n"
    )
    work = (
        "while _rp_sel.get_map() or _rp_p.poll() is None:\n"
        "    if time.monotonic() >= _rp_deadline:\n"
        "        if _rp_timeout: break\n"
        "        try: os.killpg(_rp_p.pid, signal.SIGKILL)\n"
        "        except ProcessLookupError: pass\n"
        "        _rp_timeout = True\n        _rp_deadline = time.monotonic() + 1\n"
        "    for _rp_key, _ in _rp_sel.select(0.1):\n"
        "        _rp_chunk = os.read(_rp_key.fileobj.fileno(), 65536)\n"
        "        if not _rp_chunk:\n            _rp_sel.unregister(_rp_key.fileobj)\n            continue\n"
        "        _rp_buf = _rp_buffers[_rp_key.data]\n"
        f"        _rp_room = max(0, {cap} - sum(map(len, _rp_buffers)))\n"
        "        _rp_buf.extend(_rp_chunk[:_rp_room])\n"
        "        _rp_truncated |= len(_rp_chunk) > _rp_room\n"
        "_rp_p.wait(timeout=1)\n"
    )
    code += (
        "try:\n" + indent(work, "    ") + "finally:\n"
        "    try: os.killpg(_rp_p.pid, signal.SIGKILL)\n"
        "    except ProcessLookupError: pass\n"
        "    if _rp_p.poll() is None:\n"
        "        _rp_p.wait(timeout=1)\n"
        "    _rp_sel.close()\n    _rp_p.stdout.close()\n    _rp_p.stderr.close()\n"
        f"print({marker!r} + json.dumps(dict(exit_code=_rp_p.returncode, stdout=_rp_buffers[0].decode('utf-8','replace'), stderr=_rp_buffers[1].decode('utf-8','replace'), truncated=_rp_truncated, timed_out=_rp_timeout)))\n"
    )
    streams = ""
    reply = idle = False
    try:
        with open_ws(ctx, prior, "jupyter", "/api/kernels/" + path_value(kid) + "/channels") as ws:
            ws.send_json(
                {
                    "header": {
                        "msg_id": mid,
                        "username": "redposture",
                        "session": mid,
                        "date": datetime.now(timezone.utc).isoformat(),
                        "msg_type": "execute_request",
                        "version": "5.3",
                    },
                    "parent_header": {},
                    "metadata": {},
                    "channel": "shell",
                    "content": {
                        "code": code,
                        "silent": False,
                        "store_history": False,
                        "user_expressions": {},
                        "allow_stdin": False,
                        "stop_on_error": True,
                    },
                    "buffers": [],
                }
            )
            while not (reply and idle):
                msg = ws.recv_json()
                if not isinstance(msg, dict) or msg.get("parent_header", {}).get("msg_id") != mid:
                    continue
                kind = msg.get("msg_type") or msg.get("header", {}).get("msg_type")
                content = msg.get("content", {})
                if kind == "stream":
                    streams += str(content.get("text") or "")
                elif kind == "execute_reply":
                    reply = True
                    if content.get("status") != "ok":
                        raise ValueError("kernel rejected execution: " + str(content.get("ename") or "unknown error"))
                elif kind == "status" and content.get("execution_state") == "idle":
                    idle = True
            if marker not in streams:
                raise ValueError("kernel finished without a command exit result")
            parsed, _ = json.JSONDecoder().raw_decode(streams.split(marker, 1)[1])
            if not isinstance(parsed, dict) or type(parsed.get("exit_code")) is not int:
                raise ValueError("invalid command exit result")
            output.update(
                executed=True,
                exit_code=parsed["exit_code"],
                stdout=str(parsed.get("stdout") or ""),
                stderr=str(parsed.get("stderr") or ""),
                status="partial" if parsed.get("truncated") or parsed.get("timed_out") else "complete",
            )
            if parsed.get("timed_out"):
                output.update(timed_out=True, error="remote command timed out")
        return output
    finally:
        _cleanup(ctx, prior, "/api/kernels/" + path_value(kid), output)


def _terminal_chunks(command: str) -> list[str]:
    # PTYs can silently discard long canonical input lines. Transfer short
    # octal-encoded pieces using shell builtins, preserving newlines and UTF-8.
    raw = command.encode()
    lines = []
    for offset in range(0, len(raw), 128):
        escaped = "".join(f"\\0{byte:03o}" for byte in raw[offset : offset + 128])
        lines.append(f"_rp_part=$(printf '%b_' '{escaped}'); _rp_code=\"${{_rp_code}}${{_rp_part%_}}\"\r")
    return lines


def _terminal(ctx: Any, prior: dict[str, Any], output: dict[str, Any]) -> dict[str, Any]:
    response = _create(ctx, prior, "/api/terminals", {}, output)
    model = json_value(response)
    if (
        response.status not in {200, 201}
        or not isinstance(model, dict)
        or not isinstance(model.get("name"), str)
        or not model["name"]
    ):
        output["error"] = f"terminal creation unconfirmed: HTTP {response.status}"
        return output
    name = model["name"]
    output.pop("cleanup_error", None)
    output.update(terminal=name, stderr_merged=True)
    nonce = secrets.token_hex(16)
    start, end = "\x1e" + nonce + "START\x1f", "\x1e" + nonce + "END:"
    ready, failed = "\x1e" + nonce + "READY\x1f", "\x1e" + nonce + "TRANSFER_FAILED\x1f"
    script = (
        f'if [ "${{#_rp_code}}" -eq {len(ctx.args.execute.encode())} ]; then '
        'if [ "$_rp_have_lc" = x ]; then export LC_ALL="$_rp_lc"; else unset LC_ALL; fi; '
        f"printf '\\036{nonce}START\\037'; ( eval \"$_rp_code\" ); _rp_rc=$?; "
        f"printf '\\036{nonce}END:%s\\037' \"$_rp_rc\"; "
        f"else printf '\\036{nonce}TRANSFER_FAILED\\037'; fi; exit\r"
    )
    received = ""
    try:
        with open_ws(ctx, prior, "jupyter", "/terminals/websocket/" + path_value(name)) as ws:
            ws.send_json(
                [
                    "stdin",
                    "stty -echo; _rp_have_lc=${LC_ALL+x}; _rp_lc=${LC_ALL-}; export LC_ALL=C; "
                    f"_rp_code=''; printf '\\036{nonce}READY\\037'\r",
                ]
            )
            while ready not in received:
                message = ws.recv_json()
                if isinstance(message, list) and len(message) >= 2 and message[0] == "stdout":
                    received += str(message[1])
            received = ""
            for chunk in _terminal_chunks(ctx.args.execute):
                ws.send_json(["stdin", chunk])
            ws.send_json(["stdin", script])
            while True:
                message = ws.recv_json()
                if isinstance(message, list) and len(message) >= 2 and message[0] == "stdout":
                    received += str(message[1])
                if failed in received:
                    raise ValueError("terminal command transfer incomplete; command not executed")
                if start not in received:
                    continue
                body = received.split(start, 1)[1]
                if end in body and "\x1f" in body.split(end, 1)[1]:
                    stdout, trailing = body.split(end, 1)
                    exit_text = trailing.split("\x1f", 1)[0]
                    if not exit_text.lstrip("-").isdigit():
                        raise ValueError("invalid terminal command exit")
                    output.update(
                        executed=True, exit_code=int(exit_text), stdout=stdout.replace("\r\n", "\n"), status="complete"
                    )
                    return output
    finally:
        _cleanup(ctx, prior, "/api/terminals/" + path_value(name), output)


def execute(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    prior = dict(prior)
    mode = ctx.args.execute_via
    output = result(ctx, "terminal" if mode == "terminal" else "kernel")
    try:
        if not prior.get("token_valid"):
            # Anonymous Jupyter still enforces XSRF on POST/DELETE. Keep the server
            # cookie local to this execution and acquire it before creating anything.
            response = api(ctx, prior, "jupyter", "GET", "/login")
            cookies = SimpleCookie()
            for key, value in response.headers.items():
                if key.lower() == "set-cookie":
                    cookies.load(value)
            if "_xsrf" in cookies:
                value = cookies["_xsrf"].value
                prior["_execution_headers"] = {"Cookie": "_xsrf=" + value, "X-XSRFToken": value}
        if mode != "terminal":
            output = _kernel(ctx, prior, output)
            if mode != "auto" or not output.pop("setup_denied", False):
                return output
            # Fallback only after a definitive rejection before command start.
            output = result(ctx, "terminal")
        return _terminal(ctx, prior, output)
    except Exception as exc:
        output["error"] = str(exc)
        return output
