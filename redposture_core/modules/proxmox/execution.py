"""Explicit guest execution through QGA or a ticket-authenticated PVE terminal."""

from __future__ import annotations

import json
import re
import shlex
import time
import uuid
from typing import Any
from urllib.parse import urlencode

from ...clients.http_api import build_http_target_url
from ...clients.websocket import WebSocket
from ..execution_api import finish


class GuestError(RuntimeError):
    pid: int | None = None
    submitted: bool = False


def _api(
    ctx: Any, state: Any, path: str, *, method: str = "GET", form: dict[str, Any] | None = None, deadline: float
) -> Any:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("guest execution deadline reached")
    auth = state.resolved_auth[0]
    headers = {"Accept": "application/json", **auth}
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    url = build_http_target_url(
        state.host or ctx.host,
        state.port or ctx.port,
        "/api2/json" + path,
        default_scheme=state.scheme or "https",
        override_bound_scheme=True,
    )
    response = state.http.request(
        method,
        url,
        headers=headers,
        body=urlencode(form, doseq=True).encode() if form is not None else None,
        timeout=min(remaining, float(getattr(ctx.args, "timeout", 5))),
        retries=0,
        replay_safe=method == "GET",
        allow_cross_origin_redirects=False,
        response_size_cap=max(1048576, ctx.args.execute_max_bytes * 6 + 65536),
    )
    if response.error:
        raise GuestError(response.error)
    if response.status != 200:
        raise GuestError(f"HTTP {response.status} from {path}: {response.body.decode('utf-8', errors='replace')}")
    if getattr(response, "truncated", False):
        raise GuestError(f"incomplete response from {path}")
    try:
        value = json.loads(response.body)
    except (ValueError, UnicodeError) as exc:
        raise GuestError(f"invalid JSON from {path}") from exc
    if not isinstance(value, dict) or "data" not in value:
        raise GuestError(f"missing API data from {path}")
    return value["data"]


def _path(guest: dict[str, Any]) -> str:
    node = str(guest.get("node") or "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", node):
        raise GuestError("missing or invalid guest node")
    vmid = str(guest.get("vmid") or "")
    if not vmid.isdecimal() or not 100 <= int(vmid) <= 999999999:
        raise GuestError("invalid guest ID")
    kind = guest.get("type")
    if kind not in {"qemu", "lxc"}:
        raise GuestError("unsupported guest type")
    return f"/nodes/{node}/{kind}/{vmid}"


def _qga(
    ctx: Any, state: Any, guest: dict[str, Any], config: dict[str, Any], command: str, deadline: float
) -> dict[str, Any]:
    path = _path(guest)
    ostype = str(config.get("ostype") or "").lower()
    if ostype.startswith(("win", "w2k", "wvista", "wxp")):
        argv = ["cmd.exe", "/d", "/s", "/c", command]
    elif ostype in {"l26", "l24", "linux", "solaris", "other-unix", "freebsd", "openbsd", "netbsd"}:
        argv = ["/bin/sh", "-c", command]
    else:
        info = _api(ctx, state, path + "/agent/get-osinfo", deadline=deadline)
        identity = info.get("result", {}) if isinstance(info, dict) else {}
        kernel = str(identity.get("kernel-name") or "").lower()
        if kernel.startswith("windows"):
            argv = ["cmd.exe", "/d", "/s", "/c", command]
        elif kernel in {"linux", "freebsd", "openbsd", "netbsd", "sunos"}:
            argv = ["/bin/sh", "-c", command]
        else:
            raise GuestError("guest operating system could not be established")
    submitted = _api(ctx, state, path + "/agent/exec", method="POST", form={"command": argv}, deadline=deadline)
    pid = submitted.get("pid") if isinstance(submitted, dict) else None
    if type(pid) is not int or pid <= 0:
        raise GuestError("guest agent did not return a process ID; command may have started")
    while True:
        try:
            result = _api(ctx, state, path + "/agent/exec-status?" + urlencode({"pid": pid}), deadline=deadline)
        except (OSError, ValueError, RuntimeError) as exc:
            error = GuestError(f"{exc} (pid:{pid}); command may still be running")
            error.pid = pid
            error.submitted = True
            raise error from exc
        if not isinstance(result, dict) or result.get("exited") not in (True, False, 0, 1):
            raise GuestError(f"invalid guest process status (pid:{pid})")
        if result["exited"]:
            code = result.get("exitcode")
            output = {
                "command": command,
                "mode": "qemu_guest_agent",
                "executed": True,
                "pid": pid,
                "exit_code": code if type(code) is int else None,
                "signal": result.get("signal"),
                "stdout": str(result.get("out-data") or ""),
                "stderr": str(result.get("err-data") or ""),
                "status": "partial" if result.get("out-truncated") or result.get("err-truncated") else "complete",
                "cleanup": "not_needed",
                "error": None,
            }
            if output["status"] == "partial":
                output["truncated"] = True
            if type(code) is not int and not result.get("signal"):
                output.update(status="partial", error="guest agent did not provide an exit status")
            return finish(output, max_bytes=ctx.args.execute_max_bytes)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"guest process did not finish before deadline (pid:{pid}); it may still be running")
        time.sleep(min(0.1, remaining))


def _terminal(
    ctx: Any, state: Any, guest: dict[str, Any], config: dict[str, Any], command: str, deadline: float
) -> dict[str, Any]:
    auth, method, user, *_ = state.resolved_auth
    if method != "password" or not any(key.lower() == "cookie" for key in auth):
        raise GuestError("LXC console requires a user ticket; API tokens cannot open consoles")
    path = _path(guest)
    if config.get("cmode", "tty") == "shell":
        terminal = path
        shell_command = command
        mode = "lxc_console"
    else:
        if user != "root@pam":
            raise GuestError("node console requires a root@pam shell; guest console is not cmode=shell")
        terminal = "/nodes/" + str(guest["node"])
        shell_command = "pct exec " + str(int(guest["vmid"])) + " -- /bin/sh -c " + shlex.quote(command)
        mode = "lxc_pct_exec"
    proxy = _api(ctx, state, terminal + "/termproxy", method="POST", form={}, deadline=deadline)
    if (
        not isinstance(proxy, dict)
        or not isinstance(proxy.get("port"), int)
        or not proxy.get("ticket")
        or not proxy.get("user")
    ):
        raise GuestError("invalid terminal proxy response")
    if any("\n" in str(proxy[key]) or "\r" in str(proxy[key]) for key in ("user", "ticket")):
        raise GuestError("invalid terminal authentication fields")
    url = build_http_target_url(
        state.host or ctx.host,
        state.port or ctx.port,
        "/api2/json" + terminal + "/vncwebsocket?" + urlencode({"port": proxy["port"], "vncticket": proxy["ticket"]}),
        default_scheme=state.scheme or "https",
        override_bound_scheme=True,
    )
    nonce = uuid.uuid4().hex
    begin, end = ("\x1e" + nonce + ":B\x1f").encode(), ("\x1e" + nonce + ":E:").encode()
    # Literal backslash escapes in the echoed input cannot match actual RS/US output.
    wrapped = (
        "printf '\\036"
        + nonce
        + ":B\\037\\n'; /bin/sh -c "
        + shlex.quote(shell_command)
        + "; rp_rc=$?; printf '\\036"
        + nonce
        + ':E:%s\\037\\n\' "$rp_rc"; exit\r'
    )
    raw = bytearray()
    with WebSocket(
        state.http,
        url,
        headers=auth,
        timeout=max(0.001, deadline - time.monotonic()),
        max_bytes=ctx.args.execute_max_bytes + 131072,
    ) as ws:
        ws.send_bytes((str(proxy["user"]) + ":" + str(proxy["ticket"]) + "\n").encode())
        while len(raw) < 2:
            raw.extend(ws.recv_bytes())
        if raw[:2] != b"OK":
            raise GuestError("terminal authentication was not acknowledged")
        del raw[:2]
        packet = wrapped.encode()
        ws.send_bytes(b"0:" + str(len(packet)).encode() + b":" + packet)
        while True:
            start = raw.find(begin)
            stop = raw.find(end, start + len(begin)) if start >= 0 else -1
            if stop >= 0:
                closing = raw.find(b"\x1f", stop + len(end))
                if closing >= 0:
                    code = raw[stop + len(end) : closing]
                    if not code.isdigit():
                        raise GuestError("invalid terminal exit status")
                    stdout_raw = bytes(raw[start + len(begin) : stop])
                    stdout_raw = (
                        stdout_raw[2:]
                        if stdout_raw.startswith(b"\r\n")
                        else stdout_raw[1:]
                        if stdout_raw.startswith(b"\n")
                        else stdout_raw
                    )
                    stdout = stdout_raw.decode("utf-8", errors="replace")
                    return finish(
                        {
                            "command": command,
                            "mode": mode,
                            "executed": True,
                            "exit_code": int(code),
                            "stdout": stdout,
                            "stderr": "",
                            "status": "complete",
                            "cleanup": "closed",
                            "error": None,
                        },
                        max_bytes=ctx.args.execute_max_bytes,
                    )
            raw.extend(ws.recv_bytes())
            if len(raw) > ctx.args.execute_max_bytes + 131072:
                raise GuestError("terminal output limit reached before completion")


def run_guest(ctx: Any, state: Any, guest: dict[str, Any], command: str) -> dict[str, Any]:
    result = {
        "command": command,
        "executed": False,
        "stdout": "",
        "stderr": "",
        "exit_code": None,
        "mode": str(guest.get("type")),
        "status": "unverified",
        "cleanup": "not_needed",
        "error": None,
    }
    try:
        if guest.get("status") != "running":
            raise GuestError("guest is not running; it was not started")
        path = _path(guest)
        deadline = time.monotonic() + ctx.args.execute_timeout
        config = _api(ctx, state, path + "/config", deadline=deadline)
        if not isinstance(config, dict):
            raise GuestError("invalid guest configuration response")
        return (
            _qga(ctx, state, guest, config, command, deadline)
            if guest["type"] == "qemu"
            else _terminal(ctx, state, guest, config, command, deadline)
        )
    except (OSError, ValueError, RuntimeError) as exc:
        result["error"] = str(exc)
        pid = getattr(exc, "pid", None)
        if pid is not None:
            result["pid"] = pid
            result["submitted"] = True
        return finish(result, max_bytes=ctx.args.execute_max_bytes)


def collect(ctx: Any, prior: dict[str, Any], state: Any) -> dict[str, Any]:
    show = bool(getattr(ctx.args, "show_vms", False))
    command = getattr(ctx.args, "execute", None)
    if not show and command is None:
        return prior
    result = {**prior, "show_vms": show, "vms": [], "vms_error": None}
    try:
        deadline = time.monotonic() + ctx.args.execute_timeout
        resources = _api(ctx, state, "/cluster/resources?type=vm", deadline=deadline)
        if not isinstance(resources, list):
            raise GuestError("invalid guest inventory response")
        selected = []
        for item in resources:
            if not isinstance(item, dict) or item.get("type") not in {"qemu", "lxc"}:
                continue
            if getattr(ctx.args, "node", None) and item.get("node") != ctx.args.node:
                continue
            if getattr(ctx.args, "vm", None) is not None and str(item.get("vmid")) != str(ctx.args.vm):
                continue
            _path(item)
            selected.append(dict(item))
        if command is not None and len(selected) != 1:
            raise GuestError("selected guest was not found uniquely in accessible inventory")
        if show:
            for guest in selected:
                marker = "redposture_" + uuid.uuid4().hex
                probe = run_guest(ctx, state, guest, "echo " + marker)
                guest["execute"] = (
                    probe["executed"] is True
                    and probe["exit_code"] == 0
                    and probe["status"] == "complete"
                    and probe["stdout"].strip() == marker
                )
                guest["execute_reason"] = (
                    None
                    if guest["execute"]
                    else probe.get("error") or "control marker or complete successful exit was not confirmed"
                )
                guest["execute_probe"] = probe
        result["vms"] = selected
        if command is not None:
            result["execution"] = run_guest(ctx, state, selected[0], command)
    except (OSError, ValueError, RuntimeError) as exc:
        result["vms_error"] = str(exc)
        if command is not None:
            result["execution"] = {
                "command": command,
                "executed": False,
                "stdout": "",
                "stderr": "",
                "exit_code": None,
                "status": "unverified",
                "cleanup": "not_needed",
                "error": str(exc),
            }
    return result
