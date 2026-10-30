"""Guest selection and real-evidence contracts for Proxmox execution."""

from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.clients.http_session import HttpResponse
from redposture_core.modules.proxmox import policy, render


def test_cli_standard_inventory_names_and_guest_selector():
    args = parse_args(
        [
            "proxmox",
            "-t",
            "127.0.0.1",
            "--show-vms",
            "--show-nodes",
            "--show-users",
            "--vm",
            "101",
            "--node",
            "pve1",
            "--execute",
            "id",
        ]
    )
    assert args.show_vms and args.nodes and args.users and args.vm == 101 and args.node == "pve1"


def test_execute_requires_explicit_guest():
    errors = []
    args = SimpleNamespace(execute="id", vm=None, node=None)
    assert policy.validate_args(args, SimpleNamespace(error=errors.append)) == 2
    assert any("--vm" in value for value in errors)


class Peer:
    def __init__(self, *, denied=False, stopped=False, wrong_marker=False, truncated=False, pid=True):
        self.calls = []
        self.command = None
        self.denied, self.stopped, self.wrong_marker, self.truncated, self.pid = (
            denied,
            stopped,
            wrong_marker,
            truncated,
            pid,
        )

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        path = urlsplit(url).path
        status = 200
        data: object
        if path.endswith("/cluster/resources"):
            data = [
                {
                    "vmid": 101,
                    "name": "billing-api",
                    "type": "qemu",
                    "node": "pve1",
                    "status": "stopped" if self.stopped else "running",
                }
            ]
        elif path.endswith("/config"):
            data = {"ostype": "l26", "agent": "1"}
        elif path.endswith("/agent/exec"):
            if self.denied:
                return HttpResponse(status=403, body=b'{"errors":"permission denied"}', headers={})
            body = parse_qs(kwargs["body"].decode())
            self.command = body["command"]
            data = {"pid": 900} if self.pid else {}
        elif path.endswith("/agent/exec-status"):
            command = self.command[-1]
            data = {
                "exited": 1,
                "exitcode": 0,
                "out-data": "wrong" if self.wrong_marker else command.removeprefix("echo ") + "\n",
                "out-truncated": self.truncated,
            }
        else:
            raise AssertionError((method, url))
        return HttpResponse(status=status, body=json.dumps({"data": data}).encode(), headers={})


def context(peer, **overrides):
    args = SimpleNamespace(
        show_vms=True,
        vm=None,
        node=None,
        execute=None,
        execute_timeout=1,
        execute_max_bytes=1048576,
        timeout=1,
        https=True,
        **overrides,
    )
    state = SimpleNamespace(
        http=peer,
        host="127.0.0.1",
        port=8006,
        scheme="https",
        resolved_auth=({"Cookie": "PVEAuthCookie=qa", "CSRFPreventionToken": "csrf"}, "password", "root@pam", "qa", []),
    )
    return SimpleNamespace(args=args, host="127.0.0.1", port=8006, lifecycle_state=state), state


def collect(peer):
    from redposture_core.modules.proxmox.execution import collect

    ctx, state = context(peer)
    return collect(ctx, {"host": ctx.host, "port": ctx.port, "is_proxmox": True}, state)


def test_show_vms_confirms_marker_and_keeps_decoded_output():
    peer = Peer()
    record = collect(peer)
    guest = record["vms"][0]
    assert guest["execute"] is True and guest["name"] == "billing-api"
    assert peer.command[:2] == ["/bin/sh", "-c"]
    posts = [item for item in peer.calls if item[0] == "POST"]
    assert len(posts) == 1 and posts[0][2]["retries"] == 0 and posts[0][2]["replay_safe"] is False
    assert posts[0][2]["headers"]["CSRFPreventionToken"] == "csrf"
    lines = render._format_vms_detail_records(record, "txt")
    assert any("billing-api (execute:True)" in line for line in lines)
    assert "\x1b" not in "\n".join(lines) + json.dumps(record)


@pytest.mark.parametrize("option", ["denied", "stopped", "wrong_marker", "truncated", "pid"])
def test_listing_never_guesses_execution_success(option):
    peer = Peer(**{option: False if option == "pid" else True})
    record = collect(peer)
    assert record["vms"][0]["execute"] is False
    assert record["vms"][0]["execute_reason"]
    if option == "stopped":
        assert not any(item[0] == "POST" for item in peer.calls)


def test_explicit_execute_selects_one_guest_and_runs_command_once():
    from redposture_core.modules.proxmox.execution import collect

    peer = Peer()
    ctx, state = context(peer)
    ctx.args.show_vms = False
    ctx.args.vm, ctx.args.execute = 101, "id && whoami"
    record = collect(ctx, {"host": ctx.host, "port": ctx.port}, state)
    assert peer.command == ["/bin/sh", "-c", "id && whoami"]
    assert record["execution"]["executed"] is True
    assert record["execution"]["stdout"] == "id && whoami\n"
    assert sum(method == "POST" for method, _, _ in peer.calls) == 1


def test_missing_selected_guest_never_sends_command():
    from redposture_core.modules.proxmox.execution import collect

    peer = Peer()
    ctx, state = context(peer)
    ctx.args.vm, ctx.args.execute = 999, "id"
    record = collect(ctx, {}, state)
    assert record["execution"]["executed"] is False
    assert not any(method == "POST" for method, _, _ in peer.calls)


@pytest.mark.parametrize(
    "ostype,argv", [("win11", ["cmd.exe", "/d", "/s", "/c"]), ("w2k22", ["cmd.exe", "/d", "/s", "/c"])]
)
def test_windows_guest_uses_cmd(ostype, argv):
    from redposture_core.modules.proxmox.execution import _qga

    peer = Peer()
    ctx, state = context(peer)
    import time

    _qga(
        ctx,
        state,
        {"node": "pve1", "type": "qemu", "vmid": 101},
        {"ostype": ostype},
        "echo marker",
        time.monotonic() + 1,
    )
    assert peer.command == argv + ["echo marker"]


def test_api_token_never_opens_lxc_console():
    from redposture_core.modules.proxmox.execution import GuestError, _terminal

    peer = Peer()
    ctx, state = context(peer)
    state.resolved_auth = ({"Authorization": "PVEAPIToken=qa"}, "pveapitoken", None, None, [])
    with pytest.raises(GuestError, match="user ticket"):
        _terminal(ctx, state, {"node": "pve1", "type": "lxc", "vmid": 101}, {"cmode": "shell"}, "id", 1)
    assert not peer.calls


def test_qga_status_failure_preserves_started_pid():
    from redposture_core.modules.proxmox.execution import run_guest

    class FailingPeer(Peer):
        def request(self, method, url, **kwargs):
            if "/agent/exec-status" in url:
                return HttpResponse(status=0, body=b"", headers={}, error="timed out")
            return super().request(method, url, **kwargs)

    peer = FailingPeer()
    ctx, state = context(peer)
    result = run_guest(ctx, state, {"node": "pve1", "type": "qemu", "vmid": 101, "status": "running"}, "id")
    assert result["pid"] == 900 and result["submitted"] is True
    assert result["executed"] is False and "may still be running" in result["error"]


@pytest.mark.parametrize(
    "cmode,expected_mode,expected_route",
    [("shell", "lxc_console", "/lxc/101/termproxy"), ("tty", "lxc_pct_exec", "/nodes/pve1/termproxy")],
)
def test_lxc_console_protocol_and_exact_leading_output(monkeypatch, cmode, expected_mode, expected_route):
    import subprocess
    import time

    from redposture_core.modules.proxmox import execution

    class ConsolePeer(Peer):
        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            assert urlsplit(url).path.endswith(expected_route)
            return HttpResponse(
                status=200, body=b'{"data":{"user":"root@pam","ticket":"ticket:full","port":5901}}', headers={}
            )

    class Terminal:
        instances = []

        def __init__(self, pool, url, **kwargs):
            self.url = url
            self.sent = []
            self.pending = [b"O", b"K"]
            self.closed = False
            self.instances.append(self)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.closed = True

        def send_bytes(self, value):
            self.sent.append(value)
            if value.startswith(b"0:"):
                _, length, script = value.split(b":", 2)
                assert len(script) == int(length)
                # Run the actual framing shell. For the node route replace only
                # pct itself; the argument vector and ID are asserted first.
                script = script.decode().rstrip("\r")
                if cmode != "shell":
                    assert "pct exec 101 -- /bin/sh -c" in script
                    script = script.replace("pct exec 101 -- ", "")
                result = subprocess.run(["/bin/sh", "-c", script], capture_output=True, timeout=2)
                # Echoed command is deliberately included before real markers.
                raw = value + result.stdout.replace(b"\n", b"\r\n")
                self.pending += [raw[i : i + 7] for i in range(0, len(raw), 7)]

        def recv_bytes(self):
            if not self.pending:
                raise ConnectionError("eof")
            return self.pending.pop(0)

    monkeypatch.setattr(execution, "WebSocket", Terminal)
    peer = ConsolePeer()
    ctx, state = context(peer)
    result = execution._terminal(
        ctx,
        state,
        {"vmid": 101, "node": "pve1", "type": "lxc"},
        {"cmode": cmode},
        "printf '\\n\\nhello\\n'",
        time.monotonic() + 2,
    )
    assert result["executed"] and result["mode"] == expected_mode and result["exit_code"] == 0
    assert result["stdout"] == "\r\n\r\nhello\r\n"
    assert Terminal.instances[-1].closed
    assert Terminal.instances[-1].sent[0] == b"root@pam:ticket:full\n"
    assert "vncticket=ticket%3Afull" in Terminal.instances[-1].url


def test_guest_agent_signal_is_visible_in_txt():
    record = {
        "host": "qa",
        "port": 8006,
        "execution": {
            "command": "id",
            "executed": True,
            "stdout": "",
            "stderr": "",
            "exit_code": None,
            "signal": 9,
            "status": "complete",
            "cleanup": "not_needed",
        },
    }
    lines = render._format_execution_detail_records(record, "txt")
    assert any("signal 9" in line for line in lines)


def test_guest_listing_without_authenticated_inventory_is_unavailable():
    lines = render._format_vms_detail_records(
        {"host": "qa", "port": 8006, "show_vms": True, "status": "auth_failed"}, "txt"
    )
    assert any("unavailable" in line for line in lines)
    assert not any("Count:0" in line for line in lines)


def test_execute_evidence_colors_and_plain_output(capsys):
    from redposture_core.modules.proxmox.actions import _render_colored_proxmox_line
    from tests.test_credential_color_contract import _assert_color, _ColorConsole

    for value, reason, color in [
        ("True", "", "1;38;5;196"),
        ("False", "HTTP 403 from agent", "1;92"),
        ("False", "timed out", "1;38;5;208"),
    ]:
        line = f"PROXMOX\tqa\t8006\t [*] VM=101 Name=billing-api (execute:{value})" + (
            f" (reason:{reason})" if reason else ""
        )
        assert _render_colored_proxmox_line(_ColorConsole(), line)
        output = capsys.readouterr().out
        _assert_color(output, "execute:" + value, color)
        assert _render_colored_proxmox_line(_ColorConsole(no_color=True), line)
        assert "\x1b" not in capsys.readouterr().out


def test_guest_cli_builds_strict_runtime_without_passing_guest_flags_to_legacy_host_stage():
    from redposture_core.modules.proxmox.stage import build_proxmox_spec
    from redposture_core.stage_runtime import AuditCommandRunner

    args = parse_args(["proxmox", "-t", "https://qa:8006", "--show-vms"])
    spec = build_proxmox_spec(args)
    AuditCommandRunner(args=args, spec=spec, emit_line=lambda line: None)
