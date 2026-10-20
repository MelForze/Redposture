"""Explicit remote execution and non-executing capability probes."""

from __future__ import annotations

import importlib
import json
from types import SimpleNamespace as NS
from urllib.parse import urlsplit

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.jupyter import actions as jupyter


class Pool:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def request(self, method, url, **kwargs):
        path = urlsplit(url).path
        body = kwargs.get("body")
        body = json.loads(body) if body else None
        self.calls.append((method, path, body, kwargs))
        response = self.handler(method, path, body)
        if isinstance(response, HttpResponse):
            return response
        code, value = response
        return HttpResponse(code, json.dumps(value).encode(), {"Content-Type": "application/json"})


def context(handler, **options):
    args = dict(
        namespace="default",
        execute="printf qa",
        execute_timeout=1,
        execute_max_bytes=1048576,
        allocation=None,
        task=None,
        execute_via="auto",
        kernel="python3",
        probe_submit=False,
    )
    args.update(options)
    return NS(args=NS(**args), credential=None, lifecycle_state=NS(http=Pool(handler)), host="127.0.0.1", port=8888)


PRIOR = {"api_endpoint": "http://127.0.0.1:8888", "status": "open_no_auth", "token_valid": False}


@pytest.mark.parametrize("module", ["nomad", "jupyter"])
def test_execute_flags_and_bounds(module):
    args = parse_args([module, "-t", "127.0.0.1", "--execute", "id", "--execute-timeout", "3"])
    assert args.execute == "id" and args.execute_timeout == 3
    policy = importlib.import_module(f"redposture_core.modules.{module}.policy")
    args.execute_timeout = 0
    assert policy.validate_args(args, NS(error=lambda _: None)) == 2


@pytest.mark.parametrize(
    "options,message",
    [
        (["--allocation", "bd0fa136-50de-4eaf-9014-a2b01f57d330"], "require --execute"),
        (["--task", "app"], "require --execute"),
        (["--execute", "id", "--task", "app"], "--task requires --allocation"),
        (["--execute", "id", "--allocation", "truncated-id"], "full UUID"),
        (["--execute", "id", "--namespace", "*"], "one explicit namespace"),
        (["--probe-submit", "--namespace", "*"], "one explicit namespace"),
    ],
)
def test_nomad_rejects_ambiguous_execution_selectors_before_network(options, message):
    from redposture_core.modules.nomad.policy import validate_args

    args = parse_args(["nomad", "-t", "127.0.0.1", *options])
    errors = []
    assert validate_args(args, NS(error=errors.append)) == 2
    assert len(errors) == 1 and message in errors[0]


@pytest.mark.parametrize(
    "options",
    [
        ["--execute", "id", "--allocation", "bd0fa136-50de-4eaf-9014-a2b01f57d330", "--task", "app"],
        ["--show-jobs", "--namespace", "*"],
    ],
)
def test_nomad_accepts_explicit_allocation_and_read_only_wildcard(options):
    from redposture_core.modules.nomad.policy import validate_args

    args = parse_args(["nomad", "-t", "127.0.0.1", *options])
    assert validate_args(args, NS(error=pytest.fail)) is None


def test_jupyter_terminal_only_surface_is_detected_without_creation():
    routes = {
        "/api": (200, {"version": "2.17.0"}),
        "/api/status": (200, {"connections": 0, "kernels": 0, "started": "now", "last_activity": "now"}),
        "/api/kernels": (403, {}),
        "/api/terminals": (200, []),
    }
    ctx = context(lambda m, p, b: routes.get(p, (404, {})), execute=None)
    record = jupyter.detect_record(ctx)
    assert record["anonymous_terminals_access"] is True
    assert record["rce_potential"] is True
    assert record["execute_verified"] is False
    assert all(method == "GET" for method, *_ in ctx.lifecycle_state.http.calls)


def test_jupyter_show_terminals_uses_verified_token():
    args = parse_args(["jupyter", "-t", "127.0.0.1", "--show-terminals"])
    assert args.show_terminals
    ctx = context(lambda m, p, b: (200, [{"name": "1"}]), execute=None, show_terminals=True)
    ctx.credential = NS(token="qa")
    result = jupyter.data_record(ctx, {**PRIOR, "token_valid": True})
    assert result["terminals"] == [{"name": "1"}]
    assert ctx.lifecycle_state.http.calls[0][3]["headers"]["Authorization"] == "token qa"


def test_nomad_probe_stopped_job_is_cleaned_and_never_executes():
    parse_args(["nomad", "-t", "127.0.0.1", "--probe-submit"])

    def handler(method, path, body):
        if method == "POST":
            assert body["Job"]["Stop"] is True
            return 200, {"JobModifyIndex": 5, "EvalID": "evaluation"}
        return 200, {}

    ctx = context(handler, execute=None, probe_submit=True)
    module = importlib.import_module("redposture_core.modules.nomad.execution")
    result = module.probe_submit(ctx, PRIOR)
    assert result["access"] == "allowed" and result["cleanup"] == "complete"
    assert [row[0] for row in ctx.lifecycle_state.http.calls] == ["POST", "DELETE"]


def test_nomad_rejected_probe_is_denied_not_executed():
    ctx = context(lambda m, p, b: (403, {"error": "Permission denied"}), execute=None)
    module = importlib.import_module("redposture_core.modules.nomad.execution")
    result = module.probe_submit(ctx, PRIOR)
    assert result["access"] == "denied"
    assert len(ctx.lifecycle_state.http.calls) == 1


def test_nomad_ambiguous_register_does_not_replay_and_attempts_cleanup():
    ctx = context(lambda m, p, b: (0, {}) if m == "POST" else (200, {}))
    module = importlib.import_module("redposture_core.modules.nomad.execution")
    result = module.execute(ctx, PRIOR)
    assert result["executed"] is False
    assert sum(c[0] == "POST" for c in ctx.lifecycle_state.http.calls) == 1
    assert any(c[0] == "DELETE" for c in ctx.lifecycle_state.http.calls)
    assert all(c[3].get("retries") == 0 for c in ctx.lifecycle_state.http.calls)


class WS:
    def __init__(self, messages):
        self.messages = iter(messages)
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def send_json(self, message):
        self.sent.append(message)

    def recv_json(self):
        return next(self.messages)


def test_nomad_allocation_exec_uses_exit_frame_and_preserves_nonzero_exit(monkeypatch):
    module = importlib.import_module("redposture_core.modules.nomad.execution")
    ws = WS([{"stdout": {"data": "cWEK"}}, {"exited": True, "result": {"exit_code": 7}}])
    monkeypatch.setattr(module, "open_ws", lambda *a, **k: ws)
    ctx = context(lambda m, p, b: (200, {"TaskStates": {"app": {"State": "running"}}}), allocation="allocation")
    result = module.execute(ctx, PRIOR)
    assert result["executed"] is True and result["exit_code"] == 7 and result["stdout"] == "qa\n"
    assert not any(c[0] in {"POST", "DELETE"} for c in ctx.lifecycle_state.http.calls)


def test_nomad_multiple_tasks_require_explicit_selection(monkeypatch):
    module = importlib.import_module("redposture_core.modules.nomad.execution")
    ctx = context(
        lambda m, p, b: (200, {"TaskStates": {"a": {"State": "running"}, "b": {"State": "running"}}}),
        allocation="allocation",
    )
    result = module.execute(ctx, PRIOR)
    assert result["executed"] is False and "--task" in result["error"]


def test_jupyter_kernel_setup_failure_cleans_only_created_kernel(monkeypatch):
    module = importlib.import_module("redposture_core.modules.jupyter.execution")
    ctx = context(lambda m, p, b: (201, {"id": "owned"}) if m == "POST" else (204, {}), execute_via="kernel")

    def fail(*a, **k):
        raise ConnectionError("handshake failed")

    monkeypatch.setattr(module, "open_ws", fail)
    result = module.execute(ctx, PRIOR)
    assert result["executed"] is False and result["cleanup"] == "complete"
    assert [(m, p) for m, p, *_ in ctx.lifecycle_state.http.calls if m != "GET"] == [
        ("POST", "/api/kernels"),
        ("DELETE", "/api/kernels/owned"),
    ]


def test_no_default_execution_requests():
    ctx = context(lambda m, p, b: (404, {}), execute=None)
    result = jupyter.data_record(ctx, PRIOR)
    assert "execution" not in result
    assert not ctx.lifecycle_state.http.calls


@pytest.mark.parametrize("status", [200, 201])
def test_terminal_creation_variants_return_exit_and_are_cleaned(monkeypatch, status):
    module = importlib.import_module("redposture_core.modules.jupyter.execution")
    monkeypatch.setattr(module.secrets, "token_hex", lambda _: "nonce")
    ws = WS([["stdout", "\x1enonceREADY\x1f"], ["stdout", "prompt\x1enonceSTART\x1fqa\r\n\x1enonceEND:3\x1f"]])
    monkeypatch.setattr(module, "open_ws", lambda *a, **k: ws)
    ctx = context(lambda m, p, b: (status, {"name": "owned"}) if m == "POST" else (204, {}), execute_via="terminal")
    output = module.execute(ctx, PRIOR)
    assert output["executed"] is True and output["exit_code"] == 3
    assert output["stdout"] == "qa\n" and output["cleanup"] == "complete"


def test_anonymous_jupyter_execution_uses_server_xsrf_cookie(monkeypatch):
    module = importlib.import_module("redposture_core.modules.jupyter.execution")

    def handler(method, path, body):
        if method == "GET":
            return HttpResponse(404, b"", {"Set-Cookie": "_xsrf=qa-xsrf; Path=/"})
        if method == "POST":
            return 201, {"id": "owned"}
        return 204, {}

    monkeypatch.setattr(module, "open_ws", lambda *a, **k: (_ for _ in ()).throw(ConnectionError("setup")))
    ctx = context(handler)
    module.execute(ctx, PRIOR)
    post = next(c for c in ctx.lifecycle_state.http.calls if c[0] == "POST")
    assert post[3]["headers"]["X-XSRFToken"] == "qa-xsrf"
    assert post[3]["headers"]["Cookie"] == "_xsrf=qa-xsrf"


@pytest.mark.parametrize("cleanup_status", [200, 500])
def test_nomad_batch_returns_output_and_cleans_unique_job(cleanup_status):
    module = importlib.import_module("redposture_core.modules.nomad.execution")
    job = {}

    def handler(method, path, body):
        if method == "POST":
            job.update(body["Job"])
            assert job["Stop"] is False
            assert job["TaskGroups"][0]["RestartPolicy"]["Attempts"] == 0
            return 200, {"EvalID": "eval"}
        if method == "DELETE":
            assert path.endswith(job["ID"])
            return cleanup_status, {}
        if path.endswith("/allocations"):
            return 200, [{"ID": "owned", "JobID": job["ID"], "ClientStatus": "complete"}]
        if path == "/v1/allocation/owned":
            return 200, {"TaskStates": {"command": {"Events": [{"Type": "Terminated", "ExitCode": 0}]}}}
        return HttpResponse(200, b"qa-output\n", {})

    ctx = context(handler)
    output = module.execute(ctx, PRIOR)
    assert output["executed"] is True and output["exit_code"] == 0
    assert output["stdout"] == "qa-output\n" and output["stderr"] == "qa-output\n"
    assert output["cleanup"] == ("complete" if cleanup_status == 200 else "failed")
    assert sum(c[0] == "POST" for c in ctx.lifecycle_state.http.calls) == 1


def test_nomad_pending_job_timeout_is_not_success_and_cleans_up():
    module = importlib.import_module("redposture_core.modules.nomad.execution")
    ctx = context(lambda m, p, b: (200, {"EvalID": "eval"}) if m == "POST" else (200, []), execute_timeout=0.01)
    output = module.execute(ctx, PRIOR)
    assert output["executed"] is False and "deadline" in output["error"]
    assert output["cleanup"] == "complete"


def test_nomad_foreign_allocation_is_never_used():
    module = importlib.import_module("redposture_core.modules.nomad.execution")
    ctx = context(
        lambda m, p, b: (200, {"EvalID": "eval"}) if m == "POST" else (200, [{"ID": "foreign", "JobID": "other"}]),
        execute_timeout=0.01,
    )
    output = module.execute(ctx, PRIOR)
    assert output["executed"] is False
    assert not any("/allocation/foreign" in c[1] for c in ctx.lifecycle_state.http.calls)


def test_nomad_eof_without_exit_is_unverified_and_preserves_output(monkeypatch):
    module = importlib.import_module("redposture_core.modules.nomad.execution")
    monkeypatch.setattr(module, "open_ws", lambda *a, **k: WS([{"stdout": {"data": "cWE="}}]))
    ctx = context(lambda m, p, b: (200, {"TaskStates": {"app": {"State": "running"}}}), allocation="allocation")
    output = module.execute(ctx, PRIOR)
    assert not output["executed"] and output["exit_code"] is None and output["stdout"] == "qa"


def test_jupyter_auto_falls_back_only_before_execution(monkeypatch):
    module = importlib.import_module("redposture_core.modules.jupyter.execution")
    monkeypatch.setattr(module.secrets, "token_hex", lambda _: "nonce")
    monkeypatch.setattr(
        module,
        "open_ws",
        lambda *a, **k: WS([["stdout", "\x1enonceREADY\x1f"], ["stdout", "\x1enonceSTART\x1fok\x1enonceEND:0\x1f"]]),
    )
    ctx = context(
        lambda m, p, b: (403, {}) if p == "/api/kernels" else (200, {"name": "owned"}) if m == "POST" else (204, {})
    )
    output = module.execute(ctx, PRIOR)
    assert output["mode"] == "terminal" and output["executed"] and output["cleanup"] == "complete"


def test_failed_kernel_stream_is_never_replayed_through_terminal(monkeypatch):
    module = importlib.import_module("redposture_core.modules.jupyter.execution")
    monkeypatch.setattr(module, "open_ws", lambda *a, **k: WS([]))
    ctx = context(lambda m, p, b: (201, {"id": "owned"}) if m == "POST" else (204, {}))
    output = module.execute(ctx, PRIOR)
    assert not output["executed"] and output["cleanup"] == "complete"
    assert not any(c[1] == "/api/terminals" for c in ctx.lifecycle_state.http.calls)


def test_nomad_reports_placement_failure_instead_of_waiting_for_timeout():
    module = importlib.import_module("redposture_core.modules.nomad.execution")

    def handler(method, path, body):
        if method == "POST":
            return 200, {"EvalID": "eval"}
        if path == "/v1/evaluation/eval":
            return 200, {"FailedTGAllocs": {"command": {"DimensionExhausted": {"cpu": 1}}}}
        return 200, []

    output = module.execute(context(handler), PRIOR)
    assert output["executed"] is False and "cpu" in output["error"]
    assert output["cleanup"] == "complete"


def test_kernel_messages_require_parent_id_result_and_terminal_status(monkeypatch):
    module = importlib.import_module("redposture_core.modules.jupyter.execution")
    monkeypatch.setattr(module.secrets, "token_hex", lambda _: "nonce")
    messages = [
        {"parent_header": {"msg_id": "other"}, "msg_type": "stream", "content": {"text": "wrong"}},
        {
            "parent_header": {"msg_id": "nonce"},
            "msg_type": "stream",
            "content": {"text": 'REDPOSTURE_RESULT_nonce{"exit_code":7,"stdout":"qa","stderr":"err"}'},
        },
        {"parent_header": {"msg_id": "nonce"}, "msg_type": "execute_reply", "content": {"status": "ok"}},
        {"parent_header": {"msg_id": "nonce"}, "msg_type": "status", "content": {"execution_state": "idle"}},
    ]
    monkeypatch.setattr(module, "open_ws", lambda *a, **k: WS(messages))
    ctx = context(lambda m, p, b: (201, {"id": "owned"}) if m == "POST" else (204, {}))
    output = module.execute(ctx, PRIOR)
    assert output["executed"] and output["exit_code"] == 7
    assert output["stdout"] == "qa" and output["stderr"] == "err" and output["cleanup"] == "complete"


@pytest.mark.parametrize("content", [{"status": "error", "ename": "RuntimeError"}, {"status": "ok"}])
def test_kernel_reply_without_command_result_is_not_verified(monkeypatch, content):
    module = importlib.import_module("redposture_core.modules.jupyter.execution")
    monkeypatch.setattr(module.secrets, "token_hex", lambda _: "nonce")
    messages = [
        {"parent_header": {"msg_id": "nonce"}, "msg_type": "execute_reply", "content": content},
        {"parent_header": {"msg_id": "nonce"}, "msg_type": "status", "content": {"execution_state": "idle"}},
    ]
    monkeypatch.setattr(module, "open_ws", lambda *a, **k: WS(messages))
    ctx = context(lambda m, p, b: (201, {"id": "owned"}) if m == "POST" else (204, {}))
    output = module.execute(ctx, PRIOR)
    assert not output["executed"] and output["cleanup"] == "complete"


@pytest.mark.parametrize(
    "name,value",
    [
        ("execute_timeout", float("nan")),
        ("execute_timeout", float("inf")),
        ("execute_timeout", 3601),
        ("execute_max_bytes", 0),
        ("execute_max_bytes", 67108865),
        ("execute", ""),
        ("execute", "a\x00b"),
        ("execute", "\ud800"),
    ],
)
def test_execution_invalid_options_fail_before_network(name, value):
    from redposture_core.modules.execution_api import validate

    args = context(lambda *_: pytest.fail("must not connect")).args
    setattr(args, name, value)
    assert validate(args, NS(error=lambda _: None)) == 2


@pytest.mark.parametrize("module", ["nomad", "jupyter"])
def test_execute_output_palette_and_no_ansi_storage(module, capsys, tmp_path, monkeypatch):
    from redposture_core.console import Console
    from redposture_core.modules.execution_api import finish
    from redposture_core.modules.token_render import colorize, inventory
    from redposture_core.stage_runtime import LineOutputSink

    output = finish(
        {
            "mode": "kernel",
            "executed": True,
            "exit_code": 0,
            "stdout": "\x1b[31mqa\x1b[0m\n",
            "stderr": "",
            "status": "complete",
            "cleanup": "complete",
        }
    )
    assert output["stdout"] == "qa\n"
    record = {"host": "127.0.0.1", "port": 8888, "execution": output}
    lines = inventory(module, record, "txt")
    console = Console()
    monkeypatch.setattr(console, "_use_color", lambda stream: True)
    for line in lines:
        colorize(console, line, module)
    text = capsys.readouterr().out
    assert "\x1b[1;38;5;196mexecuted:True\x1b[0m" in text
    assert "\x1b[1;38;5;208m stdout: qa\x1b[0m" in text
    plain = Console(no_color=True)
    path = tmp_path / "result.txt"
    sink = LineOutputSink(str(path), lambda line: colorize(plain, line, module))
    try:
        sink.emit_many(lines)
    finally:
        sink.close()
    assert "\x1b" not in capsys.readouterr().out + path.read_text() + json.dumps(record)


def test_nomad_keeps_job_alive_until_command_result_is_read():
    module = importlib.import_module("redposture_core.modules.nomad.execution")
    state = {}

    def handler(method, path, body):
        if method == "POST":
            state.update(body["Job"])
            return 200, {"EvalID": "eval"}
        if path.endswith("/allocations"):
            return 200, [{"ID": "owned", "JobID": state["ID"], "ClientStatus": "running"}]
        if path == "/v1/allocation/owned":
            return 200, {"TaskStates": {"command": {"State": "running", "Events": []}}}
        if path.startswith("/v1/client/fs/logs"):
            return HttpResponse(200, ("qa\x1eREDPOSTURE_EXIT_" + state["ID"] + ":7\x1f").encode(), {})
        return 200, {}

    output = module.execute(context(handler), PRIOR)
    assert output["executed"] and output["exit_code"] == 7 and output["stdout"] == "qa"
    assert output["cleanup"] == "complete"


def test_execution_output_limit_is_shared_between_streams():
    from redposture_core.modules.execution_api import finish

    output = finish({"stdout": "abcdef", "stderr": "ghijkl", "status": "complete"}, max_bytes=8)
    assert len((output["stdout"] + output["stderr"]).encode()) <= 8
    assert output["status"] == "partial" and output["truncated"] is True


def test_jupyter_xsrf_preflight_failure_is_reported():
    module = importlib.import_module("redposture_core.modules.jupyter.execution")

    def fail(*args):
        raise TimeoutError("preflight timeout")

    output = module.execute(context(fail), PRIOR)
    assert output["error"] == "preflight timeout" and output["cleanup"] == "not_needed"


def test_small_output_limit_still_allows_resource_id_and_cleanup():
    from redposture_core.modules.execution_api import api

    ctx = context(lambda *_: (201, {"id": "owned-resource"}), execute_max_bytes=1)
    api(ctx, PRIOR, "jupyter", "POST", "/api/kernels", {"name": "python3"})
    assert ctx.lifecycle_state.http.calls[0][3]["response_size_cap"] >= 65536


def test_kernel_deadline_survives_closed_stdout_and_stderr(monkeypatch, capsys):
    import os
    import signal

    module = importlib.import_module("redposture_core.modules.jupyter.execution")
    ws = WS([])
    monkeypatch.setattr(module, "open_ws", lambda *a, **k: ws)
    ctx = context(
        lambda m, p, b: (201, {"id": "owned"}) if m == "POST" else (204, {}),
        execute="exec 1>&- 2>&-; sleep 30",
        execute_timeout=0.1,
    )
    module.execute(ctx, {**PRIOR, "token_valid": True})
    scope = {}
    try:
        exec(ws.sent[0]["content"]["code"], scope)
        assert scope["_rp_p"].poll() is not None
        assert '"timed_out": true' in capsys.readouterr().out
    finally:
        process = scope.get("_rp_p")
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)


@pytest.mark.parametrize("count,color", [(0, "\x1b[1;92m"), (2, "\x1b[1;38;5;196m")])
def test_terminal_counts_follow_airflow_palette(count, color, capsys, monkeypatch):
    from redposture_core.console import Console
    from redposture_core.modules.token_render import colorize

    console = Console()
    monkeypatch.setattr(console, "_use_color", lambda stream: True)
    assert colorize(console, f"JUPYTER\t127.0.0.1\t8888\t [*] Terminals Enumeration (terminals:{count})", "jupyter")
    assert color + f"terminals:{count}" in capsys.readouterr().out


@pytest.mark.parametrize("text", ["\x1b7qa\x1b8", "\x1b(Bqa", "\x1bPhidden\x1b\\qa", "qa\x1b"])
def test_execution_strips_all_ansi_forms(text):
    from redposture_core.modules.execution_api import finish

    assert finish({"stdout": text})["stdout"] == "qa"


def test_terminal_transfer_preserves_long_unicode_and_multiline_command():
    import subprocess

    from redposture_core.modules.jupyter.execution import _terminal_chunks

    command = "true; " * 900 + "printf 'Привет\\n';\nprintf 'quoted\\r'\n"
    chunks = _terminal_chunks(command)
    assert all(len(line.encode()) < 1000 for line in chunks)
    script = "_rp_code='';\n" + "".join(chunks).replace("\r", "\n") + 'printf "%s" "$_rp_code"'
    run = subprocess.run(["/bin/sh", "-c", script], capture_output=True, timeout=5)
    assert run.returncode == 0 and run.stdout == command.encode()


def test_terminal_transfer_failure_is_not_execution(monkeypatch):
    module = importlib.import_module("redposture_core.modules.jupyter.execution")
    monkeypatch.setattr(module.secrets, "token_hex", lambda _: "nonce")
    ws = WS([["stdout", "\x1enonceREADY\x1f"], ["stdout", "\x1enonceTRANSFER_FAILED\x1f"]])
    monkeypatch.setattr(module, "open_ws", lambda *a, **k: ws)
    ctx = context(lambda m, p, b: (200, {"name": "owned"}) if m == "POST" else (204, {}), execute_via="terminal")
    output = module.execute(ctx, PRIOR)
    assert not output["executed"] and "transfer incomplete" in output["error"]
    assert output["cleanup"] == "complete"


@pytest.mark.parametrize("mode", ["kernel", "terminal"])
def test_ambiguous_resource_creation_reports_unresolved_cleanup(mode):
    module = importlib.import_module("redposture_core.modules.jupyter.execution")
    ctx = context(lambda m, p, b: (500, {}), execute_via=mode)
    output = module.execute(ctx, {**PRIOR, "token_valid": True})
    assert not output["executed"] and output["cleanup"] == "failed"
    assert "resource ID unknown" in output["cleanup_error"]
    assert sum(call[0] == "POST" for call in ctx.lifecycle_state.http.calls) == 1


def test_kernel_finalizer_kills_group_after_shell_has_exited(monkeypatch):
    import os

    module = importlib.import_module("redposture_core.modules.jupyter.execution")
    ws = WS([])
    monkeypatch.setattr(module, "open_ws", lambda *a, **k: ws)
    ctx = context(lambda m, p, b: (201, {"id": "owned"}) if m == "POST" else (204, {}), execute="true")
    module.execute(ctx, {**PRIOR, "token_valid": True})
    calls = []
    original = os.killpg

    def killpg(pid, signal):
        calls.append(pid)
        return original(pid, signal)

    monkeypatch.setattr(os, "killpg", killpg)
    scope = {}
    exec(ws.sent[0]["content"]["code"], scope)
    assert scope["_rp_p"].returncode == 0 and calls == [scope["_rp_p"].pid]
