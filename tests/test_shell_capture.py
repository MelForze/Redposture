from __future__ import annotations

import argparse
import base64
import re
import subprocess
import sys
from types import SimpleNamespace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redposture_core.clients.docker_engine import DockerEngineClient, DockerHTTPResponse, decode_docker_stream_bytes
from redposture_core.modules.clickhouse import actions as ch_actions
from redposture_core.modules.clickhouse import stage as ch_stage
from redposture_core.modules.docker import actions as docker_actions
from redposture_core.modules.kubeapi import actions as kube_actions
from redposture_core.modules.oracle import actions as oracle_actions
from redposture_core.modules.postgres import actions as pg_actions
from redposture_core.modules.postgres import stage as pg_stage
from redposture_core.shell_capture import (
    CommandResult,
    ShellView,
    build_capture_command,
    format_result,
    hex_preview,
    parse_capture_lines,
    result_text_lines,
    save_result_stream,
)


def _encoded_lines(token: str, stdout: bytes, stderr: bytes, *, code: int = 0) -> list[str]:
    return [
        f"RP:{token}:STATUS:{code}",
        f"RP:{token}:STDOUT:{len(stdout)}",
        base64.b64encode(stdout).decode("ascii"),
        f"RP:{token}:ENDSTDOUT",
        f"RP:{token}:STDERR:{len(stderr)}",
        base64.b64encode(stderr).decode("ascii"),
        f"RP:{token}:ENDSTDERR",
        f"RP:{token}:END",
    ]


@pytest.mark.parametrize("payload", [b"", b"plain\ntext\n", b"\x00\xff\x1b[31m", bytes(range(256))])
def test_capture_protocol_round_trips_stdout_and_stderr(payload: bytes) -> None:
    result = parse_capture_lines(_encoded_lines("abc123", payload, payload[::-1]), "abc123", max_bytes=1024)
    assert result.stdout == payload
    assert result.stderr == payload[::-1]
    assert result.exit_code == 0
    assert not result.truncated


def test_capture_protocol_rejects_corruption_and_incomplete_results() -> None:
    lines = _encoded_lines("abc123", b"abc", b"")
    with pytest.raises(ValueError, match="incomplete"):
        parse_capture_lines(lines[:-1], "abc123", max_bytes=1024)
    lines[2] = "not-base64!"
    with pytest.raises(ValueError, match="base64"):
        parse_capture_lines(lines, "abc123", max_bytes=1024)


def test_capture_protocol_reports_truncation_without_silent_loss() -> None:
    lines = _encoded_lines("abc123", b"1234", b"")
    lines[1] = "RP:abc123:STDOUT:100"
    result = parse_capture_lines(lines, "abc123", max_bytes=4)
    assert result.stdout == b"1234"
    assert result.stdout_total == 100
    assert result.truncated


def test_capture_command_quotes_input_and_bounds_remote_output() -> None:
    script = build_capture_command("printf '%s' 'a;b'", "abc123", max_bytes=4096)
    assert "printf" in script
    assert "head -c 4096" in script
    assert "RP:abc123:END" in script
    assert "base64" in script


def test_capture_command_runs_and_preserves_binary_output() -> None:
    script = build_capture_command("printf '\\211PNG\\000\\377'; printf 'bad\\000\\376' >&2; exit 7", "abc123")
    completed = subprocess.run(["/bin/sh", "-c", script], capture_output=True, check=True)
    result = parse_capture_lines(completed.stdout.decode("ascii").splitlines(), "abc123")
    assert result.stdout == b"\x89PNG\x00\xff"
    assert result.stderr == b"bad\x00\xfe"
    assert result.exit_code == 7


def test_binary_output_is_safely_previewed_and_saved(tmp_path) -> None:
    result = CommandResult(stdout=b"\x89PNG\r\n\x00\xff", stderr=b"", exit_code=0)
    lines = format_result(result)
    rendered = "\n".join(line for line, _color in lines)
    assert "(binary)" in rendered
    assert "89 50 4e 47" in rendered
    assert "\x1b" not in rendered
    destination = tmp_path / "image.bin"
    saved = save_result_stream(result, destination)
    assert saved == 8
    assert destination.read_bytes() == result.stdout


def test_hex_preview_never_exceeds_requested_byte_count() -> None:
    rendered = "\n".join(hex_preview(bytes(range(32)), limit=17))
    assert "10" in rendered
    assert "11 12" not in rendered


def test_text_output_escapes_terminal_control_sequences() -> None:
    result = CommandResult(stdout=b"hello\x1b[31m\n", stderr=b"", exit_code=0)
    rendered = "\n".join(line for line, _color in format_result(result))
    assert "\x1b" not in rendered
    assert "1b" in rendered


@pytest.mark.parametrize("payload", [b"\x7f", "\u202e".encode()])
def test_terminal_control_characters_never_render_raw(payload: bytes) -> None:
    result = CommandResult(stdout=payload, exit_code=0)
    rendered = "\n".join(line for line, _ in format_result(result))
    assert payload.decode("utf-8") not in rendered
    assert "(binary)" in rendered


def test_one_shot_result_lines_show_text_and_binary_without_loss() -> None:
    text_result = CommandResult(stdout=b"hello\n", stderr=b"warning\n", exit_code=0)
    assert result_text_lines(text_result) == ["hello", "stderr: warning"]
    binary_result = CommandResult(stdout=b"\x00\xff", exit_code=0)
    assert "00 ff" in "\n".join(result_text_lines(binary_result))


def test_postgres_one_shot_renderer_keeps_output_on_nonzero_exit() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 5432,
        "execute_command": "cat /missing",
        "execute_ok": False,
        "execute_output": ["stderr: not found"],
        "execute_error": "exit code 1",
        "execute_exit_code": 1,
        "execute_stderr_base64": "bm90IGZvdW5k",
    }
    lines = pg_actions._format_execute_detail_records(record, "txt")
    assert any("stderr: not found" in line for line in lines)
    assert any("exit code 1" in line for line in lines)
    import json

    payload = json.loads(pg_actions._format_execute_detail_records(record, "json")[0])
    assert payload["exit_code"] == 1
    assert payload["stderr_base64"] == "bm90IGZvdW5k"


def test_clickhouse_one_shot_actions_preserve_binary_and_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ch_actions,
        "_run_execute_command_bytes",
        lambda *_a, **_k: CommandResult(stdout=b"\x00\xff", stderr=b"denied\n", exit_code=7),
    )
    result = ch_actions._run_clickhouse_actions_on_session(
        object(),
        database="default",
        show_databases=False,
        show_tables=False,
        show_columns=False,
        table_targets=[],
        table_columns=[],
        dump_table_rows=False,
        dump_row_limit=None,
        execute_command="id",
        sql_command=None,
        limited_session=True,
    )
    assert result["execute_ok"] is False
    assert result["execute_exit_code"] == 7
    assert result["execute_stdout_base64"] == "AP8="
    assert "00 ff" in "\n".join(result["execute_output"])


def test_clickhouse_one_shot_renderer_keeps_output_on_nonzero_exit() -> None:
    import json

    record = {
        "host": "127.0.0.1",
        "port": 9000,
        "execute_command": "cat /missing",
        "execute_attempted": True,
        "execute_ok": False,
        "execute_output": ["stderr: not found"],
        "execute_error": "exit code 1",
        "execute_exit_code": 1,
        "execute_stderr_base64": "bm90IGZvdW5k",
    }
    lines = ch_actions._format_execute_detail_records(record, "txt")
    assert any("stderr: not found" in line for line in lines)
    payload = json.loads(ch_actions._format_execute_detail_records(record, "json")[0])
    assert payload["exit_code"] == 1
    assert payload["stderr_base64"] == "bm90IGZvdW5k"


def test_postgres_capture_preserves_bytes_across_copy_text_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pg_actions.secrets, "token_hex", lambda _n: "abc123")
    statements: list[str] = []

    def fake_query(_sock: object, sql: str):
        statements.append(sql)
        if sql.startswith("SELECT line FROM"):
            return [[line] for line in _encoded_lines("abc123", b"\x00\xff", b"error\n", code=4)], None
        return [], None

    monkeypatch.setattr(pg_actions, "_pg_query_rows", fake_query)
    result = pg_actions._pg_try_execute_command_bytes(object(), "printf test", max_bytes=1024)
    assert result.stdout == b"\x00\xff"
    assert result.stderr == b"error\n"
    assert result.exit_code == 4
    assert any(sql.startswith("COPY ") and "FROM PROGRAM" in sql for sql in statements)
    assert statements[-1].startswith("DROP TABLE")


def test_postgres_capture_does_not_retry_after_command_submission(monkeypatch: pytest.MonkeyPatch) -> None:
    opens: list[object] = []

    class FakeSocket:
        def __enter__(self):
            opens.append(self)
            return self

        def __exit__(self, *_args):
            return None

        def close(self):
            return None

    monkeypatch.setattr(pg_actions, "_pg_open_socket", lambda *_a, **_k: FakeSocket())
    monkeypatch.setattr(pg_actions, "_pg_startup_and_auth", lambda *_a, **_k: None)
    monkeypatch.setattr(pg_actions, "_pg_send_terminate", lambda *_a, **_k: None)
    monkeypatch.setattr(
        pg_actions,
        "_pg_try_execute_command_bytes",
        lambda *_a, **_k: (_ for _ in ()).throw(ConnectionResetError("RST")),
    )
    result = pg_actions._pg_execute_remote_command_bytes(
        "127.0.0.1", 5432, 1, 3, "postgres", "password", "postgres", "touch /tmp/once"
    )
    assert len(opens) == 1
    assert result.outcome_unknown
    assert "RST" in str(result.error)


def test_postgres_one_shot_does_not_replay_after_disconnect(monkeypatch: pytest.MonkeyPatch) -> None:
    connections: list[object] = []

    class FakeSocket:
        def __enter__(self):
            connections.append(self)
            return self

        def __exit__(self, *_args):
            return None

    monkeypatch.setattr(pg_actions, "_pg_open_socket", lambda *_a, **_k: FakeSocket())
    monkeypatch.setattr(
        pg_actions,
        "_pg_startup_and_auth",
        lambda *_a, **_k: pg_actions._PgSession(auth_required=True, auth_method="cleartext", server_version="16.0"),
    )
    monkeypatch.setattr(pg_actions, "_collect_postgres_privileges", lambda *_a: (True, True, True, 0, None))
    monkeypatch.setattr(pg_actions, "_pg_query_databases", lambda *_a: ([], None))
    monkeypatch.setattr(pg_actions, "_pg_send_terminate", lambda *_a: None)
    monkeypatch.setattr(
        pg_actions,
        "_pg_try_execute_command_bytes",
        lambda *_a, **_k: (_ for _ in ()).throw(ConnectionResetError("RST")),
    )
    result = pg_actions._audit_postgres_host(
        "127.0.0.1",
        5432,
        1.0,
        3,
        username="postgres",
        password="pass",
        defcreds=False,
        database="postgres",
        show_databases=False,
        show_tables=False,
        show_row_counts=False,
        show_columns=False,
        table_targets=[],
        table_targets_by_database={},
        table_columns=[],
        dump_table_rows=False,
        dump_row_limit=None,
        execute_command="touch /tmp/once",
        sql_command=None,
    )
    assert len(connections) == 1
    assert result["execute_outcome_unknown"] is True


def test_clickhouse_capture_preserves_raw_rows_and_exit_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ch_actions.secrets, "token_hex", lambda _n: "abc123")
    queries: list[str] = []

    def fake_query(_session: object, query: str):
        queries.append(query)
        return [[line] for line in _encoded_lines("abc123", b"\x00\xff", b"failed\n", code=9)], None

    monkeypatch.setattr(ch_actions, "_query_rows", fake_query)
    result = ch_actions._run_execute_command_bytes(object(), "printf test", max_bytes=1024)
    assert result.stdout == b"\x00\xff"
    assert result.stderr == b"failed\n"
    assert result.exit_code == 9
    assert "executable(" in queries[0]


def test_clickhouse_capture_reports_incomplete_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ch_actions, "_query_rows", lambda *_a: ([["ordinary output"]], None))
    result = ch_actions._run_execute_command_bytes(object(), "id")
    assert result.outcome_unknown


def test_clickhouse_capture_marks_disconnect_after_submission_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ch_actions, "_query_rows", lambda *_a: (_ for _ in ()).throw(ConnectionResetError("RST")))
    result = ch_actions._run_execute_command_bytes(object(), "touch /tmp/once")
    assert result.outcome_unknown
    assert "RST" in str(result.error)


def test_shell_view_saves_previous_binary_result_and_changes_preview(tmp_path) -> None:
    class Console:
        def __init__(self) -> None:
            self.lines: list[tuple[str, str | None]] = []

        def plain(self, text: str, color: str | None = None) -> None:
            self.lines.append((text, color))

    console = Console()
    view = ShellView()
    view.last = CommandResult(stdout=b"\x00\xff", exit_code=0)
    assert view.handle(":hex stdout 2", console) == (True, False)
    assert any("00 ff" in line for line, _ in console.lines)
    assert view.handle(":base64 stdout 2", console) == (True, False)
    assert any("AP8=" in line for line, _ in console.lines)
    destination = tmp_path / "out.bin"
    assert view.handle(f":save stdout {destination}", console) == (True, False)
    assert destination.read_bytes() == b"\x00\xff"
    assert view.handle(":limit 16M", console) == (True, False)
    assert view.capture_bytes == 16 * 1024 * 1024
    assert view.handle(":exit", console) == (True, True)


def test_shell_view_coloring_respects_no_color(capsys, monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core.console import Console

    monkeypatch.setenv("FORCE_COLOR", "1")
    view = ShellView()
    view.show(CommandResult(stdout=b"ok\n", exit_code=0), Console(no_color=False))
    assert "\x1b[" in capsys.readouterr().out
    view.show(CommandResult(stdout=b"ok\n", exit_code=0), Console(no_color=True))
    assert "\x1b[" not in capsys.readouterr().out


def test_shell_view_keeps_in_process_command_history(monkeypatch: pytest.MonkeyPatch) -> None:
    history: list[str] = []
    monkeypatch.setitem(sys.modules, "readline", SimpleNamespace(add_history=history.append))
    ShellView().remember("id")
    assert history == ["id"]


def test_postgres_os_shell_shows_binary_and_saves_last_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path, capsys
) -> None:
    from redposture_core.console import Console

    destination = tmp_path / "capture.bin"
    inputs = iter(["slow-command", "cat /tmp/file", f":save stdout {destination}", ":exit"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(inputs))
    monkeypatch.setattr(
        pg_stage,
        "build_postgres_plan",
        lambda _args: SimpleNamespace(require_single_target_spec=lambda: (0, "127.0.0.1", 5432, None)),
    )
    monkeypatch.setattr(
        pg_stage.actions,
        "_audit_postgres_host",
        lambda **_kw: {"is_postgres": True, "status": "valid_credentials", "effective_username": "postgres"},
    )
    commands: list[str] = []

    def run_command(**kwargs):
        commands.append(kwargs["command"])
        if kwargs["command"] == "slow-command":
            raise KeyboardInterrupt
        return CommandResult(stdout=b"\x00\xff", exit_code=0)

    monkeypatch.setattr(pg_stage.actions, "_pg_execute_remote_command_bytes", run_command)
    args = argparse.Namespace(
        os_shell=True,
        sql_shell=False,
        username="postgres",
        password="pass",
        database="postgres",
        timeout=1.0,
        retries=0,
        debug=False,
        port=5432,
        target="127.0.0.1",
    )
    assert pg_stage._run_postgres_shell(args, Console(no_color=True)) == 0
    assert commands == ["slow-command", "cat /tmp/file"]
    assert destination.read_bytes() == b"\x00\xff"
    rendered = capsys.readouterr().out
    assert "(binary)" in rendered
    assert "outcome unknown" in rendered


def test_clickhouse_os_shell_shows_binary_result(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    from redposture_core.console import Console

    inputs = iter(["slow-command", "printf test", ":exit"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(inputs))
    monkeypatch.setattr(
        ch_stage,
        "build_clickhouse_plan",
        lambda _args: SimpleNamespace(require_single_target_spec=lambda: (0, "127.0.0.1", 9000, None)),
    )
    monkeypatch.setattr(
        ch_stage,
        "_check_clickhouse_shell_target",
        lambda *_a, **_kw: {
            "is_clickhouse": True,
            "status": "valid_credentials",
            "effective_username": "default",
            "protocol": "native",
        },
    )
    monkeypatch.setattr(ch_stage, "_emit_clickhouse_record", lambda *_a: None)
    monkeypatch.setattr(ch_stage.actions, "_load_readline_module", lambda: None)
    monkeypatch.setattr(
        ch_stage.actions,
        "_open_shell_session",
        lambda **_kw: (SimpleNamespace(protocol="native", client=object()), None),
    )
    monkeypatch.setattr(ch_stage.actions, "_close_client", lambda *_a: None)
    monkeypatch.setattr(ch_stage.actions, "_add_readline_history", lambda *_a: None)

    def run_command(_session, command, **_kw):
        if command == "slow-command":
            raise KeyboardInterrupt
        return CommandResult(stdout=b"\x00\xff", exit_code=0)

    monkeypatch.setattr(ch_stage.actions, "_run_execute_command_bytes", run_command)
    args = argparse.Namespace(
        os_shell=True, sql_shell=False, port=9000, target="127.0.0.1", timeout=1.0, retries=0, debug=False
    )
    assert (
        ch_stage._run_clickhouse_os_shell(
            args, logger=SimpleNamespace(log=lambda *_a, **_k: None), console=Console(no_color=True)
        )
        == 0
    )
    rendered = capsys.readouterr().out
    assert "(binary)" in rendered
    assert "outcome unknown" in rendered


def test_docker_exec_stream_preserves_binary_channels() -> None:
    def frame(channel: int, payload: bytes) -> bytes:
        return bytes([channel, 0, 0, 0]) + len(payload).to_bytes(4, "big") + payload

    decoded = decode_docker_stream_bytes(frame(1, b"\x00\xff") + frame(2, b"\x89PNG"))
    assert decoded == {"stdout": b"\x00\xff", "stderr": b"\x89PNG"}


def test_docker_exec_result_exposes_lossless_binary_output(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = bytes([1, 0, 0, 0]) + (2).to_bytes(4, "big") + b"\x00\xff"
    client = DockerEngineClient("127.0.0.1", 2375)

    def fake_request(_method: str, path: str, **_kwargs):
        body = b'{"ExitCode":0}' if path.endswith("/json") else payload
        return DockerHTTPResponse(200, "OK", {}, body)

    monkeypatch.setattr(client, "request", fake_request)
    result = client.start_exec("exec-id")
    assert result["stdout"] == "[binary 2 B]"
    assert result["stdout_base64"] == "AP8="
    assert result["exit_code"] == 0


def test_docker_exec_txt_shows_binary_hex_preview() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 2375,
        "exec_result": {"ok": True, "stdout": "[binary 2 B]", "stderr": "", "stdout_base64": "AP8=", "exit_code": 0},
    }
    rendered = "\n".join(docker_actions._format_exec_lines(record, "txt"))
    assert "00 ff" in rendered
    assert "binary" in rendered


def test_docker_exec_nonzero_exit_keeps_stderr() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 2375,
        "exec_result": {"ok": False, "exit_code": 7, "stderr": "denied\n", "stdout": "", "command": "id"},
    }
    rendered = "\n".join(docker_actions._format_exec_lines(record, "txt"))
    assert "exit:7" in rendered
    assert "denied" in rendered


@pytest.mark.parametrize(
    ("formatter", "renderer", "record"),
    [
        (
            docker_actions._format_exec_lines,
            docker_actions._render_colored_docker_line,
            {
                "host": "127.0.0.1",
                "port": 2375,
                "exec_result": {"ok": True, "stdout": "[binary 2 B]", "stdout_base64": "AP8="},
            },
        ),
        (
            kube_actions._format_detail_records,
            kube_actions._render_colored_kubeapi_line,
            {
                "host": "127.0.0.1",
                "port": 6443,
                "status": "valid_credentials",
                "exec_result": {"ok": True, "stdout": "[binary 2 B]", "stdout_base64": "AP8="},
            },
        ),
    ],
)
def test_binary_detail_color_and_no_color(formatter, renderer, record, capsys, monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core.console import Console

    monkeypatch.setenv("FORCE_COLOR", "1")
    line = formatter(record, "txt")[-1]
    assert "00 ff" in line
    assert renderer(Console(no_color=False), line)
    assert "\x1b[" in capsys.readouterr().out
    assert renderer(Console(no_color=True), line)
    assert "\x1b[" not in capsys.readouterr().out


def test_kubeapi_exec_txt_shows_binary_hex_preview() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 6443,
        "status": "valid_credentials",
        "exec_result": {"ok": True, "stdout": "[binary 2 B]", "stderr": "", "stdout_base64": "AP8=", "exit_code": 0},
    }
    rendered = "\n".join(kube_actions._format_detail_records(record, "txt"))
    assert "00 ff" in rendered


def test_oracle_scheduler_exec_preserves_binary_when_readback_is_available() -> None:
    class Client:
        def scheduler_exec(self, command: str, *, capture_output: bool):
            assert capture_output
            token_match = re.search(r"RP:([0-9a-f]+):STATUS", command)
            assert token_match is not None
            lines = _encoded_lines(token_match.group(1), b"\x00\xff", b"warning\n")
            return {"ok": True, "output_available": True, "output": "\n".join(lines) + "\n__redposture_exit_code=0\n"}

    result = oracle_actions._run_oracle_exec(Client(), "printf test", "scheduler")
    assert result["ok"] is True
    assert result["exit_code"] == 0
    assert result["stdout_base64"] == "AP8="
    assert "00 ff" in result["output"]


def test_oracle_auto_does_not_replay_nonzero_scheduler_command() -> None:
    class Client:
        def scheduler_exec(self, command: str, *, capture_output: bool):
            assert capture_output
            token_match = re.search(r"RP:([0-9a-f]+):STATUS", command)
            assert token_match is not None
            return {
                "ok": True,
                "output_available": True,
                "output": "\n".join(_encoded_lines(token_match.group(1), b"", b"denied\n", code=7)),
            }

        def java_exec(self, _command: str):
            pytest.fail("command must not be replayed by Java")

    result = oracle_actions._run_oracle_exec(Client(), "exit 7", "auto")
    assert result["exit_code"] == 7
    assert result["ok"] is False


def test_oracle_auto_does_not_replay_after_scheduler_disconnect() -> None:
    class Client:
        def scheduler_exec(self, command: str, *, capture_output: bool):
            assert capture_output
            raise ConnectionResetError("RST after job submission")

        def java_exec(self, _command: str):
            pytest.fail("ambiguous Scheduler command must not be replayed")

    result = oracle_actions._run_oracle_exec(Client(), "touch /tmp/once", "auto")
    assert result["ok"] is False
    assert result["outcome_unknown"] is True


def test_oracle_auto_does_not_replay_after_incomplete_scheduler_capture() -> None:
    class Client:
        def scheduler_exec(self, command: str, *, capture_output: bool):
            assert capture_output
            return {"ok": True, "output_available": True, "output": "partial frame"}

        def java_exec(self, _command: str):
            pytest.fail("completed Scheduler job must not be replayed")

    result = oracle_actions._run_oracle_exec(Client(), "touch /tmp/once", "auto")
    assert result["ok"] is True
    assert result["outcome_unknown"] is True


@given(
    stdout=st.binary(max_size=4096), stderr=st.binary(max_size=4096), exit_code=st.integers(min_value=0, max_value=255)
)
def test_capture_protocol_fuzz_round_trip(stdout: bytes, stderr: bytes, exit_code: int) -> None:
    lines = _encoded_lines("f00d", stdout, stderr, code=exit_code)
    result = parse_capture_lines(lines, "f00d")
    assert (result.stdout, result.stderr, result.exit_code) == (stdout, stderr, exit_code)
    rendered = "\n".join(line for line, _ in format_result(result))
    assert "\x00" not in rendered
    assert "\x1b" not in rendered


@given(
    stdout=st.binary(max_size=1024),
    stderr=st.binary(max_size=1024),
    corruption=st.sampled_from(("missing_end", "wrong_token", "wrong_size", "bad_base64", "extra_row")),
)
def test_capture_protocol_fuzz_rejects_corrupt_frames(stdout: bytes, stderr: bytes, corruption: str) -> None:
    lines = _encoded_lines("f00d", stdout, stderr)
    if corruption == "missing_end":
        lines.pop()
    elif corruption == "wrong_token":
        lines[0] = lines[0].replace("f00d", "beef")
    elif corruption == "wrong_size":
        lines[1] = f"RP:f00d:STDOUT:{len(stdout) + 1}"
    elif corruption == "bad_base64":
        lines[2] = "!"
    else:
        lines.insert(-1, "unexpected")
    with pytest.raises(ValueError):
        parse_capture_lines(lines, "f00d")


@given(stdout=st.binary(max_size=512), stderr=st.binary(max_size=512), split=st.integers(min_value=0, max_value=512))
def test_docker_exec_frame_fuzz_keeps_channels(stdout: bytes, stderr: bytes, split: int) -> None:
    def frame(channel: int, data: bytes) -> bytes:
        return bytes([channel, 0, 0, 0]) + len(data).to_bytes(4, "big") + data

    payload = frame(1, stdout[:split]) + frame(2, stderr) + frame(1, stdout[split:])
    assert decode_docker_stream_bytes(payload) == {"stdout": stdout, "stderr": stderr}
