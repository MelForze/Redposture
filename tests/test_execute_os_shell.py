from __future__ import annotations

import importlib
import re
import sys
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.console import Console
from redposture_core.modules import execution_api


def test_piped_shell_transcript_shows_command_before_result(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    commands = iter(["id", "exit"])

    def fake_input(prompt: str) -> str:
        print(prompt, end="")
        return next(commands)

    monkeypatch.setattr("builtins.input", fake_input)
    ctx = SimpleNamespace(args=SimpleNamespace(execute=None, execute_max_bytes=128, debug=False))
    execution_api.run_os_shell(
        ctx,
        {"status": "open_no_auth"},
        SimpleNamespace(),
        module="jupyter",
        surface="terminal",
        execute_once=lambda *_args: {"execution": {"executed": True, "exit_code": 0, "stdout": "uid=70\n"}},
    )
    plain = re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out)
    assert "jupyter-os> id\n[+] exit:0" in plain


def test_interactive_shell_reuses_confirmed_record_and_runs_each_command(monkeypatch, capsys) -> None:
    commands = iter(["id", ":limit 64", "pwd", "exit"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(commands))
    args = SimpleNamespace(execute=None, execute_timeout=3, execute_max_bytes=128, debug=False)
    ctx = SimpleNamespace(args=args, host="127.0.0.1", port=8080)
    state = SimpleNamespace(execution={"stale": True}, ui_execution={"stale": True})
    calls: list[tuple[str, int]] = []
    record = {"is_service": True, "status": "open_no_auth"}

    def execute_once(current_ctx, current_record, current_state):
        assert current_record == record
        assert current_state is state
        command = current_ctx.args.execute
        calls.append((command, current_ctx.args.execute_max_bytes))
        return {
            **current_record,
            "execution": {
                "command": command,
                "executed": True,
                "exit_code": 0,
                "stdout": command + "\n",
                "stderr": "",
                "status": "complete",
                "cleanup": "complete",
            },
        }

    execution_api.run_os_shell(ctx, record, state, module="qa", surface="temporary worker", execute_once=execute_once)

    assert calls == [("id", 128), ("pwd", 64)]
    assert args.execute is None
    assert args.execute_max_bytes == 128
    assert "os-shell ready" not in capsys.readouterr().out


def test_interactive_shell_reports_unverified_result_and_cleanup_failure(monkeypatch, capsys) -> None:
    commands = iter(["id", "exit"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(commands))
    ctx = SimpleNamespace(
        args=SimpleNamespace(execute=None, execute_timeout=3, execute_max_bytes=128, debug=False),
        host="127.0.0.1",
        port=8080,
    )
    output = iter(
        [
            {
                "execution": {
                    "executed": False,
                    "status": "unverified",
                    "error": "worker result unavailable; command was not retried",
                    "cleanup": "failed",
                    "cleanup_error": "temporary job remains",
                }
            }
        ]
    )
    execution_api.run_os_shell(
        ctx,
        {"status": "open_no_auth"},
        SimpleNamespace(),
        module="qa",
        surface="temporary worker",
        execute_once=lambda *_args: next(output),
    )
    rendered = capsys.readouterr().out
    assert "worker result unavailable" in rendered
    assert "cleanup failed: temporary job remains" in rendered


def test_interactive_shell_refuses_unconfirmed_surface_before_prompt(monkeypatch, capsys) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: pytest.fail("unsupported surface prompted for commands"))
    ctx = SimpleNamespace(
        args=SimpleNamespace(execute=None, execute_timeout=3, execute_max_bytes=128, debug=False),
        host="127.0.0.1",
        port=8080,
    )
    execution_api.run_os_shell(
        ctx,
        {"is_kafka_ui": False},
        SimpleNamespace(),
        module="kafka",
        surface="Provectus Kafka UI",
        execute_once=lambda *_args: pytest.fail("unsupported surface executed"),
        preflight=lambda record: "--os-shell requires confirmed Provectus Kafka UI access",
    )
    assert "requires confirmed Provectus Kafka UI access" in capsys.readouterr().err


def test_interactive_shell_reports_nonzero_exit_and_truncation_without_fake_total(monkeypatch, capsys) -> None:
    commands = iter(["false", "exit"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(commands))
    ctx = SimpleNamespace(
        args=SimpleNamespace(execute=None, execute_timeout=3, execute_max_bytes=128, debug=False),
        host="127.0.0.1",
        port=8080,
    )
    execution_api.run_os_shell(
        ctx,
        {"status": "open_no_auth"},
        SimpleNamespace(),
        module="qa",
        surface="temporary worker",
        execute_once=lambda *_args: {
            "execution": {
                "executed": True,
                "exit_code": 7,
                "stdout": "abc",
                "stderr": "",
                "status": "partial",
                "truncated": True,
            }
        },
    )
    rendered = capsys.readouterr().out
    assert "[-] exit:7" in rendered
    assert "stdout:3 B  stderr:0 B  (truncated)" in rendered
    assert "stdout:4 B" not in rendered


def test_interactive_shell_respects_no_color_even_when_color_is_forced(monkeypatch, capsys) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    commands = iter(["id", "exit"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(commands))
    ctx = SimpleNamespace(
        args=SimpleNamespace(execute=None, execute_timeout=3, execute_max_bytes=128, debug=False, no_color=True),
        host="127.0.0.1",
        port=8080,
    )
    execution_api.run_os_shell(
        ctx,
        {"status": "open_no_auth"},
        SimpleNamespace(),
        module="qa",
        surface="temporary worker",
        execute_once=lambda *_args: {
            "execution": {"executed": True, "exit_code": 0, "stdout": "ok\n", "stderr": "", "status": "complete"}
        },
    )
    assert "\x1b[" not in capsys.readouterr().out


def test_os_shell_validation_rejects_one_shot_execute_output_file_and_json(capsys) -> None:
    for changes, expected in (
        ({"execute": "id"}, "cannot be combined with --execute"),
        ({"output": "out.txt"}, "cannot be used with -o/--output"),
        ({"output_format": "json"}, "requires --format txt"),
        ({"discover": True}, "cannot be combined with --discover"),
    ):
        values = {"os_shell": True, "execute": None, "output": None, "output_format": "txt", **changes}
        args = SimpleNamespace(**values)
        console = Console()
        assert execution_api.validate_os_shell(args, console, forbidden=("discover",)) == 2
        captured = capsys.readouterr()
        assert expected in captured.out + captured.err


def test_spark_and_yarn_os_shell_flags_are_rejected_with_surface_reason(capsys) -> None:
    from redposture_core.modules.spark import policy as spark_policy
    from redposture_core.modules.yarn import policy as yarn_policy

    for policy in (spark_policy, yarn_policy):
        args = SimpleNamespace(
            os_shell=True,
            execute=None,
            execute_timeout=30,
            execute_max_bytes=1048576,
            output=None,
            output_format="txt",
            targets="127.0.0.1",
            target=None,
            token=None,
            token_file=None,
            insecure=False,
            tls_ca=None,
            tls_cert=None,
            tls_key=None,
            timeout=5,
            retries=0,
            workers=1,
            discover=False,
            enum_cve=False,
        )
        console = Console()
        assert policy.validate_args(args, console) == 2
        message = capsys.readouterr().err.lower()
        assert "worker log" in message or "node log" in message
        assert "reliable interactive command result" in message


def test_os_shell_flag_is_exposed_on_all_requested_execute_modules() -> None:
    for module in ("kafka", "consul", "jenkins", "nomad", "jupyter", "portainer", "nexus", "spark", "yarn"):
        args = parse_args([module, "-t", "127.0.0.1", "--os-shell"])
        assert args.os_shell is True


@pytest.mark.parametrize(
    ("module", "policy_module", "conflict"),
    (
        ("kafka", "kafka", "--discover"),
        ("kafka", "kafka", "--enum-cve"),
        ("consul", "consul", "--discover"),
        ("consul", "consul", "--enum-cve"),
        ("nomad", "nomad", "--show-members"),
    ),
)
def test_os_shell_rejects_competing_module_actions(module: str, policy_module: str, conflict: str, capsys) -> None:
    from importlib import import_module

    args = parse_args([module, "-t", "127.0.0.1", "--os-shell", conflict])
    policy = import_module(f"redposture_core.modules.{policy_module}.policy")
    assert policy.validate_args(args, Console()) == 2
    assert "cannot be combined" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("module", "builder"),
    (
        ("kafka", "build_kafka_spec"),
        ("consul", "build_consul_spec"),
        ("jenkins", "build_jenkins_spec"),
        ("nomad", "build_nomad_spec"),
        ("jupyter", "build_jupyter_spec"),
        ("portainer", "build_portainer_spec"),
        ("nexus", "build_nexus_spec"),
    ),
)
def test_module_data_phase_enters_shell_without_running_inventory(module: str, builder: str, monkeypatch) -> None:
    args = parse_args([module, "-t", "127.0.0.1", "--os-shell"])
    stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
    calls = []
    monkeypatch.setattr(
        stage,
        "run_os_shell",
        lambda *call_args, **call_kwargs: calls.append((call_args, call_kwargs)),
    )
    spec = getattr(stage, builder)(args)
    record = AuditRecord.from_mapping({"host": "127.0.0.1", "port": 1234}, module=module, service=module)
    ctx = SimpleNamespace(args=args, lifecycle_state=SimpleNamespace())

    assert spec.data(ctx, record) == record
    assert len(calls) == 1
    assert calls[0][1]["module"] == module


@pytest.mark.parametrize(
    ("mode", "surface"),
    (("kernel", "Jupyter kernel"), ("terminal", "Jupyter terminal"), ("auto", "Jupyter kernel or terminal (auto)")),
)
def test_jupyter_shell_names_selected_execution_surface(mode: str, surface: str, monkeypatch) -> None:
    from redposture_core.modules.jupyter import stage

    args = parse_args(["jupyter", "-t", "127.0.0.1", "--os-shell", "--execute-via", mode])
    seen: list[str] = []
    monkeypatch.setattr(stage, "run_os_shell", lambda *_args, **kwargs: seen.append(kwargs["surface"]))
    spec = stage.build_jupyter_spec(args)
    record = AuditRecord.from_mapping({"host": "127.0.0.1", "port": 8888}, module="jupyter", service="jupyter")

    spec.data(SimpleNamespace(args=args, lifecycle_state=SimpleNamespace()), record)

    assert seen == [surface]
