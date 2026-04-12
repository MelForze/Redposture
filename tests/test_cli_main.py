from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core import cli
from redposture_core.cli_args import (
    COMMAND_CLICKHOUSE,
    COMMAND_COLLECT,
    COMMAND_CONSUL,
    COMMAND_ELASTIC,
    COMMAND_ETCD,
    COMMAND_EXPORTERS,
    COMMAND_GITLAB,
    COMMAND_GRAFANA,
    COMMAND_KAFKA,
    COMMAND_KUBEAPI,
    COMMAND_POSTGRES,
    COMMAND_PROXMOX,
    COMMAND_QDRANT,
    COMMAND_REDIS,
    COMMAND_REGISTRY,
    COMMAND_SCAN,
    COMMAND_SELFCERT,
    COMMAND_TRIGGER,
    COMMAND_ZOOKEEPER,
)


def test_tee_console_output_mirrors_stdout_and_stderr(tmp_path, capsys) -> None:
    log_path = tmp_path / "redposture.log"

    with cli._tee_console_output(str(log_path)):
        print("stdout line")
        print("stderr line", file=__import__("sys").stderr)

    captured = capsys.readouterr()
    logged = log_path.read_text(encoding="utf-8")
    assert "stdout line" in captured.out
    assert "stderr line" in captured.err
    assert "stdout line" in logged
    assert "stderr line" in logged


@pytest.mark.parametrize(
    ("args", "patch_target"),
    [
        (SimpleNamespace(command=COMMAND_EXPORTERS, exporters_action=COMMAND_SCAN), "run_scan_stage"),
        (SimpleNamespace(command=COMMAND_EXPORTERS, exporters_action=COMMAND_TRIGGER), "run_trigger_stage"),
        (SimpleNamespace(command=COMMAND_EXPORTERS, exporters_action=COMMAND_COLLECT), "run_collect_stage"),
        (SimpleNamespace(command=COMMAND_SCAN), "run_scan_stage"),
        (SimpleNamespace(command=COMMAND_TRIGGER), "run_trigger_stage"),
        (SimpleNamespace(command=COMMAND_COLLECT), "run_collect_stage"),
        (SimpleNamespace(command=COMMAND_REDIS), "run_redis_stage"),
        (SimpleNamespace(command=COMMAND_REGISTRY), "run_registry_stage"),
        (SimpleNamespace(command=COMMAND_GRAFANA), "run_grafana_stage"),
        (SimpleNamespace(command=COMMAND_GITLAB), "run_gitlab_stage"),
        (SimpleNamespace(command=COMMAND_CONSUL), "run_consul_stage"),
        (SimpleNamespace(command=COMMAND_ELASTIC), "run_elastic_stage"),
        (SimpleNamespace(command=COMMAND_QDRANT), "run_qdrant_stage"),
        (SimpleNamespace(command=COMMAND_KUBEAPI), "run_kubeapi_stage"),
        (SimpleNamespace(command=COMMAND_KAFKA), "run_kafka_stage"),
        (SimpleNamespace(command=COMMAND_POSTGRES), "run_postgres_stage"),
        (SimpleNamespace(command=COMMAND_CLICKHOUSE), "run_clickhouse_stage"),
        (SimpleNamespace(command=COMMAND_ETCD), "run_etcd_stage"),
        (SimpleNamespace(command=COMMAND_PROXMOX), "run_proxmox_stage"),
        (SimpleNamespace(command=COMMAND_ZOOKEEPER), "run_zookeeper_stage"),
    ],
)
def test_run_command_dispatches_to_stage_functions(
    monkeypatch: pytest.MonkeyPatch,
    args: SimpleNamespace,
    patch_target: str,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cli, patch_target, lambda *_args, **_kwargs: calls.append(patch_target) or 7)
    assert cli._run_command(args, logger=object()) == 7
    assert calls == [patch_target]


def test_run_command_dispatches_to_selfcert(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "run_selfcert_stage", lambda args: 13)
    assert cli._run_command(SimpleNamespace(command=COMMAND_SELFCERT), logger=object()) == 13


def test_run_command_rejects_unsupported_commands(capsys) -> None:
    assert cli._run_command(SimpleNamespace(command=COMMAND_EXPORTERS, exporters_action="weird"), logger=object()) == 2
    assert "unsupported exporters action" in capsys.readouterr().err

    assert cli._run_command(SimpleNamespace(command="weird"), logger=object()) == 2
    assert "unsupported command: weird" in capsys.readouterr().err


def test_main_returns_error_on_proxy_parse_failure(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    args = SimpleNamespace(command=COMMAND_GRAFANA, log="", proxy="http://proxy.local", debug=False, no_color=False)
    monkeypatch.setattr(cli, "parse_args", lambda _argv=None: args)
    monkeypatch.setattr(cli, "parse_proxy_config", lambda _raw: (None, "bad proxy"))

    assert cli.main(["grafana", "-t", "127.0.0.1"]) == 2
    assert "failed to parse --proxy: bad proxy" in capsys.readouterr().err


def test_main_ignores_proxy_parsing_for_proxmox(monkeypatch: pytest.MonkeyPatch) -> None:
    args = SimpleNamespace(command=COMMAND_PROXMOX, log="", proxy="http://proxy.local", debug=False, no_color=False)
    calls: list[str] = []
    monkeypatch.setattr(cli, "parse_args", lambda _argv=None: args)
    monkeypatch.setattr(cli, "parse_proxy_config", lambda _raw: (_ for _ in ()).throw(AssertionError("unexpected")))
    monkeypatch.setattr(cli, "_run_command", lambda *_args, **_kwargs: calls.append("run") or 0)

    assert cli.main(["proxmox", "-t", "127.0.0.1"]) == 0
    assert calls == ["run"]


def test_main_tees_output_and_runs_command_on_success(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    log_path = tmp_path / "run.log"
    args = SimpleNamespace(command=COMMAND_GRAFANA, log=str(log_path), proxy="", debug=False, no_color=False)
    calls: list[str] = []

    monkeypatch.setattr(cli, "parse_args", lambda _argv=None: args)

    def _fake_run_command(_args, _logger) -> int:
        print("runtime stdout")
        print("runtime stderr", file=__import__("sys").stderr)
        calls.append("run")
        return 0

    monkeypatch.setattr(cli, "_run_command", _fake_run_command)

    assert cli.main(["grafana", "-t", "127.0.0.1"]) == 0
    assert calls == ["run"]
    logged = log_path.read_text(encoding="utf-8")
    assert "runtime stdout" in logged
    assert "runtime stderr" in logged


def test_main_returns_error_when_log_file_cannot_be_opened(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    args = SimpleNamespace(command=COMMAND_GRAFANA, log="/tmp/redposture.log", proxy="", debug=False, no_color=False)
    monkeypatch.setattr(cli, "parse_args", lambda _argv=None: args)
    monkeypatch.setattr(
        cli,
        "_tee_console_output",
        lambda _path: (_ for _ in ()).throw(OSError("permission denied")),
    )

    assert cli.main(["grafana", "-t", "127.0.0.1"]) == 2
    assert "failed to open --log file '/tmp/redposture.log': permission denied" in capsys.readouterr().err


def test_main_applies_and_resets_no_color_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    args = SimpleNamespace(command=COMMAND_GRAFANA, log="", proxy="", debug=False, no_color=True)
    calls: list[bool] = []
    monkeypatch.setattr(cli, "parse_args", lambda _argv=None: args)
    monkeypatch.setattr(cli, "_run_command", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(cli, "set_console_no_color", lambda enabled: calls.append(bool(enabled)))

    assert cli.main(["grafana", "-t", "127.0.0.1", "--no-color"]) == 0
    assert calls[0] is True
    assert calls[-1] is False
