from __future__ import annotations

import argparse

import pytest

from redposture_core.stage_scan import run_scan_stage


def _args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "debug": False,
        "timeout": 1.0,
        "retries": 1,
        "workers": 4,
        "targets": "127.0.0.1",
        "hosts": None,
        "hosts_file": None,
        "ports": None,
        "profiles_file": None,
        "output": None,
        "output_format": "txt",
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_run_scan_stage_rejects_non_positive_timeout(capsys: pytest.CaptureFixture[str]) -> None:
    rc = run_scan_stage(_args(timeout=0.0))
    assert rc == 2
    assert "--timeout must be > 0" in capsys.readouterr().err


def test_run_scan_stage_rejects_negative_retries(capsys: pytest.CaptureFixture[str]) -> None:
    rc = run_scan_stage(_args(retries=-1))
    assert rc == 2
    assert "--retries must be >= 0" in capsys.readouterr().err


def test_run_scan_stage_handles_target_parse_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_scan.collect_scan_targets",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad targets")),
    )

    rc = run_scan_stage(_args())
    assert rc == 2
    assert "failed to parse targets" in capsys.readouterr().err


def test_run_scan_stage_handles_ports_parse_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])
    monkeypatch.setattr(
        "redposture_core.stage_scan.collect_scan_ports",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad ports")),
    )

    rc = run_scan_stage(_args(ports="x"))
    assert rc == 2
    assert "failed to parse --ports" in capsys.readouterr().err


def test_run_scan_stage_handles_profiles_load_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        "redposture_core.stage_scan.load_profiles",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad profiles")),
    )

    rc = run_scan_stage(_args())
    assert rc == 2
    assert "failed to load profiles" in capsys.readouterr().err


def test_run_scan_stage_requires_hosts(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_targets", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        "redposture_core.stage_scan.load_profiles", lambda *_args, **_kwargs: {"discovery_exporters": []}
    )

    rc = run_scan_stage(_args())
    assert rc == 2
    assert "scan requires -t/--targets" in capsys.readouterr().err


def test_run_scan_stage_streams_txt_and_passes_custom_ports(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    captured: dict[str, object] = {}

    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_ports", lambda *_args, **_kwargs: [9100])
    monkeypatch.setattr(
        "redposture_core.stage_scan.load_profiles", lambda *_args, **_kwargs: {"discovery_exporters": []}
    )

    def fake_scan(*_args: object, **kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        captured.update(kwargs)
        emit_line = kwargs.get("emit_line")
        if callable(emit_line):
            emit_line("SCAN\t127.0.0.1\t9100\t [*] ignored summary")
            emit_line("SCAN\t127.0.0.1\t9100\t [+] Node Exporter")
        return 1, 1, {"127.0.0.1": [{"exporter": "node_exporter", "port": 9100}]}

    monkeypatch.setattr("redposture_core.stage_scan.scan_exporter_presence", fake_scan)

    rc = run_scan_stage(_args(ports="9100"))
    assert rc == 0
    out = capsys.readouterr().out
    assert "Node Exporter" in out
    assert "ignored summary" not in out
    assert "scan complete" in out
    assert captured.get("custom_ports") == [9100]


def test_run_scan_stage_prints_json_lines_as_is(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        "redposture_core.stage_scan.load_profiles", lambda *_args, **_kwargs: {"discovery_exporters": []}
    )

    def fake_scan(*_args: object, **kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        emit_line = kwargs.get("emit_line")
        if callable(emit_line):
            emit_line('{"type":"scan"}')
        return 1, 0, {"127.0.0.1": []}

    monkeypatch.setattr("redposture_core.stage_scan.scan_exporter_presence", fake_scan)

    rc = run_scan_stage(_args(output_format="json"))
    assert rc == 0
    assert '{"type":"scan"}' in capsys.readouterr().out


def test_run_scan_stage_output_mode_reports_per_host_summary(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_targets", lambda *_args, **_kwargs: ["h1", "h2"])
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        "redposture_core.stage_scan.load_profiles", lambda *_args, **_kwargs: {"discovery_exporters": []}
    )

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return (
            2,
            1,
            {"h1": [{"exporter": "node_exporter", "port": 9100, "status": 200, "method": "GET", "url": "u"}], "h2": []},
        )

    monkeypatch.setattr("redposture_core.stage_scan.scan_exporter_presence", fake_scan)

    rc = run_scan_stage(_args(output="scan.txt"))
    assert rc == 0
    out = capsys.readouterr().out
    assert "h1: detected 1 exporter(s)" in out
    assert "h2: no known exporters detected" in out
