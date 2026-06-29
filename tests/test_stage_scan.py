from __future__ import annotations

import argparse
from types import SimpleNamespace

import pytest

from redposture_core import stage_scan
from redposture_core.exporters.output import format_scan_record
from redposture_core.stage_scan import run_scan_stage
from redposture_core.utils import ScanTargetSpec


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


def test_run_scan_stage_large_cidr_uses_chunked_output_and_single_summary(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    output_path = tmp_path / "scan.txt"
    calls: list[tuple[list[str], str]] = []

    monkeypatch.setattr(stage_scan, "DEFAULT_MAX_NETWORK_HOSTS", 1)
    monkeypatch.setattr(
        stage_scan,
        "load_profiles",
        lambda _path: {"discovery_exporters": [{"name": "node_exporter", "port": 9100, "markers": ()}]},
    )

    def fake_scan_exporter_presence(
        hosts,
        timeout,
        output_path,
        output_format="json",
        logger=None,
        emit_line=None,
        workers=10,
        retries=3,
        discovery_exporters=None,
        custom_ports=None,
        emit_summary=True,
        show_progress=False,
        progress_leave=True,
        output_mode="w",
        progress_owner=None,
    ):
        _ = (
            timeout,
            logger,
            workers,
            retries,
            discovery_exporters,
            custom_ports,
            emit_summary,
            show_progress,
            progress_leave,
            progress_owner,
        )
        host_list = list(hosts)
        calls.append((host_list, output_mode))
        lines = []
        for host in host_list:
            lines.append(
                format_scan_record(
                    {
                        "timestamp": "2026-03-27T00:00:00Z",
                        "host": host,
                        "port": 9100,
                        "exporter": "node_exporter",
                        "detected": False,
                        "url": f"http://{host}:9100/metrics",
                        "method": "none",
                        "status": 404,
                        "error": None,
                        "marker_hit": None,
                    },
                    output_format,
                )
            )
        if output_path:
            with open(output_path, output_mode, encoding="utf-8") as fh:
                for line in lines:
                    fh.write(line + "\n")
        if emit_line is not None:
            for line in lines:
                emit_line(line)
        return len(host_list), 0, {host: [] for host in host_list}

    monkeypatch.setattr(stage_scan, "scan_exporter_presence", fake_scan_exporter_presence)

    rc = run_scan_stage(_args(targets="10.0.0.0/30", output=str(output_path), workers=1))

    assert rc == 0
    assert calls == [(["10.0.0.1", "10.0.0.2"], "w")]
    lines = output_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    assert "not detected" in lines[0]
    assert "not detected" in lines[1]
    assert lines[-1].startswith("SCAN")
    assert "checks=2" in lines[-1]
    assert "found=0" in lines[-1]


def test_run_scan_stage_handles_target_parse_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_scan.collect_scan_target_specs",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad targets")),
    )

    rc = run_scan_stage(_args())
    assert rc == 2
    assert "failed to parse targets" in capsys.readouterr().err


def test_run_scan_stage_handles_ports_parse_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_scan.collect_scan_target_specs",
        lambda *_args, **_kwargs: [ScanTargetSpec(host="127.0.0.1")],
    )
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
    monkeypatch.setattr(
        "redposture_core.stage_scan.collect_scan_target_specs",
        lambda *_args, **_kwargs: [ScanTargetSpec(host="127.0.0.1")],
    )
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        "redposture_core.stage_scan.load_profiles",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad profiles")),
    )

    rc = run_scan_stage(_args())
    assert rc == 2


def test_run_scan_stage_handles_scan_output_os_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_scan.collect_scan_target_specs",
        lambda *_args, **_kwargs: [SimpleNamespace(host="127.0.0.1", scheme=None, explicit_port=None)],
    )
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        "redposture_core.stage_scan.load_profiles",
        lambda *_args, **_kwargs: {"discovery_exporters": [{"port": 9100}]},
    )

    def raise_oserror(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        raise OSError("cannot write output")

    monkeypatch.setattr("redposture_core.stage_scan.scan_exporter_presence", raise_oserror)

    rc = run_scan_stage(_args(output="scan.txt"))
    assert rc == 2
    assert "failed to process scan output" in capsys.readouterr().err


def test_run_scan_stage_handles_explicit_url_group_os_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_scan.collect_scan_target_specs",
        lambda *_args, **_kwargs: [SimpleNamespace(host="127.0.0.1", scheme="http", explicit_port=19100)],
    )
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        "redposture_core.stage_scan.load_profiles",
        lambda *_args, **_kwargs: {"discovery_exporters": [{"port": 9100}]},
    )

    def raise_oserror(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        raise OSError("cannot append output")

    monkeypatch.setattr("redposture_core.stage_scan.scan_exporter_presence", raise_oserror)

    rc = run_scan_stage(_args(output="scan.txt"))
    assert rc == 2
    assert "failed to process scan output" in capsys.readouterr().err


def test_run_scan_stage_requires_hosts(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_target_specs", lambda *_args, **_kwargs: [])
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

    monkeypatch.setattr(
        "redposture_core.stage_scan.collect_scan_target_specs",
        lambda *_args, **_kwargs: [ScanTargetSpec(host="127.0.0.1")],
    )
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


def test_run_scan_stage_debug_emit_line_variants_and_hosts_file(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    captured_targets: list[object] = []

    def fake_collect(targets: object, *_args: object, **_kwargs: object) -> list[ScanTargetSpec]:
        captured_targets.append(targets)
        return [ScanTargetSpec(host="127.0.0.1")]

    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_target_specs", fake_collect)
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        "redposture_core.stage_scan.load_profiles", lambda *_args, **_kwargs: {"discovery_exporters": []}
    )

    def fake_scan(*_args: object, **kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        emit_line = kwargs.get("emit_line")
        if callable(emit_line):
            emit_line("SCAN\t127.0.0.1\t9100\t [*] debug summary")
            emit_line("BROKEN [+] non-scan success")
            emit_line("SCAN\t127.0.0.1\t9100\t [!] warning detail")
            emit_line("SCAN\t127.0.0.1\t9100\t [-] negative detail")
            emit_line("SCAN\t127.0.0.1\t9100\t plain debug detail")
        return 1, 1, {"127.0.0.1": [{"exporter": "node_exporter", "port": 9100}]}

    monkeypatch.setattr("redposture_core.stage_scan.scan_exporter_presence", fake_scan)

    rc = run_scan_stage(_args(hosts_file="hosts.txt", debug=True))

    assert rc == 0
    assert captured_targets == ["127.0.0.1,hosts.txt"]
    out = capsys.readouterr().out
    assert "debug summary" in out
    assert "non-scan success" in out
    assert "warning detail" in out
    assert "negative detail" in out
    assert "plain debug detail" in out


def test_run_scan_stage_prints_json_lines_as_is(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_scan.collect_scan_target_specs",
        lambda *_args, **_kwargs: [ScanTargetSpec(host="127.0.0.1")],
    )
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
    monkeypatch.setattr(
        "redposture_core.stage_scan.collect_scan_target_specs",
        lambda *_args, **_kwargs: [ScanTargetSpec(host="h1"), ScanTargetSpec(host="h2")],
    )
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


def test_run_scan_stage_output_mode_deduplicates_explicit_url_hits(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    specs = [
        ScanTargetSpec(host="h1", scheme="http", explicit_port=9100),
        ScanTargetSpec(host="h1", scheme="http", explicit_port=9101),
    ]
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_target_specs", lambda *_args, **_kwargs: specs)
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        "redposture_core.stage_scan.load_profiles",
        lambda *_args, **_kwargs: {"discovery_exporters": [{"port": 9100}, {"port": 9101}]},
    )

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return (
            1,
            1,
            {
                "h1": [
                    {
                        "exporter": "node_exporter",
                        "port": 9100,
                        "status": 200,
                        "method": "GET",
                        "url": "http://h1:9100/metrics",
                    }
                ]
            },
        )

    monkeypatch.setattr("redposture_core.stage_scan.scan_exporter_presence", fake_scan)

    rc = run_scan_stage(_args(output="scan.txt", targets="http://h1:9100/metrics,http://h1:9101/metrics"))

    assert rc == 0
    out = capsys.readouterr().out
    assert "h1: detected 1 exporter(s) [node_exporter]" in out


def test_run_scan_stage_debug_emits_staged_markers(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_scan.collect_scan_target_specs",
        lambda *_args, **_kwargs: [ScanTargetSpec(host="127.0.0.1")],
    )
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        "redposture_core.stage_scan.load_profiles", lambda *_args, **_kwargs: {"discovery_exporters": []}
    )
    monkeypatch.setattr(
        "redposture_core.stage_scan.scan_exporter_presence",
        lambda *_args, **_kwargs: (1, 0, {"127.0.0.1": []}),
    )

    rc = run_scan_stage(_args(debug=True))
    assert rc == 0
    out = capsys.readouterr().out
    assert "pass=1 detect start total=1" in out
    assert "pass=2 deep start total=0" in out
    assert "stage2_gate=skip reason=detected=0" in out
    assert "stage_timing_summary status=ok attempts=1/1" in out


def test_run_scan_stage_explicit_url_targets_use_single_global_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    specs = [
        ScanTargetSpec(host="127.0.0.1", scheme="http", explicit_port=19100),
        ScanTargetSpec(host="127.0.0.1", scheme="http", explicit_port=19102),
        ScanTargetSpec(host="127.0.0.1", scheme="http", explicit_port=19104),
        ScanTargetSpec(host="127.0.0.1", scheme="http", explicit_port=19113),
        ScanTargetSpec(host="127.0.0.1", scheme="http", explicit_port=19114),
    ]
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_target_specs", lambda *_args, **_kwargs: specs)
    monkeypatch.setattr("redposture_core.stage_scan.collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        "redposture_core.stage_scan.load_profiles",
        lambda *_args, **_kwargs: {"discovery_exporters": [{"port": 19100}]},
    )

    scan_show_progress_flags: list[bool] = []
    scan_calls = 0

    def fake_scan(*_args: object, **kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        nonlocal scan_calls
        scan_calls += 1
        scan_show_progress_flags.append(bool(kwargs.get("show_progress", True)))
        hosts = kwargs.get("hosts") or []
        custom_ports = kwargs.get("custom_ports") or []
        checks = len(hosts) * len(custom_ports)
        return checks, 0, {"127.0.0.1": []}

    monkeypatch.setattr("redposture_core.stage_scan.scan_exporter_presence", fake_scan)

    progress_totals: list[int] = []
    progress_advances: list[int] = []
    progress_closed = 0

    class DummyProgressBar:
        def __init__(self, _label: str, total: int, *, enabled: bool = True, leave: bool = True) -> None:
            del enabled, leave
            progress_totals.append(total)

        def advance(self, amount: int = 1) -> None:
            progress_advances.append(amount)

        def close(self) -> None:
            nonlocal progress_closed
            progress_closed += 1

    monkeypatch.setattr(
        "redposture_core.stage_scan.start_command_progress",
        lambda _args, label, total, **kwargs: DummyProgressBar(label, total, **kwargs),
    )

    rc = run_scan_stage(
        _args(
            targets=(
                "http://127.0.0.1:19100/metrics,http://127.0.0.1:19102/metrics,"
                "http://127.0.0.1:19104/metrics,http://127.0.0.1:19113/metrics,"
                "http://127.0.0.1:19114/metrics"
            )
        )
    )
    assert rc == 0
    assert scan_calls == 5
    assert scan_show_progress_flags == [False, False, False, False, False]
    assert progress_totals == [5]
    assert sum(progress_advances) == 5
    assert progress_closed == 1
