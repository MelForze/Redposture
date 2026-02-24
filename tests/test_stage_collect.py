from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from redposture_core.logger import AttemptLogger
from redposture_core.stage_collect import run_collect_stage


def _base_args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "debug": False,
        "timeout": 1.0,
        "workers": 4,
        "retries": 1,
        "targets": "10.0.0.1",
        "hosts": None,
        "hosts_file": None,
        "profiles_file": None,
        "output": None,
        "output_format": "txt",
        "save_responses_dir": None,
        "deep": False,
        "pprof_seconds": 5,
        "trace_seconds": 2,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_collect_stage_runs_scan_before_collect(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    captured: dict[str, object] = {}

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        calls.append("scan")
        return 4, 1, {"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        calls.append("collect")
        captured["found_by_host"] = kwargs.get("found_by_host")
        return 2, 2

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)

    rc = run_collect_stage(_base_args(), AttemptLogger())
    assert rc == 0
    assert calls == ["scan", "collect"]
    assert captured["found_by_host"] == {"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]}


def test_collect_stage_skips_collect_when_scan_finds_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        calls.append("scan")
        return 4, 0, {"10.0.0.1": []}

    def fake_collect(*_args: object, **_kwargs: object) -> tuple[int, int]:
        calls.append("collect")
        return 0, 0

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)

    rc = run_collect_stage(_base_args(), AttemptLogger())
    assert rc == 0
    assert calls == ["scan"]


def test_collect_stage_hides_scan_and_meta_without_debug(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        emit_line = kwargs.get("emit_line")
        if callable(emit_line):
            emit_line("SCAN     10.0.0.1                         9100   [+] Node Exporter")
            emit_line("SCAN     summary                          -      [*] hosts=1 checks=1 found=1")
        return 1, 1, {"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        emit_line = kwargs.get("emit_line")
        if callable(emit_line):
            emit_line(
                "COLLECT  10.0.0.1                         9100   [+] Node Exporter url=http://10.0.0.1:9100/debug/vars"
            )
            emit_line("COLLECT  summary                          -      [*] hosts=1 requests=1 success=1")
        return 1, 1

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)

    rc = run_collect_stage(_base_args(debug=False), AttemptLogger())
    assert rc == 0

    out = capsys.readouterr().out
    assert "SCAN" not in out
    assert "collect started" not in out
    assert "collect complete" in out
    assert "Node Exporter url=http://10.0.0.1:9100/debug/vars" in out


def test_collect_stage_creates_empty_index_when_save_dir_set_and_no_hits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    save_dir = tmp_path / "collect_raw"

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return 4, 0, {"10.0.0.1": []}

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)

    rc = run_collect_stage(_base_args(save_responses_dir=str(save_dir)), AttemptLogger())
    assert rc == 0
    assert (save_dir / "index.jsonl").exists()


def test_collect_stage_runs_validation_always(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    captured: dict[str, object] = {}

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        calls.append("scan")
        return 1, 1, {"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        calls.append("collect")
        captured["save_responses_dir"] = kwargs.get("save_responses_dir")
        records_sink = kwargs.get("records_sink")
        if isinstance(records_sink, list):
            records_sink.append(
                {
                    "host": "10.0.0.1",
                    "port": 9100,
                    "exporter": "node_exporter",
                    "endpoint": "/debug/vars",
                    "body": "password=secret",
                }
            )
        return 1, 1

    def fake_validate_records(
        records: list[dict[str, object]],
        *,
        input_format: str,
        show: bool,
        max_lines: int,
        fail_on_creds: bool,
        debug: bool,
        console: object,
    ) -> int:
        calls.append("validate")
        captured["records_len"] = len(records)
        captured["input_format"] = input_format
        captured["show"] = show
        captured["max_lines"] = max_lines
        captured["fail_on_creds"] = fail_on_creds
        captured["debug"] = debug
        captured["console_set"] = console is not None
        return 0

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)
    monkeypatch.setattr("redposture_core.stage_collect.run_validation_records", fake_validate_records)

    rc = run_collect_stage(
        _base_args(
            save_responses_dir="collect_raw",
        ),
        AttemptLogger(),
    )
    assert rc == 0
    assert calls == ["scan", "collect", "validate"]
    assert captured["save_responses_dir"] == "collect_raw"
    assert captured["records_len"] == 1
    assert captured["input_format"] == "auto"
    assert captured["show"] is True
    assert captured["max_lines"] == 0
    assert captured["fail_on_creds"] is False
    assert captured["debug"] is False
    assert captured["console_set"] is True


def test_collect_stage_builds_deep_endpoints_with_custom_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars", "/debug/pprof/profile?seconds={pprof_seconds}"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return 1, 1, {"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]}

    def fake_collect(*_args: object, **kwargs: object) -> tuple[int, int]:
        captured["collect_debug_endpoints"] = kwargs.get("collect_debug_endpoints")
        return 1, 1

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)

    rc = run_collect_stage(
        _base_args(
            deep=True,
            pprof_seconds=11,
            trace_seconds=4,
        ),
        AttemptLogger(),
    )

    assert rc == 0
    endpoints = tuple(captured["collect_debug_endpoints"])  # type: ignore[arg-type]
    assert "/debug/vars" in endpoints
    assert "/debug/pprof/profile?seconds=11" in endpoints
    assert "/debug/pprof/trace?seconds=4" in endpoints
