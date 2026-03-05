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
    assert "DISCOVER" in out
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
        record_callback = kwargs.get("record_callback")
        if callable(record_callback):
            record_callback(
                {
                    "host": "10.0.0.1",
                    "port": 9100,
                    "exporter": "node_exporter",
                    "endpoint": "/debug/vars",
                    "body": "password=secret",
                }
            )
        return 1, 1

    class FakeAccumulator:
        def __init__(self, *, input_format: str, max_lines: int) -> None:
            calls.append("validator_init")
            self._records: list[dict[str, object]] = []
            captured["input_format"] = input_format
            captured["max_lines"] = max_lines

        def feed(self, record: dict[str, object]) -> None:
            calls.append("validator_feed")
            self._records.append(record)

        def finish(
            self,
            *,
            show: bool,
            fail_on_creds: bool,
            debug: bool,
            console: object,
            source: str,
            records_total: int | None = None,
        ) -> int:
            calls.append("validate")
            captured["records_len"] = len(self._records)
            captured["show"] = show
            captured["fail_on_creds"] = fail_on_creds
            captured["debug"] = debug
            captured["console_set"] = console is not None
            captured["source"] = source
            return 0

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.collect_exporter_debug_data", fake_collect)
    monkeypatch.setattr("redposture_core.stage_collect.ValidationRecordAccumulator", FakeAccumulator)

    rc = run_collect_stage(
        _base_args(
            save_responses_dir="collect_raw",
        ),
        AttemptLogger(),
    )
    assert rc == 0
    assert calls == ["validator_init", "scan", "collect", "validator_feed", "validate"]
    assert captured["save_responses_dir"] == "collect_raw"
    assert captured["records_len"] == 1
    assert captured["input_format"] == "auto"
    assert captured["show"] is True
    assert captured["max_lines"] == 0
    assert captured["fail_on_creds"] is False
    assert captured["debug"] is False
    assert captured["console_set"] is True
    assert captured["source"] == "stream"


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


@pytest.mark.parametrize("debug_mode", [False, True])
def test_collect_stage_hides_validate_summary_line(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    debug_mode: bool,
) -> None:
    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "discovery_exporters": [],
            "collect_exporters": [],
            "collect_debug_endpoints": ["/debug/vars"],
        }

    def fake_scan(*_args: object, **_kwargs: object) -> tuple[int, int, dict[str, list[dict[str, object]]]]:
        return 1, 0, {"10.0.0.1": []}

    class FakeAccumulator:
        def __init__(self, *, input_format: str, max_lines: int) -> None:
            _ = input_format
            _ = max_lines

        def feed(self, record: dict[str, object]) -> None:
            _ = record

        def finish(
            self,
            *,
            show: bool,
            fail_on_creds: bool,
            debug: bool,
            console: object,
            source: str,
            records_total: int | None = None,
        ) -> int:
            _ = (show, fail_on_creds, debug, source, records_total)
            console.plain("VALIDATE\t-\t-\t [!] validate complete: lines=10 credential_hits=2")
            return 0

    monkeypatch.setattr("redposture_core.stage_collect.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_collect.scan_exporter_presence", fake_scan)
    monkeypatch.setattr("redposture_core.stage_collect.ValidationRecordAccumulator", FakeAccumulator)

    rc = run_collect_stage(_base_args(debug=debug_mode), AttemptLogger())
    assert rc == 0

    out = capsys.readouterr().out
    assert "validate complete: lines=" not in out
