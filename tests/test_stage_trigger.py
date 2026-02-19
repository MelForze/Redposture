from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from honeycore.logger import AttemptLogger
from honeycore.stage_trigger import run_trigger_stage


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
        "callback_ip": "10.0.0.2",
        "callback_dns": None,
        "with_listen": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_trigger_with_listen_starts_listeners_before_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_start_listeners(*_args: object, **_kwargs: object) -> tuple[list[object], None]:
        calls.append("start")
        return [], None

    def fake_scan(*_args: object, **_kwargs: object) -> dict[str, object]:
        calls.append("scan")
        return {
            "detected_exporters": 1,
            "attempted": 1,
            "triggered": 1,
            "failed": 0,
            "by_host": {"10.0.0.1": {"detected": 1, "attempted": 1, "success": 1, "fail": 0}},
            "by_callback": {"10.0.0.2": {"success": 1, "fail": 0}},
        }

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {"trigger_exporters": []}

    def fake_stop_listeners(*_args: object, **_kwargs: object) -> None:
        calls.append("stop")

    def fake_sleep(_seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("honeycore.stage_trigger.start_listeners_for_trigger", fake_start_listeners)
    monkeypatch.setattr("honeycore.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("honeycore.stage_trigger.scan_exporters_and_trigger", fake_scan)
    monkeypatch.setattr("honeycore.stage_trigger.stop_started_listeners", fake_stop_listeners)
    monkeypatch.setattr("honeycore.stage_trigger.time.sleep", fake_sleep)

    rc = run_trigger_stage(_base_args(with_listen=True), AttemptLogger())
    assert rc == 0
    assert calls == ["start", "scan", "stop"]


def test_trigger_without_listen_does_not_start_listeners(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_start_listeners(*_args: object, **_kwargs: object) -> tuple[list[object], None]:
        calls.append("start")
        return [], None

    def fake_scan(*_args: object, **_kwargs: object) -> dict[str, object]:
        calls.append("scan")
        return {
            "detected_exporters": 1,
            "attempted": 1,
            "triggered": 1,
            "failed": 0,
            "by_host": {"10.0.0.1": {"detected": 1, "attempted": 1, "success": 1, "fail": 0}},
            "by_callback": {"10.0.0.2": {"success": 1, "fail": 0}},
        }

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {"trigger_exporters": []}

    monkeypatch.setattr("honeycore.stage_trigger.start_listeners_for_trigger", fake_start_listeners)
    monkeypatch.setattr("honeycore.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("honeycore.stage_trigger.scan_exporters_and_trigger", fake_scan)

    rc = run_trigger_stage(_base_args(with_listen=False), AttemptLogger())
    assert rc == 0
    assert calls == ["scan"]


def test_trigger_uses_both_callback_ip_and_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_targets: list[str] = []

    def fake_scan(*_args: object, **kwargs: object) -> dict[str, object]:
        targets = kwargs.get("callback_targets")
        assert isinstance(targets, list)
        captured_targets.extend(str(item) for item in targets)
        return {
            "detected_exporters": 1,
            "attempted": 2,
            "triggered": 2,
            "failed": 0,
            "by_host": {"10.0.0.1": {"detected": 1, "attempted": 2, "success": 2, "fail": 0}},
            "by_callback": {
                "10.0.0.2": {"success": 1, "fail": 0},
                "honeypot.example.com": {"success": 1, "fail": 0},
            },
        }

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {"trigger_exporters": []}

    monkeypatch.setattr("honeycore.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("honeycore.stage_trigger.scan_exporters_and_trigger", fake_scan)

    rc = run_trigger_stage(
        _base_args(with_listen=False, callback_dns="honeypot.example.com"),
        AttemptLogger(),
    )
    assert rc == 0
    assert captured_targets == ["10.0.0.2", "honeypot.example.com"]


def test_trigger_requires_callback_ip_or_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {"trigger_exporters": []}

    monkeypatch.setattr("honeycore.stage_trigger.load_profiles", fake_load_profiles)
    rc = run_trigger_stage(
        _base_args(callback_ip=None, callback_dns=None),
        AttemptLogger(),
    )
    assert rc == 2


def test_trigger_rejects_hostname_in_callback_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {"trigger_exporters": []}

    monkeypatch.setattr("honeycore.stage_trigger.load_profiles", fake_load_profiles)
    rc = run_trigger_stage(
        _base_args(callback_ip="honeypot.example.com", callback_dns=None),
        AttemptLogger(),
    )
    assert rc == 2


def test_trigger_output_file_contains_full_unclipped_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_path = tmp_path / "trigger.txt"
    long_startup = "x" * 220

    def fake_scan(*_args: object, **kwargs: object) -> dict[str, object]:
        logger = kwargs.get("logger")
        if isinstance(logger, AttemptLogger):
            logger.log("postgres", ("10.0.0.4", 5432), startup={"application_name": long_startup})
        return {
            "detected_exporters": 1,
            "attempted": 1,
            "triggered": 1,
            "failed": 0,
            "by_host": {"10.0.0.1": {"detected": 1, "attempted": 1, "success": 1, "fail": 0}},
            "by_callback": {"10.0.0.2": {"success": 1, "fail": 0}},
        }

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {"trigger_exporters": []}

    monkeypatch.setattr("honeycore.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("honeycore.stage_trigger.scan_exporters_and_trigger", fake_scan)

    rc = run_trigger_stage(
        _base_args(with_listen=False, output=str(output_path), debug=True),
        AttemptLogger(),
    )
    assert rc == 0
    saved = output_path.read_text(encoding="utf-8")
    assert long_startup in saved
    assert "[Postgres]" in saved


def test_trigger_without_listen_enables_attempt_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_scan(*_args: object, **kwargs: object) -> dict[str, object]:
        captured["logger_is_set"] = kwargs.get("logger") is not None
        captured["log_trigger_events_only"] = kwargs.get("log_trigger_events_only")
        return {
            "detected_exporters": 1,
            "attempted": 1,
            "triggered": 1,
            "failed": 0,
            "by_host": {"10.0.0.1": {"detected": 1, "attempted": 1, "success": 1, "fail": 0}},
            "by_callback": {"10.0.0.2": {"success": 1, "fail": 0}},
        }

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {"trigger_exporters": []}

    monkeypatch.setattr("honeycore.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("honeycore.stage_trigger.scan_exporters_and_trigger", fake_scan)

    rc = run_trigger_stage(
        _base_args(with_listen=False, output="trigger.txt", debug=False),
        AttemptLogger(),
    )
    assert rc == 0
    assert captured == {"logger_is_set": True, "log_trigger_events_only": True}


def test_trigger_with_listen_disables_trigger_attempt_logs(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_start_listeners(*_args: object, **_kwargs: object) -> tuple[list[object], None]:
        return [], None

    def fake_scan(*_args: object, **kwargs: object) -> dict[str, object]:
        captured["logger_is_set"] = kwargs.get("logger") is not None
        captured["log_trigger_events_only"] = kwargs.get("log_trigger_events_only")
        return {
            "detected_exporters": 1,
            "attempted": 1,
            "triggered": 1,
            "failed": 0,
            "by_host": {"10.0.0.1": {"detected": 1, "attempted": 1, "success": 1, "fail": 0}},
            "by_callback": {"10.0.0.2": {"success": 1, "fail": 0}},
        }

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {"trigger_exporters": []}

    def fake_stop_listeners(*_args: object, **_kwargs: object) -> None:
        return None

    def fake_sleep(_seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("honeycore.stage_trigger.start_listeners_for_trigger", fake_start_listeners)
    monkeypatch.setattr("honeycore.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("honeycore.stage_trigger.scan_exporters_and_trigger", fake_scan)
    monkeypatch.setattr("honeycore.stage_trigger.stop_started_listeners", fake_stop_listeners)
    monkeypatch.setattr("honeycore.stage_trigger.time.sleep", fake_sleep)

    rc = run_trigger_stage(
        _base_args(with_listen=True, output=None, debug=False),
        AttemptLogger(),
    )
    assert rc == 0
    assert captured == {"logger_is_set": False, "log_trigger_events_only": True}
