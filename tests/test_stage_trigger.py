from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from redposture_core.logger import AttemptLogger
from redposture_core.stage_trigger import _patch_trigger_exporters_for_with_listen, run_trigger_stage


def _base_args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "debug": False,
        "timeout": 1.0,
        "workers": 4,
        "retries": 1,
        "ports": None,
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

    monkeypatch.setattr("redposture_core.stage_trigger.start_listeners_for_trigger", fake_start_listeners)
    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_trigger.scan_exporters_and_trigger", fake_scan)
    monkeypatch.setattr("redposture_core.stage_trigger.stop_started_listeners", fake_stop_listeners)
    monkeypatch.setattr("redposture_core.stage_trigger.time.sleep", fake_sleep)

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

    monkeypatch.setattr("redposture_core.stage_trigger.start_listeners_for_trigger", fake_start_listeners)
    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_trigger.scan_exporters_and_trigger", fake_scan)

    rc = run_trigger_stage(_base_args(with_listen=False), AttemptLogger())
    assert rc == 0
    assert calls == ["scan"]


def test_trigger_custom_ports_override_exporter_port(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_ports: list[int] = []

    def fake_scan(*_args: object, **kwargs: object) -> dict[str, object]:
        exporters = kwargs.get("trigger_exporters")
        assert isinstance(exporters, list)
        for item in exporters:
            assert isinstance(item, dict)
            captured_ports.append(int(item.get("port", 0)))
        return {
            "detected_exporters": 0,
            "attempted": 0,
            "triggered": 0,
            "failed": 0,
            "by_host": {"10.0.0.1": {"detected": 0, "attempted": 0, "success": 0, "fail": 0}},
            "by_callback": {"10.0.0.2": {"success": 0, "fail": 0}},
        }

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "trigger_exporters": [
                {
                    "name": "redis_exporter",
                    "port": 9121,
                    "detect_path": "/metrics",
                    "markers": ("redis_up",),
                    "trigger_path": "/scrape",
                    "target_fmt": "{our_host}:6379",
                }
            ]
        }

    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_trigger.scan_exporters_and_trigger", fake_scan)

    rc = run_trigger_stage(
        _base_args(with_listen=False, ports="19121,29121"),
        AttemptLogger(),
    )
    assert rc == 0
    assert captured_ports == [19121, 29121]


def test_trigger_custom_single_port_override_exporter_port(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_ports: list[int] = []

    def fake_scan(*_args: object, **kwargs: object) -> dict[str, object]:
        exporters = kwargs.get("trigger_exporters")
        assert isinstance(exporters, list)
        for item in exporters:
            assert isinstance(item, dict)
            captured_ports.append(int(item.get("port", 0)))
        return {
            "detected_exporters": 0,
            "attempted": 0,
            "triggered": 0,
            "failed": 0,
            "by_host": {"10.0.0.1": {"detected": 0, "attempted": 0, "success": 0, "fail": 0}},
            "by_callback": {"10.0.0.2": {"success": 0, "fail": 0}},
        }

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "trigger_exporters": [
                {
                    "name": "redis_exporter",
                    "port": 9121,
                    "detect_path": "/metrics",
                    "markers": ("redis_up",),
                    "trigger_path": "/scrape",
                    "target_fmt": "{our_host}:6379",
                }
            ]
        }

    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_trigger.scan_exporters_and_trigger", fake_scan)

    rc = run_trigger_stage(
        _base_args(with_listen=False, ports="19121"),
        AttemptLogger(),
    )
    assert rc == 0
    assert captured_ports == [19121]


def test_trigger_custom_ports_override_exporter_port_from_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_ports: list[int] = []
    ports_file = tmp_path / "ports.txt"
    ports_file.write_text("19121\n29121\n", encoding="utf-8")

    def fake_scan(*_args: object, **kwargs: object) -> dict[str, object]:
        exporters = kwargs.get("trigger_exporters")
        assert isinstance(exporters, list)
        for item in exporters:
            assert isinstance(item, dict)
            captured_ports.append(int(item.get("port", 0)))
        return {
            "detected_exporters": 0,
            "attempted": 0,
            "triggered": 0,
            "failed": 0,
            "by_host": {"10.0.0.1": {"detected": 0, "attempted": 0, "success": 0, "fail": 0}},
            "by_callback": {"10.0.0.2": {"success": 0, "fail": 0}},
        }

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "trigger_exporters": [
                {
                    "name": "redis_exporter",
                    "port": 9121,
                    "detect_path": "/metrics",
                    "markers": ("redis_up",),
                    "trigger_path": "/scrape",
                    "target_fmt": "{our_host}:6379",
                }
            ]
        }

    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_trigger.scan_exporters_and_trigger", fake_scan)

    rc = run_trigger_stage(
        _base_args(with_listen=False, ports=str(ports_file)),
        AttemptLogger(),
    )
    assert rc == 0
    assert captured_ports == [19121, 29121]


def test_trigger_rejects_invalid_ports_value(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {"trigger_exporters": []}

    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    rc = run_trigger_stage(_base_args(with_listen=False, ports="bad-port"), AttemptLogger())
    assert rc == 2


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
                "redposture.example.com": {"success": 1, "fail": 0},
            },
        }

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {"trigger_exporters": []}

    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_trigger.scan_exporters_and_trigger", fake_scan)

    rc = run_trigger_stage(
        _base_args(with_listen=False, callback_dns="redposture.example.com"),
        AttemptLogger(),
    )
    assert rc == 0
    assert captured_targets == ["10.0.0.2", "redposture.example.com"]


def test_trigger_requires_callback_ip_or_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {"trigger_exporters": []}

    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    rc = run_trigger_stage(
        _base_args(callback_ip=None, callback_dns=None),
        AttemptLogger(),
    )
    assert rc == 2


def test_trigger_rejects_hostname_in_callback_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {"trigger_exporters": []}

    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    rc = run_trigger_stage(
        _base_args(callback_ip="redposture.example.com", callback_dns=None),
        AttemptLogger(),
    )
    assert rc == 2


def test_trigger_output_file_contains_full_unclipped_event(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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

    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_trigger.scan_exporters_and_trigger", fake_scan)

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

    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_trigger.scan_exporters_and_trigger", fake_scan)

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

    monkeypatch.setattr("redposture_core.stage_trigger.start_listeners_for_trigger", fake_start_listeners)
    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_trigger.scan_exporters_and_trigger", fake_scan)
    monkeypatch.setattr("redposture_core.stage_trigger.stop_started_listeners", fake_stop_listeners)
    monkeypatch.setattr("redposture_core.stage_trigger.time.sleep", fake_sleep)

    rc = run_trigger_stage(
        _base_args(with_listen=True, output=None, debug=False),
        AttemptLogger(),
    )
    assert rc == 0
    assert captured == {"logger_is_set": False, "log_trigger_events_only": True}


def test_trigger_with_listen_debug_disables_callback_dedup(monkeypatch: pytest.MonkeyPatch) -> None:
    class ProbeLogger(AttemptLogger):
        def __init__(self) -> None:
            super().__init__()
            self.calls: list[bool] = []

        def set_trigger_callback_mode(  # type: ignore[override]
            self,
            enabled: bool,
            callback_targets: list[str] | tuple[str, ...] | None = None,
            *,
            deduplicate: bool = True,
        ) -> None:
            self.calls.append(bool(deduplicate))
            super().set_trigger_callback_mode(enabled, callback_targets=callback_targets, deduplicate=deduplicate)

    def fake_start_listeners(*_args: object, **_kwargs: object) -> tuple[list[object], None]:
        return [], None

    def fake_scan(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "detected_exporters": 0,
            "attempted": 0,
            "triggered": 0,
            "failed": 0,
            "by_host": {"10.0.0.1": {"detected": 0, "attempted": 0, "success": 0, "fail": 0}},
            "by_callback": {"10.0.0.2": {"success": 0, "fail": 0}},
        }

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {"trigger_exporters": []}

    def fake_stop_listeners(*_args: object, **_kwargs: object) -> None:
        return None

    def fake_sleep(_seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("redposture_core.stage_trigger.start_listeners_for_trigger", fake_start_listeners)
    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_trigger.scan_exporters_and_trigger", fake_scan)
    monkeypatch.setattr("redposture_core.stage_trigger.stop_started_listeners", fake_stop_listeners)
    monkeypatch.setattr("redposture_core.stage_trigger.time.sleep", fake_sleep)

    logger = ProbeLogger()
    rc = run_trigger_stage(
        _base_args(with_listen=True, output=None, debug=True),
        logger,
    )
    assert rc == 0
    assert logger.calls and logger.calls[0] is False


def test_trigger_with_listen_scan_rows_show_target_once_not_callback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_start_listeners(*_args: object, **_kwargs: object) -> tuple[list[object], None]:
        return [], None

    def fake_scan(*_args: object, **kwargs: object) -> dict[str, object]:
        emit = kwargs.get("emit_trigger_event")
        assert callable(emit)
        emit(
            {
                "phase": "callback_attempt",
                "host": "127.0.0.1",
                "exporter": "redis_exporter",
                "exporter_port": 16379,
                "callback_target": "127.0.0.1",
                "callback_port": "16379",
            }
        )
        emit(
            {
                "phase": "callback_attempt",
                "host": "127.0.0.1",
                "exporter": "redis_exporter",
                "exporter_port": 16379,
                "callback_target": "host.docker.internal",
                "callback_port": "16379",
            }
        )
        return {
            "detected_exporters": 1,
            "attempted": 2,
            "triggered": 2,
            "failed": 0,
            "by_host": {"127.0.0.1": {"detected": 1, "attempted": 2, "success": 2, "fail": 0}},
            "by_callback": {
                "127.0.0.1": {"success": 1, "fail": 0},
                "host.docker.internal": {"success": 1, "fail": 0},
            },
        }

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {"trigger_exporters": []}

    def fake_stop_listeners(*_args: object, **_kwargs: object) -> None:
        return None

    def fake_sleep(_seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("redposture_core.stage_trigger.start_listeners_for_trigger", fake_start_listeners)
    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_trigger.scan_exporters_and_trigger", fake_scan)
    monkeypatch.setattr("redposture_core.stage_trigger.stop_started_listeners", fake_stop_listeners)
    monkeypatch.setattr("redposture_core.stage_trigger.time.sleep", fake_sleep)

    rc = run_trigger_stage(
        _base_args(with_listen=True, callback_dns="host.docker.internal", output=None, debug=False),
        AttemptLogger(),
    )
    assert rc == 0

    out = capsys.readouterr().out
    scan_lines = [line for line in out.splitlines() if "SCAN" in line]
    assert len(scan_lines) == 1
    assert "127.0.0.1" in scan_lines[0]
    assert "16379" in scan_lines[0]
    assert "Redis Exporter" in scan_lines[0]
    assert "host.docker.internal" not in scan_lines[0]


def test_trigger_with_listen_summary_uses_received_callbacks(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    logger = AttemptLogger()

    def fake_start_listeners(*_args: object, **_kwargs: object) -> tuple[list[object], None]:
        return [], None

    def fake_scan(*_args: object, **_kwargs: object) -> dict[str, object]:
        logger.log("redis", ("127.0.0.1", 60100), username="default", password="redis", listen_port=16379)
        logger.log("postgres", ("127.0.0.1", 60101), username="postgres", password="postgres", listen_port=15432)
        return {
            "detected_exporters": 4,
            "attempted": 4,
            "triggered": 1,
            "failed": 3,
            "by_host": {"127.0.0.1": {"detected": 4, "attempted": 4, "success": 1, "fail": 3}},
            "by_callback": {"10.0.0.2": {"success": 1, "fail": 3}},
            "by_exporter": {
                "redis_exporter": {"detected": 1, "attempted": 1, "success": 1, "fail": 0},
                "postgres_exporter": {"detected": 1, "attempted": 1, "success": 0, "fail": 1},
                "blackbox_exporter": {"detected": 1, "attempted": 1, "success": 0, "fail": 1},
                "proxmox_exporter": {"detected": 1, "attempted": 1, "success": 0, "fail": 1},
            },
        }

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {"trigger_exporters": []}

    def fake_stop_listeners(*_args: object, **_kwargs: object) -> None:
        return None

    def fake_sleep(_seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("redposture_core.stage_trigger.start_listeners_for_trigger", fake_start_listeners)
    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_trigger.scan_exporters_and_trigger", fake_scan)
    monkeypatch.setattr("redposture_core.stage_trigger.stop_started_listeners", fake_stop_listeners)
    monkeypatch.setattr("redposture_core.stage_trigger.time.sleep", fake_sleep)

    rc = run_trigger_stage(_base_args(with_listen=True), logger)
    assert rc == 0
    out = capsys.readouterr().out
    assert "trigger complete: hosts=1 detected=4 attempts=4 success=2 fail=2" in out


def test_trigger_with_listen_warns_when_proxmox_tls_is_disabled_for_pve_profile(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_start_listeners(*_args: object, **_kwargs: object) -> tuple[list[object], None]:
        return [], None

    def fake_scan(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "detected_exporters": 0,
            "attempted": 0,
            "triggered": 0,
            "failed": 0,
            "by_host": {"10.0.0.1": {"detected": 0, "attempted": 0, "success": 0, "fail": 0}},
            "by_callback": {"10.0.0.2": {"success": 0, "fail": 0}},
        }

    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {
            "trigger_exporters": [
                {
                    "name": "proxmox_exporter",
                    "port": 9221,
                    "detect_path": "/metrics",
                    "markers": ("pve_", "proxmox_"),
                    "trigger_path": "/pve",
                    "target_fmt": "{our_host}:8006",
                }
            ]
        }

    def fake_stop_listeners(*_args: object, **_kwargs: object) -> None:
        return None

    def fake_sleep(_seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("redposture_core.stage_trigger.start_listeners_for_trigger", fake_start_listeners)
    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_trigger.scan_exporters_and_trigger", fake_scan)
    monkeypatch.setattr("redposture_core.stage_trigger.stop_started_listeners", fake_stop_listeners)
    monkeypatch.setattr("redposture_core.stage_trigger.time.sleep", fake_sleep)

    rc = run_trigger_stage(
        _base_args(with_listen=True, proxmox_tls=False),
        AttemptLogger(),
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "proxmox callback likely to fail" in out
    assert "--proxmox-tls" in out


def test_patch_with_listen_proxmox_target_includes_ticket_path() -> None:
    args = argparse.Namespace(
        postgres_port=15432,
        redis_port=16379,
        proxmox_port=18006,
        blackbox_port=19115,
        proxmox_tls=True,
    )
    exporters = [{"name": "proxmox_exporter", "target_fmt": "https://{our_host}:8006/api2/json/access/ticket"}]
    patched = _patch_trigger_exporters_for_with_listen(exporters, args)
    assert patched[0]["target_fmt"] == "https://{our_host}:18006/api2/json/access/ticket"


def test_patch_with_listen_proxmox_target_for_pve_path_uses_host_port() -> None:
    args = argparse.Namespace(
        postgres_port=15432,
        redis_port=16379,
        proxmox_port=18006,
        blackbox_port=19115,
        proxmox_tls=True,
    )
    exporters = [{"name": "proxmox_exporter", "trigger_path": "/pve", "target_fmt": "{our_host}:8006"}]
    patched = _patch_trigger_exporters_for_with_listen(exporters, args)
    assert patched[0]["target_fmt"] == "{our_host}:18006"


def test_patch_with_listen_postgres_target_uses_dsn() -> None:
    args = argparse.Namespace(
        postgres_port=15432,
        redis_port=16379,
        proxmox_port=18006,
        blackbox_port=19115,
        proxmox_tls=False,
    )
    exporters = [
        {
            "name": "postgres_exporter",
            "target_fmt": "postgresql://real_user:real_pass@db.example.internal:5432/appdb?sslmode=require",
        }
    ]
    patched = _patch_trigger_exporters_for_with_listen(exporters, args)
    assert patched[0]["target_fmt"] == "postgresql://real_user:real_pass@{our_host}:15432/appdb?sslmode=require"


def test_patch_with_listen_redis_target_preserves_credentials() -> None:
    args = argparse.Namespace(
        postgres_port=15432,
        redis_port=16379,
        proxmox_port=18006,
        blackbox_port=19115,
        proxmox_tls=False,
    )
    exporters = [
        {
            "name": "redis_exporter",
            "target_fmt": "redis://default:redis@cache.example.internal:6379/1?dial_timeout=1s",
        }
    ]
    patched = _patch_trigger_exporters_for_with_listen(exporters, args)
    assert patched[0]["target_fmt"] == "redis://default:redis@{our_host}:16379/1?dial_timeout=1s"


def test_patch_with_listen_blackbox_target_preserves_credentials() -> None:
    args = argparse.Namespace(
        postgres_port=15432,
        redis_port=16379,
        proxmox_port=18006,
        blackbox_port=19115,
        proxmox_tls=False,
    )
    exporters = [{"name": "blackbox_exporter", "target_fmt": "http://blackbox:blackbox@{our_host}"}]
    patched = _patch_trigger_exporters_for_with_listen(exporters, args)
    assert patched[0]["target_fmt"] == "http://blackbox:blackbox@{our_host}:19115"
