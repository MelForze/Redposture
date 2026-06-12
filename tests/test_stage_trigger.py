from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from redposture_core import stage_trigger as trigger
from redposture_core.console import Console
from redposture_core.logger import AttemptLogger
from redposture_core.stage_trigger import (
    _patch_trigger_exporters_for_with_listen,
    _run_trigger_credential_checks,
    run_trigger_stage,
)


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
        "output_format": "txt",
        "callback_ip": "10.0.0.2",
        "callback_dns": None,
        "with_listen": False,
        "listen_seconds": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_trigger_small_helpers_cover_text_json_and_filters(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert trigger._clip_text("abcdef", 3) == "abc"
    assert trigger._safe_int("42") == 42
    assert trigger._safe_int("bad") is None
    assert trigger._as_text("  x  ") == "x"
    assert trigger._as_text("") is None

    assert trigger._json_record_from_trigger_event({"phase": "detect_hit"}) is None
    event = {
        "phase": "callback_result",
        "host": "10.0.0.1",
        "exporter": "redis_exporter",
        "exporter_port": "9121",
        "callback_port": "6379",
        "callback_target": "10.0.0.2",
        "trigger_url": "http://x",
        "target": "redis://x",
        "success": True,
        "probe_success": True,
        "status": "200",
    }
    rec = trigger._json_record_from_trigger_event(event)
    assert rec is not None
    assert rec["status"] == "trigger_success"
    assert rec["http_status"] == 200

    out_file = tmp_path / "trigger_records.jsonl"
    trigger._write_trigger_json_records(str(out_file), [rec])
    assert out_file.exists()
    assert out_file.read_text(encoding="utf-8").strip()

    trigger._write_trigger_json_records(None, [rec])
    stdout = capsys.readouterr().out
    assert '"source_type": "trigger"' in stdout

    assert trigger._parse_trigger_exporter_filter(None) == set()
    assert trigger._parse_trigger_exporter_filter("redis,postgres_exporter") == {
        "redis_exporter",
        "postgres_exporter",
    }
    with pytest.raises(ValueError):
        trigger._parse_trigger_exporter_filter("unknown")

    assert trigger._parse_postgres_auth_modules(["a,b", "b", "c"]) == ["a", "b", "c"]
    assert trigger._merge_trigger_query_auth_module("x=1&auth_module=old", "new") == "x=1&auth_module=new"

    expanded = trigger._expand_trigger_exporters_postgres_auth_modules(
        [{"name": "postgres_exporter", "trigger_query": "x=1"}, {"name": "redis_exporter"}],
        ["scram", "md5"],
    )
    assert len(expanded) == 3
    assert sum(1 for item in expanded if item["name"] == "postgres_exporter") == 2

    filtered = trigger._filter_trigger_exporters(
        [{"name": "redis_exporter"}, {"name": "postgres_exporter"}],
        {"redis_exporter"},
    )
    assert filtered == [{"name": "redis_exporter"}]

    overridden = trigger._override_trigger_exporter_ports([{"name": "redis_exporter", "port": 9121}], [19121, 29121])
    assert [int(item["port"]) for item in overridden] == [19121, 29121]

    assert trigger._callback_event_has_complete_creds({"username": "u", "password": "p"}) is True
    assert trigger._callback_event_has_complete_creds({"username": "u", "password": ""}) is False
    assert trigger._callback_event_remote_host({"remote_addr": "10.0.0.1:1234"}) == "10.0.0.1"


def test_auto_adjust_listener_services_for_trigger_exporters() -> None:
    console = Console(debug=True)
    args = argparse.Namespace(with_listen=True, services="redis", debug=True)
    trigger._auto_adjust_listener_services_for_trigger_exporters(args, {"postgres_exporter"}, console)
    assert set(str(args.services).split(",")) == {"redis", "postgres"}

    args_default = argparse.Namespace(with_listen=True, services="postgres,redis,proxmox,blackbox", debug=False)
    trigger._auto_adjust_listener_services_for_trigger_exporters(args_default, {"redis_exporter"}, console)
    assert args_default.services == "redis"


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


def test_trigger_with_listen_seconds_auto_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monotonic_values = iter([10.0, 10.2, 10.7])
    sleep_calls: list[float] = []

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

    monkeypatch.setattr("redposture_core.stage_trigger.start_listeners_for_trigger", fake_start_listeners)
    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_trigger.scan_exporters_and_trigger", fake_scan)
    monkeypatch.setattr("redposture_core.stage_trigger.stop_started_listeners", fake_stop_listeners)
    monkeypatch.setattr("redposture_core.stage_trigger.time.monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr("redposture_core.stage_trigger.time.sleep", lambda seconds: sleep_calls.append(seconds))

    rc = run_trigger_stage(_base_args(with_listen=True, listen_seconds=0.5), AttemptLogger())
    assert rc == 0
    assert calls == ["start", "scan", "stop"]
    assert sleep_calls == [pytest.approx(0.3)]


def test_trigger_credential_checks_postgres_passes_sql_command_none(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_kwargs: list[dict[str, object]] = []

    class _DummyLogger:
        def get_trigger_callback_events(self) -> list[dict[str, str]]:
            return [
                {
                    "service": "postgres",
                    "username": "postgres",
                    "password": "postgres",
                    "remote_addr": "10.10.10.10:12345",
                }
            ]

        def write_text_line(self, _line: str) -> None:
            return

    def fake_audit_postgres_host(**kwargs: object) -> dict[str, object]:
        captured_kwargs.append(dict(kwargs))
        return {
            "status": "auth_required",
            "error": "password authentication failed",
            "superuser": False,
            "can_execute_commands": False,
            "can_read_tables": False,
            "table_count": 0,
        }

    monkeypatch.setattr("redposture_core.stage_postgres._audit_postgres_host", fake_audit_postgres_host)

    args = argparse.Namespace(timeout=1.0, retries=0)
    _run_trigger_credential_checks(args, _DummyLogger(), Console(debug=False))

    assert captured_kwargs
    assert captured_kwargs[0].get("sql_command") is None


def test_trigger_credential_checks_redis_hides_auth_error_details_without_debug(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class _DummyLogger:
        def get_trigger_callback_events(self) -> list[dict[str, str]]:
            return [
                {
                    "service": "redis",
                    "username": "default",
                    "password": "password",
                    "remote_addr": "10.10.10.10:12345",
                }
            ]

        def write_text_line(self, _line: str) -> None:
            return

    def fake_audit_redis_host(**_kwargs: object) -> dict[str, object]:
        return {
            "status": "auth_required",
            "error": "ERR wrong number of arguments for 'auth' command",
            "key_count": None,
        }

    monkeypatch.setattr("redposture_core.stage_redis._audit_redis_host", fake_audit_redis_host)

    args = argparse.Namespace(timeout=1.0, retries=0, debug=False)
    _run_trigger_credential_checks(args, _DummyLogger(), Console(debug=False))

    out = capsys.readouterr().out
    assert "default:password auth failed" in out
    assert "wrong number of arguments" not in out


def test_trigger_credential_checks_redis_shows_auth_error_details_in_debug(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class _DummyLogger:
        def get_trigger_callback_events(self) -> list[dict[str, str]]:
            return [
                {
                    "service": "redis",
                    "username": "default",
                    "password": "password",
                    "remote_addr": "10.10.10.10:12345",
                }
            ]

        def write_text_line(self, _line: str) -> None:
            return

    def fake_audit_redis_host(**_kwargs: object) -> dict[str, object]:
        return {
            "status": "auth_required",
            "error": "ERR wrong number of arguments for 'auth' command",
            "key_count": None,
        }

    monkeypatch.setattr("redposture_core.stage_redis._audit_redis_host", fake_audit_redis_host)

    args = argparse.Namespace(timeout=1.0, retries=0, debug=True)
    _run_trigger_credential_checks(args, _DummyLogger(), Console(debug=True))

    out = capsys.readouterr().out
    assert "default:password auth failed" in out
    assert "wrong number of arguments" in out


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


def test_trigger_txt_multi_batch_uses_single_dynamic_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    progress_instances: list[object] = []

    class FakeProgress:
        def __init__(self, label: str, total: int) -> None:
            self.label = label
            self.total = total
            self.set_totals: list[int] = []
            self.advances: list[int] = []
            self.closed = False

        def advance(self, step: int = 1) -> None:
            self.advances.append(int(step))

        def set_total(self, total: int) -> None:
            self.total = int(total)
            self.set_totals.append(int(total))

        def close(self) -> None:
            self.closed = True

    def fake_start_progress(_args: argparse.Namespace, label: str, total: int, **_kwargs: object) -> FakeProgress:
        progress = FakeProgress(label, total)
        progress_instances.append(progress)
        return progress

    def fake_scan(*_args: object, **kwargs: object) -> dict[str, object]:
        hosts = kwargs.get("hosts")
        exporters = kwargs.get("trigger_exporters")
        callbacks = kwargs.get("callback_targets")
        progress_advance = kwargs.get("progress_advance")
        progress_add_total = kwargs.get("progress_add_total")
        assert isinstance(hosts, list)
        assert isinstance(exporters, list)
        assert isinstance(callbacks, list)
        assert callable(progress_advance)
        assert callable(progress_add_total)

        detect_units = len(hosts) * len(exporters)
        deep_units = detect_units * len(callbacks)
        for _ in range(detect_units):
            progress_advance(1)
        progress_add_total(deep_units)
        progress_advance(deep_units)
        return {
            "detected_exporters": detect_units,
            "attempted": deep_units,
            "triggered": deep_units,
            "failed": 0,
            "by_host": {
                str(host): {
                    "detected": len(exporters),
                    "attempted": len(exporters),
                    "success": len(exporters),
                    "fail": 0,
                }
                for host in hosts
            },
            "by_callback": {str(callback): {"success": detect_units, "fail": 0} for callback in callbacks},
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

    monkeypatch.setattr("redposture_core.stage_trigger.start_command_progress", fake_start_progress)
    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_trigger.scan_exporters_and_trigger", fake_scan)

    rc = run_trigger_stage(
        _base_args(
            with_listen=False,
            targets="10.0.0.1,http://10.0.0.2:19308/scrape",
            ports="19121,29121",
        ),
        AttemptLogger(),
    )

    assert rc == 0
    assert len(progress_instances) == 1
    progress = progress_instances[0]
    assert progress.label == "TRIGGER"
    assert progress.total == 6
    assert progress.set_totals == [5, 6]
    assert sum(progress.advances) == 6
    assert progress.closed is True


def test_trigger_json_does_not_start_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    start_calls = 0

    def fake_start_progress(*_args: object, **_kwargs: object) -> object:
        nonlocal start_calls
        start_calls += 1
        raise AssertionError("json trigger must not start progress")

    def fake_scan(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "detected_exporters": 0,
            "attempted": 0,
            "triggered": 0,
            "failed": 0,
            "by_host": {"10.0.0.1": {"detected": 0, "attempted": 0, "success": 0, "fail": 0}},
            "by_callback": {"10.0.0.2": {"success": 0, "fail": 0}},
        }

    monkeypatch.setattr("redposture_core.stage_trigger.start_command_progress", fake_start_progress)
    monkeypatch.setattr("redposture_core.stage_trigger.scan_exporters_and_trigger", fake_scan)

    rc = run_trigger_stage(_base_args(with_listen=False, output_format="json"), AttemptLogger())

    assert rc == 0
    assert start_calls == 0


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


def test_trigger_json_output_writes_structured_records(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output_path = tmp_path / "trigger.json"

    def fake_scan(*_args: object, **kwargs: object) -> dict[str, object]:
        emit = kwargs.get("emit_trigger_event")
        assert callable(emit)
        emit(
            {
                "phase": "callback_result",
                "host": "10.0.0.1",
                "exporter": "redis_exporter",
                "exporter_port": 9121,
                "callback_target": "10.0.0.2",
                "callback_port": 6379,
                "target": "redis://10.0.0.2:6379",
                "trigger_url": "http://10.0.0.1:9121/scrape?target=redis://10.0.0.2:6379",
                "status": 200,
                "probe_success": True,
                "success": True,
            }
        )
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
        _base_args(with_listen=False, output=str(output_path), output_format="json"),
        AttemptLogger(),
    )
    assert rc == 0
    lines = output_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["source_type"] == "trigger"
    assert payload["host"] == "10.0.0.1"
    assert payload["callback_target"] == "10.0.0.2"
    assert payload["listen_port"] == 6379
    assert payload["status"] == "trigger_success"
    assert payload["probe_success"] is True


def test_trigger_json_with_listen_requires_output(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {"trigger_exporters": []}

    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    rc = run_trigger_stage(
        _base_args(with_listen=True, output=None, output_format="json"),
        AttemptLogger(),
    )
    assert rc == 2


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

        def set_trigger_callback_mode(
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


def test_trigger_with_listen_closes_progress_before_credential_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeProgress:
        def __init__(self) -> None:
            self.closed = False

        def advance(self, step: int = 1) -> None:
            _ = step

        def set_total(self, total: int) -> None:
            _ = total

        def close(self) -> None:
            self.closed = True

    progress = FakeProgress()

    def fake_scan(*_args: object, **kwargs: object) -> dict[str, object]:
        progress_advance = kwargs.get("progress_advance")
        progress_add_total = kwargs.get("progress_add_total")
        assert callable(progress_advance)
        assert callable(progress_add_total)
        progress_advance(1)
        progress_add_total(1)
        progress_advance(1)
        return {
            "detected_exporters": 1,
            "attempted": 1,
            "triggered": 1,
            "failed": 0,
            "by_host": {"10.0.0.1": {"detected": 1, "attempted": 1, "success": 1, "fail": 0}},
            "by_callback": {"10.0.0.2": {"success": 1, "fail": 0}},
            "by_exporter": {"redis_exporter": {"attempted": 1, "success": 1, "fail": 0}},
        }

    def fake_start_listeners(*_args: object, **_kwargs: object) -> tuple[list[object], None]:
        return [], None

    def fake_check_credentials(*_args: object, **_kwargs: object) -> None:
        assert progress.closed is True

    monkeypatch.setattr("redposture_core.stage_trigger.start_command_progress", lambda *_a, **_k: progress)
    monkeypatch.setattr("redposture_core.stage_trigger.start_listeners_for_trigger", fake_start_listeners)
    monkeypatch.setattr("redposture_core.stage_trigger.scan_exporters_and_trigger", fake_scan)
    monkeypatch.setattr("redposture_core.stage_trigger._run_trigger_credential_checks", fake_check_credentials)

    rc = run_trigger_stage(
        _base_args(with_listen=True, check_credentials=True, listen_seconds=0),
        AttemptLogger(),
    )

    assert rc == 0
    assert progress.closed is True


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


def test_trigger_stage_argument_and_validation_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    rc = run_trigger_stage(_base_args(timeout=0), AttemptLogger())
    assert rc == 2
    rc = run_trigger_stage(_base_args(retries=-1), AttemptLogger())
    assert rc == 2
    rc = run_trigger_stage(_base_args(with_listen=True, listen_seconds=-1), AttemptLogger())
    assert rc == 2
    rc = run_trigger_stage(_base_args(with_listen=False, check_credentials=True), AttemptLogger())
    assert rc == 2

    monkeypatch.setattr(
        "redposture_core.stage_trigger.collect_scan_target_specs",
        lambda *_a, **_k: [argparse.Namespace(host="10.0.0.1", scheme="https", explicit_port=9121)],
    )
    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", lambda *_a, **_k: {"trigger_exporters": []})
    rc = run_trigger_stage(_base_args(), AttemptLogger())
    assert rc == 2

    monkeypatch.setattr(
        "redposture_core.stage_trigger.collect_scan_target_specs",
        lambda *_a, **_k: [argparse.Namespace(host="10.0.0.1", scheme=None, explicit_port=None)],
    )
    monkeypatch.setattr(
        "redposture_core.stage_trigger.load_profiles",
        lambda *_a, **_k: {"trigger_exporters": [{"name": "redis_exporter", "port": 9121}]},
    )
    rc = run_trigger_stage(_base_args(trigger_exporters_filter="postgres"), AttemptLogger())
    assert rc == 2

    rc = run_trigger_stage(_base_args(postgres_auth_modules=["scram"]), AttemptLogger())
    assert rc == 2


def test_trigger_stage_target_parse_and_output_error_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_trigger.collect_scan_target_specs",
        lambda *_a, **_k: (_ for _ in ()).throw(ValueError("bad targets")),
    )
    rc = run_trigger_stage(_base_args(), AttemptLogger())
    assert rc == 2

    monkeypatch.setattr(
        "redposture_core.stage_trigger.collect_scan_target_specs",
        lambda *_a, **_k: [argparse.Namespace(host="10.0.0.1", scheme=None, explicit_port=None)],
    )
    monkeypatch.setattr(
        "redposture_core.stage_trigger.load_profiles",
        lambda *_a, **_k: (_ for _ in ()).throw(OSError("profiles fail")),
    )
    rc = run_trigger_stage(_base_args(), AttemptLogger())
    assert rc == 2

    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", lambda *_a, **_k: {"trigger_exporters": []})
    monkeypatch.setattr(
        "redposture_core.stage_trigger.collect_scan_ports",
        lambda *_a, **_k: (_ for _ in ()).throw(ValueError("bad ports")),
    )
    rc = run_trigger_stage(_base_args(ports="bad"), AttemptLogger())
    assert rc == 2

    monkeypatch.setattr("redposture_core.stage_trigger.collect_scan_ports", lambda *_a, **_k: [])
    logger = AttemptLogger()
    monkeypatch.setattr(
        logger,
        "set_text_output",
        lambda *_a, **_k: (_ for _ in ()).throw(OSError("cannot open")),
    )
    rc = run_trigger_stage(_base_args(output="trigger.txt"), logger)
    assert rc == 2


def test_trigger_stage_debug_emits_staged_markers(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_load_profiles(_path: object) -> dict[str, object]:
        return {"trigger_exporters": [{"name": "redis_exporter", "port": 9121}]}

    def fake_scan(*_args: object, **kwargs: object) -> dict[str, object]:
        stage_cb = kwargs.get("emit_stage_event")
        assert callable(stage_cb)
        stage_cb({"kind": "pass", "pass": "detect", "event": "start", "total": 1})
        stage_cb(
            {
                "kind": "pass",
                "pass": "detect",
                "event": "complete",
                "total": 1,
                "detected_exporters": 1,
                "deep_candidates": 1,
            }
        )
        stage_cb({"kind": "gate", "host": "10.0.0.1", "gate": "run", "reason": "detected=1"})
        stage_cb({"kind": "pass", "pass": "deep", "event": "start", "total": 1})
        stage_cb(
            {
                "kind": "stage_trace",
                "stage_name": "data",
                "attempt": 1,
                "duration_ms": 12,
                "result": "ok",
                "error": "-",
            }
        )
        stage_cb({"kind": "pass", "pass": "deep", "event": "complete", "total": 1, "processed": 1})
        stage_cb(
            {
                "kind": "timing_summary",
                "status": "ok",
                "attempts": "1/1",
                "detect_ms": 5,
                "data_ms": 12,
                "total_ms": 20,
            }
        )
        return {
            "detected_exporters": 1,
            "attempted": 1,
            "triggered": 1,
            "failed": 0,
            "by_host": {"10.0.0.1": {"detected": 1, "attempted": 1, "success": 1, "fail": 0}},
            "by_callback": {"10.0.0.2": {"success": 1, "fail": 0}},
            "by_exporter": {},
        }

    monkeypatch.setattr(
        "redposture_core.stage_trigger.collect_scan_target_specs",
        lambda *_a, **_k: [argparse.Namespace(host="10.0.0.1", scheme=None, explicit_port=None)],
    )
    monkeypatch.setattr("redposture_core.stage_trigger.load_profiles", fake_load_profiles)
    monkeypatch.setattr("redposture_core.stage_trigger.scan_exporters_and_trigger", fake_scan)

    rc = run_trigger_stage(_base_args(debug=True), AttemptLogger())
    assert rc == 0
    out = capsys.readouterr().out
    assert "pass=1 detect start total=1" in out
    assert "stage2_gate=run reason=detected=1" in out
    assert "pass=2 deep complete processed=1" in out
    assert "stage_timing_summary status=ok attempts=1/1" in out
