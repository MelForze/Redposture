"""Trigger summary and post-callback credential verification contracts."""

from __future__ import annotations

import argparse

import pytest

from redposture_core import stage_postgres, stage_redis, stage_trigger


class _Console:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def info(self, value: str) -> None:
        self.lines.append(value)

    def debug(self, value: str) -> None:
        self.lines.append(value)

    def _diagnostic_stream(self):
        return None

    def _paint(self, value: str, _color: str, _stream) -> str:
        return value

    def plain(self, value: str, *, stream=None) -> None:
        self.lines.append(value)


class _Logger:
    def __init__(self, events: list[dict[str, object]] | None = None) -> None:
        self.events = events or []
        self.rows: list[str] = []

    def get_trigger_callback_events(self):
        return self.events

    def get_trigger_callback_stats(self):
        return {"total": 2, "by_service": {"redis": 1, "postgres": 1}}

    def write_text_line(self, value: str) -> None:
        self.rows.append(value)


@pytest.mark.parametrize("service", ["redis", "postgres"])
@pytest.mark.parametrize("status", ["valid_credentials", "weak_default_creds", "open_no_auth", "auth_required", "fail"])
def test_trigger_check_renders_actual_credential_state_after_callback(
    monkeypatch: pytest.MonkeyPatch, service: str, status: str
) -> None:
    event = {
        "service": service,
        "remote_addr": "127.0.0.1:12345",
        "listen_port": 6379,
        "username": "alice",
        "password": "secret",
    }
    logger = _Logger([event])
    console = _Console()
    record = {"status": status, "key_count": 2, "error": "unavailable"}
    monkeypatch.setattr(stage_redis, "_audit_redis_host", lambda **_kwargs: record)
    monkeypatch.setattr(stage_postgres, "_audit_postgres_host", lambda **_kwargs: record)
    stage_trigger._run_trigger_credential_checks(argparse.Namespace(timeout=1, retries=0, debug=True), logger, console)
    assert len(logger.rows) == 2
    detail = logger.rows[-1]
    expected_marker = (
        "[+]"
        if status in {"valid_credentials", "weak_default_creds", "open_no_auth"}
        else ("[-]" if status == "auth_required" else "[!]")
    )
    assert expected_marker in detail
    if status == "valid_credentials":
        assert "alice:secret" in detail


def test_trigger_request_summary_counts_only_correlated_callback_services(monkeypatch: pytest.MonkeyPatch) -> None:
    console = _Console()
    logger = _Logger()
    result = {
        "detected_exporters": 2,
        "attempted": 4,
        "accepted": 4,
        "triggered": 4,
        "failed": 0,
        "by_exporter": {
            "redis_exporter": {"attempted": 3},
            "postgres_exporter": {"attempted": 1},
            "foreign_exporter": {"attempted": 100},
        },
        "by_host": {"127.0.0.1": {"detected": 2, "attempted": 4, "success": 4, "fail": 0}},
        "by_callback": {"127.0.0.2": {"attempted": 4, "success": 4, "fail": 0}},
    }
    monkeypatch.setattr(stage_trigger, "scan_exporters_and_trigger", lambda **_kwargs: result)
    stage_trigger._run_trigger_requests(
        argparse.Namespace(timeout=1, retries=0, workers=2, with_listen=True, debug=True),
        logger,
        console,
        ["127.0.0.1"],
        ["127.0.0.2"],
        [],
        True,
        False,
    )
    assert any("confirmed=2" in line and "unconfirmed=2" in line for line in console.lines)
    assert any("callback_success=2" in line for line in console.lines)
