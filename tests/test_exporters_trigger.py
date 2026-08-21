from __future__ import annotations

import urllib.error
from typing import Any

from redposture_core.exporters.trigger import (
    detect_trigger_exporter_task,
    scan_exporters_and_trigger,
    trigger_detected_exporter_task,
)


class _Logger:
    def __init__(self) -> None:
        self.rows: list[tuple[str, tuple[str, int], dict[str, Any]]] = []

    def log(self, source: str, target: tuple[str, int], **fields: Any) -> None:
        self.rows.append((source, target, dict(fields)))


def _exporter(name: str = "redis_exporter", port: int = 9121, marker: str = "redis_up") -> dict[str, Any]:
    return {
        "name": name,
        "port": port,
        "detect_path": "/metrics",
        "markers": (marker,),
        "trigger_path": "/probe",
        "target_fmt": "redis://{our_host}:6379",
    }


def test_detect_trigger_exporter_task_logs_errors_markers_and_events() -> None:
    logger = _Logger()
    events: list[dict[str, Any]] = []
    exporter = _exporter()

    def raises(_url: str, _timeout: float, _retries: int) -> tuple[int, str]:
        raise urllib.error.URLError(TimeoutError("timed out"))

    result = detect_trigger_exporter_task(logger, "host-a", exporter, 1.0, 0, raises)
    assert result["detected"] is False
    assert logger.rows[-1][2]["phase"] == "detect_error"

    before = len(logger.rows)
    result = detect_trigger_exporter_task(logger, "host-a", exporter, 1.0, 0, raises, log_trigger_events_only=True)
    assert result["detected"] is False
    assert len(logger.rows) == before

    result = detect_trigger_exporter_task(
        logger,
        "host-a",
        exporter,
        1.0,
        0,
        lambda *_args: (503, "redis_up 1\n"),
    )
    assert result["detected"] is False

    result = detect_trigger_exporter_task(
        logger,
        "host-a",
        exporter,
        1.0,
        0,
        lambda *_args: (200, "generic_metric 1\n"),
    )
    assert result["detected"] is False

    result = detect_trigger_exporter_task(
        logger,
        "host-a",
        exporter,
        1.0,
        0,
        lambda *_args: (200, "redis_up 1\n"),
        emit_trigger_event=events.append,
    )
    assert result == {"host": "host-a", "exporter": "redis_exporter", "port": 9121, "detected": True}
    assert logger.rows[-1][2]["phase"] == "detected"
    assert events[-1]["phase"] == "detect_hit"
    assert events[-1]["detect_url"] == "http://host-a:9121/metrics"

    result = detect_trigger_exporter_task(
        logger,
        "host-a",
        exporter,
        1.0,
        0,
        lambda *_args: (404, "redis_up 1\n"),
    )
    assert result["detected"] is False


def test_trigger_2xx_without_probe_metric_is_accepted_but_unconfirmed() -> None:
    events: list[dict[str, Any]] = []
    result = trigger_detected_exporter_task(
        None,
        "2001:db8::10",
        _exporter(),
        ["2001:db8::20"],
        1.0,
        0,
        lambda *_args: (202, "accepted\n"),
        emit_trigger_event=events.append,
    )

    assert result["attempted"] == 1
    assert result["accepted"] == 1
    assert result["unconfirmed"] == 1
    assert result["success"] == 0
    assert result["by_callback"]["2001:db8::20"]["accepted"] == 1
    assert result["by_callback"]["2001:db8::20"]["unconfirmed"] == 1
    callback_result = next(item for item in events if item["phase"] == "callback_result")
    assert callback_result["accepted"] is True
    assert callback_result["confirmed"] is False
    assert callback_result["success"] is False
    assert callback_result["trigger_url"].startswith("http://[2001:db8::10]:9121/")
    assert "redis://[2001:db8::20]:6379" in callback_result["target"]


def test_trigger_detected_exporter_task_success_failure_and_exception_branches() -> None:
    logger = _Logger()
    events: list[dict[str, Any]] = []
    exporter = _exporter()

    def fake_get(url: str, _timeout: float, _retries: int) -> tuple[int, str]:
        if "10.0.0.1" in url:
            return 200, "probe_success 1\n"
        if "10.0.0.2" in url:
            return 200, "probe_success 0\n"
        if "10.0.0.3" in url:
            return 500, "probe_success nope\n"
        raise TimeoutError("callback timed out")

    result = trigger_detected_exporter_task(
        logger,
        "exporter-host",
        exporter,
        ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
        1.0,
        0,
        fake_get,
        emit_trigger_event=events.append,
    )

    assert result["attempted"] == 4
    assert result["success"] == 1
    assert result["by_callback"]["10.0.0.1"] == {
        "attempted": 1,
        "accepted": 1,
        "unconfirmed": 0,
        "success": 1,
        "fail": 0,
    }
    assert result["by_callback"]["10.0.0.2"] == {
        "attempted": 1,
        "accepted": 1,
        "unconfirmed": 0,
        "success": 0,
        "fail": 1,
    }
    assert result["by_callback"]["10.0.0.4"] == {
        "attempted": 1,
        "accepted": 0,
        "unconfirmed": 0,
        "success": 0,
        "fail": 1,
    }
    assert any(row[2].get("phase") == "triggered" for row in logger.rows)
    assert sum(1 for row in logger.rows if row[2].get("phase") == "trigger_error") == 3
    result_events = [event for event in events if event["phase"] == "callback_result"]
    assert [event["success"] for event in result_events] == [True, False, False, False]
    assert result_events[1]["error"] == "probe_success=0"
    assert result_events[2]["error"] == "status=500"
    assert "timed out" in result_events[3]["error"]


def test_scan_exporters_and_trigger_counts_progress_events_and_not_found() -> None:
    logger = _Logger()
    trigger_events: list[dict[str, Any]] = []
    stage_events: list[dict[str, Any]] = []
    progress_advances: list[int] = []
    progress_totals: list[int] = []
    exporters = [
        _exporter("redis_exporter", 19121, "redis_up"),
        _exporter("postgres_exporter", 19187, "pg_up") | {"target_fmt": "postgresql://{our_host}:5432/postgres"},
    ]

    def fake_get(url: str, _timeout: float, _retries: int) -> tuple[int, str]:
        if url.endswith("/metrics"):
            if "host-a:19121" in url:
                return 200, "redis_up 1\n"
            if "host-b:19187" in url:
                return 200, "pg_up 1\n"
            return 200, "generic 1\n"
        if "10.0.0.1" in url:
            return 200, "probe_success 1\n"
        return 200, "probe_success 0\n"

    summary = scan_exporters_and_trigger(
        logger,
        ["host-a", "host-b", "host-c"],
        ["10.0.0.1", "10.0.0.2"],
        1.0,
        workers=2,
        retries=0,
        trigger_exporters=exporters,
        emit_trigger_event=trigger_events.append,
        emit_stage_event=stage_events.append,
        progress_advance=progress_advances.append,
        progress_add_total=progress_totals.append,
        http_get_text_fn=fake_get,
    )

    assert summary["hosts"] == 3
    assert summary["detected_exporters"] == 2
    assert summary["attempted"] == 4
    assert summary["triggered"] == 2
    assert summary["failed"] == 2
    assert summary["by_host"]["host-c"] == {
        "detected": 0,
        "attempted": 0,
        "accepted": 0,
        "unconfirmed": 0,
        "success": 0,
        "fail": 0,
    }
    assert summary["by_callback"]["10.0.0.1"]["success"] == 2
    assert summary["by_exporter"]["redis_exporter"] == {
        "detected": 1,
        "attempted": 2,
        "accepted": 2,
        "unconfirmed": 0,
        "success": 1,
        "fail": 1,
    }
    assert sum(progress_advances) == 10  # six detect jobs plus four callback attempts.
    assert progress_totals == [2, 2]
    assert any(event.get("kind") == "timing_summary" for event in stage_events)
    assert any(
        event.get("kind") == "gate" and event.get("host") == "host-c" and event.get("gate") == "skip"
        for event in stage_events
    )
    assert sum(1 for event in trigger_events if event["phase"] == "detect_hit") == 2
    assert any(row[2].get("phase") == "not_found" for row in logger.rows)


def test_scan_exporters_and_trigger_log_only_suppresses_not_found_log() -> None:
    logger = _Logger()

    summary = scan_exporters_and_trigger(
        logger,
        ["host-a"],
        ["10.0.0.1"],
        1.0,
        workers=1,
        retries=0,
        trigger_exporters=[_exporter()],
        log_trigger_events_only=True,
        http_get_text_fn=lambda *_args: (200, "no marker\n"),
    )

    assert summary["detected_exporters"] == 0
    assert logger.rows == []
