from __future__ import annotations

import time
from urllib.parse import urlparse

from redposture_core.scanner import scan_exporters_and_trigger


def test_scan_then_trigger_phase_order(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    detect_calls: list[str] = []
    trigger_calls: list[str] = []
    emitted_phases: list[str] = []

    def fake_http_get_text(url: str, timeout: float, retries: int = 1) -> tuple[int, str]:
        parsed = urlparse(url)
        if parsed.path.startswith("/detect"):
            detect_calls.append(url)
            if parsed.path == "/detect/slow":
                time.sleep(0.05)
            marker = "marker_fast" if parsed.path == "/detect/fast" else "marker_slow"
            return 200, marker

        trigger_calls.append(url)
        return 200, "probe_success 1"

    monkeypatch.setattr("redposture_core.scanner.http_get_text", fake_http_get_text)

    exporters = [
        {
            "name": "fast_exporter",
            "port": 1111,
            "detect_path": "/detect/fast",
            "trigger_path": "/trigger/fast",
            "markers": ["marker_fast"],
            "target_fmt": "http://{our_host}:80",
        },
        {
            "name": "slow_exporter",
            "port": 2222,
            "detect_path": "/detect/slow",
            "trigger_path": "/trigger/slow",
            "markers": ["marker_slow"],
            "target_fmt": "http://{our_host}:80",
        },
    ]

    def emit(event: dict[str, object]) -> None:
        phase = str(event.get("phase") or "")
        emitted_phases.append(phase)

    summary = scan_exporters_and_trigger(
        logger=None,
        hosts=["127.0.0.1"],
        callback_targets=["cb.local"],
        timeout=1.0,
        workers=2,
        retries=0,
        trigger_exporters=exporters,
        log_trigger_events_only=True,
        emit_trigger_event=emit,
    )

    assert summary["detected_exporters"] == 2
    assert summary["attempted"] == 2
    assert summary["triggered"] == 2
    assert len(detect_calls) == 2
    assert len(trigger_calls) == 2

    # Two-phase guarantee: all detect events must happen before callback attempts.
    assert emitted_phases
    first_callback_idx = emitted_phases.index("callback_attempt")
    assert all(phase == "detect_hit" for phase in emitted_phases[:first_callback_idx])


def test_trigger_progress_callbacks_cover_detect_and_deep(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    exporters = [
        {
            "name": "fast_exporter",
            "port": 1111,
            "detect_path": "/detect/fast",
            "trigger_path": "/trigger/fast",
            "markers": ["marker_fast"],
            "target_fmt": "http://{our_host}:80",
        },
        {
            "name": "slow_exporter",
            "port": 2222,
            "detect_path": "/detect/slow",
            "trigger_path": "/trigger/slow",
            "markers": ["marker_slow"],
            "target_fmt": "http://{our_host}:80",
        },
    ]
    advances: list[int] = []
    total_additions: list[int] = []

    def fake_http_get_text(url: str, timeout: float, retries: int = 1) -> tuple[int, str]:
        parsed = urlparse(url)
        if parsed.path.startswith("/detect"):
            marker = "marker_fast" if parsed.path == "/detect/fast" else "marker_slow"
            return 200, marker
        return 200, "probe_success 1"

    monkeypatch.setattr("redposture_core.scanner.http_get_text", fake_http_get_text)

    summary = scan_exporters_and_trigger(
        logger=None,
        hosts=["127.0.0.1"],
        callback_targets=["cb1.local", "cb2.local"],
        timeout=1.0,
        workers=2,
        retries=0,
        trigger_exporters=exporters,
        log_trigger_events_only=True,
        progress_advance=advances.append,
        progress_add_total=total_additions.append,
    )

    assert summary["detected_exporters"] == 2
    assert summary["attempted"] == 4
    assert total_additions == [2, 2]
    assert advances.count(1) == 2
    assert sum(advances) == 6


def test_trigger_progress_callbacks_detect_only_no_hits(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    exporters = [
        {
            "name": "missing_exporter",
            "port": 1111,
            "detect_path": "/detect/missing",
            "trigger_path": "/trigger/missing",
            "markers": ["never-here"],
            "target_fmt": "http://{our_host}:80",
        }
    ]
    advances: list[int] = []
    total_additions: list[int] = []

    def fake_http_get_text(url: str, timeout: float, retries: int = 1) -> tuple[int, str]:
        return 200, "ordinary metrics"

    monkeypatch.setattr("redposture_core.scanner.http_get_text", fake_http_get_text)

    summary = scan_exporters_and_trigger(
        logger=None,
        hosts=["127.0.0.1", "127.0.0.2"],
        callback_targets=["cb.local"],
        timeout=1.0,
        workers=2,
        retries=0,
        trigger_exporters=exporters,
        log_trigger_events_only=True,
        progress_advance=advances.append,
        progress_add_total=total_additions.append,
    )

    assert summary["detected_exporters"] == 0
    assert summary["attempted"] == 0
    assert advances == [1, 1]
    assert total_additions == []
