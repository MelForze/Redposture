from __future__ import annotations

from pathlib import Path

import pytest

from redposture_core.logger import AttemptLogger


def test_logger_outputs_human_readable_info(capsys: pytest.CaptureFixture[str]) -> None:
    logger = AttemptLogger()
    logger.log("blackbox", ("10.0.0.1", 9115), method="GET", path="/probe", module="http_2xx")
    captured = capsys.readouterr()
    out = captured.out
    assert "[INFO]" in out
    assert "[BLACKBOX]" in out
    assert "10.0.0.1:9115" in out
    assert "method=GET" in out
    assert "path=/probe" in out
    assert "module=http_2xx" in out
    assert "\x1b[1;96m" in out


def test_logger_scanner_detect_phase_uses_scan_tag(capsys: pytest.CaptureFixture[str]) -> None:
    logger = AttemptLogger()
    logger.log("scanner", ("10.0.0.8", 9115), phase="detected", exporter="blackbox_exporter")
    captured = capsys.readouterr()
    out = captured.out
    assert "[SCAN]" in out


def test_logger_scanner_trigger_phase_uses_trigger_tag(capsys: pytest.CaptureFixture[str]) -> None:
    logger = AttemptLogger()
    logger.log("scanner", ("10.0.0.8", 9115), phase="triggered", exporter="blackbox_exporter")
    captured = capsys.readouterr()
    out = captured.out
    assert "[TRIGGER]" in out


def test_logger_highlights_password_events(capsys: pytest.CaptureFixture[str]) -> None:
    logger = AttemptLogger()
    logger.log("redis", ("10.0.0.2", 6379), username="default", password="secret", command="AUTH")
    captured = capsys.readouterr()
    out = captured.out
    assert "[CRED]" in out
    assert "user=default" in out
    assert "pass=secret" in out
    assert "\x1b[1;38;5;208m" in out


def test_logger_displays_empty_password(capsys: pytest.CaptureFixture[str]) -> None:
    logger = AttemptLogger()
    logger.log("proxmox", ("10.0.0.3", 8006), username="root@pam", password="")
    captured = capsys.readouterr()
    out = captured.out
    assert "[WARN]" in out
    assert "pass=<empty>" in out
    assert "\x1b[1;93m" in out


def test_logger_trigger_callback_mode_prints_callback_line_with_creds(capsys: pytest.CaptureFixture[str]) -> None:
    logger = AttemptLogger()
    logger.set_trigger_callback_mode(True, callback_targets=["127.0.0.1"])
    logger.log("redis", ("10.0.0.5", 50001), username="default", password="secret", listen_port=6379)
    captured = capsys.readouterr()
    out = captured.out
    assert "TRIGGER" in out
    assert "10.0.0.5" in out
    assert "127.0.0.1" not in out
    assert "Redis Exporter" in out
    assert "(CRED!)" in out
    assert "pass=secret" in out
    assert "\x1b[1;38;5;208m" in out


def test_logger_trigger_callback_mode_prints_callback_line_without_creds(capsys: pytest.CaptureFixture[str]) -> None:
    logger = AttemptLogger()
    logger.set_trigger_callback_mode(True)
    logger.log("blackbox", ("10.0.0.6", 50002), method="GET", path="/probe", listen_port=9115)
    captured = capsys.readouterr()
    out = captured.out
    assert "TRIGGER" in out
    assert "Blackbox Exporter" in out
    assert "(CRED!)" not in out
    assert "(SSRF!)" in out
    assert "[SSRF]" in out
    assert "\x1b[1;38;5;208m" in out


def test_logger_trigger_callback_mode_deduplicates_repeated_events(capsys: pytest.CaptureFixture[str]) -> None:
    logger = AttemptLogger()
    logger.set_trigger_callback_mode(True)
    logger.log("postgres", ("10.0.0.7", 50003), username="postgres", password="postgres", listen_port=5432)
    logger.log("postgres", ("10.0.0.7", 50004), username="postgres", password="postgres", listen_port=5432)
    captured = capsys.readouterr()
    out = captured.out
    assert out.count("TRIGGER") == 1
    assert out.count("[CRED]") == 1


def test_logger_trigger_callback_mode_debug_shows_duplicates(capsys: pytest.CaptureFixture[str]) -> None:
    logger = AttemptLogger()
    logger.set_trigger_callback_mode(True, deduplicate=False)
    logger.log("postgres", ("10.0.0.7", 50003), username="postgres", password="postgres", listen_port=5432)
    logger.log("postgres", ("10.0.0.7", 50004), username="postgres", password="postgres", listen_port=5432)
    captured = capsys.readouterr()
    out = captured.out
    assert out.count("TRIGGER") == 2
    assert out.count("[CRED]") == 2


def test_logger_trigger_callback_stats_are_unique_even_in_debug_mode() -> None:
    logger = AttemptLogger()
    logger.set_trigger_callback_mode(True, deduplicate=False)
    logger.log("redis", ("10.0.0.8", 50003), username="default", password="redis", listen_port=6379)
    logger.log("redis", ("10.0.0.8", 50004), username="default", password="redis", listen_port=6379)
    stats = logger.get_trigger_callback_stats()
    assert stats["total"] == 1
    assert stats["by_service"]["redis"] == 1


def test_logger_writes_full_unclipped_line_to_text_file(tmp_path: Path) -> None:
    logger = AttemptLogger()
    output_file = tmp_path / "trigger.txt"
    logger.set_text_output(str(output_file))

    long_startup = "x" * 220
    logger.log("postgres", ("10.0.0.4", 5432), startup={"application_name": long_startup})
    logger.close()

    saved = output_file.read_text(encoding="utf-8")
    assert long_startup in saved
    assert "[Postgres]" in saved
