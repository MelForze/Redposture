from __future__ import annotations

from pathlib import Path

import pytest

from honeycore.logger import AttemptLogger


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
    assert "\x1b[36m" in out


def test_logger_highlights_password_events(capsys: pytest.CaptureFixture[str]) -> None:
    logger = AttemptLogger()
    logger.log("redis", ("10.0.0.2", 6379), username="default", password="secret", command="AUTH")
    captured = capsys.readouterr()
    out = captured.out
    assert "[CRED]" in out
    assert "user=default" in out
    assert "pass=secret" in out
    assert "\x1b[31m" in out


def test_logger_displays_empty_password(capsys: pytest.CaptureFixture[str]) -> None:
    logger = AttemptLogger()
    logger.log("proxmox", ("10.0.0.3", 8006), username="root@pam", password="")
    captured = capsys.readouterr()
    out = captured.out
    assert "[WARN]" in out
    assert "pass=<empty>" in out
    assert "\x1b[33m" in out


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
