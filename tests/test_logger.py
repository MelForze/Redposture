from __future__ import annotations

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
    assert "[CRED]" in out
    assert "pass=<empty>" in out
