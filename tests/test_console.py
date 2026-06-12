from __future__ import annotations

import io
import sys

import pytest

from redposture_core.console import Console, set_console_no_color, should_use_color


class _FakeStream(io.StringIO):
    def __init__(self, *, tty: bool) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def test_should_use_color_gates_on_isatty_when_no_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert should_use_color(_FakeStream(tty=True)) is True
    assert should_use_color(_FakeStream(tty=False)) is False


def test_should_use_color_no_color_env_disables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.setenv("NO_COLOR", "1")
    assert should_use_color(_FakeStream(tty=True)) is False


def test_should_use_color_force_color_overrides_non_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert should_use_color(_FakeStream(tty=False)) is True


def test_console_paint_skips_ansi_when_piped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    console = Console(debug=False)
    piped = _FakeStream(tty=False)
    assert console._paint("hello", "green", stream=piped) == "hello"
    tty = _FakeStream(tty=True)
    assert "\x1b[" in console._paint("hello", "green", stream=tty)


def test_paint_returns_plain_text_for_unknown_color() -> None:
    console = Console(debug=False)
    assert console._paint("hello", "not-a-color", stream=sys.stdout) == "hello"


def test_paint_wraps_known_color_with_ansi() -> None:
    console = Console(debug=False)
    rendered = console._paint("hello", "green", stream=sys.stdout)
    assert "\x1b[" in rendered
    assert "hello" in rendered


def test_render_tagged_payload_line_success(capsys: pytest.CaptureFixture[str]) -> None:
    console = Console(debug=False)
    line = "SCAN\t127.0.0.1\t9100\t[+] Node Exporter"
    ok = console.render_tagged_payload_line(line, "SCAN")
    assert ok is True
    out = capsys.readouterr().out
    assert "127.0.0.1\t9100\t" in out
    assert "[+] Node Exporter" in out


def test_render_tagged_payload_line_rejects_invalid_input() -> None:
    console = Console(debug=False)
    assert console.render_tagged_payload_line("INVALID", "SCAN") is False
    assert console.render_tagged_payload_line("OTHER\t1\t2\t3", "SCAN") is False


def test_info_success_warn_and_error_write_to_expected_streams(
    capsys: pytest.CaptureFixture[str],
) -> None:
    console = Console(debug=False)
    console.info("hello")
    console.success("ok")
    console.warn("warn")
    console.error("bad")

    captured = capsys.readouterr()
    assert "hello" in captured.out
    assert "ok" in captured.out
    assert "warn" in captured.out
    assert "bad" in captured.err


def test_debug_outputs_only_when_enabled(capsys: pytest.CaptureFixture[str]) -> None:
    console_off = Console(debug=False)
    console_off.debug("hidden")
    out_off = capsys.readouterr().out
    assert "hidden" not in out_off

    console_on = Console(debug=True)
    console_on.debug("visible")
    out_on = capsys.readouterr().out
    assert "visible" in out_on


def test_set_console_no_color_disables_ansi_rendering() -> None:
    set_console_no_color(True)
    try:
        console = Console(debug=False)
        rendered = console._paint("hello", "green", stream=sys.stdout)
        assert rendered == "hello"
    finally:
        set_console_no_color(False)


def test_console_constructor_no_color_overrides_global() -> None:
    set_console_no_color(True)
    try:
        console = Console(debug=False, no_color=False)
        rendered = console._paint("hello", "green", stream=sys.stdout)
        assert "\x1b[" in rendered
    finally:
        set_console_no_color(False)
