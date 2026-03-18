from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from redposture_core.console import Console
from redposture_core.progress import ProgressBar, _progress_enabled, iter_completed_with_progress


class _FakeStream:
    def __init__(self, *, tty: bool) -> None:
        self._tty = tty
        self.buffer = ""

    def isatty(self) -> bool:
        return self._tty

    def write(self, data: str) -> int:
        self.buffer += data
        return len(data)

    def flush(self) -> None:
        return


@pytest.mark.parametrize(
    ("enabled", "tty", "env", "expected"),
    [
        (True, True, None, True),
        (False, True, None, False),
        (True, False, None, False),
        (True, True, "1", False),
        (True, True, "true", False),
    ],
)
def test_progress_enabled_respects_flags_and_env(
    monkeypatch: pytest.MonkeyPatch,
    enabled: bool,
    tty: bool,
    env: str | None,
    expected: bool,
) -> None:
    if env is None:
        monkeypatch.delenv("REDPOSTURE_NO_PROGRESS", raising=False)
    else:
        monkeypatch.setenv("REDPOSTURE_NO_PROGRESS", env)
    assert _progress_enabled(_FakeStream(tty=tty), enabled=enabled) is expected


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        (None, "-:--:--"),
        (0.0, "0:00:00"),
        (59.0, "0:00:59"),
        (3661.0, "1:01:01"),
    ],
)
def test_format_eta(seconds: float | None, expected: str) -> None:
    assert ProgressBar._format_eta(seconds) == expected


def test_visible_len_strips_ansi_sequences() -> None:
    colored = "\x1b[31mhello\x1b[0m world"
    assert ProgressBar._visible_len(colored) == len("hello world")


def test_progress_bar_renders_and_closes() -> None:
    stream = _FakeStream(tty=True)
    bar = ProgressBar("collect", total=3, enabled=True, stream=stream, leave=True)

    bar.advance()
    bar.advance(2)
    bar.close()

    assert "Running redposture against 3 targets" in stream.buffer
    assert "100%" in stream.buffer


def test_progress_bar_leave_false_clears_line() -> None:
    stream = _FakeStream(tty=True)
    bar = ProgressBar("scan", total=1, enabled=True, stream=stream, leave=False)

    bar.advance()
    bar.close()

    # leave=False suppresses the final rendered row when completion is immediate.
    assert stream.buffer == ""


def test_progress_bar_pause_for_output_clears_current_row() -> None:
    stream = _FakeStream(tty=True)
    bar = ProgressBar("scan", total=2, enabled=True, stream=stream, leave=True)
    bar.advance()
    before = stream.buffer

    bar.pause_for_output()

    assert len(stream.buffer) > len(before)
    bar.close()


def test_console_plain_suspends_and_resumes_active_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = _FakeStream(tty=True)
    bar = ProgressBar("scan", total=2, enabled=True, stream=stream, leave=True)
    bar.advance()

    events: list[str] = []
    original_pause = bar.pause_for_output
    original_resume = bar.resume_after_output

    def wrapped_pause() -> None:
        events.append("pause")
        original_pause()

    def wrapped_resume() -> None:
        events.append("resume")
        original_resume()

    monkeypatch.setattr(bar, "pause_for_output", wrapped_pause)
    monkeypatch.setattr(bar, "resume_after_output", wrapped_resume)

    console = Console(debug=False)
    console.plain("SCAN\t127.0.0.1\t9100\t [*] Node Exporter", stream=stream)
    bar.close()

    assert events[:2] == ["pause", "resume"]
    assert "SCAN\t127.0.0.1\t9100\t [*] Node Exporter" in stream.buffer


def test_iter_completed_with_progress_returns_all_futures() -> None:
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_map = {executor.submit(lambda x: x + 1, i): i for i in range(5)}
        values = [future.result() for future in iter_completed_with_progress(future_map, label="TEST", enabled=False)]

    assert sorted(values) == [1, 2, 3, 4, 5]
