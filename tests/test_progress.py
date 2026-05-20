from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from redposture_core.console import Console
from redposture_core.progress import (
    CommandProgressOwner,
    NoOpProgress,
    ProgressBar,
    _progress_enabled,
    iter_completed_with_progress,
)
from redposture_core.stage_runtime import start_command_progress


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


def test_progress_bar_does_not_render_initial_by_default() -> None:
    stream = _FakeStream(tty=True)
    bar = ProgressBar("collect", total=3, enabled=True, stream=stream, leave=True)

    assert stream.buffer == ""
    bar.close()


def test_output_backed_command_progress_renders_initial_line() -> None:
    stream = _FakeStream(tty=True)
    owner = CommandProgressOwner(enabled=True, stream=stream)
    args = SimpleNamespace(output="results.txt", _progress_owner=owner)

    progress = start_command_progress(args, "proxmox", 10)

    assert "Running redposture against 10 targets" in stream.buffer
    assert "0%" in stream.buffer
    progress.close()
    owner.close()


def test_progress_bar_set_total_updates_target_count_text() -> None:
    stream = _FakeStream(tty=True)
    bar = ProgressBar("trigger", total=2, enabled=True, stream=stream, leave=True)

    bar.advance()
    bar.set_total(3)
    bar.advance(2)
    bar.close()

    assert "Running redposture against 2 targets" in stream.buffer
    assert "Running redposture against 3 targets" in stream.buffer


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


def test_nested_progress_bar_is_suppressed_by_default() -> None:
    stream = _FakeStream(tty=True)
    outer = ProgressBar("outer", total=2, enabled=True, stream=stream, leave=True)
    outer.advance()
    before_inner = stream.buffer

    inner = ProgressBar("inner", total=1, enabled=True, stream=stream, leave=True)
    inner.advance()
    inner.close()
    outer.close()

    assert "Running redposture against 1 target" not in stream.buffer[len(before_inner) :]


def test_nested_progress_bar_can_be_explicitly_allowed() -> None:
    stream = _FakeStream(tty=True)
    outer = ProgressBar("outer", total=2, enabled=True, stream=stream, leave=True)
    outer.advance()

    inner = ProgressBar("inner", total=1, enabled=True, stream=stream, leave=True, allow_nested=True)
    inner.advance()
    inner.close()
    outer.close()

    assert "Running redposture against 1 target" in stream.buffer


def test_console_plain_without_prior_progress_render_does_not_insert_blank_progress_row() -> None:
    stream = _FakeStream(tty=True)
    bar = ProgressBar("scan", total=2, enabled=True, stream=stream, leave=True)

    console = Console(debug=False)
    console.plain("ELASTIC\t127.0.0.1\t9200\t [*] Elasticsearch API", stream=stream)
    bar.close()

    assert "ELASTIC\t127.0.0.1\t9200\t [*] Elasticsearch API" in stream.buffer
    assert not stream.buffer.startswith("\r")
    assert stream.buffer.startswith("ELASTIC\t127.0.0.1\t9200\t [*] Elasticsearch API\n")


def test_console_plain_suspends_and_resumes_active_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = _FakeStream(tty=True)
    bar = ProgressBar("scan", total=2, enabled=True, stream=stream, leave=True)
    bar.advance()

    events: list[str] = []
    original_begin = bar.begin_output
    original_end = bar.end_output

    def wrapped_begin() -> bool:
        events.append("begin")
        return original_begin()

    def wrapped_end() -> None:
        events.append("end")
        original_end()

    monkeypatch.setattr(bar, "begin_output", wrapped_begin)
    monkeypatch.setattr(bar, "end_output", wrapped_end)

    console = Console(debug=False)
    console.plain("SCAN\t127.0.0.1\t9100\t [*] Node Exporter", stream=stream)
    bar.close()

    assert events[:2] == ["begin", "end"]
    assert "SCAN\t127.0.0.1\t9100\t [*] Node Exporter" in stream.buffer


def test_iter_completed_with_progress_returns_all_futures() -> None:
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_map = {executor.submit(lambda x: x + 1, i): i for i in range(5)}
        values = [future.result() for future in iter_completed_with_progress(future_map, label="TEST", enabled=False)]

    assert sorted(values) == [1, 2, 3, 4, 5]


def test_command_progress_owner_owns_single_progress_handle() -> None:
    stream = _FakeStream(tty=True)
    owner = CommandProgressOwner(enabled=True, stream=stream)

    first = owner.start("first", 2)
    first.advance()
    second = owner.start("second", 1)
    second.advance()
    owner.close()

    assert "Running redposture against 2 targets" in stream.buffer
    assert "Running redposture against 1 target" in stream.buffer


def test_command_progress_owner_returns_noop_when_disabled() -> None:
    owner = CommandProgressOwner(enabled=False)
    handle = owner.start("scan", 10)

    assert isinstance(handle, NoOpProgress)
