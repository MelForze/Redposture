"""New crash boundaries and network-blocked continuation cancellation (offline)."""

from __future__ import annotations

import json
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Generator
from pathlib import Path

import pytest

from redposture_core.scheduler import BoundedScheduler
from redposture_core.stage_spray import AttemptJournal, RateGate
from redposture_core.ui_export import UIExport

ROOT = Path(__file__).resolve().parents[1]


def _await_marker(child: subprocess.Popen[str], marker: Path) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if marker.exists():
            return
        if child.poll() is not None:
            stdout, stderr = child.communicate()
            pytest.fail(f"fixture exited before boundary: {child.returncode=} {stdout=} {stderr=}")
        time.sleep(0.01)
    pytest.fail(f"fixture did not reach {marker.name}")


@pytest.mark.parametrize("boundary", ["before_replace", "after_replace"])
def test_ui_export_sigkill_recovers_committed_rows_across_publication(tmp_path: Path, boundary: str) -> None:
    """SQLite is authoritative on both sides of JSONL publication, without duplicates."""
    with UIExport(str(tmp_path), "http://127.0.0.1:1", "portainer", resume=False) as writer:
        writer.add("one", "items", {"id": 1})
        output = Path(writer.finish(complete=False)["path"])
    marker = tmp_path / "boundary"
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            """
import os, sys, time
from pathlib import Path
from redposture_core.ui_export import UIExport
directory, marker, boundary = sys.argv[1:]
original = os.replace
def replace(src, dst):
    if boundary == 'after_replace':
        original(src, dst)
    Path(marker).write_text('ready')
    while True:
        time.sleep(1)
os.replace = replace
with UIExport(directory, 'http://127.0.0.1:1', 'portainer', resume=True) as writer:
    writer.add('two', 'items', {'id': 2})
    writer.finish(complete=True)
""",
            str(tmp_path),
            str(marker),
            boundary,
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _await_marker(child, marker)
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=5)
    assert child.returncode == -signal.SIGKILL
    published = [json.loads(line)["value"]["id"] for line in output.read_text().splitlines()]
    assert published == ([1] if boundary == "before_replace" else [1, 2])
    with UIExport(str(tmp_path), "http://127.0.0.1:1", "portainer", resume=None) as resumed:
        assert resumed.has("one") and resumed.has("two")
        assert not resumed.add("two", "items", {"id": 2})
        result = resumed.finish(complete=True)
    assert result["count"] == 2
    assert [json.loads(line)["value"]["id"] for line in output.read_text().splitlines()] == [1, 2]


def test_spray_sigkill_persists_inflight_status_and_origin_stop(tmp_path: Path) -> None:
    """An abrupt exit retains both the no-retry attempt and the server stop decision."""
    checkpoint, marker = tmp_path / "spray.sqlite3", tmp_path / "committed"
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            """
import sys, time
from pathlib import Path
from redposture_core.stage_spray import AttemptJournal, RateGate
journal = AttemptJournal(sys.argv[1], 'campaign22', False)
journal.put('done', 'airflow', '127.0.0.1', 8080, 0, 'invalid', 'denied')
journal.put('inflight', 'airflow', '127.0.0.1', 8080, 1, 'started', 'request begun')
gate = RateGate(1, 60, journal=journal)
gate.claim('http://127.0.0.1:8080', 'account')
gate.stop('http://127.0.0.1:8080', 'server rate limit')
Path(sys.argv[2]).write_text('ready')
while True:
    time.sleep(1)
""",
            str(checkpoint),
            str(marker),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _await_marker(child, marker)
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=5)
    assert child.returncode == -signal.SIGKILL
    journal = AttemptJournal(str(checkpoint), "campaign22", True)
    try:
        assert journal.get("done") == ("invalid", "denied")
        assert journal.get("inflight") == ("inconclusive", "request began before interruption; not retried")
        gate = RateGate(1, 60, journal=journal)
        assert gate.reserve("http://127.0.0.1:8080", "account") == (False, "server rate limit")
        assert gate.reserve("http://127.0.0.1:8081", "account")[0] is True
        assert gate.sent_account[("http://127.0.0.1:8080", "account")] > time.monotonic() + 45
    finally:
        journal.close()


def test_cooldown_target_does_not_hold_single_worker_or_dispatch_early() -> None:
    gate = RateGate(20, 0)
    assert gate.claim("cooling", "account") == 0
    gate.sent_origin["cooling"] = time.monotonic() + 0.15
    dispatches: list[tuple[str, float]] = []
    deadline = gate.sent_origin["cooling"]

    def worker(origin: str) -> Generator[float, None, str]:
        while delay := gate.claim(origin, "account"):
            yield delay
        dispatches.append((origin, time.monotonic()))
        return origin

    result = list(BoundedScheduler[str, str](max_workers=1, max_inflight=2).iter_paused(["cooling", "ready"], worker))
    assert result == [("ready", "ready"), ("cooling", "cooling")]
    assert dispatches[0][0] == "ready" and dispatches[0][1] < deadline
    assert dispatches[1][1] >= deadline


def test_multiple_cooling_targets_do_not_starve_later_ready_targets() -> None:
    """Three parked origins leave a bounded slot for every later ready origin."""
    gate = RateGate(20, 0)
    cooling = [f"cooling-{i}" for i in range(3)]
    ready = [f"ready-{i}" for i in range(6)]
    for origin in cooling:
        gate.sent_origin[origin] = time.monotonic() + 60
    began: set[str] = set()
    dispatches: list[str] = []
    results: list[str] = []
    cancelled, finished = threading.Event(), threading.Event()
    errors: list[BaseException] = []

    def worker(origin: str) -> Generator[float, None, str]:
        began.add(origin)
        while delay := gate.claim(origin, "account"):
            yield delay
        dispatches.append(origin)
        return origin

    def coordinate() -> None:
        iterator = BoundedScheduler[str, str](max_workers=2, max_inflight=4).iter_paused(
            [*cooling, *ready], worker, cancelled=cancelled
        )
        try:
            for _origin, value in iterator:
                results.append(value)
                if len(results) == len(ready):
                    break
        except BaseException as exc:
            errors.append(exc)
        finally:
            iterator.close()
            finished.set()

    coordinator = threading.Thread(target=coordinate)
    try:
        coordinator.start()
        assert finished.wait(1), "cooling origins starved ready targets beyond the bounded source window"
        assert not errors
        assert set(results) == set(ready)
        assert set(dispatches) == set(ready)
        assert set(cooling) <= began
    finally:
        cancelled.set()
        coordinator.join(2)
    assert not coordinator.is_alive()


def test_cancel_blocked_socket_read_drops_result_and_closes_continuation() -> None:
    entered, cancelled, closed = (threading.Event() for _ in range(3))
    reader, peer = socket.socketpair()
    reader.settimeout(2)
    results: list[tuple[int, int]] = []

    def worker(value: int) -> Generator[float, None, int]:
        try:
            entered.set()
            reader.recv(1)
            yield 30
            return value
        finally:
            reader.close()
            closed.set()

    scheduler = BoundedScheduler[int, int](max_workers=1, max_inflight=1)
    coordinator = threading.Thread(
        target=lambda: results.extend(scheduler.iter_paused([1], worker, cancelled=cancelled))
    )
    try:
        coordinator.start()
        assert entered.wait(1)
        cancelled.set()
        coordinator.join(0.5)
        assert not coordinator.is_alive(), "cancellation waited for the socket read"
        assert results == []
        peer.shutdown(socket.SHUT_WR)
        assert closed.wait(1), "continuation retained its socket after the blocked read returned"
    finally:
        peer.close()
        coordinator.join(3)
        reader.close()


def test_ctrl_c_exits_paused_scheduler_while_socket_read_is_blocked(tmp_path: Path) -> None:
    marker = tmp_path / "socket-read-started"
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            """
import socket, sys
from pathlib import Path
from redposture_core.scheduler import BoundedScheduler
reader, peer = socket.socketpair()
reader.settimeout(10)
def worker(value):
    Path(sys.argv[1]).write_text('ready')
    reader.recv(1)
    yield 0
    return value
try:
    list(BoundedScheduler(max_workers=1).iter_paused([1], worker))
except KeyboardInterrupt:
    raise SystemExit(130)
""",
            str(marker),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _await_marker(child, marker)
        child.send_signal(signal.SIGINT)
        stdout, stderr = child.communicate(timeout=2)
        assert child.returncode == 130, (stdout, stderr)
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=5)
