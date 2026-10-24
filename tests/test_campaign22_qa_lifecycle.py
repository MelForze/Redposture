"""QA startup/interrupt boundaries using only fake Docker and owned child processes."""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from scripts import run_qa_handoff as qa

ROOT = Path(__file__).resolve().parents[1]


def test_logged_command_startup_failure_records_diagnostic(tmp_path: Path) -> None:
    log = tmp_path / "nested" / "startup.log"
    code, elapsed = qa._run_logged([str(tmp_path / "missing-executable")], log, timeout=1)
    assert code == 127 and elapsed < 2
    assert "could not start:" in log.read_text()


@pytest.mark.parametrize("interrupted_step", ["up", "seed", "download"])
def test_gitlab_interrupt_at_each_startup_boundary_cleans_owned_resources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, interrupted_step: str
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(qa, "_docker_project_is_empty", lambda _project: True)
    monkeypatch.setattr(qa, "_gitlab_ports_are_free", lambda _compose: (True, []))
    monkeypatch.setattr(qa, "compose_images", lambda _compose: ["owned:test"])
    monkeypatch.setattr(qa, "missing_images", lambda _images: ["owned:test"])

    def remove(images: list[str]) -> list[str]:
        assert images == ["owned:test"]
        calls.append("remove-images")
        return []

    def run(_command: list[str], log: Path, **_kwargs: Any) -> tuple[int, float]:
        calls.append(log.stem)
        if log.stem == interrupted_step:
            raise KeyboardInterrupt
        return 0, 0.0

    monkeypatch.setattr(qa, "remove_images", remove)
    monkeypatch.setattr(qa, "_run_logged", run)
    with pytest.raises(KeyboardInterrupt):
        qa._gitlab_blob_qa(tmp_path, "campaign22-owned-fake", sys.executable)
    expected = ["up", "seed", "download"]
    assert calls == expected[: expected.index(interrupted_step) + 1] + ["down", "remove-images"]


def test_gitlab_failed_cleanup_preserves_images_for_remaining_containers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(qa, "_docker_project_is_empty", lambda _project: True)
    monkeypatch.setattr(qa, "_gitlab_ports_are_free", lambda _compose: (True, []))
    monkeypatch.setattr(qa, "compose_images", lambda _compose: ["owned:test"])
    monkeypatch.setattr(qa, "missing_images", lambda _images: ["owned:test"])
    monkeypatch.setattr(qa, "remove_images", lambda _images: calls.append("unexpected-image-removal"))

    def run(_command: list[str], log: Path, **_kwargs: Any) -> tuple[int, float]:
        calls.append(log.stem)
        return 7, 0.0

    monkeypatch.setattr(qa, "_run_logged", run)
    result = qa._gitlab_blob_qa(tmp_path, "campaign22-owned-fake", sys.executable)
    assert result["status"] == "failed"
    assert "cleanup failed (exit 7)" in result["reason"]
    assert calls == ["up", "down"]


def _interrupt_owned_command(tmp_path: Path, *, descendant: bool) -> bool:
    """Return whether an owned grandchild keeps making progress after runner exits."""
    marker = tmp_path / "ready.json"
    heartbeat = tmp_path / "heartbeat"
    observed_signal = tmp_path / "sigint"
    command_script = tmp_path / "owned_command.py"
    command_script.write_text(
        """
import json, os, signal, subprocess, sys, time
from pathlib import Path
marker, heartbeat, observed, descendant = sys.argv[1:]
def interrupted(_signum, _frame):
    Path(observed).write_text('SIGINT')
    raise SystemExit(130)
signal.signal(signal.SIGINT, interrupted)
if descendant == 'yes':
    child = subprocess.Popen([sys.executable, '-c', '''
import signal, sys, time
from pathlib import Path
signal.signal(signal.SIGINT, signal.SIG_IGN)
for i in range(250):
    Path(sys.argv[1]).write_text(str(i))
    time.sleep(0.02)
''', heartbeat])
    while not Path(heartbeat).exists():
        time.sleep(0.01)
Path(marker).write_text(json.dumps({'pgid': os.getpgrp()}))
time.sleep(10)
""",
        encoding="utf-8",
    )
    wrapper = subprocess.Popen(
        [
            sys.executable,
            "-c",
            """
import sys
from pathlib import Path
from scripts.run_qa_handoff import _run_logged
try:
    _run_logged(sys.argv[2:], Path(sys.argv[1]), timeout=20)
except KeyboardInterrupt:
    raise SystemExit(130)
""",
            str(tmp_path / "command.log"),
            sys.executable,
            str(command_script),
            str(marker),
            str(heartbeat),
            str(observed_signal),
            "yes" if descendant else "no",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    group: int | None = None
    try:
        deadline = time.monotonic() + 5
        while not marker.exists() and time.monotonic() < deadline:
            assert wrapper.poll() is None, "runner exited before owned fixture was ready"
            time.sleep(0.01)
        assert marker.exists(), "owned command did not start"
        group = int(json.loads(marker.read_text())["pgid"])
        wrapper.send_signal(signal.SIGINT)
        stdout, stderr = wrapper.communicate(timeout=5)
        assert wrapper.returncode == 130, (stdout, stderr)
        assert observed_signal.read_text() == "SIGINT"
        if not descendant:
            with pytest.raises(ProcessLookupError):
                os.killpg(group, 0)
            return False
        previous = heartbeat.read_text()
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            current = heartbeat.read_text()
            if current and current != previous:
                (tmp_path / "observation.json").write_text(
                    json.dumps(
                        {
                            "runner_exit": wrapper.returncode,
                            "command_received": observed_signal.read_text(),
                            "owned_process_group": group,
                            "heartbeat_after_runner_exit": [previous, current],
                            "descendant_progress_after_runner_exit": True,
                            "cleanup": "test finally SIGKILLs the owned process group",
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                return True
            time.sleep(0.01)
        return False
    finally:
        if group is None and marker.exists():
            group = int(json.loads(marker.read_text())["pgid"])
        if group is not None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(group, signal.SIGKILL)
        if wrapper.poll() is None:
            wrapper.kill()
        wrapper.communicate(timeout=5)


def test_logged_command_ctrl_c_stops_owned_direct_child(tmp_path: Path) -> None:
    assert not _interrupt_owned_command(tmp_path, descendant=False)


def test_logged_command_ctrl_c_must_stop_descendant_that_ignores_sigint(tmp_path: Path) -> None:
    """A finished direct child must not leave its QA process group running."""
    assert not _interrupt_owned_command(tmp_path, descendant=True), (
        "_run_logged returned after SIGINT but an owned descendant still updates its heartbeat"
    )
