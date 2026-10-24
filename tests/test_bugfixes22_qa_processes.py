"""Bounded timeout cleans descendants even when the immediate child exits."""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


def test_timeout_reaps_owned_process_group_after_direct_child_exits(tmp_path: Path) -> None:
    marker, heartbeat = tmp_path / "ready.json", tmp_path / "heartbeat"
    child_code = """
import json,os,signal,subprocess,sys,time
from pathlib import Path
signal.signal(signal.SIGTERM, lambda *args: sys.exit(0))
p=subprocess.Popen([sys.executable,'-c', "import signal,sys,time; from pathlib import Path; signal.signal(signal.SIGTERM,signal.SIG_IGN); [(Path(sys.argv[1]).write_text(str(i)),time.sleep(.01)) for i in range(1000)]",sys.argv[2]])
while not Path(sys.argv[2]).exists(): time.sleep(.01)
Path(sys.argv[1]).write_text(json.dumps({'pgid':os.getpgrp()}))
time.sleep(20)
"""
    wrapper = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys; from pathlib import Path; from scripts.run_qa_handoff import _run_logged; code,_=_run_logged(sys.argv[2:],Path(sys.argv[1]),timeout=1); sys.exit(code)",
            str(tmp_path / "run.log"),
            sys.executable,
            "-c",
            child_code,
            str(marker),
            str(heartbeat),
        ],
        start_new_session=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 4
        while not marker.exists() and time.monotonic() < deadline:
            assert wrapper.poll() is None
            time.sleep(0.01)
        assert marker.exists()
        try:
            stdout, stderr = wrapper.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            raise AssertionError("one-second timeout did not terminate owned command within five seconds") from None
        assert wrapper.returncode == 124, (stdout, stderr)
        before = heartbeat.read_text()
        time.sleep(0.1)
        assert heartbeat.read_text() == before, "orphan continues running after timeout"
        assert "timed out" in (tmp_path / "run.log").read_text()
    finally:
        if marker.exists():
            with contextlib.suppress(ProcessLookupError):
                os.killpg(json.loads(marker.read_text())["pgid"], signal.SIGKILL)
        if wrapper.poll() is None:
            wrapper.kill()
        wrapper.communicate(timeout=3)
