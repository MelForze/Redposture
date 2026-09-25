"""Process-level SIGINT checks for large scans and nested discovery work."""

from __future__ import annotations

import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import cast

import pytest

pytestmark = pytest.mark.local_output_audit

ROOT = Path(__file__).resolve().parents[1]


class _HangingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("0.0.0.0", 0), _HangingHandler)
        self.connection_count = 0
        self.enough_connections = threading.Event()
        self.release = threading.Event()
        self.lock = threading.Lock()


class _HangingHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = cast(_HangingServer, self.server)
        with server.lock:
            server.connection_count += 1
            if server.connection_count >= 8:
                server.enough_connections.set()
        cast(socket.socket, self.request).settimeout(0.1)
        server.release.wait(timeout=10)


def _interrupt(process: subprocess.Popen[str], *, timeout: float = 8.0) -> tuple[str, str, float]:
    started = time.monotonic()
    process.send_signal(signal.SIGINT)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate(timeout=3)
        pytest.fail(f"process did not stop after SIGINT\nstdout={stdout}\nstderr={stderr}")
    return stdout, stderr, time.monotonic() - started


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX SIGINT process semantics")
def test_sigint_stops_live_ten_thousand_target_scan_without_traceback(tmp_path: Path) -> None:
    server = _HangingServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    targets = tmp_path / "targets.txt"
    targets.write_text(
        "\n".join(f"http://127.0.0.1:{server.server_address[1]}/?target={index}" for index in range(10_000)),
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "redposture.py",
            "grafana",
            "-t",
            str(targets),
            "--workers",
            "64",
            "--timeout",
            "30",
            "--retries",
            "0",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert server.enough_connections.wait(timeout=5)
        stdout, stderr, elapsed = _interrupt(process)
    finally:
        server.release.set()
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=3)
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    assert process.returncode == 130
    assert elapsed < 5
    assert "interrupted by user" in stderr
    assert "Traceback" not in stdout + stderr


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX SIGINT process semantics")
def test_sigint_detaches_blocked_nested_discovery_workers(tmp_path: Path) -> None:
    script = tmp_path / "nested_discovery.py"
    script.write_text(
        """
import sys
import time
from types import SimpleNamespace

from redposture_core.audit_models import AuditRecord
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, ModuleAuditSpec


def detect(ctx):
    return AuditRecord(host=ctx.host, port=ctx.port, module="qa", service="qa", status="open_no_auth")


def discover(ctx, record):
    print("DISCOVERY_STARTED", flush=True)
    list(ctx.nested_scheduler.iter_completed(range(10_000), lambda _item: time.sleep(30), key=ctx.host, per_key_limit=8))
    return record


spec = ModuleAuditSpec(
    module="qa",
    label="QA",
    default_port=1,
    detect=detect,
    data=discover,
    is_detected=lambda _record: True,
    record_retention_limit=0,
)
runner = AuditCommandRunner(args=SimpleNamespace(debug=False), spec=spec, emit_line=lambda _line: None)
try:
    runner.run_plan(AuditCommandPlan(targets_by_port={1: ("target",)}, workers=64))
except KeyboardInterrupt:
    print("INTERRUPTED", flush=True)
    raise SystemExit(130)
""".strip()
        + "\n",
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [sys.executable, str(script)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.5)
    stdout, stderr, elapsed = _interrupt(process)

    assert process.returncode == 130
    assert "DISCOVERY_STARTED" in stdout
    assert "INTERRUPTED" in stdout
    assert elapsed < 5
    assert "Traceback" not in stdout + stderr
