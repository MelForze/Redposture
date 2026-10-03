"""Subprocess crash boundaries for resumable discovery and exporter collection."""

from __future__ import annotations

import json
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from redposture_core.modules.clickhouse.discover.checkpoint import CheckpointStore
from redposture_core.stage_collect import _load_collect_checkpoint_state, _load_collect_completed_jobs


def _wait_for(path: Path, *, contains: str | None = None) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if path.exists() and (contains is None or contains in path.read_text(encoding="utf-8")):
            return
        time.sleep(0.01)
    pytest.fail(f"timed out waiting for {path}")


def _kill_child(child: subprocess.Popen[str]) -> None:
    if child.poll() is None:
        child.send_signal(signal.SIGKILL)
    child.communicate(timeout=10)
    assert child.returncode == -signal.SIGKILL


@pytest.mark.skipif(not hasattr(signal, "SIGKILL"), reason="POSIX SIGKILL required")
def test_clickhouse_checkpoint_survives_sigkill_before_atomic_replace(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.json"
    first = CheckpointStore(path, "target:9000", resume=False)
    first.update(chunk_id="part-1", chunk={"status": "complete"}, status="running")
    marker = tmp_path / "before-replace"
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            """
import os, sys, time
from pathlib import Path
from redposture_core.modules.clickhouse.discover import checkpoint
original = os.replace
def stop_before_replace(src, dst):
    Path(sys.argv[2]).write_text('ready', encoding='utf-8')
    while True:
        time.sleep(1)
checkpoint.os.replace = stop_before_replace
store = checkpoint.CheckpointStore(Path(sys.argv[1]), 'target:9000', resume=True)
store.update(chunk_id='part-2', chunk={'status': 'complete'}, status='complete')
""",
            str(path),
            str(marker),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_for(marker)
    finally:
        _kill_child(child)

    resumed = CheckpointStore(path, "target:9000", resume=True)
    assert resumed.is_complete("part-1")
    assert not resumed.is_complete("part-2")
    resumed.update(chunk_id="part-2", chunk={"status": "complete"}, status="complete")
    assert resumed.is_complete("part-1") and resumed.is_complete("part-2")
    assert json.loads(path.read_text(encoding="utf-8"))["targets"]["target:9000"]["status"] == "complete"


def test_clickhouse_rejects_truncated_checkpoint_without_erasing_it(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.json"
    path.write_text('{"schema_version":1,"targets":', encoding="utf-8")
    with pytest.raises(ValueError, match="invalid checkpoint"):
        CheckpointStore(path, "target:9000", resume=True)
    assert path.read_text(encoding="utf-8").endswith('"targets":')


def test_collect_checkpoint_ignores_torn_jsonl_tail_and_uses_latest_complete_row(tmp_path: Path) -> None:
    path = tmp_path / "collect.jsonl"
    key = ("127.0.0.1", "node_exporter", 9100, "/debug/vars")
    rows = [
        {"host": key[0], "exporter": key[1], "port": key[2], "endpoint": key[3], "ok": False},
        {"host": key[0], "exporter": key[1], "port": key[2], "endpoint": key[3], "ok": True},
    ]
    path.write_text("\n".join(json.dumps(row) for row in rows) + '\n{"host":"torn"', encoding="utf-8")
    assert _load_collect_checkpoint_state(str(path))[key]["ok"] is True
    assert _load_collect_completed_jobs(str(path)) == {key}


@pytest.mark.known_defect_audit
@pytest.mark.skipif(not hasattr(signal, "SIGKILL"), reason="POSIX SIGKILL required")
def test_collect_resume_does_not_duplicate_output_after_sigkill(tmp_path: Path) -> None:
    """Document the output/checkpoint race in asynchronous postprocessing."""

    output = tmp_path / "collect.jsonl"
    checkpoint = tmp_path / "checkpoint.jsonl"
    marker = tmp_path / "callback-started"
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            """
import sys, time
from pathlib import Path
from redposture_core.exporters.collect import collect_exporter_debug_data
def task(host, exporter, port, endpoint, timeout, retries):
    return ({'host':host, 'exporter':exporter, 'port':port, 'endpoint':endpoint,
             'url':f'http://{host}:{port}{endpoint}', 'timestamp':'2026-10-03T00:00:00Z',
             'ok':True, 'status':200, 'elapsed_ms':1, 'content_type':'text/plain',
             'error':None, 'truncated':False, 'body':'ok'}, True)
def blocked_callback(record):
    Path(sys.argv[3]).write_text('ready', encoding='utf-8')
    while True:
        time.sleep(1)
collect_exporter_debug_data(logger=None, hosts=['127.0.0.1'], timeout=1,
    output_path=sys.argv[1], output_format='json', emit_line=None, workers=1, retries=0,
    collect_exporters=[{'name':'node_exporter','port':9100}],
    collect_debug_endpoints=['/debug/vars'],
    found_by_host={'127.0.0.1':[{'exporter':'node_exporter','port':9100}]},
    adaptive_collect=False, collect_task_fn=task, checkpoint_path=sys.argv[2],
    record_callback=blocked_callback, emit_summary=False)
""",
            str(output),
            str(checkpoint),
            str(marker),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_for(marker)
        _wait_for(output, contains='"endpoint": "/debug/vars"')
    finally:
        _kill_child(child)

    key = ("127.0.0.1", "node_exporter", 9100, "/debug/vars")
    assert key not in _load_collect_completed_jobs(str(checkpoint))

    from redposture_core.exporters.collect import collect_exporter_debug_data

    def task(host: str, exporter: str, port: int, endpoint: str, *_args: object):
        return (
            {
                "host": host,
                "exporter": exporter,
                "port": port,
                "endpoint": endpoint,
                "url": f"http://{host}:{port}{endpoint}",
                "timestamp": "2026-10-03T00:00:00Z",
                "ok": True,
                "status": 200,
                "elapsed_ms": 1,
                "content_type": "text/plain",
                "error": None,
                "truncated": False,
                "body": "ok",
            },
            True,
        )

    collect_exporter_debug_data(
        logger=None,
        hosts=["127.0.0.1"],
        timeout=1,
        output_path=str(output),
        output_format="json",
        emit_line=None,
        workers=1,
        retries=0,
        collect_exporters=[{"name": "node_exporter", "port": 9100}],
        collect_debug_endpoints=["/debug/vars"],
        found_by_host={"127.0.0.1": [{"exporter": "node_exporter", "port": 9100}]},
        adaptive_collect=False,
        collect_task_fn=task,
        checkpoint_path=str(checkpoint),
        resume_completed_jobs=_load_collect_completed_jobs(str(checkpoint)),
        output_mode="a",
        checkpoint_mode="a",
        emit_summary=False,
    )
    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert len([record for record in records if record.get("endpoint") == "/debug/vars"]) == 1


@pytest.mark.known_defect_audit
@pytest.mark.skipif(not hasattr(signal, "SIGKILL"), reason="POSIX SIGKILL required")
def test_collect_resume_does_not_lose_output_after_sigkill(tmp_path: Path) -> None:
    """A durable checkpoint can also win the race against the output file."""

    output = tmp_path / "collect.jsonl"
    checkpoint = tmp_path / "checkpoint.jsonl"
    marker = tmp_path / "before-output"
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            """
import sys, time
from pathlib import Path
from redposture_core.exporters import collect
def task(host, exporter, port, endpoint, timeout, retries):
    return ({'host':host, 'exporter':exporter, 'port':port, 'endpoint':endpoint,
             'url':f'http://{host}:{port}{endpoint}', 'timestamp':'2026-10-03T00:00:00Z',
             'ok':True, 'status':200, 'elapsed_ms':1, 'content_type':'text/plain',
             'error':None, 'truncated':False, 'body':'ok'}, True)
def blocked_output(*args):
    Path(sys.argv[3]).write_text('ready', encoding='utf-8')
    while True:
        time.sleep(1)
collect.emit_output_line = blocked_output
collect.collect_exporter_debug_data(logger=None, hosts=['127.0.0.1'], timeout=1,
    output_path=sys.argv[1], output_format='json', emit_line=None, workers=1, retries=0,
    collect_exporters=[{'name':'node_exporter','port':9100}],
    collect_debug_endpoints=['/debug/vars'],
    found_by_host={'127.0.0.1':[{'exporter':'node_exporter','port':9100}]},
    adaptive_collect=False, collect_task_fn=task, checkpoint_path=sys.argv[2],
    emit_summary=False)
""",
            str(output),
            str(checkpoint),
            str(marker),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_for(marker)
        _wait_for(checkpoint, contains='"ok": true')
    finally:
        _kill_child(child)

    key = ("127.0.0.1", "node_exporter", 9100, "/debug/vars")
    assert key in _load_collect_completed_jobs(str(checkpoint))
    assert len([line for line in output.read_text(encoding="utf-8").splitlines() if '"endpoint"' in line]) == 1
