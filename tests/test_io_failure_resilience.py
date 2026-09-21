"""Filesystem and output-channel failure contracts."""

from __future__ import annotations

import errno
from pathlib import Path
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.modules.clickhouse.discover import checkpoint as checkpoint_module
from redposture_core.modules.clickhouse.discover.checkpoint import CheckpointStore
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, LineOutputSink, ModuleAuditSpec


def test_output_sink_reports_read_only_destination(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def denied(*_args: object, **_kwargs: object) -> object:
        raise PermissionError(errno.EACCES, "read-only file system")

    monkeypatch.setattr("builtins.open", denied)
    sink = LineOutputSink(str(tmp_path / "result.txt"), lambda _line: None)

    with pytest.raises(PermissionError, match="read-only"):
        sink.prepare()


def test_output_sink_propagates_disk_full_and_closes_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    class FullDisk:
        closed = False

        def write(self, _value: str) -> None:
            raise OSError(errno.ENOSPC, "No space left on device")

        def flush(self) -> None:
            return

        def close(self) -> None:
            self.closed = True

    handle = FullDisk()
    monkeypatch.setattr("builtins.open", lambda *_args, **_kwargs: handle)
    sink = LineOutputSink("result.txt", lambda _line: None)

    with pytest.raises(OSError) as raised:
        sink.emit_many(["record"])
    sink.close()

    assert raised.value.errno == errno.ENOSPC
    assert handle.closed is True


def test_broken_stdout_still_closes_lifecycle_and_output_file(tmp_path: Path) -> None:
    closed: list[str] = []

    def detect(ctx: object) -> AuditRecord:
        return AuditRecord(host=str(ctx.host), port=int(ctx.port), module="qa", service="qa", status="detected")

    def broken_pipe(_line: str) -> None:
        raise BrokenPipeError(errno.EPIPE, "consumer closed")

    output = tmp_path / "result.txt"
    runner = AuditCommandRunner(
        args=SimpleNamespace(debug=False),
        spec=ModuleAuditSpec(
            module="qa",
            label="QA",
            default_port=1,
            detect=detect,
            data=lambda _ctx, record: record,
            is_detected=lambda _record: True,
            render=lambda record: [f"QA {record.host} {record.port} {record.status}"],
            lifecycle_state_factory=lambda _ctx: "lifecycle",
            lifecycle_state_close=closed.append,
        ),
        emit_line=broken_pipe,
    )

    with pytest.raises(BrokenPipeError):
        runner.run_plan(AuditCommandPlan(targets_by_port={1: ("target",)}, workers=1, output_path=str(output)))

    assert closed == ["lifecycle"]
    assert output.read_text(encoding="utf-8") == "QA target 1 detected\n"


def test_checkpoint_replace_failure_preserves_previous_valid_document(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "checkpoint.json"
    store = CheckpointStore(path, "target", resume=False)
    before = path.read_bytes()

    def fail_replace(_source: object, _destination: object) -> None:
        raise OSError(errno.EIO, "simulated replace failure")

    monkeypatch.setattr(checkpoint_module.os, "replace", fail_replace)
    with pytest.raises(OSError, match="replace failure"):
        store.update(status="complete")

    assert path.read_bytes() == before
    assert not list(tmp_path.glob(".checkpoint.json.*"))
