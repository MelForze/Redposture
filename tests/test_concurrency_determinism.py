"""Repeatability and atomic-output checks under deliberately reordered work."""

from __future__ import annotations

import random
import threading
import time
from types import SimpleNamespace

from redposture_core.audit_models import AuditRecord
from redposture_core.scheduler import SharedNestedScheduler
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, LineOutputSink, ModuleAuditSpec


def test_nested_scheduler_order_is_stable_across_randomized_completion() -> None:
    expected = [value * value for value in range(200)]
    for seed in range(12):
        scheduler = SharedNestedScheduler(max_workers=16)
        randomizer = random.Random(seed)
        delays = [randomizer.random() * 0.002 for _ in expected]

        def work(value: int, current_delays: list[float] = delays) -> int:
            time.sleep(current_delays[value])
            return value * value

        try:
            assert scheduler.map_ordered(range(200), work, key=f"target-{seed}", per_key_limit=8) == expected
        finally:
            scheduler.close()


def test_parallel_audit_completion_order_never_loses_or_duplicates_targets() -> None:
    targets = tuple(f"target-{index:03d}" for index in range(100))
    observed: list[list[str]] = []
    for run in range(8):
        lines: list[str] = []

        def detect(ctx: object, run_index: int = run) -> AuditRecord:
            index = int(str(ctx.host).rsplit("-", 1)[1])
            time.sleep(((index * 17 + run_index * 13) % 11) * 0.0002)
            return AuditRecord(host=str(ctx.host), port=1, module="qa", service="qa", status="detected")

        AuditCommandRunner(
            args=SimpleNamespace(debug=False),
            spec=ModuleAuditSpec(
                module="qa",
                label="QA",
                default_port=1,
                detect=detect,
                is_detected=lambda _record: True,
                render=lambda record: [record.host],
            ),
            emit_line=lines.append,
        ).run_plan(AuditCommandPlan(targets_by_port={1: targets}, workers=32))
        observed.append(lines)

    assert all(sorted(lines) == list(targets) for lines in observed)
    assert len({tuple(lines) for lines in observed}) > 1


def test_multiline_sink_blocks_never_interleave(tmp_path) -> None:
    console: list[str] = []
    sink = LineOutputSink(str(tmp_path / "atomic.txt"), console.append)
    barrier = threading.Barrier(17)

    def producer(index: int) -> None:
        barrier.wait(timeout=3)
        sink.emit_many([f"{index}:begin", f"{index}:end"])

    threads = [threading.Thread(target=producer, args=(index,)) for index in range(16)]
    for thread in threads:
        thread.start()
    barrier.wait(timeout=3)
    for thread in threads:
        thread.join(timeout=3)
        assert not thread.is_alive()
    sink.close()

    assert (tmp_path / "atomic.txt").read_text(encoding="utf-8").splitlines() == console
    assert len(console) == 32
    for offset in range(0, len(console), 2):
        assert console[offset].removesuffix(":begin") == console[offset + 1].removesuffix(":end")
