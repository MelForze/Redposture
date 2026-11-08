from __future__ import annotations

import gc
from types import SimpleNamespace

from redposture_core.stage_runtime import AuditCommandRunner, ModuleAuditSpec


def runner(debug=True):
    return AuditCommandRunner(
        args=SimpleNamespace(debug=debug),
        spec=ModuleAuditSpec(module="test", label="TEST", default_port=9),
        emit_line=lambda _: None,
    )


def test_recycled_object_ids_do_not_erase_transport_statistics():
    class Pool:
        def stats(self):
            return {"requests": 1, "connections": 1, "reused": 0, "retries": 0}

    owner = runner()
    for _ in range(1000):
        pool = Pool()
        owner._capture_transport_stats(pool)
        owner._capture_transport_stats(pool)
        del pool
    assert owner._transport_stats["requests"] == 1000
    assert owner._transport_stats["connections"] == 1000


def test_disabled_debug_does_not_poll_closed_pool_statistics():
    class Pool:
        def stats(self):
            raise AssertionError("unused transport statistics in non-debug run")

    runner(debug=False)._capture_transport_stats(Pool())


def test_unhashable_pools_are_deduplicated_without_retaining_closed_objects():
    class Pool:
        def __eq__(self, other: object) -> bool:
            return self is other

        def stats(self):
            return {"requests": 1}

    owner = runner()
    assert Pool.__hash__ is None
    pools = [Pool() for _ in range(100)]
    for pool in pools:
        owner._capture_transport_stats(SimpleNamespace(http=pool, pool=pool))
    assert owner._transport_stats["requests"] == 100
    assert len(owner._transport_pool_refs) == 100
    del pools, pool
    gc.collect()
    assert len(owner._transport_pool_refs) == 0


def test_broken_diagnostic_snapshot_does_not_prevent_resource_cleanup():
    class State:
        def stats(self):
            raise OSError("stats unavailable")

    closed = []
    owner = AuditCommandRunner(
        args=SimpleNamespace(debug=True),
        spec=ModuleAuditSpec(module="test", label="TEST", default_port=9, lifecycle_state_close=closed.append),
        emit_line=lambda _: None,
    )
    state = State()
    owner._register_lifecycle_state(state)
    owner._close_lifecycle_state(state)
    assert closed == [state]
    assert owner._transport_uncertain_pools == 1
