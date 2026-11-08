"""Native detection can park a finish continuation without parking a worker."""

from __future__ import annotations

import threading
from concurrent.futures import Future
from contextvars import ContextVar

import pytest

from redposture_core import scheduler


def test_unresolved_future_releases_worker_and_resumes_in_its_own_context():
    ready = Future()
    calls = []

    def work(item):
        calls.append((item, "begin"))
        if item == "waiting":
            yield ready
            ready.result()
        else:
            ready.set_result(None)
        calls.append((item, "end"))
        return item

    pool = scheduler._PausedWorkerPool(max_workers=1, max_inflight=2, worker=work)
    pool.submit(scheduler._Task(1, "waiting"))
    pool.submit(scheduler._Task(2, "ready"))
    try:
        result = [pool.results.get(timeout=2), pool.results.get(timeout=2)]
    finally:
        pool.close()
    assert [r.value for r in result] == ["ready", "waiting"]
    assert not any(r.error for r in result)
    assert calls == [("waiting", "begin"), ("ready", "begin"), ("ready", "end"), ("waiting", "end")]


def test_pool_finishes_other_item_during_pause_and_keeps_job_context():
    marker = ContextVar("paused-finish-test", default="outside")
    calls = []

    def work(item):
        token = marker.set(item)
        try:
            calls.append((item, "begin"))
            if item == "paused":
                yield 0.05
            assert marker.get() == item
            calls.append((item, "end"))
            return item
        finally:
            marker.reset(token)

    pool = scheduler._PausedWorkerPool(max_workers=1, max_inflight=2, worker=work)
    pool.submit(scheduler._Task(10, "paused"))
    pool.submit(scheduler._Task(20, "ready"))
    try:
        results = [pool.results.get(timeout=2), pool.results.get(timeout=2)]
    finally:
        pool.close()
    assert [(r.index, r.item, r.value, r.error) for r in results] == [
        (20, "ready", "ready", None),
        (10, "paused", "paused", None),
    ]
    assert calls == [("paused", "begin"), ("ready", "begin"), ("ready", "end"), ("paused", "end")]
    assert marker.get() == "outside" and not pool._thread.is_alive()


def test_cancel_closes_parked_context_and_does_not_wait_for_long_pause():
    entered, closed = threading.Event(), threading.Event()
    marker = ContextVar("paused-close-test", default=None)

    def work(item):
        token = marker.set(item)
        try:
            entered.set()
            yield 60
        finally:
            assert marker.get() == item
            marker.reset(token)
            closed.set()

    pool = scheduler._PausedWorkerPool(max_workers=1, max_inflight=2, worker=work)
    pool.submit(scheduler._Task(1, "one"))
    assert entered.wait(2)
    pool.cancel()
    assert closed.wait(2)
    pool._thread.join(2)
    assert not pool._thread.is_alive() and marker.get() is None
    pool.cancel()


@pytest.mark.parametrize("fault", ["worker", "bad-delay"])
def test_paused_pool_transports_failure_instead_of_losing_main_consumer(fault):
    def work(item):
        if fault == "worker":
            raise RuntimeError("fixture worker failed")
        yield "not a valid delay"
        return item

    pool = scheduler._PausedWorkerPool(max_workers=1, max_inflight=2, worker=work)
    pool.submit(scheduler._Task(1, "one"))
    try:
        result = pool.results.get(timeout=2)
        assert isinstance(result.error, (RuntimeError, ValueError))
    finally:
        pool.cancel()
        pool._thread.join(2)
    assert not pool._thread.is_alive()
