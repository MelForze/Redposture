"""Detection continuations preserve exceptions, overrides and task-local state."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest


def test_sync_sender_exceptions_are_thrown_into_decision_tree():
    from redposture_core.detection_io import DetectCall, run_sync

    def fail():
        raise OSError("offline")

    def steps():
        try:
            yield DetectCall(fail, (), {})
        except OSError:
            return "transport_failure"

    assert run_sync(steps()) == "transport_failure"


def test_async_uses_registered_continuation_and_yields_retry_sleep():
    from redposture_core.detection_io import DetectCall, DetectDelay, run_async

    calls = []

    def forbidden():
        raise AssertionError("sync I/O on event loop")

    def child():
        calls.append("native")
        yield DetectDelay(0.001)
        return 7

    def root():
        return (yield DetectCall(forbidden, (), {}))

    assert asyncio.run(run_async(root(), object(), {forbidden: child})) == 7
    assert calls == ["native"]


def test_unregistered_helper_requests_full_legacy_verification():
    from redposture_core.clients.async_http_detect import AsyncHttpFallback
    from redposture_core.detection_io import DetectCall, run_async

    def root():
        yield DetectCall(lambda: pytest.fail("must not run blocking override"), (), {})

    with pytest.raises(AsyncHttpFallback):
        asyncio.run(run_async(root(), object(), {}))


def test_interleaved_detection_restores_thread_local_context_before_every_resume():
    from redposture_core.detection_io import DetectDelay, run_async

    current = SimpleNamespace(value=None)

    def steps(value):
        for _ in range(4):
            assert current.value == value
            yield DetectDelay(0.001)
        return value

    async def run():
        return await asyncio.gather(
            *(
                run_async(
                    steps(i), object(), {}, activate=__import__("functools").partial(setattr, current, "value", i)
                )
                for i in range(32)
            )
        )

    assert asyncio.run(run()) == list(range(32))


@pytest.mark.parametrize("outcome", ["success", "error", "cancel"])
def test_resume_scope_restores_bindings_during_wait_and_after_cleanup(outcome):
    from threading import local

    from redposture_core.detection_io import DetectCall, DetectDelay, run_async

    current = local()
    sentinel = object()
    current.existing = sentinel
    current.empty = None
    original = dict(current.__dict__)
    closed = []

    def activate():
        current.existing = "target"
        current.added = "target"
        del current.empty

    def forbidden():
        pytest.fail("blocking helper")

    def child():
        assert current.existing == current.added == "target"
        try:
            yield DetectDelay(0.01)
            if outcome == "error":
                raise ValueError("failed response")
            return "result"
        finally:
            assert current.existing == current.added == "target"
            closed.append("child")

    def root():
        try:
            return (yield DetectCall(forbidden, (), {}))
        finally:
            assert current.existing == current.added == "target"
            closed.append("root")

    async def run():
        task = asyncio.create_task(
            run_async(root(), object(), {forbidden: child}, activate=activate, thread_locals=(current,))
        )
        await asyncio.sleep(0)
        assert current.__dict__ == original
        if outcome == "cancel":
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        elif outcome == "error":
            with pytest.raises(ValueError, match="failed response"):
                await task
        else:
            assert await task == "result"
        assert current.__dict__ == original

    asyncio.run(run())
    assert closed == ["child", "root"]
    assert current.__dict__ == original
