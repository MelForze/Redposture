"""Inflight credits wake each waiter once, including cancelled grants."""

import asyncio
from typing import Any, cast

from redposture_core.detect_backoff import DetectSlots


def test_batch_release_is_linear_and_preserves_fifo():
    checks = []
    granted = []

    class Waiter:
        def __init__(self, index):
            self.index = index

        def done(self):
            checks.append(self.index)
            return self.index % 7 == 0

        def set_result(self, value):
            granted.append(self.index)

    slots = DetectSlots(4096)
    slots.active = 4096
    slots.waiters.extend(cast(Any, Waiter(i)) for i in range(4096))
    slots.release_many(4096)
    assert checks == list(range(4096))
    assert granted == [i for i in range(4096) if i % 7]
    assert slots.active == len(granted)
    assert not slots.waiters
    slots.release_many(len(granted))
    assert slots.active == 0


def test_cancelled_grant_transfers_credit_without_leak():
    async def run():
        slots = DetectSlots(1)
        await slots.acquire()
        first = asyncio.create_task(slots.acquire())
        second = asyncio.create_task(slots.acquire())
        await asyncio.sleep(0)
        slots.release_many(1)
        first.cancel()
        await asyncio.gather(first, return_exceptions=True)
        await asyncio.wait_for(second, 1)
        assert slots.active == 1
        slots.release()
        assert slots.active == 0

    asyncio.run(run())
