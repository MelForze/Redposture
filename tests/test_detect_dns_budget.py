from __future__ import annotations

import asyncio
import socket
import threading
import time

import pytest

from redposture_core.clients.detect_dns import BoundedSystemResolver, ResolutionUnavailable


def test_stalled_dns_is_coalesced_bounded_and_cancellable_without_executor(monkeypatch):
    release = threading.Event()
    entered = threading.Event()
    calls = []

    def stalled(host, port, *args):
        calls.append((host, port))
        entered.set()
        assert release.wait(2)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", stalled)
    resolver = BoundedSystemResolver(workers=1, queued=1, idle_timeout=0.02)

    async def run():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "run_in_executor", lambda *a: pytest.fail("default executor must not resolve DNS"))
        task = asyncio.create_task(resolver.resolve("one.invalid", 80, 1))
        while not entered.is_set():
            await asyncio.sleep(0.001)
        shared = asyncio.create_task(resolver.resolve("one.invalid", 80, 1))
        await asyncio.sleep(0)
        queued = resolver.submit("two.invalid", 80)
        with pytest.raises(ResolutionUnavailable, match="saturated"):
            resolver.submit("three.invalid", 80)
        started = time.monotonic()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert time.monotonic() - started < 0.2
        assert resolver._running == 1 and len(resolver._pending) == 2
        release.set()
        assert (await shared)[0][4][0] == "127.0.0.1"
        await asyncio.wrap_future(queued)
        for _ in range(100):
            if resolver._running == 0:
                break
            await asyncio.sleep(0.01)
        assert resolver._running == 0 and not resolver._pending
        assert calls == [("one.invalid", 80), ("two.invalid", 80)]

    try:
        asyncio.run(run())
    finally:
        release.set()


def test_dns_timeout_requests_legacy_verification_and_late_error_is_consumed(monkeypatch):
    release = threading.Event()

    def stalled(*a):
        assert release.wait(2)
        raise socket.gaierror(-2, "fixture hostname not found")

    monkeypatch.setattr(socket, "getaddrinfo", stalled)
    resolver = BoundedSystemResolver(workers=1, queued=1, idle_timeout=0.02)

    async def run():
        errors = []
        asyncio.get_running_loop().set_exception_handler(lambda loop, context: errors.append(context))
        with pytest.raises(ResolutionUnavailable, match="timed out"):
            await resolver.resolve("slow.invalid", 80, 0.02)
        release.set()
        for _ in range(100):
            if resolver._running == 0:
                break
            await asyncio.sleep(0.01)
        assert not errors and resolver._running == 0

    try:
        asyncio.run(run())
    finally:
        release.set()


def test_worker_start_failure_does_not_poison_resolver_queue(monkeypatch):
    resolver = BoundedSystemResolver(workers=1, queued=1, idle_timeout=0.02)
    original_start = threading.Thread.start
    monkeypatch.setattr(
        threading.Thread, "start", lambda self: (_ for _ in ()).throw(RuntimeError("can't start new thread"))
    )
    with pytest.raises(ResolutionUnavailable, match="worker"):
        resolver.submit("localhost", 80)
    assert resolver._running == 0 and not resolver._pending and resolver._queue.empty()
    monkeypatch.setattr(threading.Thread, "start", original_start)
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]
    )

    async def recover():
        assert await resolver.resolve("localhost", 80, 1)
        for _ in range(100):
            if resolver._running == 0:
                break
            await asyncio.sleep(0.01)
        assert resolver._running == 0 and not resolver._pending

    asyncio.run(recover())
