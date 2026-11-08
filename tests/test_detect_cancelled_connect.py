"""Private native-loop SDK sockets must not depend on cyclic GC for close."""

from __future__ import annotations

import asyncio
import gc
import os
import socket

import pytest

from redposture_core.clients.async_resolver import install_numeric_resolver


def test_private_loop_closes_socket_when_pending_connect_is_cancelled(monkeypatch):
    async def run():
        loop = asyncio.get_running_loop()
        started = asyncio.Event()
        addresses = []

        async def pending(sock, address):
            addresses.append(address)
            started.set()
            await asyncio.Future()

        monkeypatch.setattr(loop, "sock_connect", pending)
        install_numeric_resolver()
        with socket.socket() as sock:
            task = asyncio.create_task(loop.sock_connect(sock, ("127.0.0.1", 12345)))
            await started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert sock.fileno() == -1, "cancelled SDK connect still owns an open descriptor"
        assert addresses == [("127.0.0.1", 12345)]

    asyncio.run(run())


@pytest.mark.parametrize("error", [None, ConnectionRefusedError("refused")])
def test_connect_success_or_regular_failure_keeps_original_ownership(monkeypatch, error):
    async def run():
        loop = asyncio.get_running_loop()
        calls = []

        async def connect(sock, address):
            calls.append((sock, address))
            if error is not None:
                raise error

        monkeypatch.setattr(loop, "sock_connect", connect)
        install_numeric_resolver()
        wrapped = loop.sock_connect
        install_numeric_resolver()
        assert loop.sock_connect is wrapped
        with socket.socket() as sock:
            if error is not None:
                with pytest.raises(ConnectionRefusedError) as failed:
                    await loop.sock_connect(sock, ("127.0.0.1", 12345))
                assert failed.value is error
            else:
                await loop.sock_connect(sock, ("127.0.0.1", 12345))
            assert sock.fileno() >= 0
            assert calls == [(sock, ("127.0.0.1", 12345))]

    asyncio.run(run())


def test_real_pymongo_negative_detection_releases_fds_without_gc():
    from redposture_core.clients.async_mongodb_detect import open_client

    directory = "/proc/self/fd" if os.path.isdir("/proc/self/fd") else "/dev/fd"
    if not os.path.isdir(directory):
        pytest.skip("OS has no per-process FD counter")
    # Import third-party modules before the baseline. Their one-time import
    # resources are not sockets belonging to these twenty failed probes.
    import pymongo  # noqa: F401
    from pymongo.errors import ServerSelectionTimeoutError

    with socket.socket() as closed_port:
        closed_port.bind(("127.0.0.1", 0))
        port = closed_port.getsockname()[1]
        before = len(os.listdir(directory))
        enabled = gc.isenabled()
        gc.disable()

        async def run():
            install_numeric_resolver()
            gate = asyncio.Semaphore(4)

            async def probe():
                async with gate:
                    client = open_client("127.0.0.1", port, timeout=0.1, auth_db="admin")
                    try:
                        with pytest.raises(ServerSelectionTimeoutError):
                            await client.hello()
                    finally:
                        await client.close()

            await asyncio.gather(*(probe() for _ in range(20)))

        try:
            asyncio.run(run())
            after = len(os.listdir(directory))
            assert after <= before + 2, f"FDs retained without GC: {before} -> {after}"
        finally:
            if enabled:
                gc.enable()
            gc.collect()
