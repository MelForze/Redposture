"""Constrained client FD budget with a growing real keepalive exporter pool."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
from pathlib import Path


async def _server() -> None:
    import resource

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft != resource.RLIM_INFINITY and soft < 2048:
        resource.setrlimit(resource.RLIMIT_NOFILE, (2048, hard))

    async def serve(reader, writer):
        try:
            while True:
                header = await reader.readuntil(b"\r\n\r\n")
                path = header.split(b" ")[1]
                body = b'node_exporter_build_info{version="1"} 1\n' if path == b"/metrics" else b'{"qa":1}'
                close = b"Connection: close\r\n" if path == b"/metrics" else b""
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n" + close + b"\r\n" + body
                )
                await writer.drain()
                if path == b"/metrics":
                    # Keep data connections persistent, but let the server
                    # actively close detect sockets, avoiding client-side
                    # ephemeral-port exhaustion between repeated trials.
                    break
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    servers = [await asyncio.start_server(serve, "127.0.0.1", 0, backlog=1024) for _ in range(600)]
    print(json.dumps([s.sockets[0].getsockname()[1] for s in servers]), flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        for server in servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in servers))


def _client() -> None:
    import resource

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from redposture_core.constants import DISCOVERY_EXPORTERS
    from redposture_core.exporters.collect import collect_exporter_debug_data

    # Start server before lowering only the client process's limit. The outer
    # pytest process and user's resource settings remain unchanged.
    server = subprocess.Popen(
        [sys.executable, __file__, "--server"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    try:
        assert server.stdout is not None
        ports = json.loads(server.stdout.readline())
        _soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (768, hard))
        exporters = [e for e in DISCOVERY_EXPORTERS if e["name"] == "node_exporter"]
        stats = {}
        errors = []

        class Log:
            def log(self, stage, target, **fields):
                if fields.get("error") and len(errors) < 5:
                    errors.append(str(fields["error"]))

        # 10k deliberate repeated attempts over 600 distinct origins exercise
        # growth past the pool's 512 idle slots while detection remains busy.
        result = collect_exporter_debug_data(
            Log(),
            [],
            timeout=1,
            retries=0,
            workers=16,
            output_path=None,
            collect_exporters=exporters,
            collect_debug_endpoints=("/debug/vars",),
            adaptive_collect=False,
            scan_work_items=(("127.0.0.1", ports[i % 600], "http") for i in range(10000)),
            scan_work_items_count=10000,
            discovery_exporters=exporters,
            stats_sink=stats,
            emit_line=lambda _: None,
        )
        print(json.dumps({"result": result, "stats": stats, "errors": errors}), flush=True)
        assert result == (10000, 10000)
        assert stats["discovery_checks"] == stats["discovery_found"] == 10000
        assert stats["discovery_errors"] == 0
    finally:
        server.terminate()
        server.wait(timeout=10)
        if server.stdout:
            server.stdout.close()


def test_scaled_collect_keeps_idle_pool_growth_within_real_fd_budget():
    import pytest

    resource = pytest.importorskip("resource")
    _soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and hard < 2048:
        pytest.skip("server requires 600 listeners plus persistent client sockets")
    process = subprocess.Popen(
        [sys.executable, __file__, "--client"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    try:
        stdout, stderr = process.communicate(timeout=90)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        pytest.fail(f"FD corpus timed out: {stdout}\n{stderr}")
    assert process.returncode == 0, stdout + "\n" + stderr


if __name__ == "__main__":
    if sys.argv[1] == "--server":
        asyncio.run(_server())
    else:
        _client()
