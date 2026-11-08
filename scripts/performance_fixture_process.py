"""Owned protocol measurement peer in a separate interpreter/GIL, never a product.

The child remains in the same resource-limited container and network namespace.
Only bounded counters and one consumed token identity cross the private pipe.
"""

from __future__ import annotations

import multiprocessing
import os
import resource
import threading
import time
from collections import Counter
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any


def _worker(
    connection: Connection, module: str, roles: dict[int, str], delay: float, slow: bool, options: dict[str, Any]
) -> None:
    fixture = None
    try:
        from scripts.profile_module_performance import Fixture

        fixture = Fixture(module, roles, delay, slow, http_peer="async", **options)
        cpu_start = time.process_time()
        connection.send({"port": fixture.port, "closed_port": fixture.closed_port})
        while True:
            command, argument = connection.recv()
            if command == "pop":
                connection.send(fixture.pop_token_identity(argument))
            elif command == "pop-grpc":
                connection.send(fixture.pop_grpc_calls(argument))
            elif command == "pop-s3":
                connection.send(fixture.pop_s3_calls(argument))
            elif command == "pop-pair":
                connection.send(fixture.pop_pair_calls(argument))
            elif command == "pop-coordination":
                connection.send(fixture.pop_coordination_calls(argument))
            elif command == "pop-read":
                connection.send(fixture.pop_read_calls(argument))
            elif command == "close":
                fixture.close()
                connection.send(
                    {
                        "stats": dict(fixture.stats),
                        "routes": fixture.routes.snapshot(),
                        "errors": fixture.errors,
                        "grpc_wire_summary": fixture.grpc_wire_summary(),
                        "s3_wire_summary": fixture.s3_wire_summary(),
                        "pair_wire_summary": fixture.pair_wire_summary(),
                        "coordination_wire_summary": fixture.coordination_wire_summary(),
                        "model_summary": fixture.model_summary(),
                        "read_wire_summary": fixture.read_wire_summary(),
                        "cpu_seconds": time.process_time() - cpu_start,
                        "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                        * (1 if os.uname().sysname == "Darwin" else 1024),
                    }
                )
                return
            else:
                raise ValueError("unknown fixture control command")
    except BaseException as exc:
        try:
            connection.send({"failure": repr(exc)})
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        if fixture is not None:
            fixture.close()
        connection.close()


class _Routes:
    def __init__(self, owner: ProcessHttpFixture):
        self.owner = owner

    def snapshot(self) -> dict[str, Any]:
        if self.owner._final is None:
            raise RuntimeError("fixture counters are available only after explicit close")
        return self.owner._final["routes"]


class ProcessHttpFixture:
    """Explicit child ownership for HTTP/native, bounded RPC, cleanup before PASS.

    Historical class name retained for existing profiles/imports. Native mode
    passes native_peer=async into the same owned worker and resource sampler.
    """

    def __init__(self, module: str, roles: dict[int, str], delay_ms: float, slow: bool, **options: Any):
        options.pop("http_peer", None)
        self.module = module
        self._lock = threading.Lock()
        self._closed = False
        self._final: dict[str, Any] | None = None
        self.routes = _Routes(self)
        context = multiprocessing.get_context("spawn")
        self._connection, child = context.Pipe()
        self._process = context.Process(
            target=_worker, args=(child, module, roles, delay_ms, slow, options), daemon=True
        )
        self._process.start()
        child.close()
        try:
            ready = self._receive()
            self.port, self.closed_port = ready["port"], ready["closed_port"]
        except BaseException:
            self._abort()
            raise

    def _receive(self) -> Any:
        if not self._connection.poll(10):
            raise TimeoutError("HTTP fixture control did not respond")
        value = self._connection.recv()
        if isinstance(value, dict) and "failure" in value:
            raise RuntimeError("HTTP fixture child failed: " + value["failure"])
        return value

    def pop_token_identity(self, index: int) -> str | None:
        with self._lock:
            if self._closed:
                raise RuntimeError("fixture already closed")
            self._connection.send(("pop", index))
            return self._receive()

    def pop_grpc_calls(self, index: int) -> dict[str, Any] | None:
        with self._lock:
            if self._closed:
                raise RuntimeError("fixture already closed")
            self._connection.send(("pop-grpc", index))
            return self._receive()

    def pop_s3_calls(self, index: int) -> dict[str, Any] | None:
        with self._lock:
            if self._closed:
                raise RuntimeError("fixture already closed")
            self._connection.send(("pop-s3", index))
            return self._receive()

    def s3_wire_summary(self) -> dict[str, int] | None:
        if self._final is None:
            raise RuntimeError("fixture counters require explicit close")
        return self._final["s3_wire_summary"]

    def pop_pair_calls(self, index: int) -> dict[str, Any] | None:
        with self._lock:
            if self._closed:
                raise RuntimeError("fixture already closed")
            self._connection.send(("pop-pair", index))
            return self._receive()

    def pair_wire_summary(self) -> dict[str, int] | None:
        if self._final is None:
            raise RuntimeError("fixture counters require explicit close")
        return self._final["pair_wire_summary"]

    def pop_coordination_calls(self, index: int) -> dict[str, Any] | None:
        with self._lock:
            if self._closed:
                raise RuntimeError("fixture already closed")
            self._connection.send(("pop-coordination", index))
            return self._receive()

    def coordination_wire_summary(self) -> dict[str, int] | None:
        if self._final is None:
            raise RuntimeError("fixture counters require explicit close")
        return self._final["coordination_wire_summary"]

    def model_summary(self) -> dict[str, int] | None:
        if self._final is None:
            raise RuntimeError("fixture counters require explicit close")
        return self._final.get("model_summary")

    def pop_read_calls(self, index: int) -> dict[str, Any] | None:
        with self._lock:
            if self._closed:
                raise RuntimeError("fixture already closed")
            self._connection.send(("pop-read", index))
            return self._receive()

    def read_wire_summary(self) -> dict[str, int] | None:
        if self._final is None:
            raise RuntimeError("fixture counters require explicit close")
        return self._final.get("read_wire_summary")

    def grpc_wire_summary(self) -> dict[str, int] | None:
        if self._final is None:
            raise RuntimeError("fixture counters require explicit close")
        return self._final["grpc_wire_summary"]

    def process_resources(self) -> dict[str, int]:
        pid = self._process.pid
        if pid is None:
            raise RuntimeError("fixture process has no PID")
        directory = Path(f"/proc/{pid}")
        status = {}
        for line in (directory / "status").read_text().splitlines():
            key, _, value = line.partition(":")
            status[key] = value.strip()
        return {
            "fd": len(list((directory / "fd").iterdir())),
            "threads": int(status["Threads"]),
            "rss_bytes": int(status["VmRSS"].split()[0]) * 1024,
        }

    @property
    def stats(self) -> Counter[str]:
        if self._final is None:
            raise RuntimeError("fixture counters require explicit close")
        return Counter(self._final["stats"])

    @property
    def errors(self) -> list[str]:
        if self._final is None:
            raise RuntimeError("fixture errors require explicit close")
        return self._final["errors"]

    def resource_summary(self) -> dict[str, Any]:
        if self._final is None:
            raise RuntimeError("fixture resource summary requires explicit close")
        return {key: self._final[key] for key in ("cpu_seconds", "peak_rss_bytes")}

    def _abort(self) -> None:
        if self._process.is_alive():
            self._process.terminate()
        self._process.join(5)
        if self._process.is_alive():
            self._process.kill()
            self._process.join(5)
        self._connection.close()
        if self._process.is_alive():
            raise RuntimeError("fixture child cleanup incomplete")
        self._process.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            with self._lock:
                self._connection.send(("close", None))
                self._final = self._receive()
            self._process.join(5)
            if self._process.is_alive() or self._process.exitcode != 0:
                raise RuntimeError("fixture child did not exit cleanly")
            self._connection.close()
            self._process.close()
        except BaseException:
            self._abort()
            raise
