"""Bounded, read-only Docker log streams through the Portainer proxy."""

from __future__ import annotations

import tempfile
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from typing import TYPE_CHECKING, Any

from ...discovery_encoded import encoded_text_prefix
from ...scheduler import NestedSchedulerCancelled
from ...secret_detection import _scan_text, detector_names

if TYPE_CHECKING:
    from ...storage_discovery import DiscoveryCollector


class DockerLogFrames:
    """Decode headers across chunks without buffering an entire frame."""

    def __init__(self, emit: Callable[[str, bytes], None], tty: bool | None) -> None:
        self.emit = emit
        self.tty = tty
        self.header = bytearray()
        self.remaining = 0
        self.channel = "stdout"

    def feed(self, data: bytes) -> None:
        if self.tty is True:
            self.emit("stdout", data)
            return
        offset = 0
        while offset < len(data):
            if self.remaining:
                size = min(self.remaining, len(data) - offset)
                self.emit(self.channel, data[offset : offset + size])
                self.remaining -= size
                offset += size
                continue
            take = min(8 - len(self.header), len(data) - offset)
            self.header.extend(data[offset : offset + take])
            offset += take
            if len(self.header) < 8:
                continue
            valid = self.header[0] in {0, 1, 2} and self.header[1:4] == b"\0\0\0"
            if self.tty is None:
                self.tty = not valid
                if self.tty:
                    self.emit("stdout", bytes(self.header) + data[offset:])
                    self.header.clear()
                    return
            if not valid:
                raise ValueError("invalid_docker_log_frame")
            self.channel = "stderr" if self.header[0] == 2 else "stdout"
            self.remaining = int.from_bytes(self.header[4:8], "big")
            self.header.clear()

    def finish(self) -> None:
        if self.tty is None and self.header:
            self.emit("stdout", bytes(self.header))
            self.header.clear()
        if self.header or self.remaining:
            raise ValueError("incomplete_docker_log_frame")


class _LogChannel:
    def __init__(self, collector: DiscoveryCollector, source: str, stack: ExitStack) -> None:
        self.collector, self.source = collector, source
        self.spool = stack.enter_context(tempfile.SpooledTemporaryFile(max_size=65536))
        self.pending = bytearray()
        self.early = True
        self.early_inspected = 0

    def write(self, data: bytes) -> None:
        self.spool.write(data)
        if not self.early:
            return
        if b"\0" in data:
            self.early = False
            self.pending.clear()
            return
        self.pending.extend(data)
        while (end := self.pending.find(b"\n")) >= 0:
            line = bytes(self.pending[: end + 1])
            del self.pending[: end + 1]
            try:
                text = line.decode("utf-8")
            except UnicodeError:
                self.early = False
                self.pending.clear()
                return
            if (
                len(line.rstrip(b"\r\n")) in {64, 76}
                and encoded_text_prefix(line)
                and not _scan_text(text, self.source, set(detector_names()) - {"high_entropy"})
            ):
                self.early = False
                self.pending.clear()
                return
            before = self.collector.bytes_inspected
            self.collector.add(self.source, text, charge=False, prefer_specific=True)
            self.early_inspected += self.collector.bytes_inspected - before
        if len(self.pending) > 65536:
            self.early = False
            self.pending.clear()

    def finish(self, *, complete: bool) -> None:
        self.spool.seek(0)
        before = self.collector.bytes_inspected
        self.collector._scan_retained_payload(self.source, self.spool, prefer_specific=True, source_complete=complete)
        self.collector.bytes_inspected -= min(self.early_inspected, self.collector.bytes_inspected - before)


def scan_container_logs(
    collector: DiscoveryCollector,
    pool: Any,
    url: str,
    source: str,
    *,
    tty: bool | None,
    headers: Mapping[str, str],
    timeout: float,
) -> tuple[bool, int | None]:
    """Read a finite log snapshot; never attach, follow, exec or write data."""
    status: int | None = None
    initial_errors = collector.partial_events
    if tty is None:
        collector.partial(source, "tty_setting_unavailable")
    with ExitStack() as stack:
        channels = {name: _LogChannel(collector, source + "/" + name, stack) for name in ("stdout", "stderr")}
        frames = DockerLogFrames(lambda name, data: channels[name].write(data), tty)

        def response(code: int, _headers: Mapping[str, str]) -> None:
            nonlocal status
            status = code

        def chunk(data: bytes) -> None:
            if not collector.charge(len(data)):
                raise TimeoutError("discover_time")
            if status == 200:
                frames.feed(data)

        complete = False
        interrupted = False
        try:
            result = pool.request_stream(
                "GET",
                url,
                headers=headers,
                on_response=response,
                on_chunk=chunk,
                timeout=timeout,
                deadline=collector.deadline,
                chunk_size=65536,
                allow_cross_origin_redirects=False,
                preserve_authorization_on_cross_origin=False,
            )
            if result.status != 200 or result.error or result.truncated:
                collector.partial(
                    source, "access_denied" if result.status in {401, 403} else result.error or f"HTTP {result.status}"
                )
            elif status != 200:
                collector.partial(source, "response_headers_unverified")
            else:
                frames.finish()
                complete = True
                collector.mark_accessible_source()
        except (OSError, ValueError) as exc:
            collector.partial(source, str(exc) or type(exc).__name__)
        except (KeyboardInterrupt, NestedSchedulerCancelled):
            interrupted = True
            collector.partial(source, "cancelled")
            raise
        finally:
            if status == 200 and not interrupted:
                for channel in channels.values():
                    try:
                        channel.finish(complete=complete)
                    except OSError as exc:
                        collector.partial(source, str(exc) or type(exc).__name__)
        return complete and collector.partial_events == initial_errors, status
