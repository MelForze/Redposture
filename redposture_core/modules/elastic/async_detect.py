"""Bounded, direct HTTP probes for slow ambiguous Elastic detection.

Only anonymous GET fingerprints use this transport.  A response whose
semantics need the shared HTTP client (redirect, unsupported framing, transport
failure) is explicitly returned for synchronous verification by the caller.
"""

from __future__ import annotations

import asyncio
import ssl
import threading
from dataclasses import dataclass

from ...clients.http_api import HttpResponse, decode_http_content
from ...clients.tls_cache import shared_client_ssl_context

# Fingerprint bodies are small.  Larger responses are replayed through the
# existing client instead of retaining five 10 MiB bodies per scan worker.
_MAX_BODY = 64 * 1024
_MAX_HEADER = 64 * 1024
_MAX_DIRECT_CONNECTIONS = 3072
# The synchronous socket timeout applies to each blocking I/O operation.
# asyncio.wait_for covers connect, write and the complete response together;
# a small scheduling allowance avoids treating a response at the requested
# timeout boundary as an async failure followed by a redundant sync replay.
_SCHEDULING_GRACE = 0.25
_DIRECT_CONNECTIONS = threading.BoundedSemaphore(_MAX_DIRECT_CONNECTIONS)


@dataclass(frozen=True)
class AsyncProbe:
    path: str
    status: int = 0
    payload: bytes = b""
    headers: dict[str, str] | None = None
    error: str | None = None
    fallback: bool = False


async def _acquire_connection() -> None:
    while not _DIRECT_CONNECTIONS.acquire(blocking=False):
        await asyncio.sleep(0.01)


async def _read_chunked(reader: asyncio.StreamReader) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    while True:
        line = await reader.readline()
        if not line or len(line) > 128:
            raise ValueError("invalid chunk size line")
        size = int(line.split(b";", 1)[0].strip(), 16)
        if size == 0:
            while True:
                trailer = await reader.readline()
                if trailer in {b"\r\n", b"\n"}:
                    return b"".join(chunks), False
                if not trailer or len(trailer) > _MAX_HEADER:
                    raise ValueError("invalid chunk trailer")
        if size < 0 or total + size > _MAX_BODY:
            return b"", True
        chunk = await reader.readexactly(size + 2)
        if not chunk.endswith(b"\r\n"):
            raise ValueError("invalid chunk delimiter")
        chunks.append(chunk[:-2])
        total += size


async def _read_http_response(reader: asyncio.StreamReader, path: str) -> AsyncProbe:
    raw_head = await reader.readuntil(b"\r\n\r\n")
    if len(raw_head) > _MAX_HEADER:
        raise ValueError("HTTP response headers exceed limit")
    lines = raw_head[:-4].split(b"\r\n")
    status_parts = lines[0].split(b" ", 2)
    if len(status_parts) < 2 or not status_parts[0].startswith(b"HTTP/"):
        raise ValueError("invalid HTTP status line")
    status = int(status_parts[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            raise ValueError("invalid HTTP response header")
        name, value = line.split(b":", 1)
        headers[name.decode("latin-1")] = value.strip().decode("latin-1")
    if 100 <= status < 200 or 300 <= status < 400:
        return AsyncProbe(path=path, fallback=True)
    lower = {key.lower(): value for key, value in headers.items()}
    transfer_encoding = lower.get("transfer-encoding", "").lower().strip()
    if transfer_encoding:
        if transfer_encoding != "chunked":
            return AsyncProbe(path=path, fallback=True)
        payload, truncated = await _read_chunked(reader)
    elif "content-length" in lower:
        length = int(lower["content-length"])
        if length < 0:
            raise ValueError("negative HTTP content length")
        truncated = length > _MAX_BODY
        payload = await reader.readexactly(min(length, _MAX_BODY + 1))
    else:
        chunks = []
        total = 0
        while True:
            chunk = await reader.read(min(64 * 1024, _MAX_BODY + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_BODY:
                break
        payload = b"".join(chunks)
        truncated = total > _MAX_BODY
    if truncated:
        return AsyncProbe(path=path, fallback=True)
    decoded = decode_http_content(HttpResponse(status=status, body=payload, headers=headers), max_bytes=_MAX_BODY)
    if decoded.error:
        return AsyncProbe(path=path, fallback=True)
    return AsyncProbe(path=path, status=status, payload=decoded.body, headers=decoded.headers)


async def _probe_one(
    host: str,
    port: int,
    path: str,
    scheme: str,
    timeout: float,
    ca_file: str | None,
) -> AsyncProbe:
    writer: asyncio.StreamWriter | None = None
    try:
        path.encode("ascii")
    except UnicodeEncodeError:
        return AsyncProbe(path=path, fallback=True)
    await _acquire_connection()
    try:

        async def exchange() -> AsyncProbe:
            nonlocal writer
            tls: ssl.SSLContext | None = None
            if scheme == "https":
                tls = shared_client_ssl_context(insecure=not bool(ca_file), ca_file=ca_file)
            writer_reader, writer = await asyncio.open_connection(
                host.strip("[]"),
                port,
                ssl=tls,
                server_hostname=host.strip("[]") if tls is not None else None,
                limit=_MAX_HEADER + 4,
            )
            authority = f"[{host.strip('[]')}]" if ":" in host.strip("[]") else host.strip("[]")
            if port != (443 if scheme == "https" else 80):
                authority = f"{authority}:{port}"
            request = (
                f"GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: RedPosture/1.0\r\nConnection: close\r\n\r\n"
            )
            writer.write(request.encode("ascii"))
            await writer.drain()
            return await _read_http_response(writer_reader, path)

        return await asyncio.wait_for(exchange(), timeout=max(0.1, float(timeout)) + _SCHEDULING_GRACE)
    except (TimeoutError, OSError, ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        return AsyncProbe(path=path, fallback=True)
    finally:
        if writer is not None:
            writer.close()
        _DIRECT_CONNECTIONS.release()


async def _probe_all(
    host: str,
    port: int,
    paths: tuple[str, ...],
    scheme: str,
    timeout: float,
    ca_file: str | None,
) -> list[AsyncProbe]:
    return list(await asyncio.gather(*(_probe_one(host, port, path, scheme, timeout, ca_file) for path in paths)))


def probe_direct_paths(
    host: str,
    port: int,
    paths: tuple[str, ...],
    scheme: str,
    timeout: float,
    ca_file: str | None,
) -> list[AsyncProbe] | None:
    """Return ordered probes, or ``None`` when already inside an event loop."""

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        return None
    return asyncio.run(_probe_all(host, port, paths, scheme, timeout, ca_file))
