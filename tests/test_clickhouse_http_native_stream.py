"""HTTP Native bytes through the actual Connect decoder or bounded reader."""

from __future__ import annotations

import hashlib
import io
import time
import tracemalloc
from pathlib import Path
from types import SimpleNamespace

from clickhouse_connect.driver.buffer import ResponseBuffer
from clickhouse_connect.driver.transform import NativeTransform

from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.clickhouse.discover.reader import read_chunk
from tests.test_clickhouse_native_stream import _varint


class _Source:
    def __init__(self, path):
        self.file = path.open("rb")
        self.gen = self.chunks()

    def chunks(self):
        while part := self.file.read(65536):
            yield part

    def close(self):
        self.file.close()


def test_http_native_large_string_is_not_decoded_whole_by_connect(tmp_path: Path):
    value = b"Aa7-value/" * 1_000_000
    expected = hashlib.sha256(value).hexdigest()
    path = tmp_path / "native.bin"
    path.write_bytes(b"\x01\x01\x07payload\x06String" + _varint(len(value)) + value)
    del value
    opened = []

    def sdk_stream(query):
        source = _Source(path)
        opened.append(source.file)
        result = NativeTransform.parse_response(ResponseBuffer(source))
        return result.rows_stream

    def raw_stream(query, *, fmt, settings=None):
        assert fmt == "Native"
        stream = path.open("rb")
        opened.append(stream)
        return stream

    client = SimpleNamespace(query_rows_stream=sdk_stream, raw_stream=raw_stream, server_tz="UTC")
    tracemalloc.start()
    try:
        result = read_chunk(
            SimpleNamespace(protocol="http", client=client), "SELECT payload", deadline=time.monotonic() + 20
        )
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert result.error is None, result.error
    assert len(result.rows) == 1
    assert isinstance(result.rows[0][0], DiskBackedText)
    assert result.rows[0][0].digest == expected
    assert all(stream.closed for stream in opened)
    assert peak < 5_000_000, peak


def test_http_native_restores_timeout_if_response_close_fails():
    from urllib3.util import Timeout

    class BrokenClose(io.BytesIO):
        def close(self):
            super().close()
            raise OSError("test close failed")

    timeout = Timeout(connect=5, read=5)
    client = SimpleNamespace(raw_stream=lambda *args, **kwargs: BrokenClose(b"\x00\x00"), timeout=timeout)
    result = read_chunk(SimpleNamespace(protocol="http", client=client), "SELECT 1", deadline=time.monotonic() + 1)
    assert result.error == "test close failed"
    assert client.timeout is timeout


def test_http_native_expired_request_timeout_has_discovery_reason():
    def expired(*args, **kwargs):
        time.sleep(0.02)
        raise OSError("socket read timed out")

    client = SimpleNamespace(raw_stream=expired)
    result = read_chunk(SimpleNamespace(protocol="http", client=client), "SELECT 1", deadline=time.monotonic() + 0.01)
    assert result.error == "discover_time"


def test_http_native_truncated_block_preserves_completed_row():
    response = io.BytesIO(b"\x01\x02\x07payload\x06String\x15password=first-secret\x64bad")
    client = SimpleNamespace(raw_stream=lambda *args, **kwargs: response)
    result = read_chunk(SimpleNamespace(protocol="http", client=client), "SELECT payload")
    assert result.rows == [["password=first-secret"]]
    assert result.error == "truncated HTTP Native block"
    assert response.closed


def test_http_native_deadline_interrupts_active_response_read():
    import threading

    stopped = threading.Event()
    closed = []

    class Response:
        connection = SimpleNamespace(sock=SimpleNamespace(shutdown=lambda how: stopped.set()))

        def read(self, size):
            assert stopped.wait(1), "response read was not interrupted"
            raise OSError("closed while reading")

        def close(self):
            closed.append(True)

    client = SimpleNamespace(raw_stream=lambda *args, **kwargs: Response())
    started = time.monotonic()
    result = read_chunk(SimpleNamespace(protocol="http", client=client), "SELECT payload", deadline=started + 0.05)
    assert result.error == "discover_time"
    assert time.monotonic() - started < 0.5
    assert closed == [True]


def test_http_native_read_does_not_lock_clients_metadata_session():
    calls = []

    def raw_stream(query, *, fmt, settings=None):
        calls.append((dict(client.params), settings))
        return io.BytesIO(b"\x01\x01\x07payload\x06String\x05hello")

    client = SimpleNamespace(raw_stream=raw_stream, params={"session_id": "metadata-session", "buffer_size": "1"})
    result = read_chunk(SimpleNamespace(protocol="http", client=client), "SELECT payload")
    assert result.error is None and result.rows == [["hello"]]
    assert calls == [({"buffer_size": "1"}, None)]
    assert client.params == {"session_id": "metadata-session", "buffer_size": "1"}
