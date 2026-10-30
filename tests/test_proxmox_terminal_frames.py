"""PVE terminals use raw binary/text frames, not JSON messages."""

from contextlib import closing

import pytest

from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.clients.websocket import WebSocket
from tests.test_execution_websocket import frame, server


def test_raw_terminal_binary_fragments_and_ping():
    # Keep the peer open through send_bytes; a closed fixture socket makes the
    # write race with server teardown instead of checking the client frame.
    with server(
        [frame(b"OK", opcode=2, fin=False), frame(b"p", opcode=9), frame("привет".encode(), opcode=0)], wait=True
    ) as (
        url,
        _,
        _,
    ):
        with (
            closing(HttpSessionPool(timeout=1)) as pool,
            WebSocket(pool, url, headers={}, timeout=1, max_bytes=1024) as ws,
        ):
            assert ws.recv_bytes() == b"OK" + "привет".encode()
            ws.send_bytes(b"0:3:id\r")


def test_json_consumer_rejects_binary_json_frame():
    with server([frame(b'{"x":1}', opcode=2)]) as (url, _, _):
        with (
            closing(HttpSessionPool(timeout=1)) as pool,
            WebSocket(pool, url, headers={}, timeout=1, max_bytes=1024) as ws,
        ):
            with pytest.raises(ValueError, match="message type"):
                ws.recv_json()
