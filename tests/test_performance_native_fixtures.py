"""Authentication fixtures must reject wrong credentials on real wire frames."""

from __future__ import annotations

import struct

import pytest
from bson import BSON

from scripts.performance_native_fixtures import RequestReader, serve_invalid_credentials


class Wire:
    def __init__(self, data):
        self.data = data
        self.replies = bytearray()

    def recv(self, size):
        data, self.data = self.data[: min(3, size)], self.data[min(3, size) :]
        return data

    def sendall(self, data):
        self.replies.extend(data)


def resp(*args):
    return f"*{len(args)}\r\n".encode() + b"".join(f"${len(arg)}\r\n".encode() + arg + b"\r\n" for arg in args)


def test_redis_requires_auth_then_rejects_wrong_pair_and_preserves_command_boundaries():
    request = resp(b"PING") + resp(b"AUTH", b"default", b"wrong") + resp(b"QUIT")
    wire = Wire(request[4:])
    messages = []
    assert serve_invalid_credentials("redis", wire, request[:4], messages.append)
    assert len(messages) == 3
    assert messages == ["ping", "auth", "quit"]
    assert (
        bytes(wire.replies)
        == b"-NOAUTH Authentication required.\r\n-WRONGPASS invalid username-password pair or user is disabled.\r\n+OK\r\n"
    )


def test_postgres_cleartext_challenge_then_specific_invalid_password_error():
    startup = struct.pack(">ii", 20, 196608) + b"user\0probe\0\0\0"
    # Keep startup length exact; the fixture never invents authentication from
    # a partial packet or a successful TCP connect.
    startup = struct.pack(">i", len(startup)) + startup[4:]
    password = b"wrong\0"
    request = struct.pack(">ii", 8, 80877103) + startup + b"p" + struct.pack(">i", len(password) + 4) + password
    wire = Wire(request[4:])
    messages = []
    assert serve_invalid_credentials("postgres", wire, request[:4], messages.append)
    assert len(messages) == 3
    assert wire.replies.startswith(b"NR" + struct.pack(">ii", 8, 3))
    assert b"C28P01\0Mpassword authentication failed\0" in wire.replies


def mongo_request(command, index):
    body = struct.pack("<iB", 0, 0) + BSON.encode(command)
    return struct.pack("<iiii", len(body) + 16, index, 0, 2013) + body


def test_mongo_public_handshake_does_not_allow_listing_or_verify_wrong_scram():
    request = (
        mongo_request({"hello": 1}, 1) + mongo_request({"listDatabases": 1}, 2) + mongo_request({"saslStart": 1}, 3)
    )
    wire = Wire(request[4:])
    messages = []
    with pytest.raises(EOFError):
        serve_invalid_credentials("mongodb", wire, request[:4], messages.append)
    reader = RequestReader(Wire(bytes(wire.replies)), b"")
    decoded = []
    for index in range(1, 4):
        length, _request_id, response_to, opcode = struct.unpack("<iiii", reader.exact(16))
        assert response_to == index and opcode == 2013
        decoded.append(BSON(reader.exact(length - 16)[5:]).decode())
    assert decoded[0]["isWritablePrimary"] is True
    assert decoded[1]["code"] == 13
    assert decoded[2]["code"] == 18
    assert len(messages) == 3


def test_unsupported_protocol_is_not_consumed_or_called_successful():
    wire = Wire(b"unchanged")
    assert not serve_invalid_credentials("oracle", wire, b"head", lambda _name: pytest.fail("unexpected frame"))
    assert wire.data == b"unchanged" and wire.replies == b""


def test_grpc_wrong_auth_is_a_specific_unauthenticated_trailer_not_unimplemented():
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import ResponseReceived, TrailersReceived

    client = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))
    client.initiate_connection()
    client.send_headers(
        1,
        [
            (":method", "POST"),
            (":scheme", "http"),
            (":authority", "qa"),
            (":path", "/grpc.health.v1.Health/Check"),
            ("content-type", "application/grpc"),
            ("authorization", "Basic cHJvYmU6d3Jvbmc="),
        ],
    )
    client.send_data(1, b"\0\0\0\0\0", end_stream=True)
    data = client.data_to_send()
    wire = Wire(data[4:])
    assert serve_invalid_credentials("grpc", wire, data[:4], lambda _: None)
    events = client.receive_data(bytes(wire.replies))
    headers = [dict(event.headers) for event in events if isinstance(event, ResponseReceived)]
    trailers = [dict(event.headers) for event in events if isinstance(event, TrailersReceived)]
    assert headers == [{":status": "200", "content-type": "application/grpc"}]
    assert trailers == [{"grpc-status": "16"}]


@pytest.mark.parametrize("size", [-1, 65537])
def test_request_reader_rejects_unbounded_fixture_request(size):
    with pytest.raises(ValueError):
        RequestReader(Wire(b""), b"").exact(size)
