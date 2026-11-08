"""The new transport-independent program must match the independent wire oracle."""

from __future__ import annotations

import struct

import pytest
from bson import BSON

from scripts.performance_native_fixtures import serve_detection_response
from tests.test_network_fingerprint_matrix import _frame, _native_response
from tests.test_performance_native_fixtures import Wire, mongo_request, resp


def requests(product):
    if product == "clickhouse":
        return b"\x00\x0aClickHouse"
    if product == "postgres":
        startup = struct.pack(">i", 196608) + b"user\0probe\0database\0postgres\0\0"
        return struct.pack(">ii", 8, 80877103) + _frame(startup)
    if product == "redis":
        return resp(b"PING") + resp(b"INFO", b"server")
    if product == "oracle":
        body = b"(DESCRIPTION=(CONNECT_DATA=(COMMAND=version)))"
        return struct.pack(">HHBBH", 8 + len(body), 0, 1, 0, 0) + body
    if product == "kafka":
        return b"".join(_frame(struct.pack(">hhih", api, 0, i, 0)) for i, api in enumerate((18, 3, 999)))
    if product in {"keeper", "zookeeper"}:
        return _frame(b"connect") + _frame(struct.pack(">ii", 3, 4)) + _frame(struct.pack(">ii", 4, -11))
    if product == "mongodb":
        return (
            mongo_request({"hello": 1}, 1) + mongo_request({"buildInfo": 1}, 2) + mongo_request({"listDatabases": 1}, 3)
        )
    if product == "grpc":
        from h2.config import H2Configuration
        from h2.connection import H2Connection

        client = H2Connection(config=H2Configuration(client_side=True))
        client.initiate_connection()
        client.send_headers(
            1,
            [
                (":method", "POST"),
                (":scheme", "http"),
                (":authority", "qa"),
                (":path", "/grpc.health.v1.Health/Check"),
                ("content-type", "application/grpc"),
            ],
            end_stream=True,
        )
        return client.data_to_send()
    raise AssertionError(product)


@pytest.mark.parametrize(
    "product", ["clickhouse", "postgres", "redis", "oracle", "kafka", "keeper", "zookeeper", "mongodb", "grpc"]
)
def test_fragmented_program_output_matches_independent_original_fixture(product):
    data = requests(product)
    old, new = Wire(data[4:]), Wire(data[4:])
    for function, wire in [
        (_native_response, old),
        (lambda p, s, i: serve_detection_response(p, s, i, lambda _: None), new),
    ]:
        try:
            function(product, wire, data[:4])
        except EOFError:
            pass  # Both peers stop when the controlled client exhausts input.
    assert old.data == new.data and bytes(old.replies) == bytes(new.replies)
    assert old.replies


@pytest.mark.parametrize("product", ["keeper", "zookeeper"])
@pytest.mark.parametrize("command", [b"srvr", b"stat", b"mntr", b"isro"])
def test_four_letter_implementation_fingerprints_are_preserved(product, command):
    old, new = Wire(b""), Wire(b"")
    _native_response(product, old, command)
    serve_detection_response(product, new, command, lambda _: None)
    assert bytes(old.replies) == bytes(new.replies)


def test_legacy_mongo_reply_framing_and_request_identity_are_preserved():
    payload = struct.pack("<i", 0) + b"admin.$cmd\0" + struct.pack("<ii", 0, -1) + BSON.encode({"ismaster": 1})
    data = struct.pack("<iiii", len(payload) + 16, 27, 0, 2004) + payload
    old, new = Wire(data[4:]), Wire(data[4:])
    for fn, wire in [(_native_response, old), (lambda p, s, i: serve_detection_response(p, s, i, lambda _: None), new)]:
        with pytest.raises(EOFError):
            fn("mongodb", wire, data[:4])
    assert old.replies == new.replies and struct.unpack("<iiii", new.replies[:16])[2:] == (27, 1)
