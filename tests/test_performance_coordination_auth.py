"""Digest adds an identity; unchanged NOAUTH is not a rejected password."""

from __future__ import annotations

import struct

import pytest

from scripts.performance_native_fixtures import serve_invalid_credentials
from tests.test_performance_native_fixtures import Wire


def frame(value):
    return struct.pack(">i", len(value)) + value


def string(value):
    raw = value.encode()
    return struct.pack(">i", len(raw)) + raw


def handshake():
    return frame(struct.pack(">iqiqi", 0, 0, 30000, 0, 16) + b"\0" * 16 + b"\0")


def auth(pair=b"admin:wrong"):
    return struct.pack(">iii", -4, 100, 0) + string("digest") + struct.pack(">i", len(pair)) + pair


@pytest.mark.parametrize("product", ["zookeeper", "keeper"])
@pytest.mark.parametrize("pair", [b"admin:wrong", b"absent:wrong", b"default:"])
def test_digest_ack_does_not_invent_password_rejection_or_acl_access(product, pair):
    data = (
        handshake()
        + frame(auth(pair))
        + frame(struct.pack(">ii", 7, 12) + string("/") + b"\0")
        + frame(struct.pack(">ii", 8, -11))
    )
    wire = Wire(data[4:])
    messages = []
    assert serve_invalid_credentials(product, wire, data[:4], messages.append)
    raw = bytes(wire.replies)
    length = struct.unpack(">i", raw[:4])[0]
    responses = raw[4 + length :]
    assert responses == frame(struct.pack(">iqi", -4, 1, 0)) + frame(struct.pack(">iqi", 7, 1, -102))
    assert messages == ["zk_opcode_100", "zk_digest_identity", "zk_opcode_12", "zk_opcode_-11"]
    assert not wire.data


@pytest.mark.parametrize("product", ["zookeeper", "keeper"])
@pytest.mark.parametrize("body", [auth(b"missing-colon"), auth()[:-1], auth() + b"trailing"])
def test_malformed_digest_frame_is_not_an_authentication_verdict(product, body):
    data = handshake() + frame(body)
    wire = Wire(data[4:])
    with pytest.raises(ValueError):
        serve_invalid_credentials(product, wire, data[:4], lambda _: None)
    raw = bytes(wire.replies)
    length = struct.unpack(">i", raw[:4])[0]
    assert len(raw) == 4 + length  # Only the ConnectResponse, never an auth decision.
