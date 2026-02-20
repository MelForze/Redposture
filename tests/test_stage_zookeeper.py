from __future__ import annotations

import struct

from redposture_core.stage_zookeeper import (
    _decode_zk_string,
    _format_znode_data,
    _normalize_znode_path,
    _parse_children_vector,
    _parse_stat,
)


def _zk_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack(">i", len(raw)) + raw


def test_normalize_znode_path() -> None:
    assert _normalize_znode_path(None) is None
    assert _normalize_znode_path("") is None
    assert _normalize_znode_path("brokers/ids") == "/brokers/ids"
    assert _normalize_znode_path("/brokers/ids") == "/brokers/ids"


def test_parse_children_vector() -> None:
    payload = struct.pack(">i", 2) + _zk_string("brokers") + _zk_string("config")
    children, offset = _parse_children_vector(payload)
    assert children == ["brokers", "config"]
    assert offset == len(payload)


def test_parse_stat_extracts_data_length_and_children() -> None:
    stat_payload = struct.pack(">qqqqiiiqiiq", 1, 2, 3, 4, 5, 6, 7, 8, 128, 4, 9)
    stat, offset = _parse_stat(stat_payload)
    assert stat["data_length"] == 128
    assert stat["num_children"] == 4
    assert offset == 68


def test_decode_zk_string_nullable() -> None:
    value, offset = _decode_zk_string(struct.pack(">i", -1))
    assert value is None
    assert offset == 4


def test_format_znode_data_text_and_binary() -> None:
    assert _format_znode_data(b"hello") == "hello"
    assert _format_znode_data(b"") == "<empty>"
    assert _format_znode_data(b"line1\nline2") == "line1\\nline2"
    assert _format_znode_data(b"\x01\x02\xff") == "<base64:AQL/>"
