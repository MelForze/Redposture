"""Deterministic malformed-input corpus for network-facing protocol parsers."""

from __future__ import annotations

import random

import pytest

from redposture_core.clients import grpc, http_api, kafka, oracle, zookeeper
from redposture_core.clients.docker_engine import decode_docker_stream
from redposture_core.clients.oracle import OracleTnsError

pytestmark = pytest.mark.protocol_fuzz


def _corpus(seed: int, *, count: int = 512, max_size: int = 256) -> tuple[bytes, ...]:
    rng = random.Random(seed)
    fixed = (
        b"",
        b"\x00",
        b"\xff" * max_size,
        b"\x00" * max_size,
        bytes(range(256)),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffff\r\n",
    )
    generated = tuple(rng.randbytes(rng.randrange(max_size + 1)) for _ in range(count))
    return fixed + generated


def test_http_grpc_and_docker_parsers_survive_arbitrary_bytes() -> None:
    for payload in _corpus(0x48545450):
        grpc._decode_grpc_frames(payload)
        grpc._decode_grpc_web_frames(payload)
        grpc._parse_http1_response(payload)
        decode_docker_stream(payload)
        try:
            http_api._parse_http_response_bytes_detailed(payload, response_cap=4096)
        except (OSError, ValueError):
            pass


def test_zookeeper_decoders_fail_closed_on_arbitrary_bytes() -> None:
    for payload in _corpus(0x5A4B):
        for parser in (
            zookeeper._decode_zk_string,
            zookeeper._decode_zk_buffer,
            zookeeper._parse_children_vector,
            zookeeper._parse_stat,
        ):
            try:
                parser(payload)
            except ValueError:
                pass
        try:
            zookeeper._parse_connect_response(payload)
        except ValueError:
            pass


def test_kafka_parsers_fail_closed_on_arbitrary_bytes() -> None:
    for payload in _corpus(0x4B41464B, count=384):
        versions = kafka._parse_apiversions_response(payload, expected_correlation_id=7)
        assert isinstance(versions.ok, bool)
        metadata, metadata_error = kafka._parse_metadata_response(payload, expected_correlation_id=7)
        assert metadata is None or isinstance(metadata, dict)
        assert metadata_error is None or isinstance(metadata_error, str)
        entries = kafka._parse_message_set_entries(payload, max_messages=32)
        assert len(entries) <= 32


def test_oracle_tns_parser_accepts_or_rejects_arbitrary_bytes_without_low_level_exceptions() -> None:
    for payload in _corpus(0x544E53):
        try:
            packet = oracle.parse_tns_packet(payload)
        except OracleTnsError:
            continue
        assert packet["length"] >= 8
        assert len(packet["payload"]) == packet["length"] - 8
