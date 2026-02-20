from __future__ import annotations

import struct

from redposture_core.stage_kafka import _parse_apiversions_response, _parse_metadata_response


def _kstr(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack(">h", len(raw)) + raw


def _partition_meta(error_code: int, partition_id: int = 0) -> bytes:
    return (
        struct.pack(">h", error_code)
        + struct.pack(">i", partition_id)
        + struct.pack(">i", 1)  # leader
        + struct.pack(">i", 1)
        + struct.pack(">i", 1)  # replicas [1]
        + struct.pack(">i", 1)
        + struct.pack(">i", 1)  # isr [1]
    )


def test_parse_apiversions_response_basic() -> None:
    correlation_id = 12
    payload = (
        struct.pack(">i", correlation_id)
        + struct.pack(">h", 0)  # error_code
        + struct.pack(">i", 1)  # api_versions array size
        + struct.pack(">h", 3)  # api key metadata
        + struct.pack(">h", 0)  # min
        + struct.pack(">h", 12)  # max
    )
    ok, error_code, error = _parse_apiversions_response(payload, correlation_id)
    assert ok is True
    assert error_code == 0
    assert error is None


def test_parse_metadata_response_mixed_access_does_not_force_auth_required() -> None:
    correlation_id = 7
    brokers = struct.pack(">i", 1) + struct.pack(">i", 1) + _kstr("kafka-1") + struct.pack(">i", 9092)

    topic_orders = (
        struct.pack(">h", 0)  # topic error
        + _kstr("orders")
        + struct.pack(">i", 2)  # partitions
        + _partition_meta(0, 0)
        + _partition_meta(0, 1)
    )
    topic_secret = (
        struct.pack(">h", 29)  # TOPIC_AUTHORIZATION_FAILED
        + _kstr("secret")
        + struct.pack(">i", 0)  # partitions
    )
    topics = struct.pack(">i", 2) + topic_orders + topic_secret

    payload = struct.pack(">i", correlation_id) + brokers + topics
    metadata, error = _parse_metadata_response(payload, correlation_id)
    assert error is None
    assert isinstance(metadata, dict)
    assert metadata["topic_map"]["orders"] == 2
    assert metadata["topic_map"]["secret"] == 0
    assert metadata["auth_required"] is False


def test_parse_metadata_response_all_auth_errors_sets_auth_required() -> None:
    correlation_id = 11
    brokers = struct.pack(">i", 1) + struct.pack(">i", 1) + _kstr("kafka-1") + struct.pack(">i", 9092)
    topic_only = (
        struct.pack(">h", 29)  # TOPIC_AUTHORIZATION_FAILED
        + _kstr("private")
        + struct.pack(">i", 0)
    )
    topics = struct.pack(">i", 1) + topic_only
    payload = struct.pack(">i", correlation_id) + brokers + topics

    metadata, error = _parse_metadata_response(payload, correlation_id)
    assert error is None
    assert isinstance(metadata, dict)
    assert metadata["auth_required"] is True
