"""Kafka auth fixture follows non-flexible SASL schemas, not arbitrary EOF."""

from __future__ import annotations

import struct
from copy import deepcopy
from typing import Any

import pytest

from scripts.performance_native_fixtures import RequestReader, serve_invalid_credentials
from tests.test_performance_native_fixtures import Wire


def packet(api: int, version: int, correlation: int, body: bytes) -> bytes:
    # Request header v1: key/version/correlation/clientId string.
    data = struct.pack(">hhih", api, version, correlation, 2) + b"qa" + body
    return struct.pack(">i", len(data)) + data


def request() -> bytes:
    auth = b"\0profile-invalid-user\0profile-invalid-password"
    return (
        packet(18, 0, 21, b"")
        + packet(17, 1, 22, struct.pack(">h", 5) + b"PLAIN")
        + packet(36, 0, 23, struct.pack(">i", len(auth)) + auth)
    )


def replies(raw: bytes) -> list[bytes]:
    reader = RequestReader(Wire(raw), b"")
    result = []
    while reader.buffer or reader.sock.data:
        size = struct.unpack(">i", reader.exact(4))[0]
        result.append(reader.exact(size))
    return result


def test_complete_kafka_plain_proof_is_explicitly_rejected_and_not_accepted_after_handshake():
    data = request()
    wire = Wire(data[4:])
    observed = []
    assert serve_invalid_credentials("kafka", wire, data[:4], observed.append)
    api, handshake, auth = replies(bytes(wire.replies))
    correlation, error, count = struct.unpack(">ihi", api[:10])
    assert (correlation, error, count) == (21, 0, 4)
    versions = [struct.unpack(">hhh", api[10 + i * 6 : 16 + i * 6]) for i in range(count)]
    assert set(versions) == {(18, 0, 0), (17, 0, 1), (36, 0, 0), (3, 0, 0)}
    assert handshake == struct.pack(">ihi", 22, 0, 1) + struct.pack(">h", 5) + b"PLAIN"
    message = b"Authentication failed"
    assert auth == struct.pack(">ihh", 23, 58, len(message)) + message + struct.pack(">i", 0)
    assert observed == ["kafka_api_18", "kafka_api_17", "kafka_api_36"]


@pytest.mark.parametrize("removed", [1, 7, 19])
def test_partial_auth_body_is_never_rejected_as_a_complete_credential(removed):
    data = request()[:-removed]
    wire = Wire(data[4:])
    observed = []
    with pytest.raises(EOFError):
        serve_invalid_credentials("kafka", wire, data[:4], observed.append)
    assert len(replies(bytes(wire.replies))) == 2
    assert "kafka_api_36" not in observed


def test_without_negotiated_plain_auth_is_not_a_password_rejection():
    data = packet(36, 0, 55, struct.pack(">i", 5) + b"\0u\0pw")
    wire = Wire(data[4:])
    assert serve_invalid_credentials("kafka", wire, data[:4], lambda _: None)
    response = replies(bytes(wire.replies))[0]
    assert struct.unpack(">ih", response[:6]) == (55, 34)


def kafka_record() -> dict[str, Any]:
    return {
        "service": "kafka",
        "is_kafka": True,
        "status": "auth_required",
        "auth_flow": "sasl_handshake",
        "transport_mode": "plaintext",
        "provided_credentials_ok": False,
        "credential_attempts": [
            {"username": "u", "password": "wrong", "ok": False, "error": "SASL auth failed: Authentication failed"}
        ],
    }


def test_kafka_explicit_native_rejection_is_recognized_without_changing_product_records():
    from scripts.performance_contracts import credential_summary, credential_verdict_errors

    record = kafka_record()
    original = deepcopy(record)
    assert credential_summary(record)["invalid"] == 1
    assert credential_verdict_errors(record, accepted_identities=set()) == []
    assert record == original


def test_default_sweep_uses_each_canonical_pair_verdict_not_the_last_native_alias():
    from scripts.performance_contracts import credential_summary, credential_verdict_errors

    record = kafka_record()
    record["attempted_credentials"] = [
        {
            "username": "u",
            "password": password,
            "source": "default",
            "status": "auth_required",
            "provided_credentials_ok": False,
            "error": "SASL auth failed: Authentication failed",
        }
        for password in ["wrong", "another"]
    ]
    summary = credential_summary(record)
    assert summary["attempts_observed"] == summary["invalid"] == 2
    assert credential_verdict_errors(record, accepted_identities=set()) == []


@pytest.mark.parametrize("fault", ["unverified", "network", "handshake", "foreign", "ui", "missing_identity"])
def test_kafka_non_password_failures_remain_unverified(fault):
    from scripts.performance_contracts import credential_verdict_errors

    record = kafka_record()
    row = record["credential_attempts"][0]
    if fault == "unverified":
        row["ok"] = None
    elif fault == "network":
        row["error"] = "unexpected EOF"
    elif fault == "handshake":
        row["error"] = "SASL handshake failed: UNSUPPORTED_SASL_MECHANISM"
    elif fault == "foreign":
        record["is_kafka"] = False
    elif fault == "ui":
        record["auth_flow"] = "http_login"
    else:
        row["password"] = None
    assert credential_verdict_errors(record, accepted_identities=set())
