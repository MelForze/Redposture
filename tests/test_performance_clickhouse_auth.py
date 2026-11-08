"""ClickHouse QA must receive a full Hello before rejecting a supplied pair."""

from __future__ import annotations

import struct

import pytest

from scripts.performance_contracts import credential_summary, credential_verdict_errors
from scripts.performance_native_fixtures import serve_invalid_credentials
from tests.test_performance_native_fixtures import Wire


def varuint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    return bytes(result) + bytes([value])


def string(value):
    return varuint(len(value)) + value


def hello():
    return (
        b"\x00"
        + string(b"ClickHouse python-driver")
        + varuint(20)
        + varuint(10)
        + varuint(54468)
        + string(b"default")
        + string(b"reader")
        + string(b"wrong")
    )


def test_complete_fragmented_hello_is_consumed_before_specific_auth_exception():
    request = hello()
    wire = Wire(request[4:])
    messages = []
    assert serve_invalid_credentials("clickhouse", wire, request[:4], messages.append)
    assert not wire.data and messages == ["hello"]
    assert wire.replies.startswith(b"\x02" + struct.pack("<i", 516))
    assert b"Authentication failed:" in wire.replies and wire.replies.endswith(b"\0\0")


@pytest.mark.parametrize("size", [1, 4, 30, len(hello()) - 1])
def test_partial_hello_does_not_manufacture_a_credential_rejection(size):
    data = hello()[:size]
    wire, messages = Wire(data[4:]), []
    with pytest.raises(EOFError):
        serve_invalid_credentials("clickhouse", wire, data[:4], messages.append)
    assert not wire.replies and not messages


@pytest.mark.parametrize("data", [b"\x01bad", b"\x00" + b"\xff" * 10, b"\x00" + varuint(65537)])
def test_invalid_packet_type_varint_or_length_has_no_auth_verdict(data):
    wire, messages = Wire(data[4:]), []
    with pytest.raises(ValueError):
        serve_invalid_credentials("clickhouse", wire, data[:4], messages.append)
    assert not wire.replies and not messages


@pytest.mark.parametrize("newline", ["\n", "\\n"])
def test_explicit_clickhouse_516_rejection_is_observed_without_changing_public_row(newline):
    attempt = {
        "username": "reader",
        "password": "wrong",
        "ok": False,
        "error": f"Code: 516.{newline}Authentication failed: password is incorrect. Stack trace:",
    }
    record = {
        "service": "clickhouse",
        "is_clickhouse": True,
        "status": "auth_required",
        "provided_credentials_ok": False,
        "credential_attempts": [attempt],
    }
    assert credential_verdict_errors(record, accepted_identities=set()) == []
    assert credential_summary(record)["invalid"] == 1
    assert "credential_state" not in attempt


@pytest.mark.parametrize("same_identity", [False, True])
def test_default_normalized_alias_needs_matching_native_rejection_proof(same_identity):
    error = "Code: 516.\\nAuthentication failed: password is incorrect. Stack trace:"
    normalized = {"username": "default", "password": "", "source": "default", "status": "auth_required", "error": error}
    native = {
        "username": "default" if same_identity else "another",
        "password": "",
        "source": "default",
        "ok": False,
        "error": error,
    }
    record = {
        "service": "clickhouse",
        "is_clickhouse": True,
        "status": "auth_required",
        "provided_credentials": False,
        "provided_credentials_ok": None,
        "attempted_credentials": [normalized],
        "credential_attempts": [native],
    }
    errors = credential_verdict_errors(record, accepted_identities=set())
    assert bool(errors) is not same_identity
    assert credential_summary(record)["invalid"] == int(same_identity)
    assert "credential_state" not in normalized


@pytest.mark.parametrize(
    "changes",
    [
        {"error": "Code: 497. Authentication failed: permissions denied"},
        {"error": "proxy error: Code: 516. Authentication failed: password is incorrect"},
        {"error": "Code: 516. network unavailable"},
        {"error": "unexpected EOF"},
        {"credential_state": "unverified"},
        {"credential_verification": "unavailable"},
        {"ok": True},
        {"ok": None},
    ],
)
def test_incomplete_conflicting_or_transport_observations_still_fail(changes):
    attempt = {
        "username": "reader",
        "password": "wrong",
        "ok": False,
        "error": "Code: 516.\nAuthentication failed: password is incorrect",
        **changes,
    }
    record = {
        "service": "clickhouse",
        "is_clickhouse": True,
        "status": "auth_required",
        "provided_credentials_ok": False,
        "credential_attempts": [attempt],
    }
    assert credential_verdict_errors(record, accepted_identities=set())


@pytest.mark.parametrize(
    "record_changes",
    [
        {"service": "other"},
        {"is_clickhouse": False},
        {"status": "open_no_auth"},
        {"provided_credentials_ok": True},
        {"provided_credentials_ok": None},
    ],
)
def test_clickhouse_text_does_not_supply_missing_product_or_root_auth_evidence(record_changes):
    record = {
        "service": "clickhouse",
        "is_clickhouse": True,
        "status": "auth_required",
        "provided_credentials_ok": False,
        "credential_attempts": [
            {
                "username": "reader",
                "password": "wrong",
                "ok": False,
                "error": "Code: 516.\nAuthentication failed: password is incorrect",
            }
        ],
        **record_changes,
    }
    assert credential_verdict_errors(record, accepted_identities=set())
