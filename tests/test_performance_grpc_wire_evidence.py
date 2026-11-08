"""Never recover omitted credential identities from the expected catalogue."""

from __future__ import annotations

import base64
import copy

import pytest

from scripts import performance_contracts as contracts

HEALTH = "/grpc.health.v1.Health/Check"
REFLECTION = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"


def headers(path, authorization=None):
    result = [(b":method", b"POST"), (b":path", path.encode())]
    if authorization is not None:
        result.append((b"authorization", authorization.encode()))
    return result


def case():
    record = {
        "service": "grpc",
        "status": "invalid_credentials",
        "provided_credentials_ok": False,
        "credential_verification_status": "available",
        "health_access": "auth_required",
        "reflection_access": "auth_required",
        "attempted_credentials": [
            {"username": None, "password": None, "provided_credential_type": "token", "status": "invalid_credentials"},
            {"username": None, "password": None, "provided_credential_type": "token", "status": "invalid_credentials"},
            {
                "username": "reader",
                "password": "p:ass",
                "provided_credential_type": "basic",
                "status": "invalid_credentials",
            },
        ],
    }
    ledger = contracts.GrpcWireLedger()
    basic = "Basic " + base64.b64encode(b"reader:p:ass").decode()
    for auth in (None, "Bearer token-one", "Bearer token-two", basic):
        for path in (HEALTH, REFLECTION):
            ledger.record(7, headers(path, auth), 16)
    return record, ledger.pop(7)


def test_full_observation_comes_from_completed_wire_calls_without_mutating_output():
    record, wire = case()
    original = copy.deepcopy(record)
    result, error = contracts.wire_grpc_record(record, wire)
    assert error is None and record == original
    assert contracts.credential_digest(result) == contracts.identity_digest(
        [(None, None, "token-one"), (None, None, "token-two"), ("reader", "p:ass", None)]
    )
    assert contracts.credential_summary(result)["duplicate_attempts"] == 0
    assert result["attempted_credentials"][0]["token"] == "token-one"
    assert "token" not in record["attempted_credentials"][0]


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "extra",
        "duplicate-token",
        "wrong-basic",
        "mixed-pair",
        "wrong-path",
        "anonymous-auth",
        "wrong-status",
        "not-post",
        "overflow",
        "malformed",
        "wire-absent",
    ],
)
def test_incomplete_ambiguous_or_changed_wire_evidence_cannot_fill_missing_values(fault):
    record, wire = case()
    if fault == "missing":
        wire["calls"].pop()
    elif fault == "extra":
        wire["calls"].append(dict(wire["calls"][-1]))
    elif fault == "duplicate-token":
        for call in wire["calls"][4:6]:
            call["authorization"] = "Bearer token-one"
    elif fault == "wrong-basic":
        for call in wire["calls"][6:8]:
            call["authorization"] = "Basic " + base64.b64encode(b"reader:other").decode()
    elif fault == "mixed-pair":
        wire["calls"][3]["authorization"] = "Bearer token-two"
    elif fault == "wrong-path":
        wire["calls"][2]["path"] = "/other.Service/Call"
    elif fault == "anonymous-auth":
        wire["calls"][0]["authorization"] = "Bearer unexpected"
    elif fault == "wrong-status":
        wire["calls"][4]["status"] = 12
    elif fault == "not-post":
        wire["calls"][4]["method"] = "GET"
    elif fault == "overflow":
        wire["complete"] = False
    elif fault == "malformed":
        wire["calls"][4] = "broken"
    elif fault == "wire-absent":
        wire = None
    before = copy.deepcopy(record)
    result, error = contracts.wire_grpc_record(record, wire)
    assert error and result is record and record == before


@pytest.mark.parametrize(
    "fault", ["unknown-verdict", "accepted", "other-alias", "bad-row", "wrong-product", "token-conflict"]
)
def test_wire_cannot_replace_a_conflicting_or_unverified_product_ledger(fault):
    record, wire = case()
    if fault == "unknown-verdict":
        record["attempted_credentials"][0]["status"] = "unverified"
    elif fault == "accepted":
        record["provided_credentials_ok"] = True
    elif fault == "other-alias":
        record["credential_attempts"] = [{"username": "unexpected", "ok": True}]
    elif fault == "bad-row":
        record["attempted_credentials"][0] = "broken"
    elif fault == "wrong-product":
        record["service"] = "other"
    elif fault == "token-conflict":
        record["attempted_credentials"][0]["token"] = "different"
    result, error = contracts.wire_grpc_record(record, wire)
    assert error and result is record


def test_root_pop_is_consuming_and_does_not_mix_target_identities():
    ledger = contracts.GrpcWireLedger()
    ledger.record(1, headers(HEALTH, "Bearer first"), 16)
    ledger.record(2, headers(HEALTH, "Bearer second"), 16)
    assert ledger.pop(1)["calls"][0]["authorization"] == "Bearer first"
    assert ledger.pop(1)["calls"] == []
    assert ledger.pop(2)["calls"][0]["authorization"] == "Bearer second"
    assert ledger.snapshot()["pending_calls"] == ledger.snapshot()["pending_targets"] == 0


@pytest.mark.parametrize("bound", ["per-root", "total", "targets", "header-size", "duplicate-authorization"])
def test_wire_storage_is_bounded_and_overflow_remains_visible(bound):
    ledger = contracts.GrpcWireLedger(per_target_limit=2, total_limit=3, target_limit=2)
    if bound == "header-size":
        ledger.record(1, headers(HEALTH, "Bearer " + "x" * 2048), 16)
    elif bound == "duplicate-authorization":
        ledger.record(1, headers(HEALTH, "Bearer first") + [(b"authorization", b"Bearer second")], 16)
    else:
        for index in [1, 1, 1] if bound == "per-root" else [1, 1, 2, 2] if bound == "total" else [1, 2, 3]:
            ledger.record(index, headers(HEALTH, "Bearer value"), 16)
    assert ledger.pop(1)["complete"] is False
    summary = ledger.snapshot()
    assert summary["overflow"] + summary["malformed"] > 0
    assert summary["pending_calls"] <= 3 and summary["pending_targets"] <= 2
    ledger.close()
    assert ledger.snapshot() == summary
    assert not ledger._calls
    ledger.close()
    with pytest.raises(RuntimeError):
        ledger.record(1, headers(HEALTH), 16)


@pytest.mark.parametrize(
    "malformed", [None, ["broken"], [(["invalid-name"], b"value")], [(b":method", ["invalid-value"])]]
)
def test_malformed_wire_headers_invalidate_evidence_without_crashing(malformed):
    ledger = contracts.GrpcWireLedger()
    ledger.record(1, malformed, 16)
    assert ledger.pop(1) == {"complete": False, "calls": []}
    assert ledger.snapshot()["malformed"] == 1


@pytest.mark.parametrize("field", ["username", "password", "token"])
def test_non_scalar_ledger_identity_does_not_crash_or_get_overwritten(field):
    record, wire = case()
    record["attempted_credentials"][0][field] = ["corrupted"]
    result, error = contracts.wire_grpc_record(record, wire)
    assert result is record and error


def test_fragmented_h2_interleaved_and_reset_streams_only_observe_complete_rpc():
    from h2.config import H2Configuration
    from h2.connection import H2Connection

    from scripts.performance_native_fixtures import serve_invalid_credentials
    from tests.test_performance_native_fixtures import Wire

    client = H2Connection(config=H2Configuration(client_side=True))
    client.initiate_connection()
    for stream, token in [(1, "unfinished"), (3, "completed"), (5, "reset")]:
        client.send_headers(
            stream,
            [
                (":method", "POST"),
                (":scheme", "http"),
                (":authority", "not-the-destination"),
                (":path", HEALTH),
                ("content-type", "application/grpc"),
                ("authorization", "Bearer " + token),
            ],
        )
    client.reset_stream(5)
    client.send_data(3, b"\0\0\0\0\0", end_stream=True)
    data = client.data_to_send()
    wire = Wire(data[4:])
    ledger = contracts.GrpcWireLedger()
    assert serve_invalid_credentials(
        "grpc", wire, data[:4], lambda _: None, grpc_observer=lambda fields, status: ledger.record(9, fields, status)
    )
    evidence = ledger.pop(9)
    assert evidence == {
        "complete": True,
        "calls": [{"method": "POST", "path": HEALTH, "authorization": "Bearer completed", "status": 16}],
    }
