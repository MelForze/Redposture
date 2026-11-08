"""Positive gRPC metadata evidence uses complete frames and actual client calls."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest
from google.protobuf import descriptor_pb2

from redposture_core.modules.grpc import actions
from redposture_core.proto import grpc_health_pb2, grpc_reflection_pb2
from scripts.performance_grpc import (
    HEALTH,
    REFLECTION,
    SERVICES,
    GrpcPayloadLedger,
    fields,
    frame,
    grpc_auth_steps,
    rpc_reply,
    unframe,
    wire_grpc_payload_record,
)
from scripts.performance_native_server import AsyncNativeFixture


def headers(path, authorization=b"Basic cHJvZmlsZS11c2VyOnByb2ZpbGUtcGFzc3dvcmQ="):
    return [
        (b":method", b"POST"),
        (b":path", path.encode()),
        *([(b"authorization", authorization)] if authorization else []),
    ]


def test_proto_responses_are_readable_by_independent_generated_messages():
    status, data = rpc_reply(
        headers(HEALTH), frame(b""), valid_pair=("profile-user", "profile-password"), limited=False
    )
    assert status == 0 and grpc_health_pb2.HealthCheckResponse.FromString(unframe(data)).status == 1
    path = sorted(REFLECTION)[0]
    request = grpc_reflection_pb2.ServerReflectionRequest(list_services="*").SerializeToString()
    status, data = rpc_reply(
        headers(path), frame(request), valid_pair=("profile-user", "profile-password"), limited=False
    )
    assert status == 0
    result = grpc_reflection_pb2.ServerReflectionResponse.FromString(unframe(data))
    assert tuple(s.name for s in result.list_services_response.service) == SERVICES
    for service in SERVICES:
        request = grpc_reflection_pb2.ServerReflectionRequest(file_containing_symbol=service).SerializeToString()
        status, data = rpc_reply(
            headers(path), frame(request), valid_pair=("profile-user", "profile-password"), limited=False
        )
        assert status == 0
        response = grpc_reflection_pb2.ServerReflectionResponse.FromString(unframe(data))
        models = [
            descriptor_pb2.FileDescriptorProto.FromString(v)
            for v in response.file_descriptor_response.file_descriptor_proto
        ]
        assert len(models) == 1 and models[0].name == "billing.proto" and models[0].package == "billing.v1"
        assert [s.name for s in models[0].service] == ["Billing", "Events"]


@pytest.mark.parametrize("authorization", [None, b"Basic d3Jvbmc6d3Jvbmc=", b"Bearer wrong", b"Bearer admin extra"])
def test_every_invalid_identity_is_denied_without_fabricated_payload(authorization):
    for path in [HEALTH, *REFLECTION, "/billing.v1.Billing/GetStatus"]:
        assert rpc_reply(
            headers(path, authorization), frame(b""), valid_pair=("profile-user", "profile-password"), limited=False
        ) == (16, b"")


def test_authentication_is_distinct_from_reflection_authorization():
    request = grpc_reflection_pb2.ServerReflectionRequest(list_services="*").SerializeToString()
    assert rpc_reply(headers(HEALTH), frame(b""), valid_pair=("profile-user", "profile-password"), limited=True)[0] == 0
    assert rpc_reply(
        headers(sorted(REFLECTION)[0]), frame(request), valid_pair=("profile-user", "profile-password"), limited=True
    ) == (7, b"")


@pytest.mark.parametrize(
    "payload", [b"", b"\0\0\0\0\x01", frame(b"\xff"), frame(b"\x0a\xff\x7f"), frame(b"\x0a\0" * 129), b"\1\0\0\0\0"]
)
def test_malformed_unary_frames_never_produce_success(payload):
    assert rpc_reply(headers(HEALTH), payload, valid_pair=("profile-user", "profile-password"), limited=False) == (
        3,
        b"",
    )


def test_wire_ledger_hashes_full_frames_and_releases_capacity():
    body, reply = frame(b""), frame(b"\x08\x01")
    ledger = GrpcPayloadLedger(body_limit=100)
    ledger.record_exchange(3, headers(HEALTH), body, 0, reply)
    value = ledger.pop(3)
    assert value["complete"] and len(value["calls"]) == 1 and ledger.pending_body_bytes == 0
    call = value["calls"][0]
    assert bytes.fromhex(call["request_hex"]) == body and call["request_sha256"] == hashlib.sha256(body).hexdigest()
    assert bytes.fromhex(call["response_hex"]) == reply and call["response_sha256"] == hashlib.sha256(reply).hexdigest()
    ledger.close()
    with pytest.raises(RuntimeError):
        ledger.record_exchange(3, headers(HEALTH), body, 0, reply)
    tiny = GrpcPayloadLedger(body_limit=1)
    tiny.record_exchange(0, headers(HEALTH), body, 0, reply)
    assert tiny.snapshot()["overflow"] == 1 and tiny.pop(0)["complete"] is False


@pytest.mark.parametrize("kind", ["basic", "bearer", "limited", "invalid", "defaults"])
def test_actual_module_health_reflection_and_descriptors(kind):
    ledger = GrpcPayloadLedger()
    pair = ("admin", "admin") if kind == "defaults" else ("profile-user", "profile-password")

    def program(host, initial, message):
        return grpc_auth_steps(
            initial,
            message,
            valid_pair=pair,
            limited=kind == "limited",
            observer=lambda h, b, s, r: ledger.record_exchange(0, h, b, s, r),
        )

    peer = AsyncNativeFixture("grpc", mode="actions", role=lambda _: "positive", program_factory=program)
    peer.start()
    try:
        result = actions._audit_grpc_host(
            "127.0.0.1",
            peer.port,
            1,
            0,
            token="admin" if kind == "bearer" else None,
            username=None if kind in {"bearer", "defaults"} else "wrong" if kind == "invalid" else pair[0],
            password=None if kind in {"bearer", "defaults"} else "wrong" if kind == "invalid" else pair[1],
            defcreds=kind == "defaults",
            preferred_scheme="http",
            run_deep_checks=True,
            analyze=True,
        )
    finally:
        peer.close()
    assert result["is_grpc"] is True and not peer.errors and peer.stats["active"] == 0
    if kind == "invalid":
        assert result["provided_credentials_ok"] is False and not result.get("services")
    else:
        assert result["provided_credentials_ok"] is True, result
        assert result["health_access"] == "authenticated"
        if kind == "limited":
            assert result["reflection_access"] == "auth_required" and not result.get("services")
        else:
            assert result["services"] == list(SERVICES)
            assert len(result["methods"]) == 2 and len(result["health_checks"]) == 3
            assert all(row["serving_status"] == "SERVING" for row in result["health_checks"])
    wire = ledger.pop(0)
    assert wire["complete"] and wire["calls"]
    observation, error = wire_grpc_payload_record(result, wire, valid_pair=pair, limited=kind == "limited")
    assert error is None, error
    assert len(observation["attempted_credentials"]) == (23 if kind == "defaults" else 1)
    statuses = {c["authorization"]: c["status"] for c in wire["calls"] if c["path"] == HEALTH}
    assert statuses[None] == 16
    if kind == "defaults":
        assert len(result["attempted_credentials"]) == 23
        assert statuses["Bearer admin"] == statuses["Basic " + base64.b64encode(b"admin:admin").decode()] == 0


def test_tiny_proto_parser_does_not_accept_unbounded_fields():
    with pytest.raises(ValueError):
        fields(b"\x0a\0" * 32769)


@pytest.mark.parametrize(
    "fault",
    [
        "missing-wire",
        "missing-frame",
        "corrupt-frame",
        "status",
        "identity",
        "method",
        "verdict",
        "malformed-auth",
        "missing-anonymous",
    ],
)
def test_corrupt_full_payload_proof_cannot_verify_a_credential(fault):
    ledger = GrpcPayloadLedger()
    pair = ("profile-user", "profile-password")
    path = sorted(REFLECTION)[0]
    reflection = frame(grpc_reflection_pb2.ServerReflectionRequest(list_services="*").SerializeToString())
    for auth in [None, b"Basic " + base64.b64encode(b"profile-user:profile-password")]:
        for target, body in [(HEALTH, frame(b"")), (path, reflection)]:
            selected = headers(target, auth)
            status, reply = rpc_reply(selected, body, valid_pair=pair, limited=False)
            ledger.record_exchange(0, selected, body, status, reply)
    record = {
        "is_grpc": True,
        "provided_credentials": True,
        "provided_username": pair[0],
        "provided_password": pair[1],
        "provided_credentials_ok": True,
        "status": "valid_credentials",
    }
    wire = ledger.pop(0)
    assert wire_grpc_payload_record(record, wire, valid_pair=pair, limited=False)[1] is None
    record, wire = deepcopy(record), deepcopy(wire)
    if fault == "missing-wire":
        wire["calls"] = []
    elif fault == "missing-frame":
        del wire["calls"][-1]["request_hex"]
    elif fault == "corrupt-frame":
        wire["calls"][-1]["response_hex"] += "ff"
    elif fault == "status":
        wire["calls"][-1]["status"] = 16
    elif fault == "identity":
        record["provided_password"] = "different"
    elif fault == "method":
        wire["calls"][-1]["method"] = "GET"
    elif fault == "verdict":
        record["provided_credentials_ok"] = False
        record["status"] = "invalid_credentials"
    elif fault == "malformed-auth":
        wire["calls"][-1]["authorization"] = []
    else:
        wire["calls"] = wire["calls"][2:]
    assert wire_grpc_payload_record(record, wire, valid_pair=pair, limited=False)[1]


@pytest.mark.parametrize("output_format", ["txt", "json"])
def test_public_cli_confirms_limited_credentials_without_granting_reflection(tmp_path, output_format):
    def program(host, initial, message):
        return grpc_auth_steps(
            initial, message, valid_pair=("profile-user", "profile-password"), limited=True, observer=lambda *args: None
        )

    peer = AsyncNativeFixture("grpc", mode="actions", role=lambda _: "positive", program_factory=program)
    peer.start()
    saved = tmp_path / ("limited." + output_format)
    try:
        result = subprocess.run(
            [
                sys.executable,
                "redposture.py",
                "grpc",
                "-t",
                f"127.0.0.1:{peer.port}",
                "--plaintext",
                "-u",
                "profile-user",
                "-p",
                "profile-password",
                "--analyze",
                "--timeout",
                "1",
                "--retries",
                "0",
                "--no-color",
                "-f",
                output_format,
                "-o",
                str(saved),
            ],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            timeout=20,
        )
    finally:
        peer.close()
    assert result.returncode == 0, result.stderr
    text = saved.read_text()
    assert "\x1b" not in text + result.stdout and not peer.errors and peer.stats["active"] == 0
    if output_format == "json":
        record = json.loads(text)
        assert record["provided_credentials_ok"] is True and record["status"] == "valid_credentials"
        assert record["health_access"] == "authenticated" and record["reflection_access"] == "auth_required"
        assert record["action_access_satisfied"] is False and not record.get("services")
    else:
        assert "[+] profile-user:profile-password" in text
