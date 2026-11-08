"""Bounded gRPC health/reflection model with received protobuf evidence.

Protocol emulation, not a real deployment. Only fixed read-only RPCs succeed.
HTTP/2 state follows https://python-hyper.org/projects/h2/en/stable/asyncio-example.html
"""

from __future__ import annotations

import base64
import functools
import hashlib
import struct
from collections.abc import Callable
from typing import Any

from scripts.performance_contracts import GrpcWireLedger
from scripts.performance_native_fixtures import ReadSome, WireProgram, Write

HEALTH = "/grpc.health.v1.Health/Check"
REFLECTION = {
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
}
SERVICES = ("billing.v1.Billing", "billing.v1.Events")
PayloadObserver = Callable[[list[tuple[bytes, bytes]], bytes, int, bytes], None]


def _varint(value: int) -> bytes:
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _field(number: int, value: bytes) -> bytes:
    return _varint(number * 8 + 2) + _varint(len(value)) + value


def fields(data: bytes) -> dict[int, list[bytes]]:
    """Small length-delimited QA messages; no unbounded protobuf allocation."""
    if len(data) > 65536:
        raise ValueError("QA protobuf size exceeded")
    offset = 0
    result: dict[int, list[bytes]] = {}

    def integer() -> int:
        nonlocal offset
        value = 0
        for bit in range(0, 70, 7):
            if offset >= len(data):
                raise ValueError("incomplete protobuf varint")
            byte = data[offset]
            offset += 1
            if bit == 63 and byte > 1:
                raise ValueError("oversized protobuf varint")
            value |= (byte & 127) << bit
            if byte < 128:
                return value
        raise ValueError("unterminated protobuf varint")

    count = 0
    while offset < len(data):
        count += 1
        if count > 128:
            raise ValueError("QA protobuf field capacity exceeded")
        tag = integer()
        if tag < 8 or tag % 8 != 2:
            raise ValueError("unexpected QA protobuf field")
        length = integer()
        if length > 65536 or offset + length > len(data):
            raise ValueError("incomplete protobuf field")
        result.setdefault(tag // 8, []).append(data[offset : offset + length])
        offset += length
    return result


def unframe(body: bytes) -> bytes:
    if len(body) < 5 or body[0] != 0 or len(body) != 5 + struct.unpack("!I", body[1:5])[0] or len(body) > 65536:
        raise ValueError("invalid unary QA gRPC frame")
    return body[5:]


def frame(payload: bytes) -> bytes:
    return b"\0" + struct.pack("!I", len(payload)) + payload


@functools.lru_cache(maxsize=1)
def descriptor() -> bytes:
    from google.protobuf import descriptor_pb2

    model = descriptor_pb2.FileDescriptorProto(name="billing.proto", package="billing.v1", syntax="proto3")
    for name, field_name in (("StatusRequest", "name"), ("StatusReply", "state")):
        message = model.message_type.add(name=name)
        message.field.add(name=field_name, number=1, label=1, type=9)
    for name in ("Billing", "Events"):
        service = model.service.add(name=name)
        service.method.add(
            name="GetStatus", input_type=".billing.v1.StatusRequest", output_type=".billing.v1.StatusReply"
        )
    return model.SerializeToString()


def rpc_reply(
    headers: list[tuple[bytes, bytes]], body: bytes, *, valid_pair: tuple[str, str] | None, limited: bool
) -> tuple[int, bytes]:
    if len(headers) > 128 or any(len(k) + len(v) > 2048 for k, v in headers):
        return 8, b""
    selected: dict[bytes, bytes] = {}
    for key, value in headers:
        if key in {b":method", b":path", b"authorization"}:
            if key in selected:
                return 3, b""
            selected[key] = value
    if selected.get(b":method") != b"POST":
        return 12, b""
    allowed = (
        {b"Basic " + base64.b64encode((valid_pair[0] + ":" + valid_pair[1]).encode()), b"Bearer admin"}
        if valid_pair is not None
        else set()
    )
    if selected.get(b"authorization") not in allowed:
        return 16, b""
    try:
        payload = unframe(body)
        values = fields(payload)
        path = selected[b":path"].decode("ascii")
    except (ValueError, KeyError, UnicodeError):
        return 3, b""
    if path == HEALTH:
        names = values.get(1, [b""])
        if len(names) != 1 or names[0] not in (b"", *(name.encode() for name in SERVICES)):
            return 5, b""
        return 0, frame(b"\x08\x01")
    if path in REFLECTION:
        if limited:
            return 7, b""
        original = _field(2, payload)
        if set(values).issubset({1, 7}) and values.get(7) == [b"*"]:
            listing = b"".join(_field(1, _field(1, name.encode())) for name in SERVICES)
            return 0, frame(original + _field(6, listing))
        symbol = values.get(4)
        if (
            symbol
            and len(symbol) == 1
            and symbol[0] in {s.encode() for s in SERVICES}
            or values.get(3) == [b"billing.proto"]
        ):
            return 0, frame(original + _field(4, _field(1, descriptor())))
        return 5, b""
    if path in {"/" + name + "/GetStatus" for name in SERVICES}:
        if limited:
            return 7, b""
        if set(values) - {1}:
            return 3, b""
        return 0, frame(_field(1, b"READY"))
    return 12, b""


class GrpcPayloadLedger(GrpcWireLedger):
    """Full bounded frames, not a reconstruction from the expected catalogue."""

    def __init__(self, *, body_limit: int = 8 * 1024 * 1024, **kwargs: Any):
        super().__init__(**kwargs)
        if body_limit < 1:
            raise ValueError("positive payload ledger bound required")
        self.body_limit = body_limit
        self.pending_body_bytes = 0

    def record_exchange(
        self, index: int, headers: list[tuple[bytes, bytes]], body: bytes, status: int, reply: bytes
    ) -> None:
        if self._final is not None:
            raise RuntimeError("wire ledger closed")
        if max(len(body), len(reply)) > 65536 or self.pending_body_bytes + len(body) + len(reply) > self.body_limit:
            self._overflow += 1
            return
        before = len(self._calls.get(index, []))
        super().record(index, headers, status)
        if len(self._calls.get(index, [])) == before + 1:
            self._calls[index][-1].update(
                request_hex=body.hex(),
                response_hex=reply.hex(),
                request_sha256=hashlib.sha256(body).hexdigest(),
                response_sha256=hashlib.sha256(reply).hexdigest(),
                retained_bytes=len(body) + len(reply),
            )
            self.pending_body_bytes += len(body) + len(reply)

    def pop(self, index: int) -> dict[str, Any]:
        value = super().pop(index)
        self.pending_body_bytes -= sum(c["retained_bytes"] for c in value["calls"])
        return value


def grpc_auth_steps(
    initial: bytes,
    message: Callable[[str], None],
    *,
    valid_pair: tuple[str, str] | None,
    limited: bool,
    observer: PayloadObserver,
) -> WireProgram:
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import DataReceived, RequestReceived, StreamEnded, StreamReset

    connection = H2Connection(config=H2Configuration(client_side=False))
    connection.initiate_connection()
    yield Write(connection.data_to_send())
    pending: dict[int, tuple[list[tuple[bytes, bytes]], bytearray]] = {}
    pending_bytes = 0
    data = initial
    while data:
        for event in connection.receive_data(data):
            if isinstance(event, RequestReceived):
                if (
                    len(pending) >= 128
                    or len(event.headers) > 128
                    or sum(len(k) + len(v) for k, v in event.headers) > 16384
                ):
                    raise ValueError("QA stream capacity exceeded")
                pending[event.stream_id] = (event.headers, bytearray())
            elif isinstance(event, StreamReset):
                removed = pending.pop(event.stream_id, None)
                if removed is not None:
                    pending_bytes -= len(removed[1])
            elif isinstance(event, DataReceived):
                if (
                    event.stream_id not in pending
                    or len(pending[event.stream_id][1]) + len(event.data) > 65536
                    or pending_bytes + len(event.data) > 262144
                ):
                    raise ValueError("QA request frame bound exceeded")
                pending[event.stream_id][1].extend(event.data)
                pending_bytes += len(event.data)
                connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            elif isinstance(event, StreamEnded):
                headers, chunks = pending.pop(event.stream_id)
                pending_bytes -= len(chunks)
                body = bytes(chunks)
                status, reply = rpc_reply(headers, body, valid_pair=valid_pair, limited=limited)
                observer(headers, body, status, reply)
                message("grpc_call")
                connection.send_headers(event.stream_id, [(":status", "200"), ("content-type", "application/grpc")])
                if reply:
                    connection.send_data(event.stream_id, reply)
                connection.send_headers(event.stream_id, [("grpc-status", str(status))], end_stream=True)
        yield Write(connection.data_to_send())
        data = yield ReadSome(65536)
    return True


def wire_grpc_payload_record(
    record: dict[str, Any], evidence: Any, *, valid_pair: tuple[str, str] | None, limited: bool
) -> tuple[dict[str, Any], str | None]:
    """Correlate public verdicts with complete received identities and frames.

    Only the observer copy is enriched; CLI output and missing verdicts are
    never filled from expected candidates. Reflection denial stays a denial.
    """
    if record.get("is_grpc") is not True or not isinstance(evidence, dict) or evidence.get("complete") is not True:
        return record, "unconfirmed gRPC payload evidence"
    calls = evidence.get("calls")
    if not isinstance(calls, list) or not 2 <= len(calls) <= 130:
        return record, "missing or oversized gRPC RPC evidence"
    grouped: dict[str | None, list[dict[str, Any]]] = {}
    for call in calls:
        if (
            not isinstance(call, dict)
            or call.get("method") != "POST"
            or not isinstance(call.get("path"), str)
            or type(call.get("status")) is not int
        ):
            return record, "malformed gRPC RPC metadata"
        auth = call.get("authorization")
        if auth is not None and (not isinstance(auth, str) or len(auth) > 1024):
            return record, "malformed received gRPC authorization"
        if any(
            not isinstance(call.get(k), str) or len(call[k]) > 131072
            for k in ("request_hex", "response_hex", "request_sha256", "response_sha256")
        ):
            return record, "missing or oversized gRPC frame receipt"
        try:
            body, response = bytes.fromhex(call["request_hex"]), bytes.fromhex(call["response_hex"])
            if (
                hashlib.sha256(body).hexdigest() != call["request_sha256"]
                or hashlib.sha256(response).hexdigest() != call["response_sha256"]
            ):
                return record, "corrupt gRPC frame receipt"
            expected_status, expected_response = rpc_reply(
                [
                    (b":method", b"POST"),
                    (b":path", call["path"].encode("ascii")),
                    *([(b"authorization", auth.encode("ascii"))] if auth else []),
                ],
                body,
                valid_pair=valid_pair,
                limited=limited,
            )
        except (ValueError, UnicodeError):
            return record, "malformed gRPC frame bytes"
        if (call["status"], response) != (expected_status, expected_response):
            return record, "gRPC response differs from received seeded RPC"
        grouped.setdefault(auth, []).append(call)
    anonymous = grouped.get(None, [])
    if not any(c["path"] == HEALTH and c["status"] == 16 for c in anonymous) or not any(
        c["path"] in REFLECTION and c["status"] == 16 for c in anonymous
    ):
        return record, "missing protected anonymous gRPC control"
    identities = []
    accepted = []
    for auth, own in grouped.items():
        if auth is None:
            continue
        if not any(c["path"] == HEALTH for c in own) or not any(c["path"] in REFLECTION for c in own):
            return record, "incomplete received credential RPC pair"
        try:
            identity: tuple[str | None, str | None, str | None]
            if auth.startswith("Basic "):
                user, password = base64.b64decode(auth[6:], validate=True).decode("utf-8").split(":", 1)
                identity = (user, password, None)
            elif auth.startswith("Bearer ") and auth[7:] and not any(c.isspace() for c in auth[7:]):
                identity = (None, None, auth[7:])
            else:
                return record, "unsupported received credential kind"
        except (ValueError, UnicodeError):
            return record, "malformed full received gRPC credential"
        identities.append(identity)
        accepted.append(any(c["status"] == 0 and c["path"] == HEALTH for c in own))
    raw_rows = record.get("attempted_credentials")
    if raw_rows is None:
        if not identities:
            return record, None
        if (
            len(identities) != 1
            or record.get("provided_credentials") is not True
            or type(record.get("provided_credentials_ok")) is not bool
        ):
            return record, "missing gRPC client credential verdict"
        raw_rows = [
            {
                **record,
                "username": record.get("provided_username"),
                "password": record.get("provided_password"),
                "source": "provided",
            }
        ]
    if not isinstance(raw_rows, list) or len(raw_rows) != len(identities):
        return record, "gRPC client/wire credential count differs"
    rows = []
    for row, identity, allowed in zip(raw_rows, identities, accepted, strict=True):
        if not isinstance(row, dict):
            return record, "malformed gRPC client credential ledger"
        observed_user, observed_password, token = identity
        if (
            row.get("username") != observed_user
            or row.get("password") != observed_password
            or row.get("token") not in (None, token)
        ):
            return record, "gRPC full received identity differs from client"
        from scripts.performance_contracts import accepted_claim

        if accepted_claim(row) is not allowed:
            return record, "gRPC credential verdict differs from protected RPC proof"
        rows.append({**row, "username": observed_user, "password": observed_password, "token": token})
    return {**record, "attempted_credentials": rows}, None


def grpc_inventory_errors(record: dict[str, Any], *, authenticated: bool, limited: bool) -> list[str]:
    if not authenticated:
        if (
            record.get("provided_credentials_ok") is not False
            or record.get("analysis_performed") is not False
            or record.get("action_access_satisfied") is not False
            or any(record.get(k) for k in ("services", "methods", "descriptors", "descriptor_protos_b64"))
        ):
            return ["gRPC rejected credential unexpectedly performed protected analysis"]
        return []
    if record.get("analysis_performed") is not True:
        return ["gRPC requested analysis was not performed"]
    if authenticated and not limited:
        if record.get("services") != list(SERVICES):
            return ["gRPC reflection services differ from known inventory"]
        methods = record.get("methods")
        if (
            not isinstance(methods, list)
            or len(methods) != 2
            or {
                (m.get("service"), m.get("method"), m.get("input_type"), m.get("output_type"))
                for m in methods
                if isinstance(m, dict)
            }
            != {(s, "GetStatus", "billing.v1.StatusRequest", "billing.v1.StatusReply") for s in SERVICES}
        ):
            return ["gRPC methods differ from seeded descriptors"]
        blobs = record.get("descriptor_protos_b64")
        if not isinstance(blobs, list) or blobs != [base64.b64encode(descriptor()).decode()]:
            return ["gRPC full descriptor differs from received schema"]
        checks = record.get("health_checks")
        if (
            not isinstance(checks, list)
            or len(checks) != 3
            or {c.get("service") for c in checks if isinstance(c, dict)} != {"", *SERVICES}
            or any(
                c.get("grpc_status") != 0 or c.get("serving_status") != "SERVING" or c.get("access") != "authenticated"
                for c in checks
            )
        ):
            return ["gRPC per-service health proof differs"]
        if record.get("action_access_satisfied") is not True:
            return ["gRPC completed inventory falsely marked unavailable"]
    else:
        if (
            any(record.get(k) for k in ("services", "methods", "descriptors", "descriptor_protos_b64"))
            or record.get("reflection_access") != "auth_required"
            or record.get("action_access_satisfied") is not False
        ):
            return ["gRPC denied reflection incorrectly reported as accessible"]
        if record.get("provided_credentials_ok") is not authenticated:
            return ["gRPC authentication/authorization verdict conflated"]
    return []
