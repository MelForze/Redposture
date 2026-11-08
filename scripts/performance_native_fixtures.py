"""Bounded negative-credential wire fixtures for native public-stage profiles.

Detection-only calibration retains its original independent wire corpus. These
fixtures deliberately require authentication so a public/anonymous success
cannot vacuously replace the requested credential checks.
"""

from __future__ import annotations

import socket
import struct
from collections.abc import Callable, Generator
from dataclasses import dataclass
from typing import Any


class RequestReader:
    def __init__(self, sock: socket.socket, initial: bytes) -> None:
        self.sock = sock
        self.buffer = bytearray(initial)

    def exact(self, size: int) -> bytes:
        if not 0 <= size <= 65536:
            raise ValueError("out-of-fixture request length")
        while len(self.buffer) < size:
            data = self.sock.recv(min(4096, size - len(self.buffer)))
            if not data:
                raise EOFError
            self.buffer.extend(data)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def line(self) -> bytes:
        while b"\r\n" not in self.buffer:
            if len(self.buffer) >= 65536:
                raise ValueError("oversized fixture line")
            data = self.sock.recv(4096)
            if not data:
                raise EOFError
            self.buffer.extend(data)
        index = self.buffer.index(b"\r\n")
        return self.exact(index + 2)[:-2]


@dataclass(frozen=True)
class Read:
    size: int


@dataclass(frozen=True)
class ReadLine:
    pass


@dataclass(frozen=True)
class ReadSome:
    size: int


@dataclass(frozen=True)
class Write:
    data: bytes


WireStep = Read | ReadLine | ReadSome | Write
WireProgram = Generator[WireStep, Any, bool]
GrpcObserver = Callable[[list[tuple[bytes, bytes]] | None, int], None]
CoordinationObserver = Callable[[str, str | None, str | None, str | None, int], None]


def drive_wire_steps(program: WireProgram, sock: socket.socket, initial: bytes = b"") -> bool:
    """Blocking compatibility driver; parser/response logic is shared with async."""
    reader = RequestReader(sock, initial)
    value: Any = None
    while True:
        try:
            step = program.send(value)
        except StopIteration as finished:
            return bool(finished.value)
        if isinstance(step, Read):
            value = reader.exact(step.size)
        elif isinstance(step, ReadLine):
            value = reader.line()
        elif isinstance(step, ReadSome):
            if not 1 <= step.size <= 65536:
                raise ValueError("out-of-fixture request length")
            if reader.buffer:
                value = bytes(reader.buffer[: step.size])
                del reader.buffer[: step.size]
            else:
                value = sock.recv(step.size)
        else:
            sock.sendall(step.data)
            value = None


def serve_invalid_credentials(
    product: str,
    sock: socket.socket,
    initial: bytes,
    message: Callable[[str], None],
    *,
    grpc_observer: GrpcObserver | None = None,
    coordination_observer: CoordinationObserver | None = None,
) -> bool:
    return drive_wire_steps(
        invalid_credential_steps(
            product, message, grpc_observer=grpc_observer, coordination_observer=coordination_observer
        ),
        sock,
        initial,
    )


def _clickhouse_varuint() -> Generator[WireStep, Any, int]:
    value = 0
    for index in range(10):
        byte = (yield Read(1))[0]
        if index == 9 and byte > 1:
            raise ValueError("out-of-range ClickHouse VarUInt")
        value |= (byte & 127) << (7 * index)
        if byte < 128:
            return value
    raise ValueError("unterminated ClickHouse VarUInt")


def _clickhouse_string() -> Generator[WireStep, Any, str]:
    size = yield from _clickhouse_varuint()
    if size > 65536:
        raise ValueError("out-of-fixture ClickHouse string")
    return (yield Read(size)).decode("utf-8")


def invalid_credential_steps(
    product: str,
    message: Callable[[str], None],
    *,
    grpc_observer: GrpcObserver | None = None,
    coordination_observer: CoordinationObserver | None = None,
) -> WireProgram:
    if product == "grpc":
        return (yield from _grpc_steps((yield Read(4)), message, status=16, observer=grpc_observer))
    if product == "kafka":
        return (yield from _kafka_invalid_steps(message))
    if product in {"zookeeper", "keeper"}:
        return (yield from _coordination_digest_steps(product, (yield Read(4)), message, coordination_observer))
    if product == "clickhouse":
        # Native ClientHello contains the credentials, unlike a TCP connect or
        # the first four bytes. Do not reject until its full body is received.
        if (yield from _clickhouse_varuint()) != 0:
            raise ValueError("expected ClickHouse ClientHello")
        yield from _clickhouse_string()  # client name
        for _ in range(3):
            yield from _clickhouse_varuint()  # version major/minor/revision
        for _ in range(3):
            yield from _clickhouse_string()  # database/user/password
        message("hello")
        text = b"Authentication failed: password is incorrect"
        yield Write(b"\x02" + struct.pack("<i", 516) + b"\x0dDB::Exception" + bytes([len(text)]) + text + b"\0\0")
        return True
    if product not in {"mongodb", "postgres", "redis"}:
        return False
    if product == "redis":
        while True:
            header = yield ReadLine()
            if not header.startswith(b"*") or not 1 <= (count := int(header[1:])) <= 64:
                raise ValueError("expected a bounded RESP command")
            args = []
            for _ in range(count):
                length = yield ReadLine()
                if not length.startswith(b"$"):
                    raise ValueError("expected RESP bulk argument")
                args.append((yield Read(int(length[1:]))))
                if (yield Read(2)) != b"\r\n":
                    raise ValueError("missing RESP CRLF")
            message(args[0].decode("ascii", "replace").lower())
            if args[0].upper() == b"AUTH":
                yield Write(b"-WRONGPASS invalid username-password pair or user is disabled.\r\n")
            elif args[0].upper() == b"QUIT":
                yield Write(b"+OK\r\n")
                return True
            else:
                yield Write(b"-NOAUTH Authentication required.\r\n")
    if product == "postgres":
        size = struct.unpack(">i", (yield Read(4)))[0]
        body = yield Read(size - 4)
        message("sslrequest" if size == 8 else "startup")
        if size == 8 and body == struct.pack(">i", 80877103):
            yield Write(b"N")
            size = struct.unpack(">i", (yield Read(4)))[0]
            (yield Read(size - 4))
            message("startup")
        yield Write(b"R" + struct.pack(">ii", 8, 3))  # AuthenticationCleartextPassword
        kind = yield Read(1)
        size = struct.unpack(">i", (yield Read(4)))[0]
        (yield Read(size - 4))
        message("password")
        if kind == b"p":
            error = b"SERROR\0VERROR\0C28P01\0Mpassword authentication failed\0\0"
            yield Write(b"E" + struct.pack(">i", len(error) + 4) + error)
        return True
    from bson import BSON

    while True:
        size, request_id, _response_to, opcode = struct.unpack("<iiii", (yield Read(16)))
        request = yield Read(size - 16)
        if opcode == 2004:
            start = request.index(b"\0", 4) + 9
            command = BSON(request[start:]).decode()
        elif opcode == 2013:
            command = BSON(request[5:]).decode()
        else:
            raise ValueError("unsupported fixture MongoDB opcode")
        name = next(iter(command)).lower()
        message(name)
        document: dict[str, Any]
        if name in {"hello", "ismaster"}:
            document = {
                "ok": 1.0,
                "ismaster": True,
                "isWritablePrimary": True,
                "minWireVersion": 0,
                "maxWireVersion": 21,
                "maxBsonObjectSize": 16777216,
                "maxMessageSizeBytes": 48000000,
                "maxWriteBatchSize": 100000,
                "saslSupportedMechs": ["SCRAM-SHA-256"],
            }
        elif name == "buildinfo":
            document = {"ok": 1.0, "version": "7.0.14", "versionArray": [7, 0, 14, 0]}
        elif name in {"saslstart", "saslcontinue", "authenticate"}:
            document = {"ok": 0.0, "code": 18, "codeName": "AuthenticationFailed", "errmsg": "Authentication failed"}
        else:
            document = {"ok": 0.0, "code": 13, "codeName": "Unauthorized", "errmsg": "not authorized"}
        bson = BSON.encode(document)
        payload = struct.pack("<iqii", 0, 0, 0, 1) + bson if opcode == 2004 else struct.pack("<iB", 0, 0) + bson
        response_opcode = 1 if opcode == 2004 else 2013
        yield Write(struct.pack("<iiii", 16 + len(payload), 1, request_id, response_opcode) + payload)


def _kafka_invalid_steps(message: Callable[[str], None]) -> WireProgram:
    """SASL PLAIN v1/API36 v0 rejection, using the official non-flexible schemas.

    Mechanism negotiation is not a password verdict. A failed legacy/raw SASL
    exchange closes without inventing a modern explicit code58 response.
    """
    negotiated: bool | None = None

    def frame(data: bytes) -> bytes:
        return struct.pack(">i", len(data)) + data

    while True:
        size = struct.unpack(">i", (yield Read(4)))[0]
        if not 1 <= size <= 65536:
            raise ValueError("out-of-fixture Kafka frame")
        request = yield Read(size)
        if negotiated is False:
            # Raw SASL token has no Kafka correlation or numeric error code.
            if len(request.split(b"\0")) != 3:
                raise ValueError("malformed raw PLAIN token")
            message("kafka_sasl_raw")
            return True
        if len(request) < 10:
            raise ValueError("truncated Kafka request header")
        api, version, correlation, client_size = struct.unpack(">hhih", request[:10])
        if client_size < -1 or 10 + max(0, client_size) > len(request):
            raise ValueError("invalid Kafka client identifier")
        body = request[10 + max(0, client_size) :]
        if api == 18:
            if version != 0 or body:
                raise ValueError("fixture requires ApiVersions v0")
            versions = [(18, 0, 0), (17, 0, 1), (36, 0, 0), (3, 0, 0)]
            response = struct.pack(">ihi", correlation, 0, len(versions)) + b"".join(
                struct.pack(">hhh", *item) for item in versions
            )
        elif api == 17:
            if version not in {0, 1} or len(body) < 2:
                raise ValueError("invalid SASL handshake")
            length = struct.unpack(">h", body[:2])[0]
            if length < 0 or len(body) != length + 2:
                raise ValueError("truncated SASL mechanism")
            accepted = body[2:] == b"PLAIN"
            response = struct.pack(">ihi", correlation, 0 if accepted else 33, 1) + b"\x00\x05PLAIN"
            negotiated = version >= 1 if accepted else None
        elif api == 36:
            if version != 0 or len(body) < 4:
                raise ValueError("invalid SaslAuthenticate v0")
            length = struct.unpack(">i", body[:4])[0]
            if length < 0 or len(body) != length + 4 or len(body[4:].split(b"\0")) != 3:
                raise ValueError("truncated or malformed PLAIN token")
            # Only a fully framed token after successful negotiation is denied.
            code = 58 if negotiated is True else 34
            error = b"Authentication failed" if code == 58 else b"Illegal SASL state"
            response = struct.pack(">ihh", correlation, code, len(error)) + error + struct.pack(">i", 0)
        else:
            return True  # Protected listener closes an unauthenticated data request.
        message("kafka_api_" + str(api))
        yield Write(frame(response))
        if api == 36:
            return True


def _coordination_digest_steps(
    product: str, initial: bytes, message: Callable[[str], None], observer: CoordinationObserver | None
) -> WireProgram:
    """A digest ACK adds an identity; protected reads still return NOAUTH.

    This is an inconclusive-password control, not an explicit credential
    rejection. The detection-only byte corpus remains independent/unchanged.
    """

    def _frame(data: bytes) -> bytes:
        return struct.pack(">i", len(data)) + data

    if initial in {b"srvr", b"stat", b"mntr", b"isro"}:
        return (yield from detection_steps(product, initial, message))
    length = struct.unpack(">i", initial)[0]
    if not 28 <= length <= 65536:
        raise ValueError("invalid ZooKeeper ConnectRequest length")
    connect = yield Read(length)
    password_length = struct.unpack(">i", connect[24:28])[0]
    if (
        struct.unpack(">i", connect[:4])[0] != 0
        or password_length < 0
        or len(connect) not in {28 + password_length, 29 + password_length}
    ):
        raise ValueError("malformed ZooKeeper ConnectRequest")
    yield Write(_frame(struct.pack(">iiqi", 0, 30000, 1, 16) + b"passwordpassword" + b"\0"))
    username = password = None
    while True:
        size = struct.unpack(">i", (yield Read(4)))[0]
        if not 8 <= size <= 65536:
            raise ValueError("invalid ZooKeeper request length")
        request = yield Read(size)
        xid, opcode = struct.unpack(">ii", request[:8])
        if opcode == -11:
            if len(request) != 8:
                raise ValueError("malformed CloseSession")
            message("zk_opcode_-11")
            return True
        if opcode == 100:
            if len(request) < 20 or xid != -4 or struct.unpack(">i", request[8:12])[0] != 0:
                raise ValueError("malformed ZooKeeper auth header")
            scheme_length = struct.unpack(">i", request[12:16])[0]
            offset = 16 + scheme_length
            if scheme_length < 0 or offset + 4 > len(request) or request[16:offset] != b"digest":
                raise ValueError("unsupported or malformed ZooKeeper auth scheme")
            auth_length = struct.unpack(">i", request[offset : offset + 4])[0]
            data = request[offset + 4 :]
            if auth_length < 0 or auth_length != len(data) or b":" not in data:
                raise ValueError("malformed ZooKeeper digest identity")
            username, password = data.decode("utf-8", errors="strict").split(":", 1)
            message("zk_opcode_100")
            message("zk_digest_identity")
            if observer is not None:
                observer("digest_ack", username, password, None, 0)
            yield Write(_frame(struct.pack(">iqi", xid, 1, 0)))
        elif opcode in {3, 4, 8, 12}:
            if len(request) < 13:
                raise ValueError("truncated ZooKeeper read request")
            path_length = struct.unpack(">i", request[8:12])[0]
            if path_length < 1 or len(request) != 13 + path_length or request[-1] not in {0, 1}:
                raise ValueError("malformed ZooKeeper read path/watch")
            path = request[12:-1].decode("utf-8", errors="strict")
            if not path.startswith("/"):
                raise ValueError("invalid ZooKeeper read path")
            message("zk_opcode_" + str(opcode))
            if observer is not None:
                observer("read", username, password, path, -102)
            yield Write(_frame(struct.pack(">iqi", xid, 1, -102)))
        elif opcode == 11 and len(request) == 8:
            message("zk_opcode_11")
            yield Write(_frame(struct.pack(">iqi", xid, 1, 0)))
        else:
            raise ValueError("unsupported ZooKeeper credential fixture request")


NATIVE_PRODUCTS = frozenset(
    {"clickhouse", "postgres", "redis", "oracle", "kafka", "keeper", "zookeeper", "mongodb", "grpc"}
)


def detection_steps(product: str, initial: bytes, message: Callable[[str], None]) -> WireProgram:
    """Wire-equivalent program for the independent fingerprint corpus.

    Keep tests.test_network_fingerprint_matrix._native_response as the separate
    byte-parity oracle. This program never asserts that auth is supported for
    products whose historical fixture only describes detection.
    """
    from tests.test_network_fingerprint_matrix import _frame, _var_string

    if product == "clickhouse":
        yield Write(
            b"\x02"
            + struct.pack("<i", 516)
            + _var_string("DB::Exception")
            + _var_string("Authentication failed: password is incorrect")
            + b"\x00\x00"
        )
        return True
    if product == "postgres":
        if initial == struct.pack(">i", 8):
            yield Read(4)
            message("sslrequest")
            yield Write(b"N")
            initial = yield Read(4)
        yield Read(struct.unpack(">i", initial)[0] - 4)
        message("startup")
        yield Write(b"R" + struct.pack(">ii", 12, 5) + b"salt")
        return True
    if product == "redis":
        yield Write(b"+PONG\r\n")
        while (yield ReadSome(4096)):
            body = b"# Server\r\nredis_version:7.0.3\r\n"
            yield Write(f"${len(body)}\r\n".encode() + body + b"\r\n")
        return True
    if product == "oracle":
        yield Read(struct.unpack(">H", initial[:2])[0] - 4)
        body = b"\x00\x00(DESCRIPTION=(ERR=0)(VERSION=TNSLSNR for Linux: Version 23.6.0.0.0)(SERVICE_NAME=FREEPDB1))"
        yield Write(struct.pack(">HHBBH", 8 + len(body), 0, 6, 0, 0) + body)
        return True
    if product == "kafka":
        while True:
            request = yield Read(struct.unpack(">i", initial)[0])
            api, _version, correlation = struct.unpack(">hhi", request[:8])
            message("kafka_api_" + str(api))
            if api == 18:
                body = struct.pack(">ihi", correlation, 0, 3) + b"".join(
                    struct.pack(">hhh", key, 0, maximum) for key, maximum in [(18, 0), (3, 0), (1, 0)]
                )
            elif api == 3:
                body = struct.pack(">iiii", correlation, 0, 0, 0)
            else:
                return True
            yield Write(_frame(body))
            initial = yield Read(4)
    if product in {"keeper", "zookeeper"}:
        if initial in {b"srvr", b"stat", b"mntr", b"isro"}:
            version = (
                "ClickHouse Keeper version: 24.8.14.39"
                if product == "keeper"
                else "Zookeeper version: 3.9.5-abc123, built on 2025-01-01"
            )
            yield Write((version + "\nMode: standalone\n").encode())
            return True
        yield Read(struct.unpack(">i", initial)[0])
        yield Write(_frame(struct.pack(">iiqi", 0, 30000, 1, 16) + b"passwordpassword" + b"\x00"))
        while True:
            size = struct.unpack(">i", (yield Read(4)))[0]
            request = yield Read(size)
            xid, opcode = struct.unpack(">ii", request[:8])
            message("zk_opcode_" + str(opcode))
            if opcode == -11:
                return True
            yield Write(_frame(struct.pack(">iqi", xid, 1, -102)))
    if product == "mongodb":
        from bson import BSON

        while True:
            length = struct.unpack("<i", initial)[0]
            request_id, _response_to, opcode = struct.unpack("<iii", (yield Read(12)))
            request = yield Read(length - 16)
            if opcode == 2004:
                start = request.index(b"\x00", 4) + 9
                command = BSON(request[start:]).decode()
            elif opcode == 2013:
                command = BSON(request[5:]).decode()
            else:
                return True
            document: dict[str, Any]
            name = next(iter(command)).lower()
            message(name)
            if name in {"hello", "ismaster"}:
                document = {
                    "ok": 1.0,
                    "ismaster": True,
                    "isWritablePrimary": True,
                    "minWireVersion": 0,
                    "maxWireVersion": 21,
                    "maxBsonObjectSize": 16777216,
                    "maxMessageSizeBytes": 48000000,
                    "maxWriteBatchSize": 100000,
                }
            elif name == "buildinfo":
                document = {"ok": 1.0, "version": "7.0.14", "versionArray": [7, 0, 14, 0]}
            elif name == "listdatabases":
                document = {"ok": 1.0, "databases": [], "totalSize": 0}
            else:
                document = {"ok": 0.0, "code": 13, "errmsg": "not authorized"}
            encoded = BSON.encode(document)
            payload = (
                struct.pack("<iqii", 0, 0, 0, 1) + encoded if opcode == 2004 else struct.pack("<iB", 0, 0) + encoded
            )
            response_opcode = 1 if opcode == 2004 else 2013
            yield Write(struct.pack("<iiii", 16 + len(payload), 1, request_id, response_opcode) + payload)
            initial = yield Read(4)
    if product == "grpc":
        return (yield from _grpc_steps(initial, message, status=12))
    raise ValueError("unsupported native fixture")


def _grpc_steps(
    initial: bytes, message: Callable[[str], None], *, status: int, observer: GrpcObserver | None = None
) -> WireProgram:
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import DataReceived, RequestReceived, StreamEnded, StreamReset

    connection = H2Connection(config=H2Configuration(client_side=False))
    connection.initiate_connection()
    yield Write(connection.data_to_send())
    pending: dict[int, list[tuple[bytes, bytes]] | None] = {}
    data = initial
    while data:
        for event in connection.receive_data(data):
            if isinstance(event, RequestReceived) and observer is not None:
                selected = [
                    (name, value) for name, value in event.headers if name in {b":method", b":path", b"authorization"}
                ]
                if len(pending) >= 128:
                    observer(None, status)
                else:
                    pending[event.stream_id] = selected if all(len(value) <= 1024 for _, value in selected) else None
            elif isinstance(event, StreamReset):
                pending.pop(event.stream_id, None)
            elif isinstance(event, DataReceived):
                connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            elif isinstance(event, StreamEnded):
                if observer is not None:
                    observer(pending.pop(event.stream_id, None), status)
                message("grpc_call")
                connection.send_headers(event.stream_id, [(":status", "200"), ("content-type", "application/grpc")])
                connection.send_headers(event.stream_id, [("grpc-status", str(status))], end_stream=True)
        yield Write(connection.data_to_send())
        data = yield ReadSome(65536)
    return True


def serve_detection_response(product: str, sock: socket.socket, initial: bytes, message: Callable[[str], None]) -> None:
    drive_wire_steps(detection_steps(product, initial, message), sock)
