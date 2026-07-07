"""Kafka protocol client helpers."""

from __future__ import annotations

import socket
import ssl
import struct
from typing import Any

from . import transport

KAFKA_CLIENT_ID = "redposture"
KAFKA_API_VERSIONS = 18
KAFKA_METADATA = 3
KAFKA_FETCH = 1
KAFKA_LIST_OFFSETS = 2
KAFKA_SASL_HANDSHAKE = 17
KAFKA_SASL_AUTHENTICATE = 36
KAFKA_AUTH_ERROR_CODES = {29, 31, 58}
KAFKA_MAX_FRAME = 16 * 1024 * 1024
KAFKA_FETCH_MAX_BYTES = 1024 * 1024
_KAFKA_DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("kafka", "kafka"),
    ("kafka", "password"),
)

# Connection-error classification + framed reads are shared via the transport layer.
_is_connection_refused_error = transport.is_connection_refused
_is_connection_timeout_error = transport.is_connection_timeout
_is_connection_refused_fail_record = transport.is_connection_refused_fail_record
_recv_exact = transport.recv_exact


class _TlsProbeError(Exception):
    """Raised when a plaintext-read yields a TLS record prelude.

    Signals the caller to close the socket, re-open it wrapped in TLS, and
    replay the Kafka protocol from ApiVersions. Kept as a distinct exception
    (not `ValueError`) so plain framing errors stay distinguishable from
    "listener is TLS, retry with wrap_socket".
    """


def _is_tls_record_prelude(raw: bytes) -> bool:
    """Return True if `raw` looks like the first bytes of a TLS record header.

    TLS record types: 0x14 ChangeCipherSpec, 0x15 Alert, 0x16 Handshake,
    0x17 ApplicationData. Second byte is the TLS major version (always 0x03
    for TLS 1.0-1.3 at the record layer); third byte is the minor version
    (0x00-0x04 in practice). Kafka frame lengths never look like this — a
    valid Kafka response of ~350 MiB would exceed `KAFKA_MAX_FRAME` and be
    rejected anyway.
    """
    if len(raw) < 3:
        return False
    return raw[0] in (0x14, 0x15, 0x16, 0x17) and raw[1] == 0x03 and raw[2] in (0x00, 0x01, 0x02, 0x03, 0x04)


def open_kafka_socket(
    host: str,
    port: int,
    timeout: float,
    *,
    use_tls: bool | None = None,
) -> tuple[socket.socket, str]:
    """Open a TCP (or TLS-wrapped) socket to a Kafka broker.

    Returns `(sock, transport_mode)` where transport_mode is `"plaintext"` or
    `"tls"`. When `use_tls is None`, the well-known SASL_SSL port 9093 is
    treated as TLS by default; all other ports open plaintext and rely on
    the caller catching `_TlsProbeError` from `_recv_kafka_frame` to retry.

    Uses `check_hostname=False` + `verify_mode=CERT_NONE` — audit tool posture
    (recon over self-signed brokers is the common case). Mirrors
    `_open_grpc_socket` in `redposture_core/clients/grpc.py`.
    """
    resolved = use_tls if use_tls is not None else (port == 9093)
    base = socket.create_connection((host, port), timeout=timeout)
    base.settimeout(timeout)
    if not resolved:
        return base, "plaintext"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        wrapped = ctx.wrap_socket(base, server_hostname=host)
        wrapped.settimeout(timeout)
    except BaseException:
        base.close()
        raise
    return wrapped, "tls"


def _clip(text: str, width: int = 64) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _build_credential_runs(
    username: str | None,
    password: str | None,
    defcreds: bool,
) -> list[tuple[str | None, str | None]]:
    runs: list[tuple[str | None, str | None]] = []
    seen: set[tuple[str | None, str | None]] = set()
    if username is not None and password is not None:
        pair = (username, password)
        runs.append(pair)
        seen.add(pair)
    if defcreds:
        for user, secret in _KAFKA_DEFAULT_CREDENTIALS:
            pair = (user, secret)
            if pair in seen:
                continue
            runs.append(pair)
            seen.add(pair)
    return runs or [(username, password)]


def _friendly_error_text(value: str) -> str:
    from ..utils import friendly_error_text

    return friendly_error_text(value)


def _friendly_error_from_exception(exc: BaseException) -> str:
    from ..utils import friendly_error_from_exception

    return friendly_error_from_exception(exc)


def _is_suppressed_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail"


def _kafka_error_name(code: int) -> str:
    # Kafka wire-protocol error codes from `Errors.java`. Extended progressively:
    # the audit path historically only mapped the auth/version subset because
    # every other outcome funnels into a single "detected" success. NOT_LEADER
    # (code 6) shows up when we probe a partition whose leader is on another
    # broker (multi-broker cluster) and we haven't yet re-connected to it —
    # the correct fix is a partition-aware Metadata refresh, which is a
    # separate feature; here we just make the log line self-explanatory.
    names = {
        0: "NO_ERROR",
        1: "OFFSET_OUT_OF_RANGE",
        3: "UNKNOWN_TOPIC_OR_PARTITION",
        5: "LEADER_NOT_AVAILABLE",
        6: "NOT_LEADER_OR_FOLLOWER",
        7: "REQUEST_TIMED_OUT",
        9: "REPLICA_NOT_AVAILABLE",
        13: "NETWORK_EXCEPTION",
        29: "TOPIC_AUTHORIZATION_FAILED",
        31: "CLUSTER_AUTHORIZATION_FAILED",
        33: "UNSUPPORTED_SASL_MECHANISM",
        35: "UNSUPPORTED_VERSION",
        57: "SECURITY_DISABLED",
        58: "SASL_AUTHENTICATION_FAILED",
    }
    return names.get(code, f"ERR_{code}")


def _is_probable_auth_error(message: str | None, error_codes: list[int] | None = None) -> bool:
    if error_codes and any(code in KAFKA_AUTH_ERROR_CODES for code in error_codes):
        return True
    text = str(message or "").lower()
    needles = (
        "authentication",
        "sasl",
        "authorization",
        "not authorized",
    )
    return any(needle in text for needle in needles)


def _is_sasl_probe_candidate(message: str | None) -> bool:
    text = str(message or "").strip().lower()
    if not text:
        return False
    needles = (
        "unexpected eof",
        "connection reset",
        "connection aborted",
        "broken pipe",
        "forcibly closed",
        "end of file",
    )
    return any(needle in text for needle in needles)


def _recv_kafka_frame(sock: socket.socket) -> bytes:
    raw_size = _recv_exact(sock, 4)
    if _is_tls_record_prelude(raw_size):
        raise _TlsProbeError(f"plaintext read returned TLS record prelude: {raw_size!r}")
    (frame_size,) = struct.unpack(">i", raw_size)
    if frame_size <= 0 or frame_size > KAFKA_MAX_FRAME:
        raise ValueError(f"invalid Kafka frame size {frame_size}")
    return _recv_exact(sock, frame_size)


def _encode_kafka_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    if len(raw) > 32767:
        raise ValueError("Kafka string exceeds int16 length")
    return struct.pack(">h", len(raw)) + raw


def _encode_kafka_nullable_string(value: str | None) -> bytes:
    if value is None:
        return struct.pack(">h", -1)
    return _encode_kafka_string(value)


def _encode_kafka_bytes(value: bytes) -> bytes:
    return struct.pack(">i", len(value)) + value


def _build_request_header(api_key: int, api_version: int, correlation_id: int, client_id: str) -> bytes:
    return (
        struct.pack(">hh", int(api_key), int(api_version))
        + struct.pack(">i", int(correlation_id))
        + _encode_kafka_string(client_id)
    )


def _send_kafka_request(
    sock: socket.socket,
    *,
    api_key: int,
    api_version: int,
    correlation_id: int,
    client_id: str,
    body: bytes = b"",
) -> bytes:
    frame = _build_request_header(api_key, api_version, correlation_id, client_id) + body
    sock.sendall(struct.pack(">i", len(frame)) + frame)
    return _recv_kafka_frame(sock)


class _KafkaReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def remaining(self) -> int:
        return len(self._data) - self._pos

    def _read(self, size: int) -> bytes:
        if size < 0:
            raise ValueError("negative read size")
        end = self._pos + size
        if end > len(self._data):
            raise ValueError("unexpected EOF while parsing Kafka response")
        chunk = self._data[self._pos : end]
        self._pos = end
        return chunk

    def read_i16(self) -> int:
        return struct.unpack(">h", self._read(2))[0]

    def read_i8(self) -> int:
        return struct.unpack(">b", self._read(1))[0]

    def read_i32(self) -> int:
        return struct.unpack(">i", self._read(4))[0]

    def read_i64(self) -> int:
        return struct.unpack(">q", self._read(8))[0]

    def read_string(self, *, nullable: bool = False) -> str | None:
        size = self.read_i16()
        if size < 0:
            if nullable:
                return None
            raise ValueError("Kafka non-nullable string is null")
        return self._read(size).decode("utf-8", errors="replace")

    def read_bytes(self, *, nullable: bool = False) -> bytes | None:
        size = self.read_i32()
        if size < 0:
            if nullable:
                return None
            raise ValueError("Kafka non-nullable bytes is null")
        return self._read(size)

    def skip_i32_array(self) -> None:
        count = self.read_i32()
        if count < 0:
            return
        self._read(4 * count)

    def read_string_array(self) -> list[str]:
        count = self.read_i32()
        if count < 0:
            return []
        result: list[str] = []
        for _ in range(count):
            value = self.read_string(nullable=False)
            result.append(str(value))
        return result


def _parse_apiversions_response(payload: bytes, expected_correlation_id: int) -> tuple[bool, int | None, str | None]:
    try:
        reader = _KafkaReader(payload)
        correlation_id = reader.read_i32()
        if correlation_id != expected_correlation_id:
            return False, None, f"unexpected correlation id {correlation_id} (expected {expected_correlation_id})"

        error_code = reader.read_i16()
        if reader.remaining() >= 4:
            count = reader.read_i32()
            if count >= 0:
                for _ in range(count):
                    if reader.remaining() < 6:
                        return False, error_code, "invalid ApiVersions entry payload"
                    _ = reader.read_i16()
                    _ = reader.read_i16()
                    _ = reader.read_i16()
        return True, int(error_code), None
    except (ValueError, struct.error) as exc:
        return False, None, f"invalid ApiVersions response: {exc}"


def _parse_metadata_response(
    payload: bytes,
    expected_correlation_id: int,
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        reader = _KafkaReader(payload)
        correlation_id = reader.read_i32()
        if correlation_id != expected_correlation_id:
            return None, f"unexpected correlation id {correlation_id} (expected {expected_correlation_id})"

        broker_count = reader.read_i32()
        if broker_count < 0:
            return None, "invalid broker array size"
        # `broker_map` is what makes partition-aware routing possible: on
        # multi-broker clusters each partition's leader can live on a
        # different broker, and ListOffsets/Fetch requests must go to that
        # specific leader (otherwise the broker returns NOT_LEADER_OR_FOLLOWER
        # = error code 6). Previously we discarded these fields entirely
        # and paid for it with cryptic dump failures on real clusters.
        broker_map: dict[int, tuple[str, int]] = {}
        for _ in range(broker_count):
            broker_node_id = reader.read_i32()
            broker_host = reader.read_string(nullable=False) or ""
            broker_port = reader.read_i32()
            if broker_host:
                broker_map[int(broker_node_id)] = (broker_host, int(broker_port))

        topic_count_raw = reader.read_i32()
        if topic_count_raw < 0:
            return None, "invalid topic metadata array size"

        topic_map: dict[str, int] = {}
        topic_errors: dict[str, int] = {}
        all_error_codes: list[int] = []
        accessible_topics = 0
        partition_leaders: dict[str, dict[int, int]] = {}

        for _ in range(topic_count_raw):
            topic_error = reader.read_i16()
            topic_name = reader.read_string(nullable=False) or ""
            partition_count_raw = reader.read_i32()
            partition_count = 0 if partition_count_raw < 0 else partition_count_raw
            all_error_codes.append(int(topic_error))

            topic_partition_leaders: dict[int, int] = {}
            for _ in range(partition_count):
                partition_error = reader.read_i16()
                partition_id = reader.read_i32()
                leader_id = reader.read_i32()
                reader.skip_i32_array()  # replicas
                reader.skip_i32_array()  # isr
                all_error_codes.append(int(partition_error))
                if leader_id >= 0:
                    topic_partition_leaders[int(partition_id)] = int(leader_id)

            if topic_name:
                topic_map[topic_name] = partition_count
                topic_errors[topic_name] = int(topic_error)
                if topic_partition_leaders:
                    partition_leaders[topic_name] = topic_partition_leaders
            if topic_error == 0:
                accessible_topics += 1

        auth_hits = [code for code in all_error_codes if code in KAFKA_AUTH_ERROR_CODES]
        auth_required = bool(auth_hits) and accessible_topics == 0

        topics_sorted = sorted(topic_map.keys())
        return (
            {
                "topic_map": topic_map,
                "topics": topics_sorted,
                "topic_count": len(topics_sorted),
                "topic_errors": topic_errors,
                "error_codes": all_error_codes,
                "auth_required": auth_required,
                "broker_map": broker_map,
                "partition_leaders": partition_leaders,
            },
            None,
        )
    except (ValueError, struct.error) as exc:
        return None, f"invalid Metadata response: {exc}"


def _build_metadata_request_body(topics: list[str] | None) -> bytes:
    if topics is None:
        return struct.pack(">i", 0)
    encoded = [struct.pack(">i", len(topics))]
    for topic in topics:
        encoded.append(_encode_kafka_string(topic))
    return b"".join(encoded)


def _probe_apiversions(sock: socket.socket, correlation_id: int) -> tuple[bool, int | None, str | None]:
    payload = _send_kafka_request(
        sock,
        api_key=KAFKA_API_VERSIONS,
        api_version=0,
        correlation_id=correlation_id,
        client_id=KAFKA_CLIENT_ID,
        body=b"",
    )
    return _parse_apiversions_response(payload, correlation_id)


def _fetch_metadata(
    sock: socket.socket,
    correlation_id: int,
    *,
    topics: list[str] | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    payload = _send_kafka_request(
        sock,
        api_key=KAFKA_METADATA,
        api_version=0,
        correlation_id=correlation_id,
        client_id=KAFKA_CLIENT_ID,
        body=_build_metadata_request_body(topics),
    )
    return _parse_metadata_response(payload, correlation_id)


def _build_list_offsets_request_body(topic: str, partition: int, *, time_value: int = -2) -> bytes:
    return (
        struct.pack(">i", -1)
        + struct.pack(">i", 1)
        + _encode_kafka_string(topic)
        + struct.pack(">i", 1)
        + struct.pack(">i", int(partition))
        + struct.pack(">q", int(time_value))
        + struct.pack(">i", 1)
    )


def _parse_list_offsets_response(payload: bytes, expected_correlation_id: int) -> tuple[int | None, str | None]:
    try:
        reader = _KafkaReader(payload)
        correlation_id = reader.read_i32()
        if correlation_id != expected_correlation_id:
            return None, f"unexpected correlation id {correlation_id} (expected {expected_correlation_id})"

        topic_count = reader.read_i32()
        if topic_count <= 0:
            return None, "ListOffsets returned empty topic list"

        _ = reader.read_string(nullable=False) or ""
        partition_count = reader.read_i32()
        if partition_count <= 0:
            return None, "ListOffsets returned empty partition list"

        _ = reader.read_i32()
        error_code = reader.read_i16()
        if error_code != 0:
            return None, f"ListOffsets failed: {_kafka_error_name(int(error_code))}"

        offset_count = reader.read_i32()
        if offset_count <= 0:
            return None, "ListOffsets returned no offsets"

        return int(reader.read_i64()), None
    except (ValueError, struct.error) as exc:
        return None, f"invalid ListOffsets response: {exc}"


KAFKA_FETCH_API_VERSION = 4  # Kafka 0.11+; required by Kafka 4.0+ which dropped v0-v3.


def _build_fetch_request_body(
    topic: str, partition: int, offset: int, *, max_bytes: int = KAFKA_FETCH_MAX_BYTES
) -> bytes:
    # Fetch v4 wire format:
    #   replica_id (-1)             | int32
    #   max_wait_ms                 | int32
    #   min_bytes                   | int32
    #   max_bytes (whole response)  | int32  <- new in v3
    #   isolation_level             | int8   <- new in v4 (0 = READ_UNCOMMITTED)
    #   topics [                    | int32 count
    #     topic name                | string
    #     partitions [              | int32 count
    #       partition_id            | int32
    #       fetch_offset            | int64
    #       partition_max_bytes     | int32
    #     ]
    #   ]
    return (
        struct.pack(">i", -1)  # replica_id
        + struct.pack(">i", 300)  # max_wait_ms
        + struct.pack(">i", 1)  # min_bytes
        + struct.pack(">i", int(max_bytes) * 2)  # max_bytes (whole response)
        + struct.pack(">b", 0)  # isolation_level READ_UNCOMMITTED
        + struct.pack(">i", 1)  # topics count
        + _encode_kafka_string(topic)
        + struct.pack(">i", 1)  # partitions count
        + struct.pack(">i", int(partition))
        + struct.pack(">q", int(offset))
        + struct.pack(">i", int(max_bytes))
    )


def _read_unsigned_varint(reader: _KafkaReader) -> int:
    shift = 0
    result = 0
    while shift < 35:
        byte = reader.read_i8() & 0xFF
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result
        shift += 7
    raise ValueError("Kafka varint is too long")


def _read_varint(reader: _KafkaReader) -> int:
    raw = _read_unsigned_varint(reader)
    return (raw >> 1) ^ -(raw & 1)


def _read_varlong(reader: _KafkaReader) -> int:
    shift = 0
    result = 0
    while shift < 70:
        byte = reader.read_i8() & 0xFF
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return (result >> 1) ^ -(result & 1)
        shift += 7
    raise ValueError("Kafka varlong is too long")


def _read_var_bytes(reader: _KafkaReader) -> bytes | None:
    size = _read_varint(reader)
    if size < 0:
        return None
    if size > reader.remaining():
        raise ValueError("unexpected EOF while parsing Kafka varbytes")
    return reader._read(size)  # noqa: SLF001


def _skip_record_headers(reader: _KafkaReader) -> None:
    header_count = _read_varint(reader)
    if header_count < 0:
        raise ValueError("invalid Kafka record header count")
    for _ in range(header_count):
        key_size = _read_varint(reader)
        if key_size < 0 or key_size > reader.remaining():
            raise ValueError("invalid Kafka record header key size")
        reader._read(key_size)  # noqa: SLF001
        value = _read_var_bytes(reader)
        _ = value


def _parse_record_batch_entries(base_offset: int, batch: bytes, max_messages: int) -> list[tuple[int, str]]:
    items: list[tuple[int, str]] = []
    reader = _KafkaReader(batch)
    if reader.remaining() < 49:
        return items
    _ = reader.read_i32()  # partition leader epoch
    magic = reader.read_i8()
    if magic != 2:
        return items
    _ = reader.read_i32()  # crc
    attributes = reader.read_i16()
    compression = int(attributes) & 0x07
    _ = reader.read_i32()  # last offset delta
    _ = reader.read_i64()  # first timestamp
    _ = reader.read_i64()  # max timestamp
    _ = reader.read_i64()  # producer id
    _ = reader.read_i16()  # producer epoch
    _ = reader.read_i32()  # base sequence
    record_count = reader.read_i32()
    if compression:
        return items
    if record_count < 0:
        raise ValueError("invalid Kafka record batch count")

    for _ in range(record_count):
        if len(items) >= max_messages:
            break
        record_size = _read_varint(reader)
        if record_size < 0:
            raise ValueError("invalid Kafka record size")
        if record_size > reader.remaining():
            raise ValueError("unexpected EOF while parsing Kafka record")
        record_reader = _KafkaReader(reader._read(record_size))  # noqa: SLF001
        _ = record_reader.read_i8()  # attributes
        _ = _read_varlong(record_reader)  # timestamp delta
        offset_delta = _read_varint(record_reader)
        _ = _read_var_bytes(record_reader)  # key
        value = _read_var_bytes(record_reader)
        _skip_record_headers(record_reader)
        if value is None:
            continue
        decoded = value.decode("utf-8", errors="replace")
        if decoded:
            items.append((int(base_offset) + int(offset_delta), decoded))
    return items


def _parse_message_set_entries(message_set: bytes, max_messages: int) -> list[tuple[int, str]]:
    items: list[tuple[int, str]] = []
    reader = _KafkaReader(message_set)

    while reader.remaining() >= 12 and len(items) < max_messages:
        try:
            offset = reader.read_i64()
            message_size = reader.read_i32()
            if message_size <= 0 or message_size > reader.remaining():
                break

            message_body = reader._read(message_size)  # noqa: SLF001
            if len(message_body) >= 5 and message_body[4] == 2:
                items.extend(_parse_record_batch_entries(int(offset), message_body, max_messages - len(items)))
                continue

            message_reader = _KafkaReader(message_body)
            if message_reader.remaining() < 6:
                continue

            _ = message_reader.read_i32()  # crc
            magic = message_reader.read_i8()
            _ = message_reader.read_i8()  # attributes
            if magic >= 1 and message_reader.remaining() >= 8:
                _ = message_reader.read_i64()  # timestamp

            _ = message_reader.read_bytes(nullable=True)  # key
            value = message_reader.read_bytes(nullable=True)
            if value is None:
                continue

            decoded = value.decode("utf-8", errors="replace")
            if decoded:
                items.append((int(offset), decoded))
        except (ValueError, struct.error):
            break

    return items


def _parse_fetch_response(
    payload: bytes,
    expected_correlation_id: int,
    *,
    expected_partition: int,
    max_messages: int,
) -> tuple[list[tuple[int, str]] | None, str | None]:
    """Parse a Fetch v4 response.

    Wire format:
      throttle_time_ms        | int32   (v1+; v0 doesn't have this)
      topics [                | int32 count
        topic_name            | string
        partitions [          | int32 count
          partition_id        | int32
          error_code          | int16
          high_watermark      | int64
          last_stable_offset  | int64   (v4+)
          aborted_txns [      | int32 count (nullable, -1 = null)
            producer_id       | int64
            first_offset      | int64
          ]
          records_size        | int32
          records             | bytes   (record-batch v2 format)
        ]
      ]
    """
    try:
        reader = _KafkaReader(payload)
        correlation_id = reader.read_i32()
        if correlation_id != expected_correlation_id:
            return None, f"unexpected correlation id {correlation_id} (expected {expected_correlation_id})"

        _ = reader.read_i32()  # throttle_time_ms

        topic_count = reader.read_i32()
        if topic_count <= 0:
            return [], None

        for _ in range(topic_count):
            _ = reader.read_string(nullable=False) or ""
            partition_count = reader.read_i32()
            for _ in range(max(0, partition_count)):
                partition = reader.read_i32()
                error_code = reader.read_i16()
                _ = reader.read_i64()  # high_watermark
                _ = reader.read_i64()  # last_stable_offset (v4+)
                aborted_count = reader.read_i32()
                if aborted_count > 0:
                    # Skip aborted transactions: each is two int64s.
                    for _ in range(aborted_count):
                        _ = reader.read_i64()  # producer_id
                        _ = reader.read_i64()  # first_offset
                records_size = reader.read_i32()
                if records_size < 0 or records_size > reader.remaining():
                    return None, "invalid Fetch message set size"
                records = reader._read(records_size)  # noqa: SLF001

                if partition != expected_partition:
                    continue
                if error_code != 0:
                    return None, f"Fetch failed: {_kafka_error_name(int(error_code))}"
                return _parse_message_set_entries(records, max_messages), None

        return [], None
    except (ValueError, struct.error) as exc:
        return None, f"invalid Fetch response: {exc}"


def _authenticate_or_probe(
    sock: socket.socket,
    correlation: int,
    username: str | None,
    password: str | None,
) -> tuple[bool, int, str | None]:
    """Bootstrap a Kafka session on `sock`: SASL PLAIN when credentials are
    provided, otherwise a bare ApiVersions probe to confirm we're talking to
    Kafka. Returns `(ok, next_correlation_id, error)`.
    """
    if username is not None and password is not None:
        hs_ok, correlation, hs_error = _sasl_handshake_plain(sock, correlation)
        if not hs_ok:
            return False, correlation, hs_error or "SASL handshake failed"
        auth_ok, correlation, auth_error = _sasl_authenticate_plain(sock, correlation, username, password)
        if not auth_ok:
            return False, correlation, auth_error or "authentication failed"
        return True, correlation, None
    is_kafka, _api_error_code, api_error = _probe_apiversions(sock, correlation)
    correlation += 1
    if not is_kafka:
        return False, correlation, api_error or "service is not kafka"
    return True, correlation, None


def _read_partition_messages_on_leader(
    leader_sock: socket.socket,
    correlation: int,
    topic: str,
    partition: int,
    remaining: int,
) -> tuple[list[str], int, str | None]:
    """Do ListOffsets + Fetch for a single partition on the leader socket.
    Returns `(items, next_correlation, error)`. Items are `[f"p{partition}@{offset} text", ...]`.
    """
    list_offsets_payload = _send_kafka_request(
        leader_sock,
        api_key=KAFKA_LIST_OFFSETS,
        api_version=0,
        correlation_id=correlation,
        client_id=KAFKA_CLIENT_ID,
        body=_build_list_offsets_request_body(topic, partition, time_value=-2),
    )
    earliest_offset, list_offsets_error = _parse_list_offsets_response(list_offsets_payload, correlation)
    correlation += 1
    if list_offsets_error:
        return [], correlation, list_offsets_error
    if earliest_offset is None:
        return [], correlation, None

    fetch_payload = _send_kafka_request(
        leader_sock,
        api_key=KAFKA_FETCH,
        api_version=KAFKA_FETCH_API_VERSION,
        correlation_id=correlation,
        client_id=KAFKA_CLIENT_ID,
        body=_build_fetch_request_body(
            topic,
            partition,
            earliest_offset,
            max_bytes=KAFKA_FETCH_MAX_BYTES,
        ),
    )
    fetch_items, fetch_error = _parse_fetch_response(
        fetch_payload,
        correlation,
        expected_partition=partition,
        max_messages=remaining,
    )
    correlation += 1
    if fetch_error:
        return [], correlation, fetch_error
    if not fetch_items:
        return [], correlation, None
    items = [f"p{partition}@{offset} {text}" for offset, text in fetch_items[:remaining]]
    return items, correlation, None


def _read_topic_messages(
    host: str,
    port: int,
    timeout: float,
    topic: str,
    max_messages: int,
    *,
    username: str | None = None,
    password: str | None = None,
    use_tls: bool | None = None,
) -> tuple[list[str] | None, str | None, str]:
    """Read up to `max_messages` messages from `topic` across all partitions.

    Partition-aware routing: after Metadata, we group each partition by its
    leader broker (multi-broker Kafka clusters have leaders spread across
    brokers) and open a fresh connection per leader for ListOffsets + Fetch.
    Sending ListOffsets to a non-leader broker returns error code 6
    (`NOT_LEADER_OR_FOLLOWER`), which is the bug this routing fixes.

    Backward-compat: when Metadata doesn't expose broker/leader info (test
    doubles, older brokers) or when the leader hostname isn't reachable
    from the client, we fall back to running everything on the bootstrap
    socket — same as the pre-fix behavior.
    """
    if max_messages <= 0:
        return [], None, "plaintext"

    try:
        sock, transport_mode = open_kafka_socket(host, port, timeout, use_tls=use_tls)
        with sock:
            correlation = 1

            ok, correlation, session_error = _authenticate_or_probe(sock, correlation, username, password)
            if not ok:
                return None, session_error, transport_mode

            metadata, metadata_error = _fetch_metadata(sock, correlation, topics=[topic])
            correlation += 1
            if metadata is None:
                return None, metadata_error or "metadata request failed", transport_mode

            topic_map = dict(metadata.get("topic_map") or {})
            if topic not in topic_map:
                return [], None, transport_mode

            partition_count = int(topic_map.get(topic) or 0)
            if partition_count <= 0:
                return [], None, transport_mode

            broker_map: dict[int, tuple[str, int]] = dict(metadata.get("broker_map") or {})
            topic_leaders: dict[int, int] = dict((metadata.get("partition_leaders") or {}).get(topic, {}))

            # Group partitions by their leader broker so we open one
            # connection per leader instead of hammering the bootstrap
            # broker with requests it can't serve.
            partitions_by_leader: dict[int, list[int]] = {}
            unassigned_partitions: list[int] = []
            for partition in range(partition_count):
                leader_id = topic_leaders.get(partition)
                if leader_id is None or leader_id not in broker_map:
                    unassigned_partitions.append(partition)
                    continue
                partitions_by_leader.setdefault(leader_id, []).append(partition)

            out: list[str] = []
            fatal_error: str | None = None

            def _handle_partitions(leader_sock: socket.socket, partitions: list[int], corr_start: int) -> int:
                nonlocal fatal_error
                corr = corr_start
                for partition in partitions:
                    if len(out) >= max_messages:
                        break
                    items, corr, err = _read_partition_messages_on_leader(
                        leader_sock, corr, topic, partition, max_messages - len(out)
                    )
                    if err:
                        # First partition failure with no data accumulated
                        # is a fatal error for the whole read; subsequent
                        # failures are recorded silently so a single bad
                        # partition doesn't kill the whole dump.
                        if not out and fatal_error is None:
                            fatal_error = err
                        continue
                    out.extend(items)
                return corr

            # 1) Per-leader connections for partitions with a known leader.
            for leader_id, partitions in partitions_by_leader.items():
                if len(out) >= max_messages:
                    break
                leader_host, leader_port = broker_map[leader_id]
                # Bootstrap-broker shortcut: if the leader IS the broker
                # we already talk to, reuse the existing socket instead of
                # spinning up a new connection.
                if (
                    (leader_host, leader_port) == (host, port)
                    or leader_host in ("", "localhost", "127.0.0.1")
                    and leader_port == port
                ):
                    correlation = _handle_partitions(sock, partitions, correlation)
                    continue
                try:
                    leader_sock, _leader_transport = open_kafka_socket(
                        leader_host, leader_port, timeout, use_tls=(transport_mode == "tls") or None
                    )
                except (TimeoutError, ConnectionError, OSError):
                    # Leader broker unreachable from the auditor's network
                    # (common for advertised-DNS-only clusters). Fall back
                    # to attempting on the bootstrap socket so we at least
                    # try; the broker will reject with NOT_LEADER but the
                    # caller sees a per-partition error, not a total fail.
                    correlation = _handle_partitions(sock, partitions, correlation)
                    continue
                try:
                    leader_corr = 1
                    ok, leader_corr, leader_session_error = _authenticate_or_probe(
                        leader_sock, leader_corr, username, password
                    )
                    if not ok:
                        if not out and fatal_error is None:
                            fatal_error = f"leader {leader_host}:{leader_port} auth failed: {leader_session_error}"
                        continue
                    _handle_partitions(leader_sock, partitions, leader_corr)
                finally:
                    try:
                        leader_sock.close()
                    except OSError:
                        pass

            # 2) Partitions without a known leader / broker_map miss:
            #    fall back to the bootstrap socket (best-effort).
            if unassigned_partitions and len(out) < max_messages:
                correlation = _handle_partitions(sock, unassigned_partitions, correlation)

            if not out and fatal_error is not None:
                return None, fatal_error, transport_mode
            return out, None, transport_mode
    except _TlsProbeError:
        if use_tls is True:
            return None, "plaintext read returned TLS record prelude", "tls"
        return _read_topic_messages(
            host,
            port,
            timeout,
            topic,
            max_messages,
            username=username,
            password=password,
            use_tls=True,
        )
    except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
        return None, _friendly_error_from_exception(exc), "plaintext" if use_tls is not True else "tls"


def _sasl_handshake_plain(sock: socket.socket, correlation_id: int) -> tuple[bool, int, str | None]:
    versions = (1, 0)
    for version in versions:
        payload = _send_kafka_request(
            sock,
            api_key=KAFKA_SASL_HANDSHAKE,
            api_version=version,
            correlation_id=correlation_id,
            client_id=KAFKA_CLIENT_ID,
            body=_encode_kafka_string("PLAIN"),
        )
        try:
            reader = _KafkaReader(payload)
            response_corr = reader.read_i32()
            if response_corr != correlation_id:
                return (
                    False,
                    correlation_id + 1,
                    f"unexpected correlation id {response_corr} (expected {correlation_id})",
                )
            error_code = reader.read_i16()
            if error_code == 35:
                continue
            if error_code != 0:
                return False, correlation_id + 1, f"SASL handshake failed: {_kafka_error_name(int(error_code))}"
            _ = reader.read_string_array()
            return True, correlation_id + 1, None
        except (ValueError, struct.error) as exc:
            return False, correlation_id + 1, f"invalid SASL handshake response: {exc}"
    return False, correlation_id + 1, "SASL handshake failed: UNSUPPORTED_VERSION"


def _sasl_authenticate_plain(
    sock: socket.socket, correlation_id: int, username: str, password: str
) -> tuple[bool, int, str | None]:
    auth_bytes = b"\x00" + username.encode("utf-8") + b"\x00" + password.encode("utf-8")

    # Preferred modern flow: SASL_AUTHENTICATE request.
    try:
        payload = _send_kafka_request(
            sock,
            api_key=KAFKA_SASL_AUTHENTICATE,
            api_version=0,
            correlation_id=correlation_id,
            client_id=KAFKA_CLIENT_ID,
            body=_encode_kafka_bytes(auth_bytes),
        )
        reader = _KafkaReader(payload)
        response_corr = reader.read_i32()
        if response_corr != correlation_id:
            return False, correlation_id + 1, f"unexpected correlation id {response_corr} (expected {correlation_id})"
        error_code = reader.read_i16()
        error_message = reader.read_string(nullable=True)
        _ = reader.read_bytes(nullable=True)
        if reader.remaining() >= 8:
            _ = reader.read_i64()
        if error_code == 0:
            return True, correlation_id + 1, None
        if error_code != 35:
            detail = (
                error_message.strip()
                if isinstance(error_message, str) and error_message.strip()
                else _kafka_error_name(int(error_code))
            )
            return False, correlation_id + 1, f"SASL auth failed: {detail}"
    except (TimeoutError, ValueError, struct.error, ConnectionError, OSError):
        pass

    # Legacy fallback: raw SASL bytes over size-prefixed frame.
    try:
        sock.sendall(struct.pack(">i", len(auth_bytes)) + auth_bytes)
    except OSError as exc:
        return False, correlation_id, _friendly_error_from_exception(exc)

    previous_timeout = sock.gettimeout()
    probe_timeout = min(float(previous_timeout or 1.0), 0.40)
    try:
        sock.settimeout(probe_timeout)
        prefix = sock.recv(4)
        if prefix:
            while len(prefix) < 4:
                chunk = sock.recv(4 - len(prefix))
                if not chunk:
                    break
                prefix += chunk
            if len(prefix) == 4:
                (frame_size,) = struct.unpack(">i", prefix)
                if frame_size > 0 and frame_size <= 8192:
                    body = _recv_exact(sock, frame_size)
                    text = body.decode("utf-8", errors="replace")
                    if _is_probable_auth_error(text):
                        return False, correlation_id, _clip(text, 96)
    except TimeoutError:
        pass
    except (ConnectionError, OSError, ValueError):
        # Some brokers may close the socket on auth failure; metadata verification below will fail.
        pass
    finally:
        try:
            sock.settimeout(previous_timeout)
        except OSError:
            pass

    return True, correlation_id, None


def _authenticate_and_fetch_metadata(
    host: str,
    port: int,
    timeout: float,
    username: str,
    password: str,
    *,
    use_tls: bool | None = None,
) -> tuple[bool, dict[str, Any] | None, str | None, str]:
    try:
        sock, transport_mode = open_kafka_socket(host, port, timeout, use_tls=use_tls)
        with sock:
            correlation = 1
            is_kafka, _api_error_code, api_error = _probe_apiversions(sock, correlation)
            correlation += 1
            if not is_kafka:
                return False, None, api_error or "service is not kafka", transport_mode

            hs_ok, correlation, hs_error = _sasl_handshake_plain(sock, correlation)
            if not hs_ok:
                return False, None, hs_error or "SASL handshake failed", transport_mode

            auth_ok, correlation, auth_error = _sasl_authenticate_plain(sock, correlation, username, password)
            if not auth_ok:
                return False, None, auth_error or "authentication failed", transport_mode

            metadata, metadata_error = _fetch_metadata(sock, correlation, topics=None)
            if metadata is None:
                return False, None, metadata_error or "metadata request failed after auth", transport_mode
            if bool(metadata.get("auth_required")):
                return False, None, "authentication failed", transport_mode
            return True, metadata, None, transport_mode
    except _TlsProbeError:
        if use_tls is True:
            return False, None, "plaintext read returned TLS record prelude", "tls"
        return _authenticate_and_fetch_metadata(host, port, timeout, username, password, use_tls=True)
    except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
        return (
            False,
            None,
            _friendly_error_from_exception(exc),
            "plaintext" if use_tls is not True else "tls",
        )


def _read_dump_topics(
    *,
    host: str,
    port: int,
    timeout: float,
    topics: list[str],
    max_messages: int,
    username: str | None,
    password: str | None,
    use_tls: bool | None = None,
) -> tuple[dict[str, list[str] | None], dict[str, str]]:
    dump_results: dict[str, list[str] | None] = {}
    dump_errors: dict[str, str] = {}
    for topic_name in topics:
        read_items, read_error, _transport = _read_topic_messages(
            host=host,
            port=port,
            timeout=timeout,
            topic=topic_name,
            max_messages=max_messages,
            username=username,
            password=password,
            use_tls=use_tls,
        )
        dump_results[topic_name] = read_items
        if read_error:
            dump_errors[topic_name] = read_error
    return dump_results, dump_errors
