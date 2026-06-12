"""Kafka protocol client helpers."""

from __future__ import annotations

import socket
import struct
from typing import Any

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
_CONNECTION_REFUSED_PREFIX = "connection refused"
_CONNECTION_TIMEOUT_PREFIX = "connection timeout"
_KAFKA_DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("kafka", "kafka"),
    ("kafka", "password"),
)


def open_kafka_socket(host: str, port: int, timeout: float) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock


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


def _is_connection_refused_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and text.startswith(_CONNECTION_REFUSED_PREFIX)


def _is_connection_refused_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail" and _is_connection_refused_error(record.get("error"))


def _is_connection_timeout_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and text.startswith(_CONNECTION_TIMEOUT_PREFIX)


def _is_suppressed_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail"


def _kafka_error_name(code: int) -> str:
    names = {
        0: "NO_ERROR",
        7: "REQUEST_TIMED_OUT",
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


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data += chunk
    return data


def _recv_kafka_frame(sock: socket.socket) -> bytes:
    raw_size = _recv_exact(sock, 4)
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
        for _ in range(broker_count):
            _ = reader.read_i32()
            _ = reader.read_string(nullable=False)
            _ = reader.read_i32()

        topic_count_raw = reader.read_i32()
        if topic_count_raw < 0:
            return None, "invalid topic metadata array size"

        topic_map: dict[str, int] = {}
        topic_errors: dict[str, int] = {}
        all_error_codes: list[int] = []
        accessible_topics = 0

        for _ in range(topic_count_raw):
            topic_error = reader.read_i16()
            topic_name = reader.read_string(nullable=False) or ""
            partition_count_raw = reader.read_i32()
            partition_count = 0 if partition_count_raw < 0 else partition_count_raw
            all_error_codes.append(int(topic_error))

            for _ in range(partition_count):
                partition_error = reader.read_i16()
                _ = reader.read_i32()
                _ = reader.read_i32()
                reader.skip_i32_array()
                reader.skip_i32_array()
                all_error_codes.append(int(partition_error))

            if topic_name:
                topic_map[topic_name] = partition_count
                topic_errors[topic_name] = int(topic_error)
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


def _build_fetch_request_body(
    topic: str, partition: int, offset: int, *, max_bytes: int = KAFKA_FETCH_MAX_BYTES
) -> bytes:
    return (
        struct.pack(">i", -1)
        + struct.pack(">i", 300)
        + struct.pack(">i", 1)
        + struct.pack(">i", 1)
        + _encode_kafka_string(topic)
        + struct.pack(">i", 1)
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
    try:
        reader = _KafkaReader(payload)
        correlation_id = reader.read_i32()
        if correlation_id != expected_correlation_id:
            return None, f"unexpected correlation id {correlation_id} (expected {expected_correlation_id})"

        topic_count = reader.read_i32()
        if topic_count <= 0:
            return [], None

        for _ in range(topic_count):
            _ = reader.read_string(nullable=False) or ""
            partition_count = reader.read_i32()
            for _ in range(max(0, partition_count)):
                partition = reader.read_i32()
                error_code = reader.read_i16()
                _ = reader.read_i64()  # high watermark
                message_set_size = reader.read_i32()
                if message_set_size < 0 or message_set_size > reader.remaining():
                    return None, "invalid Fetch message set size"
                message_set = reader._read(message_set_size)  # noqa: SLF001

                if partition != expected_partition:
                    continue
                if error_code != 0:
                    return None, f"Fetch failed: {_kafka_error_name(int(error_code))}"
                return _parse_message_set_entries(message_set, max_messages), None

        return [], None
    except (ValueError, struct.error) as exc:
        return None, f"invalid Fetch response: {exc}"


def _read_topic_messages(
    host: str,
    port: int,
    timeout: float,
    topic: str,
    max_messages: int,
    *,
    username: str | None = None,
    password: str | None = None,
) -> tuple[list[str] | None, str | None]:
    if max_messages <= 0:
        return [], None

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            correlation = 1

            if username is not None and password is not None:
                hs_ok, correlation, hs_error = _sasl_handshake_plain(sock, correlation)
                if not hs_ok:
                    return None, hs_error or "SASL handshake failed"
                auth_ok, correlation, auth_error = _sasl_authenticate_plain(sock, correlation, username, password)
                if not auth_ok:
                    return None, auth_error or "authentication failed"
            else:
                is_kafka, _api_error_code, api_error = _probe_apiversions(sock, correlation)
                correlation += 1
                if not is_kafka:
                    return None, api_error or "service is not kafka"

            metadata, metadata_error = _fetch_metadata(sock, correlation, topics=[topic])
            correlation += 1
            if metadata is None:
                return None, metadata_error or "metadata request failed"

            topic_map = dict(metadata.get("topic_map") or {})
            if topic not in topic_map:
                return [], None

            partition_count = int(topic_map.get(topic) or 0)
            if partition_count <= 0:
                return [], None

            out: list[str] = []
            for partition in range(partition_count):
                if len(out) >= max_messages:
                    break

                list_offsets_payload = _send_kafka_request(
                    sock,
                    api_key=KAFKA_LIST_OFFSETS,
                    api_version=0,
                    correlation_id=correlation,
                    client_id=KAFKA_CLIENT_ID,
                    body=_build_list_offsets_request_body(topic, partition, time_value=-2),
                )
                earliest_offset, list_offsets_error = _parse_list_offsets_response(list_offsets_payload, correlation)
                correlation += 1
                if list_offsets_error:
                    if not out:
                        return None, list_offsets_error
                    continue
                if earliest_offset is None:
                    continue

                fetch_payload = _send_kafka_request(
                    sock,
                    api_key=KAFKA_FETCH,
                    api_version=0,
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
                    max_messages=max_messages - len(out),
                )
                correlation += 1
                if fetch_error:
                    if not out:
                        return None, fetch_error
                    continue
                if not fetch_items:
                    continue

                for offset, text in fetch_items:
                    out.append(f"p{partition}@{offset} {text}")
                    if len(out) >= max_messages:
                        break

            return out, None
    except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
        return None, _friendly_error_from_exception(exc)


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
) -> tuple[bool, dict[str, Any] | None, str | None]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            correlation = 1
            is_kafka, _api_error_code, api_error = _probe_apiversions(sock, correlation)
            correlation += 1
            if not is_kafka:
                return False, None, api_error or "service is not kafka"

            hs_ok, correlation, hs_error = _sasl_handshake_plain(sock, correlation)
            if not hs_ok:
                return False, None, hs_error or "SASL handshake failed"

            auth_ok, correlation, auth_error = _sasl_authenticate_plain(sock, correlation, username, password)
            if not auth_ok:
                return False, None, auth_error or "authentication failed"

            metadata, metadata_error = _fetch_metadata(sock, correlation, topics=None)
            if metadata is None:
                return False, None, metadata_error or "metadata request failed after auth"
            if bool(metadata.get("auth_required")):
                return False, None, "authentication failed"
            return True, metadata, None
    except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
        return False, None, _friendly_error_from_exception(exc)


def _read_dump_topics(
    *,
    host: str,
    port: int,
    timeout: float,
    topics: list[str],
    max_messages: int,
    username: str | None,
    password: str | None,
) -> tuple[dict[str, list[str] | None], dict[str, str]]:
    dump_results: dict[str, list[str] | None] = {}
    dump_errors: dict[str, str] = {}
    for topic_name in topics:
        read_items, read_error = _read_topic_messages(
            host=host,
            port=port,
            timeout=timeout,
            topic=topic_name,
            max_messages=max_messages,
            username=username,
            password=password,
        )
        dump_results[topic_name] = read_items
        if read_error:
            dump_errors[topic_name] = read_error
    return dump_results, dump_errors
