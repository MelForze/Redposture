"""Kafka broker audit stage."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import struct
import sys
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .console import Console
from .logger import AttemptLogger
from .utils import collect_scan_ports, collect_scan_targets, utc_now_iso

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


def _clip(text: str, width: int = 64) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _friendly_error_text(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return "connection failed"
    lower = text.lower()
    if "connection refused" in lower:
        return "connection refused (service is not listening on target port)"
    if "timed out" in lower or "timeout" in lower:
        return "connection timeout"
    if "name or service not known" in lower or "nodename nor servname provided" in lower:
        return "dns lookup failed"
    if "temporary failure in name resolution" in lower:
        return "dns lookup temporary failure"
    if "no route to host" in lower or "network is unreachable" in lower:
        return "network unreachable"
    if "operation not permitted" in lower:
        return "operation not permitted by local environment"
    match = re.search(r"\[errno\s+(-?\d+)\]\s*(.*)", text, flags=re.IGNORECASE)
    if match:
        errno_num = match.group(1)
        detail = (match.group(2) or "").strip()
        if errno_num in {"61", "111"}:
            return "connection refused (service is not listening on target port)"
        if errno_num in {"60", "110"}:
            return "connection timeout"
        if errno_num in {"8", "-2"}:
            return "dns lookup failed"
        if errno_num in {"65", "101", "113"}:
            return "network unreachable"
        if detail:
            return detail
    return text


def _friendly_error_from_exception(exc: BaseException) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "connection timeout"
    return _friendly_error_text(str(exc))


def _is_connection_refused_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and text.startswith(_CONNECTION_REFUSED_PREFIX)


def _is_connection_refused_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail" and _is_connection_refused_error(record.get("error"))


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


def _parse_message_set_entries(message_set: bytes, max_messages: int) -> list[tuple[int, str]]:
    items: list[tuple[int, str]] = []
    reader = _KafkaReader(message_set)

    while reader.remaining() >= 12 and len(items) < max_messages:
        try:
            offset = reader.read_i64()
            message_size = reader.read_i32()
            if message_size <= 0 or message_size > reader.remaining():
                break

            message_reader = _KafkaReader(reader._read(message_size))  # noqa: SLF001
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

            if username and password:
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
) -> tuple[dict[str, list[str]], dict[str, str]]:
    dump_results: dict[str, list[str]] = {}
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


def _audit_kafka_via_sasl_fallback(
    host: str,
    port: int,
    timeout: float,
    username: str | None,
    password: str | None,
    show_topics: bool,
    query_topic: str | None,
    dump: bool,
    max_messages: int,
) -> dict[str, Any] | None:
    provided_credentials = bool(username and password)
    started = time.monotonic()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            correlation = 1
            hs_ok, correlation, hs_error = _sasl_handshake_plain(sock, correlation)
            if not hs_ok:
                return None

            auth_required = True
            provided_credentials_ok: bool | None = None
            topic_map: dict[str, int] | None = None
            error_parts: list[str] = []

            if provided_credentials and username and password:
                auth_ok, correlation, auth_error = _sasl_authenticate_plain(sock, correlation, username, password)
                provided_credentials_ok = auth_ok
                if auth_ok:
                    metadata, metadata_error = _fetch_metadata(sock, correlation, topics=None)
                    if metadata is not None:
                        topic_map = dict(metadata.get("topic_map") or {})
                    elif metadata_error:
                        error_parts.append(metadata_error)
                elif auth_error:
                    error_parts.append(auth_error)
            elif hs_error:
                error_parts.append(hs_error)

            topic_names = sorted(topic_map.keys()) if isinstance(topic_map, dict) else None
            topic_count = len(topic_names) if isinstance(topic_names, list) else None

            query_topic_name = (query_topic or "").strip()
            query_topic_value: str | None = None
            if query_topic_name:
                if isinstance(topic_map, dict):
                    if query_topic_name in topic_map:
                        query_topic_value = f"{query_topic_name} (partitions:{int(topic_map[query_topic_name])})"
                    else:
                        query_topic_value = f"{query_topic_name}:<not found>"
                elif provided_credentials_ok:
                    query_topic_value = f"{query_topic_name}:<not available>"
                else:
                    query_topic_value = f"{query_topic_name}:<authentication required>"

            dump_topics: list[str] = []
            dump_results: dict[str, list[str]] = {}
            dump_errors: dict[str, str] = {}
            dump_error: str | None = None
            if dump:
                if isinstance(topic_map, dict):
                    if query_topic_name:
                        if query_topic_name in topic_map:
                            dump_topics = [query_topic_name]
                        else:
                            dump_error = "topic not found"
                    else:
                        dump_topics = sorted(topic_map.keys())
                elif provided_credentials_ok:
                    dump_error = "topic metadata unavailable"
                else:
                    dump_error = "authentication required"

                if dump_topics:
                    dump_results, dump_errors = _read_dump_topics(
                        host=host,
                        port=port,
                        timeout=timeout,
                        topics=dump_topics,
                        max_messages=max_messages,
                        username=username if provided_credentials_ok else None,
                        password=password if provided_credentials_ok else None,
                    )

            topic_messages: list[str] | None = None
            topic_read_error: str | None = None
            if dump and query_topic_name:
                topic_messages = dump_results.get(query_topic_name)
                topic_read_error = dump_errors.get(query_topic_name) or dump_error

            status = "valid_credentials" if provided_credentials_ok else "auth_required"
            error = "; ".join(item for item in error_parts if str(item).strip()) or None

            return {
                "timestamp": utc_now_iso(),
                "host": host,
                "port": port,
                "is_kafka": True,
                "status": status,
                "auth_required": auth_required,
                "provided_credentials": provided_credentials,
                "provided_username": username,
                "provided_credentials_ok": provided_credentials_ok,
                "show_topics": show_topics,
                "query_topic": query_topic_name or None,
                "topic_count": topic_count,
                "topics": topic_names,
                "query_topic_value": query_topic_value,
                "dump": bool(dump),
                "max_messages": max_messages if dump else None,
                "dump_topics": dump_topics if dump else None,
                "dump_results": dump_results if dump else None,
                "dump_errors": dump_errors if dump else None,
                "dump_error": dump_error,
                "topic_messages": topic_messages,
                "topic_read_error": topic_read_error,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "error": error,
            }
    except (TimeoutError, ConnectionError, OSError, ValueError):
        return None


def _audit_kafka_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    show_topics: bool,
    query_topic: str | None,
    dump: bool,
    max_messages: int,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    provided_credentials = bool(username and password)
    last_error: str | None = None

    for attempt in range(attempts):
        started = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)

                correlation = 1
                is_kafka, api_error_code, api_error = _probe_apiversions(sock, correlation)
                correlation += 1
                if not is_kafka:
                    if _is_sasl_probe_candidate(api_error):
                        fallback_record = _audit_kafka_via_sasl_fallback(
                            host=host,
                            port=port,
                            timeout=timeout,
                            username=username,
                            password=password,
                            show_topics=show_topics,
                            query_topic=query_topic,
                            dump=dump,
                            max_messages=max_messages,
                        )
                        if fallback_record is not None:
                            return fallback_record
                    return {
                        "timestamp": utc_now_iso(),
                        "host": host,
                        "port": port,
                        "is_kafka": False,
                        "status": "fail",
                        "auth_required": None,
                        "provided_credentials": provided_credentials,
                        "provided_username": username,
                        "provided_credentials_ok": None,
                        "show_topics": show_topics,
                        "query_topic": query_topic,
                        "dump": bool(dump),
                        "max_messages": max_messages if dump else None,
                        "topic_count": None,
                        "topics": None,
                        "query_topic_value": None,
                        "dump_topics": None,
                        "dump_results": None,
                        "dump_errors": None,
                        "dump_error": None,
                        "topic_messages": None,
                        "topic_read_error": None,
                        "elapsed_ms": int((time.monotonic() - started) * 1000),
                        "error": api_error
                        or (
                            f"ApiVersions failed ({_kafka_error_name(int(api_error_code))})"
                            if api_error_code is not None
                            else "service is not kafka"
                        ),
                    }

                metadata, metadata_error = _fetch_metadata(sock, correlation, topics=None)

                auth_required: bool | None = None
                topic_map: dict[str, int] | None = None
                error_parts: list[str] = []

                if metadata is not None:
                    auth_required = bool(metadata.get("auth_required"))
                    if not auth_required:
                        topic_map = dict(metadata.get("topic_map") or {})
                    else:
                        error_codes = metadata.get("error_codes")
                        if isinstance(error_codes, list) and error_codes:
                            names = sorted(
                                {
                                    _kafka_error_name(int(code))
                                    for code in error_codes
                                    if int(code) in KAFKA_AUTH_ERROR_CODES
                                }
                            )
                            if names:
                                error_parts.append(f"auth errors: {','.join(names)}")
                else:
                    if _is_probable_auth_error(metadata_error):
                        auth_required = True
                    else:
                        auth_required = None
                    if metadata_error:
                        error_parts.append(metadata_error)

                provided_credentials_ok: bool | None = None
                if (auth_required is True or auth_required is None) and provided_credentials and username and password:
                    auth_ok, auth_metadata, auth_error = _authenticate_and_fetch_metadata(
                        host, port, timeout, username, password
                    )
                    provided_credentials_ok = auth_ok
                    if auth_ok and auth_metadata is not None:
                        auth_required = True
                        topic_map = dict(auth_metadata.get("topic_map") or {})
                        error_parts = []
                    elif auth_error:
                        error_parts.append(auth_error)
                        if auth_required is None:
                            auth_required = True

                topic_names = sorted(topic_map.keys()) if isinstance(topic_map, dict) else None
                topic_count = len(topic_names) if isinstance(topic_names, list) else None

                query_topic_name = (query_topic or "").strip()
                query_topic_value: str | None = None
                if query_topic_name:
                    if isinstance(topic_map, dict):
                        if query_topic_name in topic_map:
                            query_topic_value = f"{query_topic_name} (partitions:{int(topic_map[query_topic_name])})"
                        else:
                            query_topic_value = f"{query_topic_name}:<not found>"
                    elif auth_required is True and not bool(provided_credentials_ok):
                        query_topic_value = f"{query_topic_name}:<authentication required>"
                    else:
                        query_topic_value = f"{query_topic_name}:<not available>"

                dump_topics: list[str] = []
                dump_results: dict[str, list[str]] = {}
                dump_errors: dict[str, str] = {}
                dump_error: str | None = None
                if dump:
                    if isinstance(topic_map, dict):
                        if query_topic_name:
                            if query_topic_name in topic_map:
                                dump_topics = [query_topic_name]
                            else:
                                dump_error = "topic not found"
                        else:
                            dump_topics = sorted(topic_map.keys())
                    elif auth_required is True and not bool(provided_credentials_ok):
                        dump_error = "authentication required"
                    else:
                        dump_error = "topic metadata unavailable"

                    if dump_topics:
                        dump_results, dump_errors = _read_dump_topics(
                            host=host,
                            port=port,
                            timeout=timeout,
                            topics=dump_topics,
                            max_messages=max_messages,
                            username=username if bool(provided_credentials_ok) else None,
                            password=password if bool(provided_credentials_ok) else None,
                        )

                topic_messages: list[str] | None = None
                topic_read_error: str | None = None
                if dump and query_topic_name:
                    topic_messages = dump_results.get(query_topic_name)
                    topic_read_error = dump_errors.get(query_topic_name) or dump_error

                if auth_required is False:
                    status = "open_no_auth"
                elif provided_credentials_ok:
                    status = "valid_credentials"
                elif auth_required is True:
                    status = "auth_required"
                else:
                    status = "unknown_auth"

                error = "; ".join(item for item in error_parts if str(item).strip()) or None

                return {
                    "timestamp": utc_now_iso(),
                    "host": host,
                    "port": port,
                    "is_kafka": True,
                    "status": status,
                    "auth_required": auth_required,
                    "provided_credentials": provided_credentials,
                    "provided_username": username,
                    "provided_credentials_ok": provided_credentials_ok,
                    "show_topics": show_topics,
                    "query_topic": query_topic_name or None,
                    "dump": bool(dump),
                    "max_messages": max_messages if dump else None,
                    "topic_count": topic_count,
                    "topics": topic_names,
                    "query_topic_value": query_topic_value,
                    "dump_topics": dump_topics if dump else None,
                    "dump_results": dump_results if dump else None,
                    "dump_errors": dump_errors if dump else None,
                    "dump_error": dump_error,
                    "topic_messages": topic_messages,
                    "topic_read_error": topic_read_error,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error": error,
                }
        except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
            last_error = _friendly_error_from_exception(exc)
            if _is_sasl_probe_candidate(last_error):
                fallback_record = _audit_kafka_via_sasl_fallback(
                    host=host,
                    port=port,
                    timeout=timeout,
                    username=username,
                    password=password,
                    show_topics=show_topics,
                    query_topic=query_topic,
                    dump=dump,
                    max_messages=max_messages,
                )
                if fallback_record is not None:
                    return fallback_record
            if attempt >= attempts - 1:
                break
            time.sleep(_retry_delay(attempt))

    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "is_kafka": False,
        "status": "fail",
        "auth_required": None,
        "provided_credentials": provided_credentials,
        "provided_username": username,
        "provided_credentials_ok": None,
        "show_topics": show_topics,
        "query_topic": (query_topic or "").strip() or None,
        "dump": bool(dump),
        "max_messages": max_messages if dump else None,
        "topic_count": None,
        "topics": None,
        "query_topic_value": None,
        "dump_topics": None,
        "dump_results": None,
        "dump_errors": None,
        "dump_error": None,
        "topic_messages": None,
        "topic_read_error": None,
        "elapsed_ms": None,
        "error": last_error or "connection failed",
    }


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{'KAFKA':<8}\t{host}\t{port}\t"


def _with_optional_topics(record: dict[str, Any], message: str) -> str:
    topic_count = record.get("topic_count")
    if not isinstance(topic_count, int):
        return f"{message} (topics:-)"
    return f"{message} (topics:{topic_count})"


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    auth_required_value = record.get("auth_required")
    auth_required_text = (
        "True" if auth_required_value is True else "False" if auth_required_value is False else "unknown"
    )
    if output_format == "json":
        return json.dumps(
            {
                "timestamp": record.get("timestamp"),
                "type": "detect",
                "host": record.get("host"),
                "port": record.get("port"),
                "service": "kafka",
                "detected": bool(record.get("is_kafka")),
                "auth_required": auth_required_value,
            },
            ensure_ascii=False,
        )
    return f"{_nxc_prefix(record)} [*] Kafka Broker (auth required:{auth_required_text})"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    status = str(record.get("status") or "fail")
    prefix = _nxc_prefix(record)
    err = _clip(str(record.get("error") or "-"), 72)

    if status == "open_no_auth":
        return _with_optional_topics(record, f"{prefix} [+] anonymous access")

    if status == "valid_credentials":
        username = str(record.get("provided_username") or "user").strip() or "user"
        return _with_optional_topics(record, f"{prefix} [+] {username}")

    if status == "auth_required":
        if record.get("provided_credentials"):
            username = str(record.get("provided_username") or "user").strip() or "user"
            base = f"{prefix} [-] {username} invalid"
        else:
            base = f"{prefix} [-] authentication required"
        if err != "-":
            return f"{base} err={err}"
        return base

    if status == "unknown_auth":
        line = f"{prefix} [!] auth status unknown"
        if err != "-":
            return f"{line} err={err}"
        return line

    line = f"{prefix} [!] connection failed"
    if err != "-":
        return f"{line} err={err}"
    return line


def _format_topics_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    show_topics = bool(record.get("show_topics"))
    query_topic = str(record.get("query_topic") or "").strip()
    query_topic_value = record.get("query_topic_value")
    dump = bool(record.get("dump"))
    max_messages = int(record.get("max_messages") or 0)
    topic_messages_raw = record.get("topic_messages")
    topic_messages: list[str] = (
        [str(item) for item in topic_messages_raw] if isinstance(topic_messages_raw, list) else []
    )
    topic_read_error = str(record.get("topic_read_error") or "").strip()

    topics = record.get("topics")
    topic_names: list[str] = []
    if isinstance(topics, list):
        topic_names = sorted(str(item) for item in topics)

    dump_topics_raw = record.get("dump_topics")
    dump_topics: list[str] = []
    if isinstance(dump_topics_raw, list):
        dump_topics = [str(item) for item in dump_topics_raw if str(item).strip()]

    dump_results_raw = record.get("dump_results")
    dump_results: dict[str, list[str]] = {}
    if isinstance(dump_results_raw, dict):
        for topic_name, values in dump_results_raw.items():
            key = str(topic_name).strip()
            if not key:
                continue
            if isinstance(values, list):
                dump_results[key] = [str(item) for item in values]
            else:
                dump_results[key] = []

    dump_errors_raw = record.get("dump_errors")
    dump_errors: dict[str, str] = {}
    if isinstance(dump_errors_raw, dict):
        for topic_name, value in dump_errors_raw.items():
            key = str(topic_name).strip()
            if not key:
                continue
            dump_errors[key] = str(value or "").strip()

    dump_error = str(record.get("dump_error") or "").strip()

    # Keep compatibility with older record fields for query-topic dump.
    if query_topic:
        if query_topic not in dump_results and topic_messages:
            dump_results[query_topic] = topic_messages
        if query_topic not in dump_errors and topic_read_error:
            dump_errors[query_topic] = topic_read_error
        if query_topic not in dump_topics and (query_topic in dump_results or query_topic in dump_errors):
            dump_topics.append(query_topic)

    if not show_topics and not query_topic and not dump:
        return []

    if output_format == "json":
        lines: list[str] = []
        if show_topics and topic_names:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "topics_list",
                        "service": "kafka",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "topic_count": record.get("topic_count"),
                        "topics": topic_names,
                    },
                    ensure_ascii=False,
                )
            )
        if query_topic:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "topic_query",
                        "service": "kafka",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "topic": query_topic,
                        "value": query_topic_value,
                    },
                    ensure_ascii=False,
                )
            )
        if dump:
            if dump_topics:
                for topic_name in dump_topics:
                    topic_dump_messages = dump_results.get(topic_name, [])
                    topic_dump_error = dump_errors.get(topic_name) or None
                    lines.append(
                        json.dumps(
                            {
                                "timestamp": record.get("timestamp"),
                                "type": "topic_dump",
                                "service": "kafka",
                                "host": record.get("host"),
                                "port": record.get("port"),
                                "topic": topic_name,
                                "max_messages": max_messages,
                                "message_count": len(topic_dump_messages),
                                "messages": topic_dump_messages,
                                "error": topic_dump_error,
                            },
                            ensure_ascii=False,
                        )
                    )
            elif dump_error:
                lines.append(
                    json.dumps(
                        {
                            "timestamp": record.get("timestamp"),
                            "type": "topic_dump",
                            "service": "kafka",
                            "host": record.get("host"),
                            "port": record.get("port"),
                            "topic": query_topic or None,
                            "max_messages": max_messages,
                            "message_count": 0,
                            "messages": [],
                            "error": dump_error,
                        },
                        ensure_ascii=False,
                    )
                )
        return lines

    prefix = _nxc_prefix(record)
    lines: list[str] = []
    if show_topics and topic_names:
        lines.append(f"{prefix} [*] Show Topics")
        for item in topic_names:
            lines.append(f"{prefix} {item}")
    if query_topic:
        lines.append(f"{prefix} [*] Topic {query_topic}")
        if isinstance(query_topic_value, str):
            lines.append(f"{prefix} {query_topic_value}")
    if dump:
        if query_topic:
            lines.append(f"{prefix} [*] Dump Topic {query_topic} (max:{max_messages})")
            topic_dump_messages = dump_results.get(query_topic, [])
            topic_dump_error = dump_errors.get(query_topic) or dump_error
            if topic_dump_messages:
                for item in topic_dump_messages:
                    lines.append(f"{prefix} {item}")
            elif topic_dump_error:
                lines.append(f"{prefix} [-] {topic_dump_error}")
            else:
                lines.append(f"{prefix} <no messages>")
        else:
            lines.append(f"{prefix} [*] Dump Topics (max:{max_messages})")
            if dump_topics:
                for topic_name in dump_topics:
                    lines.append(f"{prefix} [*] Topic {topic_name}")
                    topic_dump_messages = dump_results.get(topic_name, [])
                    topic_dump_error = dump_errors.get(topic_name, "")
                    if topic_dump_messages:
                        for item in topic_dump_messages:
                            lines.append(f"{prefix} {item}")
                    elif topic_dump_error:
                        lines.append(f"{prefix} [-] {topic_dump_error}")
                    else:
                        lines.append(f"{prefix} <no messages>")
            elif dump_error:
                lines.append(f"{prefix} [-] {dump_error}")
            else:
                lines.append(f"{prefix} <no topics>")
    return lines


def _render_colored_kafka_line(console: Console, line: str) -> bool:
    if not line.startswith("KAFKA"):
        return False

    marker_color = {
        "[*]": "cyan",
        "[+]": "bright_green",
        "[-]": "yellow",
        "[!]": "red",
    }

    for marker in ("[!]", "[-]", "[+]", "[*]"):
        token = f" {marker} "
        if token not in line:
            continue

        left, right = line.split(token, 1)
        tag = "KAFKA"
        rest = left[len(tag) :] if left.startswith(tag) else left

        spans: list[tuple[int, int, str]] = []
        auth_true = "(auth required:True)"
        auth_false = "(auth required:False)"
        auth_unknown = "(auth required:unknown)"
        idx_true = right.find(auth_true)
        if idx_true >= 0:
            spans.append((idx_true, idx_true + len(auth_true), "bright_green"))
        idx_false = right.find(auth_false)
        if idx_false >= 0:
            spans.append((idx_false, idx_false + len(auth_false), "red"))
        idx_unknown = right.find(auth_unknown)
        if idx_unknown >= 0:
            spans.append((idx_unknown, idx_unknown + len(auth_unknown), "yellow"))

        topics_match = re.search(r"\(topics:(\d+)(?: [^)]*)?\)", right)
        if topics_match:
            topics_value = topics_match.group(1).strip()
            if topics_value.isdigit() and int(topics_value) > 0:
                spans.append((topics_match.start(), topics_match.end(), "red"))

        if not spans:
            right_colored = console._paint(right, "white", sys.stdout)
        else:
            chunks: list[str] = []
            cursor = 0
            for start, end, color in sorted(spans, key=lambda item: item[0]):
                if start < cursor:
                    continue
                if start > cursor:
                    chunks.append(console._paint(right[cursor:start], "white", sys.stdout))
                chunks.append(console._paint(right[start:end], color, sys.stdout))
                cursor = end
            if cursor < len(right):
                chunks.append(console._paint(right[cursor:], "white", sys.stdout))
            right_colored = "".join(chunks)

        colored = (
            f"{console._paint(tag, 'blue', sys.stdout)}"
            f"{console._paint(rest, 'white', sys.stdout)} "
            f"{console._paint(marker, marker_color[marker], sys.stdout)} "
            f"{right_colored}"
        )
        console.plain(colored)
        return True

    return False


def _emit_line(out_fh: Any, emit_line: Callable[[str], None] | None, line: str) -> None:
    if out_fh is not None:
        out_fh.write(line + "\n")
        out_fh.flush()
    if emit_line is not None:
        emit_line(line)


def audit_kafka_targets(
    hosts: list[str],
    port: int,
    timeout: float,
    retries: int,
    workers: int,
    username: str | None,
    password: str | None,
    show_topics: bool,
    query_topic: str | None,
    dump: bool,
    max_messages: int,
    output_path: str | None,
    output_format: str,
    emit_line: Callable[[str], None] | None = None,
    logger: AttemptLogger | None = None,
    append_output: bool = False,
    suppress_connection_refused_debug_errors: bool = False,
) -> tuple[int, int, int, int, int]:
    total = 0
    open_no_auth = 0
    valid = 0
    auth_required = 0
    failed = 0

    out_fh: Any = None
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        out_fh = open(output_path, "a" if append_output else "w", encoding="utf-8")

    try:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
            future_map = {
                executor.submit(
                    _audit_kafka_host,
                    host,
                    port,
                    timeout,
                    retries,
                    username,
                    password,
                    show_topics,
                    query_topic,
                    dump,
                    max_messages,
                ): host
                for host in hosts
            }
            for future in as_completed(future_map):
                record = future.result()
                total += 1
                status = str(record.get("status") or "fail")
                if status == "open_no_auth":
                    open_no_auth += 1
                elif status == "valid_credentials":
                    valid += 1
                elif status == "auth_required":
                    auth_required += 1
                else:
                    failed += 1

                if bool(record.get("is_kafka")):
                    _emit_line(out_fh, emit_line, _format_detect_record(record, output_format))

                suppress_auth_required_status_line = (
                    output_format == "txt"
                    and bool(record.get("is_kafka"))
                    and status == "auth_required"
                    and not bool(record.get("provided_credentials"))
                )
                suppress_connection_refused_status_line = (
                    suppress_connection_refused_debug_errors
                    and output_format == "txt"
                    and _is_connection_refused_fail_record(record)
                )
                if not suppress_auth_required_status_line and not suppress_connection_refused_status_line:
                    _emit_line(out_fh, emit_line, _format_record(record, output_format))
                if bool(record.get("is_kafka")):
                    for topics_line in _format_topics_detail_records(record, output_format):
                        _emit_line(out_fh, emit_line, topics_line)

                if logger is not None and not (
                    suppress_connection_refused_debug_errors and _is_connection_refused_fail_record(record)
                ):
                    logger.log(
                        "kafka",
                        (str(record.get("host") or "-"), int(record.get("port") or port)),
                        phase="audit",
                        status=record.get("status"),
                        auth_required=record.get("auth_required"),
                        provided_credentials_ok=record.get("provided_credentials_ok"),
                        topic_count=record.get("topic_count"),
                        topic=record.get("query_topic"),
                        dump=record.get("dump"),
                        dump_topics=record.get("dump_topics"),
                        dump_error=record.get("dump_error"),
                        topic_read_error=record.get("topic_read_error"),
                        error=record.get("error"),
                    )
    finally:
        if out_fh is not None:
            out_fh.close()

    return total, open_no_auth, valid, auth_required, failed


def run_kafka_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
    console = Console(debug=args.debug)

    if args.timeout <= 0:
        console.error("--timeout must be > 0")
        return 2
    if args.retries < 0:
        console.error("--retries must be >= 0")
        return 2
    if args.max_messages <= 0:
        console.error("--max-messages must be > 0")
        return 2
    if bool(args.username) != bool(args.password):
        console.error("--username and --password must be set together")
        return 2
    try:
        ports = collect_scan_ports(getattr(args, "ports", None))
    except ValueError as exc:
        console.error(f"failed to parse --port: {exc}")
        return 2
    if not ports:
        ports = [int(args.port)]

    targets = getattr(args, "targets", None) or getattr(args, "hosts", None)
    hosts_file = getattr(args, "hosts_file", None)
    if hosts_file:
        targets = f"{targets},{hosts_file}" if targets else hosts_file

    try:
        hosts = collect_scan_targets(targets)
    except (OSError, ValueError) as exc:
        console.error(f"failed to parse targets: {exc}")
        return 2

    if not hosts:
        console.error("kafka requires -t/--targets")
        return 2

    stream_to_stdout = not bool(args.output)

    def emit_line(line: str) -> None:
        if args.output_format != "txt":
            print(line, flush=True)
            return
        if line.startswith("KAFKA") and all(token not in line for token in (" [*] ", " [+] ", " [-] ", " [!] ")):
            if console.render_tagged_payload_line(line, "KAFKA", payload_color="orange"):
                return
            console.plain(line, color="white")
            return
        if _render_colored_kafka_line(console, line):
            return
        if args.debug:
            console.plain(line)

    if args.debug and stream_to_stdout and args.output_format == "txt":
        mode_parts: list[str] = []
        if args.username and args.password:
            mode_parts.append("provided-creds")
        if args.show_topics:
            mode_parts.append("show-topics")
        if args.topic:
            mode_parts.append(f"topic={args.topic}")
        if args.dump:
            mode_parts.append(f"dump,max={args.max_messages}")
        mode = ",".join(mode_parts) if mode_parts else "detect-only"
        console.info(
            f"kafka audit started: hosts={len(hosts)} ports={len(ports)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} mode={mode} format=txt"
        )
    if args.debug and not stream_to_stdout:
        mode_parts = []
        if args.username and args.password:
            mode_parts.append("provided-creds")
        if args.show_topics:
            mode_parts.append("show-topics")
        if args.topic:
            mode_parts.append(f"topic={args.topic}")
        if args.dump:
            mode_parts.append(f"dump,max={args.max_messages}")
        mode = ",".join(mode_parts) if mode_parts else "detect-only"
        console.info(
            f"kafka audit started: hosts={len(hosts)} ports={len(ports)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} mode={mode} "
            f"format={args.output_format} output={args.output}"
        )

    total = 0
    open_no_auth = 0
    valid = 0
    auth_required = 0
    failed = 0
    try:
        for idx, audit_port in enumerate(ports):
            part_total, part_open, part_valid, part_auth, part_failed = audit_kafka_targets(
                hosts=hosts,
                port=audit_port,
                timeout=args.timeout,
                retries=args.retries,
                workers=args.workers,
                username=args.username,
                password=args.password,
                show_topics=args.show_topics,
                query_topic=args.topic,
                dump=args.dump,
                max_messages=args.max_messages,
                output_path=args.output,
                output_format=args.output_format,
                emit_line=emit_line,
                logger=logger if args.debug else None,
                append_output=idx > 0,
                suppress_connection_refused_debug_errors=bool(args.debug),
            )
            total += part_total
            open_no_auth += part_open
            valid += part_valid
            auth_required += part_auth
            failed += part_failed
    except OSError as exc:
        console.error(f"failed to process kafka output: {exc}")
        return 2

    if stream_to_stdout:
        if (
            total > 0
            and open_no_auth == 0
            and valid == 0
            and auth_required == 0
            and failed == total
            and args.output_format == "txt"
        ):
            console.warn("all kafka targets are unreachable; check host/port, network reachability, and service status")

    if args.debug:
        console.info(
            f"kafka audit complete: total={total} anonymous={open_no_auth} valid={valid} "
            f"auth_required={auth_required} fail={failed}"
        )

    return 0
